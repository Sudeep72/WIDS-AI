from __future__ import annotations

import json
import logging
import socket
import sqlite3
import threading
import time
import uuid
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from wids_ai.correlation.schema import Alert, AttackMapping
from wids_ai.rules.schema import Evidence
from wids_ai.siem import exporter as exporter_module
from wids_ai.siem.exporter import FileSink, HttpSink, NanoSIEMExporter, Sink
from wids_ai.siem.mapping import SYSLOG_SEVERITY, alert_to_event
from wids_ai.siem.schema import (
    NANOSIEM_EVENT_KEYS,
    NANOSIEM_FIELD_KEYS,
    NormalizedEvent,
)
from wids_ai.storage.db import Database

NOW = datetime(2026, 11, 2, 12, 0, 5, tzinfo=UTC)


def _alert(
    *,
    alert_id: str = "ALT-0123456789abcdef",
    severity: str = "high",
    hit_count: int = 1,
    ssid: str = "LabNet",
    why: str = "Evil twin evidence was observed for BSSID 02:de:ad:be:ef:01.",
) -> Alert:
    evidence = Evidence(
        field="distinct_bssids",
        observed=2,
        threshold=2,
        operator="ge",
        text="distinct_bssids was 2, expected ge 2",
        rule_ids=("WIDS-EVIL-001",),
    )
    return Alert(
        id=alert_id,
        timestamp=NOW,
        family="evil_twin_rogue_ap",
        severity=severity,  # type: ignore[arg-type]
        risk_score=72,
        rule_evidence=[evidence],
        evidence=[evidence],
        ml_anomaly_score=0.42,
        why=why,
        reasons=[],
        indicators_found=[evidence],
        indicators_not_found=[],
        recommended_check="Verify the BSSID and OUI against the trusted inventory.",
        bssids=("02:de:ad:be:ef:01",),
        ssids=(ssid,),
        clients=("00:aa:bb:cc:dd:ee",),
        mitre_attack=AttackMapping(
            tactic="Credential Access",
            technique="T1557",
            technique_name="Adversary-in-the-Middle",
            matrix="Enterprise",
            verified=True,
        ),
        rule_ids=("WIDS-EVIL-001",),
        raw_frame_counts={"WIDS-EVIL-001": 3},
        first_seen=NOW,
        last_seen=NOW + timedelta(seconds=10),
        hit_count=hit_count,
    )


def _payload(alert: Alert | None = None) -> dict:
    return alert_to_event(alert or _alert(), host="lab-sensor-1").model_dump(mode="json")


def test_schema_has_exact_twenty_key_contract() -> None:
    expected = (
        "event_id",
        "timestamp",
        "ingested_at",
        "host",
        "source_ip",
        "dest_ip",
        "source_port",
        "dest_port",
        "log_source",
        "facility",
        "severity",
        "program",
        "pid",
        "message",
        "raw",
        "fields",
        "tags",
        "anomaly_score",
        "sigma_matches",
        "alert_id",
    )
    assert expected == NANOSIEM_EVENT_KEYS
    payload = _payload()
    assert tuple(payload) == expected
    assert len(payload) == 20
    assert tuple(payload["fields"]) == NANOSIEM_FIELD_KEYS


def test_event_types_and_null_ip_contract() -> None:
    payload = _payload()
    assert isinstance(payload["event_id"], str)
    assert isinstance(payload["timestamp"], str)
    assert payload["timestamp"].endswith("+00:00")
    assert isinstance(payload["ingested_at"], str)
    assert payload["ingested_at"].endswith("+00:00")
    assert payload["host"] == "lab-sensor-1"
    for key in ("source_ip", "dest_ip", "source_port", "dest_port", "facility", "pid"):
        assert payload[key] is None
    assert payload["log_source"] == "json"
    assert payload["program"] == "wids-ai"
    assert isinstance(payload["message"], str)
    assert isinstance(payload["raw"], str)
    assert len(payload["raw"].encode("utf-8")) <= 8192
    assert isinstance(json.loads(payload["raw"]), dict)
    assert isinstance(payload["fields"], dict)
    assert isinstance(payload["tags"], list)
    assert payload["anomaly_score"] is None
    assert payload["sigma_matches"] == []
    assert payload["alert_id"] is None
    assert payload["severity"] == "err"
    assert uuid.UUID(payload["event_id"]).version == 5


def test_severity_mapping_is_exact() -> None:
    expected = {
        "critical": "crit",
        "high": "err",
        "medium": "warning",
        "low": "notice",
        "informational": "info",
    }
    assert expected == SYSLOG_SEVERITY
    for wids_severity, syslog_severity in expected.items():
        event = alert_to_event(_alert(severity=wids_severity), host="sensor")
        assert event.severity == syslog_severity
        assert event.fields["wids_severity"] == wids_severity


def test_tags_fields_and_attack_mapping_are_exact() -> None:
    event = alert_to_event(_alert(), host="sensor", ingested_at=NOW + timedelta(seconds=1))
    assert event.tags == [
        "wids",
        "wids:family:evil_twin_rogue_ap",
        "wids:severity:high",
        "attack:T1557",
    ]
    fields = event.fields
    assert fields["wids_alert_id"] == "ALT-0123456789abcdef"
    assert fields["wids_family"] == "evil_twin_rogue_ap"
    assert fields["wids_rule_ids"] == ["WIDS-EVIL-001"]
    assert fields["wids_risk_score"] == 72
    assert fields["wids_ml_score"] == pytest.approx(0.42)
    assert fields["wids_bssids"] == ["02:de:ad:be:ef:01"]
    assert fields["wids_ssids"] == ["LabNet"]
    assert fields["wids_clients"] == ["00:aa:bb:cc:dd:ee"]
    assert fields["wids_hit_count"] == 1
    assert fields["mitre_tactic"] == "Credential Access"
    assert fields["mitre_technique"] == "T1557"
    assert fields["mitre_technique_name"] == "Adversary-in-the-Middle"
    assert fields["wids_schema_version"] == 1
    assert event.timestamp == "2026-11-02T12:00:05+00:00"
    assert event.ingested_at == "2026-11-02T12:00:06+00:00"


def test_no_technique_omits_attack_tag() -> None:
    alert = _alert().model_copy(update={"mitre_attack": None})
    event = alert_to_event(alert, host="sensor")
    assert event.tags == [
        "wids",
        "wids:family:evil_twin_rogue_ap",
        "wids:severity:high",
    ]
    assert event.fields["mitre_technique"] is None


def test_event_id_is_deterministic_and_tracks_state() -> None:
    first = alert_to_event(_alert(), host="sensor")
    second = alert_to_event(_alert(), host="other-sensor")
    changed = alert_to_event(_alert(hit_count=2), host="sensor")
    expected = str(uuid.uuid5(uuid.NAMESPACE_URL, "ALT-0123456789abcdef:1"))
    assert first.event_id == second.event_id == expected
    assert changed.event_id != first.event_id


def test_host_defaults_to_machine_hostname() -> None:
    event = alert_to_event(_alert())
    assert event.host == socket.gethostname()


def test_message_is_complete_and_capped_at_sentence_boundary() -> None:
    short = alert_to_event(_alert(), host="sensor")
    assert short.message == (
        "WIDS-AI evil_twin_rogue_ap (risk 72): "
        "Evil twin evidence was observed for BSSID 02:de:ad:be:ef:01."
    )
    long_text = "First sentence remains whole. " + ("word " * 300)
    event = alert_to_event(_alert(why=long_text), host="sensor")
    assert len(event.message) <= 500
    assert event.message.endswith((".", "!", "?", "..."))
    assert "First sentence remains whole." in event.message


def test_raw_keeps_one_evidence_copy_and_api_contract() -> None:
    alert = _alert()
    event = alert_to_event(alert, host="sensor")
    raw = json.loads(event.raw)
    assert "evidence" in raw
    assert "rule_evidence" not in raw
    assert "indicators_found" not in raw
    api_payload = alert.model_dump(mode="json")
    assert "evidence" in api_payload
    assert "indicators_found" in api_payload


def test_raw_is_valid_and_bounded_for_oversized_alert() -> None:
    alert = _alert().model_copy(
        update={
            "ssids": tuple("X" * 800 for _ in range(100)),
            "why": "Y" * 4000,
        }
    )
    event = alert_to_event(alert, host="sensor")
    assert len(event.raw.encode("utf-8")) <= 8192
    parsed = json.loads(event.raw)
    assert isinstance(parsed, dict)
    assert parsed.get("_truncated") is True


def test_ndjson_integrity_with_hostile_ssid(tmp_path: Path) -> None:
    hostile = '<img src=x onerror=alert(1)>\n"quote" \\ backslash \u0000 caf\u00e9 \u03bb\u2028'
    alert = _alert(ssid=hostile, why=f"Observed SSID {hostile}.\nSecond line")
    event = alert_to_event(alert, host="sensor")
    path = tmp_path / "events.ndjson"
    sink = FileSink(path)
    sink.deliver(event, event.model_dump(mode="json"))
    sink.close()
    raw = path.read_bytes()
    assert b"\r" not in raw
    lines = raw.decode("utf-8").splitlines()
    assert len(lines) == 1
    loaded = json.loads(lines[0])
    assert loaded == event.model_dump(mode="json")
    serialized = lines[0]
    assert "onerror=alert(1)" in serialized
    assert "caf\u00e9" in serialized or "caf\u00e9" in loaded["fields"]["wids_ssids"][0]
    assert "\u0000" not in serialized
    assert "\nSecond line" not in serialized
    assert "\u2028" not in serialized
    assert loaded["fields"]["wids_ssids"][0].endswith("\u03bb")


def test_file_sink_rotates_and_appends(tmp_path: Path) -> None:
    path = tmp_path / "events.ndjson"
    sink = FileSink(path, max_bytes=20, backup_count=2)
    event = alert_to_event(_alert(), host="sensor")
    payload = event.model_dump(mode="json")
    sink.deliver(event, payload)
    sink.deliver(event, payload)
    sink.close()
    assert path.with_name("events.ndjson.1").exists()
    assert json.loads(path.read_text(encoding="utf-8").strip())["event_id"] == event.event_id


def test_export_is_idempotent_until_hit_count_changes(tmp_path: Path) -> None:
    path = tmp_path / "events.ndjson"
    with Database(tmp_path / "wids.db") as db:
        exporter = NanoSIEMExporter(db, [FileSink(path)], sensor_name="sensor")
        assert exporter.export([_alert()]) == 1
        assert exporter.export([_alert()]) == 0
        assert exporter.export([_alert(hit_count=2)]) == 1
        exporter.close()
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["event_id"] != json.loads(lines[1])["event_id"]


class _Server:
    def __init__(self, status: int = 200, delay: float = 0.0) -> None:
        self.status = status
        self.delay = delay
        self.received: list[dict] = []
        self.attempts = 0
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                outer.attempts += 1
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length)
                outer.received.append(json.loads(body))
                if outer.delay:
                    time.sleep(outer.delay)
                self.send_response(outer.status)
                self.end_headers()

            def log_message(self, format: str, *args) -> None:
                return

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        _host, port = self.httpd.server_address[:2]
        return f"http://127.0.0.1:{port}/ingest"

    def __enter__(self) -> _Server:
        self.thread.start()
        return self

    def __exit__(self, *_args) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)


def test_http_sink_success() -> None:
    event = alert_to_event(_alert(), host="sensor")
    payload = event.model_dump(mode="json")
    with _Server() as server:
        sink = HttpSink(server.url, retries=0)
        sink.deliver(event, payload)
        sink.close()
        assert server.attempts == 1
        assert server.received == [payload]


def test_http_sink_retries_500() -> None:
    event = alert_to_event(_alert(), host="sensor")
    payload = event.model_dump(mode="json")
    with _Server(status=500) as server:
        sink = HttpSink(server.url, retries=2, backoff=0.001)
        sink.deliver(event, payload)
        sink.close()
        assert server.attempts == 3


def test_http_sink_timeout_is_bounded() -> None:
    event = alert_to_event(_alert(), host="sensor")
    payload = event.model_dump(mode="json")
    with _Server(delay=0.2) as server:
        sink = HttpSink(server.url, timeout=0.03, retries=1, backoff=0.001)
        started = time.monotonic()
        sink.deliver(event, payload)
        sink.close()
        elapsed = time.monotonic() - started
        assert server.attempts >= 2
        assert elapsed < 2.0


def test_http_sink_queue_overflow_drops_without_blocking(
    caplog: pytest.LogCaptureFixture,
) -> None:
    release = threading.Event()
    started = threading.Event()

    class BlockingHttpSink(HttpSink):
        def _post(self, payload: dict) -> None:
            started.set()
            release.wait(timeout=2)

    event = alert_to_event(_alert(), host="sensor")
    payload = event.model_dump(mode="json")
    sink = BlockingHttpSink("http://127.0.0.1:9", queue_size=1, retries=0)
    with caplog.at_level(logging.WARNING, logger="wids_ai.siem.exporter"):
        sink.deliver(event, payload)
        assert started.wait(timeout=1)
        sink.deliver(event, payload)
        assert sink.deliver(event, payload) is False
        assert "queue full" in caplog.text
    release.set()
    sink.close()


def test_http_sink_https_only_except_localhost() -> None:
    with pytest.raises(ValueError, match="HTTPS"):
        HttpSink("http://example.com/ingest")
    with pytest.raises(ValueError, match="HTTPS"):
        HttpSink("ftp://example.com/ingest")
    local = HttpSink("http://localhost:9/ingest", retries=0)
    local.close()
    loopback = HttpSink("http://127.0.0.1:9/ingest", retries=0)
    loopback.close()
    secure = HttpSink("https://example.com/ingest", retries=0)
    secure.close()


def test_token_never_appears_in_logs_or_errors(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    secret = "nanosiem-super-secret-token"
    monkeypatch.setenv("NANOSIEM_TOKEN", secret)
    event = alert_to_event(_alert(), host="sensor")
    payload = event.model_dump(mode="json")

    def explode(*_args, **_kwargs):
        raise RuntimeError(f"request failed with {secret}")

    monkeypatch.setattr(exporter_module.urllib.request, "urlopen", explode)
    sink = HttpSink("https://example.com/ingest", token_env="NANOSIEM_TOKEN", retries=0)
    with caplog.at_level(logging.DEBUG):
        sink.deliver(event, payload)
        sink.close()
    assert secret not in caplog.text
    assert secret not in repr(sink)


def test_pipeline_continues_when_one_sink_is_down(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    class DownSink(Sink):
        def deliver(self, event: NormalizedEvent, payload: dict) -> None:
            raise ConnectionError("down")

    class GoodSink(Sink):
        def __init__(self) -> None:
            self.events: list[dict] = []

        def deliver(self, event: NormalizedEvent, payload: dict) -> None:
            self.events.append(payload)

    good = GoodSink()
    with Database(tmp_path / "wids.db") as db:
        exporter = NanoSIEMExporter(db, [DownSink(), good], sensor_name="sensor")
        with caplog.at_level(logging.WARNING):
            assert exporter.export([_alert()]) == 1
        exporter.close()
    assert len(good.events) == 1
    assert "SIEM sink failure" in caplog.text


def test_validator_accepts_events_and_reports_bad_line(tmp_path: Path, capsys) -> None:
    from tools.validate_in_nanosiem import main

    schema = tmp_path / "schema.py"
    schema.write_text(
        "from datetime import datetime\n"
        "class NormalizedEvent:\n"
        "    def __init__(self, **kwargs): self.__dict__.update(kwargs)\n"
        "    def get_field(self, path):\n"
        "        value = self.__dict__\n"
        "        for part in path.split('.'):\n"
        "            value = value[part] if isinstance(value, dict) else getattr(value, part)\n"
        "        return value\n",
        encoding="utf-8",
        newline="\n",
    )
    events = tmp_path / "events.ndjson"
    event = alert_to_event(_alert(), host="sensor")
    events.write_text(json.dumps(event.model_dump(mode="json")) + "\n", encoding="utf-8")
    assert main(["--schema-file", str(schema), "--file", str(events)]) == 0
    assert "PASS 1/1 events" in capsys.readouterr().out
    bad = tmp_path / "bad.ndjson"
    bad.write_text('{"event_id":"missing"}\n', encoding="utf-8")
    assert main(["--schema-file", str(schema), "--file", str(bad)]) == 1
    output = capsys.readouterr().out
    assert "FAIL line 1" in output
    assert "exact failure" not in output


@pytest.mark.slow
def test_cli_analyze_writes_ndjson(tmp_path: Path, synthetic_dataset) -> None:
    from wids_ai.capture.base import PcapSource
    from wids_ai.cli import main
    from wids_ai.inventory import APInventory
    from wids_ai.parser.dot11 import parse_frame

    dataset = synthetic_dataset(42)
    inventory_path = tmp_path / "inventory.json"
    APInventory.from_frames(
        frame
        for packet in PcapSource(dataset / "benign_baseline.pcap").packets()
        if (frame := parse_frame(packet)) is not None
    ).save(inventory_path)
    config_path = tmp_path / "config.yml"
    config_path.write_text(
        f"storage:\n  database_path: {json.dumps(str(tmp_path / 'wids.db'))}\n",
        encoding="utf-8",
        newline="\n",
    )
    output = tmp_path / "alerts.json"
    ndjson = tmp_path / "events.ndjson"
    result = main(
        [
            "analyze",
            str(dataset / "mixed_evil_twin.pcap"),
            "--config",
            str(config_path),
            "--inventory",
            str(inventory_path),
            "--rules",
            str(Path(__file__).resolve().parent.parent / "wids_ai" / "rules" / "rules"),
            "--model",
            str(tmp_path / "missing-models"),
            "--trusted-model-root",
            str(tmp_path),
            "--out",
            str(output),
            "--siem-file",
            str(ndjson),
            "--siem-sensor-name",
            "lab-sensor-1",
        ]
    )
    assert result == 0
    events = [json.loads(line) for line in ndjson.read_text(encoding="utf-8").splitlines()]
    assert events
    assert all(tuple(event) == NANOSIEM_EVENT_KEYS for event in events)
    assert all(event["host"] == "lab-sensor-1" for event in events)
    assert all(event["fields"]["wids_family"] == "evil_twin_rogue_ap" for event in events)


def test_exported_states_table_migration(tmp_path: Path) -> None:
    with Database(tmp_path / "wids.db") as db:
        assert db.was_exported("ALT-test:1") is False
        db.mark_exported("ALT-test:1")
        assert db.was_exported("ALT-test:1") is True
    with sqlite3.connect(tmp_path / "wids.db") as connection:
        version = connection.execute("SELECT MAX(version) FROM schema_version").fetchone()[0]
        table = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'exported_states'"
        ).fetchone()
    assert version == 5
    assert table[0] == "exported_states"


def test_export_marks_failed_alert_states_for_retry(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    class DownSink(Sink):
        def deliver(self, event: NormalizedEvent, payload: dict) -> bool:
            raise ConnectionError("down")

    with Database(tmp_path / "wids.db") as db:
        exporter = NanoSIEMExporter(db, [DownSink()], sensor_name="sensor")
        with caplog.at_level(logging.WARNING):
            assert exporter.export([_alert()]) == 0
        assert exporter.failed[0].id == "ALT-0123456789abcdef"
        assert db.was_exported(f"{exporter.failed[0].id}:1") is False
        exporter.close()


def test_http_sink_reports_failure_to_callback(monkeypatch: pytest.MonkeyPatch) -> None:
    messages: list[str] = []
    event = alert_to_event(_alert(), host="sensor")
    payload = event.model_dump(mode="json")

    def explode(*_args, **_kwargs):
        raise TimeoutError("timed out")

    monkeypatch.setattr(exporter_module.urllib.request, "urlopen", explode)
    sink = HttpSink(
        "https://example.com/ingest",
        retries=0,
        failure_callback=messages.append,
    )
    sink.deliver(event, payload)
    sink.close()
    assert messages
    assert messages[0].startswith("SIEM export failed:")
    assert "timed out" not in messages[0]

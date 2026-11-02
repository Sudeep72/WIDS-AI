from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from wids_ai.correlation.schema import Alert, AttackMapping
from wids_ai.inventory import APInventory, KnownAP
from wids_ai.rules.schema import Evidence
from wids_ai.storage.db import Database


def _ap(ssid: str = "LabNet") -> APInventory:
    return APInventory(
        aps={
            "00:11:22:33:44:55": KnownAP(
                bssid="00:11:22:33:44:55",
                ssid=ssid,
                oui="00:11:22",
                channels=(6,),
                security="open",
                trust_score=70,
            )
        }
    )


def _alert(alert_id: str = "ALT-1", severity: str = "high") -> Alert:
    now = datetime(2025, 1, 1, tzinfo=UTC)
    return Alert(
        id=alert_id,
        timestamp=now,
        family="evil_twin_rogue_ap",
        severity=severity,  # type: ignore[arg-type]
        risk_score=70,
        rule_evidence=[
            Evidence(field="distinct_bssids", observed=2, threshold=2, text="two BSSIDs")
        ],
        evidence=[Evidence(field="distinct_bssids", observed=2, threshold=2, text="two BSSIDs")],
        ml_anomaly_score=0.4,
        why="two BSSIDs were observed",
        reasons=[],
        indicators_found=[],
        indicators_not_found=[],
        recommended_check="verify",
        bssids=("00:11:22:33:44:55",),
        ssids=("LabNet",),
        clients=(),
        mitre_attack=AttackMapping(
            tactic="Credential Access", technique="T1557", technique_name="Adversary-in-the-Middle"
        ),
        rule_ids=("WIDS-EVIL-001",),
        raw_frame_counts={"WIDS-EVIL-001": 1},
        first_seen=now,
        last_seen=now,
    )


def test_db_round_trip_and_migration(tmp_path: Path) -> None:
    db = Database(tmp_path / "wids.db")
    run_id = db.start_run("test.pcap")
    db.save_inventory(_ap())
    db.save_alert(_alert(), run_id)
    db.finish_run(run_id, 10, 3)
    assert db.get_alert("ALT-1")["family"] == "evil_twin_rogue_ap"
    assert db.list_alerts(limit=50)[0]["id"] == "ALT-1"
    assert db.list_aps()[0]["trust_score"] == 70
    assert db.get_stats()["frames_processed"] == 10
    with sqlite3.connect(tmp_path / "wids.db") as connection:
        version = connection.execute("SELECT MAX(version) FROM schema_version").fetchone()[0]
    assert version == 2


def test_api_endpoints_and_security_headers(tmp_path: Path) -> None:
    db = Database(tmp_path / "wids.db")
    db.save_inventory(_ap())
    db.save_alert(_alert())
    from wids_ai.api.main import create_app

    client = TestClient(create_app(db))
    health = client.get("/api/health")
    assert health.status_code == 200
    assert health.headers["content-security-policy"] == "default-src 'self'"
    assert health.headers["x-content-type-options"] == "nosniff"
    assert health.headers["x-frame-options"] == "DENY"
    assert health.headers["referrer-policy"] == "no-referrer"
    assert client.get("/api/stats").status_code == 200
    assert client.get("/api/aps").json()[0]["ssid"] == "LabNet"
    assert client.get("/api/alerts").json()[0]["id"] == "ALT-1"
    assert client.get("/api/alerts/ALT-1").json()["why"] == "two BSSIDs were observed"


def test_api_pagination_and_validation(tmp_path: Path) -> None:
    db = Database(tmp_path / "wids.db")
    from wids_ai.api.main import create_app

    client = TestClient(create_app(db))
    assert client.get("/api/alerts?limit=501").status_code == 422
    assert client.get("/api/alerts?severity=bad").status_code == 422
    assert client.get("/api/alerts?since=not-a-date").status_code == 422
    assert client.get("/api/alerts?family=bad%20family").status_code == 422


def test_xss_and_json_breaking_text_are_plain_data(tmp_path: Path) -> None:
    payload = '<img src=x onerror=alert(1)> "quote" \\ backslash \u0000 ü'
    db = Database(tmp_path / "wids.db")
    db.save_inventory(_ap(payload))
    from wids_ai.api.main import create_app

    response = TestClient(create_app(db)).get("/api/aps")
    assert response.status_code == 200
    assert response.json()[0]["ssid"] == '<img src=x onerror=alert(1)> "quote" \\ backslash  ü'


def test_sql_injection_filters_do_not_leak_errors(tmp_path: Path) -> None:
    db = Database(tmp_path / "wids.db")
    from wids_ai.api.main import create_app

    client = TestClient(create_app(db))
    for query in [
        "severity=high%27%20OR%201%3D1--",
        "family=%27%20OR%201%3D1--",
        "since=%27%20OR%201%3D1--",
    ]:
        response = client.get(f"/api/alerts?{query}")
        assert response.status_code in {422, 200}
        if response.status_code == 200:
            assert response.json() == []


def test_dashboard_assets_have_no_external_urls_or_dangerous_sinks() -> None:
    root = Path(__file__).resolve().parent.parent / "dashboard"
    html = (root / "index.html").read_text(encoding="utf-8")
    js = (root / "app.js").read_text(encoding="utf-8")
    css = (root / "style.css").read_text(encoding="utf-8")
    combined = (html + js + css).replace("http://www.w3.org/2000/svg", "")
    assert "http://" not in combined
    assert "https://" not in combined
    forbidden = ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(")
    assert not any(token in js for token in forbidden)
    assert "/static/app.js" in html
    assert "/static/style.css" in html
    assert "section + section" in css
    assert "No ML score data" in js
    assert "dBm" in js


@pytest.mark.slow
def test_replay_mixed_and_benign(tmp_path: Path, synthetic_dataset) -> None:
    from wids_ai.replay import replay_pcap

    dataset = synthetic_dataset(42)
    db = Database(tmp_path / "replay.db")
    inventory_path = tmp_path / "inventory.json"
    APInventory.from_frames(
        frame
        for packet in __import__("wids_ai.capture.base", fromlist=["PcapSource"])
        .PcapSource(dataset / "benign_baseline.pcap")
        .packets()
        if (
            frame := __import__("wids_ai.parser.dot11", fromlist=["parse_frame"]).parse_frame(
                packet
            )
        )
        is not None
    ).save(inventory_path)
    result = replay_pcap(
        dataset / "mixed_evil_twin.pcap",
        db,
        inventory_path=inventory_path,
        model_root=tmp_path / "missing-models",
        trusted_model_root=tmp_path,
        sleep=False,
    )
    assert result.alerts
    families = {item["family"] for item in db.list_alerts(limit=50)}
    assert "evil_twin_rogue_ap" in families
    benign_db = Database(tmp_path / "benign.db")
    replay_pcap(
        dataset / "benign_baseline.pcap",
        benign_db,
        inventory_path=inventory_path,
        model_root=tmp_path / "missing-models",
        trusted_model_root=tmp_path,
        sleep=False,
    )
    assert all(
        item["severity"] in {"informational", "low"} for item in benign_db.list_alerts(limit=50)
    )


@pytest.mark.slow
def test_replay_ap_state_frames_and_sparkline(tmp_path: Path, synthetic_dataset) -> None:
    from fastapi.testclient import TestClient

    from wids_ai.api.main import create_app
    from wids_ai.capture.base import PcapSource
    from wids_ai.parser.dot11 import parse_frame
    from wids_ai.replay import replay_pcap

    dataset = synthetic_dataset(42)
    inventory_path = tmp_path / "inventory.json"
    benign_frames = [
        frame
        for packet in PcapSource(dataset / "benign_baseline.pcap").packets()
        if (frame := parse_frame(packet)) is not None
    ]
    APInventory.from_frames(benign_frames).save(inventory_path)
    db = Database(tmp_path / "ap.db")
    result = replay_pcap(
        dataset / "mixed_evil_twin.pcap",
        db,
        inventory_path=inventory_path,
        model_root=tmp_path / "models",
        trusted_model_root=tmp_path,
        sleep=False,
    )
    client = TestClient(create_app(db))
    aps = {item["bssid"]: item for item in client.get("/api/aps").json()}
    assert aps["02:de:ad:be:ef:01"]["flagged"] is True
    assert aps["02:de:ad:be:ef:01"]["flag_reason"] == "not in trusted inventory"
    assert aps["02:de:ad:be:ef:01"]["trust_score"] < 50
    assert aps["00:11:22:33:44:55"]["trust_score"] >= 80
    assert aps["00:11:22:33:44:55"]["flagged"] is True
    assert aps["00:11:22:33:44:55"]["flag_reason"] == "duplicate SSID"
    stats = client.get("/api/stats").json()
    assert stats["frames_processed"] == result.frames
    assert stats["latest_ml_scores"]
    assert all(0.0 <= item["score"] <= 1.0 for item in stats["latest_ml_scores"])
    for ap in aps.values():
        assert ap["rssi"] is None or round(ap["rssi"], 1) == ap["rssi"]
        assert isinstance(ap["security"], str)


def test_ap_security_is_single_mode_and_rssi_rounded(tmp_path: Path) -> None:
    db = Database(tmp_path / "api.db")
    inventory = APInventory(
        aps={
            "00:11:22:33:44:55": KnownAP(
                bssid="00:11:22:33:44:55",
                ssid="LabNet",
                oui="00:11:22",
                channels=(6,),
                security="open",
                mean_rssi=-42.12345,
                trust_score=90,
            )
        }
    )
    db.save_inventory(inventory)
    ap = db.list_aps()[0]
    assert ap["security"] == "open"
    assert ap["rssi"] == -42.1


def test_legacy_security_list_is_read_as_single_mode(tmp_path: Path) -> None:
    db = Database(tmp_path / "legacy.db")
    with sqlite3.connect(tmp_path / "legacy.db") as connection:
        connection.execute(
            """
            INSERT INTO aps(bssid, ssid, oui, channels, rssi, security, trust_score, flagged, flag_reason, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "00:aa:bb:cc:dd:ee",
                "LegacyNet",
                "00:aa:bb",
                "[]",
                -40.04,
                '["open", "wep"]',
                80,
                0,
                None,
                "2025-01-01T00:00:00+00:00",
            ),
        )
        connection.commit()
    row = db.list_aps()[0]
    assert row["security"] == "wep"
    assert row["rssi"] == -40.0

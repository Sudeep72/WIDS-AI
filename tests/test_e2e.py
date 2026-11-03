from __future__ import annotations

import json
from pathlib import Path

import pytest

from wids_ai.capture.base import PcapSource
from wids_ai.cli import main
from wids_ai.config import PROJECT_ROOT
from wids_ai.evaluation import (
    SEEDS,
    TOLERANCE,
    actionable,
    attack_bounds,
    scenario_hit,
    scenario_rows,
)
from wids_ai.inventory import APInventory
from wids_ai.ml.isolation_forest import load_model
from wids_ai.parser.dot11 import parse_frame
from wids_ai.replay import replay_pcap
from wids_ai.siem.mapping import alert_to_event
from wids_ai.siem.schema import NANOSIEM_EVENT_KEYS
from wids_ai.storage.db import Database
from wids_ai.synthetic.generator import EXPECTED_ALERT_FAMILY

SCENARIOS = tuple(EXPECTED_ALERT_FAMILY)
pytestmark = pytest.mark.slow


def _ndjson_signature(alerts) -> tuple[str, ...]:
    path = Path(".tmp") / "e2e-ndjson.ndjson"
    path.parent.mkdir(exist_ok=True)
    path.write_text(
        "".join(
            json.dumps(alert_to_event(alert, host="e2e").model_dump(mode="json")) + "\n"
            for alert in alerts
        ),
        encoding="utf-8",
        newline="\n",
    )
    events = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert all(tuple(event) == NANOSIEM_EVENT_KEYS for event in events)
    return tuple(event["event_id"] for event in events)


@pytest.mark.slow
@pytest.mark.parametrize("seed", SEEDS)
def test_five_seed_end_to_end(seed: int, evaluated_seed) -> None:
    artifacts = evaluated_seed(seed)
    labels = artifacts.labels
    assert labels["benign_baseline"]["attack_family"] == "benign"
    assert labels["benign_noisy"]["attack_family"] == "benign"
    baseline = artifacts.results["benign_baseline"]
    assert actionable(list(baseline.alerts)) == []
    assert all(alert.severity in {"informational", "low"} for alert in baseline.alerts)
    # Noisy benign is intentionally a false-positive challenge. Its actionable
    # outcome is measured in EVALUATION.md and must not be tuned away here.
    noisy = artifacts.results["benign_noisy"]
    assert all(alert.risk_score <= 100 for alert in noisy.alerts)
    for result in artifacts.results.values():
        _ndjson_signature(result.alerts)
    measured = {row["scenario"]: row for row in scenario_rows(artifacts)}
    for name in SCENARIOS:
        metadata = labels[name]
        result = artifacts.results[name]
        start, end = attack_bounds(metadata)
        hit = scenario_hit(list(result.alerts), EXPECTED_ALERT_FAMILY[name], start, end)
        if name == "mixed_low_slow_deauth":
            # This is a measured miss candidate. Do not tune thresholds to force it.
            if hit is not None:
                first_seen = hit.first_seen or hit.timestamp
                assert start - TOLERANCE <= first_seen <= end + TOLERANCE
        else:
            assert hit is not None, f"{name}: expected family missing"
            first_seen = hit.first_seen or hit.timestamp
            assert start - TOLERANCE <= first_seen <= end + TOLERANCE
        assert not measured[name]["clear_false_positive"], (
            f"{name}: clear cross-family false positive"
        )
        if name == "mixed_evil_twin_matching_oui" and hit is not None:
            assert "WIDS-EVIL-003" not in set(hit.rule_ids)
        assert _ndjson_signature(result.alerts)
        assert len({alert.id for alert in result.alerts}) == len(result.alerts)

    dataset = artifacts.dataset
    inventory_path = artifacts.work_root / f"inventory-{seed}.json"
    APInventory.from_frames(
        frame
        for packet in PcapSource(dataset / "benign_baseline.pcap").packets()
        if (frame := parse_frame(packet)) is not None
    ).save(inventory_path)
    config_path = artifacts.work_root / f"config-{seed}.yml"
    config_path.write_text(
        f"storage:\n  database_path: {json.dumps(str(artifacts.work_root / f'cli-{seed}.db'))}\n",
        encoding="utf-8",
        newline="\n",
    )
    cli_output = artifacts.work_root / f"cli-alerts-{seed}.json"

    assert (
        main(
            [
                "analyze",
                str(dataset / "mixed_evil_twin.pcap"),
                "--config",
                str(config_path),
                "--inventory",
                str(inventory_path),
                "--rules",
                str(PROJECT_ROOT / "wids_ai" / "rules" / "rules"),
                "--model",
                str(artifacts.model_root),
                "--trusted-model-root",
                str(artifacts.work_root),
                "--out",
                str(cli_output),
            ]
        )
        == 0
    )
    cli_alerts = json.loads(cli_output.read_text(encoding="utf-8"))
    db = Database(artifacts.work_root / f"replay-{seed}.db")
    try:
        replay_pcap(
            dataset / "mixed_evil_twin.pcap",
            db,
            inventory_path=inventory_path,
            model_root=artifacts.model_root,
            trusted_model_root=artifacts.work_root,
            sleep=False,
        )
        replay_ids = {item["id"] for item in db.list_alerts(limit=500)}
    finally:
        db.close()
    assert {alert["id"] for alert in cli_alerts} == replay_ids


def test_models_use_seed_specific_training(evaluated_seed) -> None:
    artifacts = evaluated_seed(99)
    for scope in ("bssid", "client", "ssid"):
        model = load_model(artifacts.model_root / scope, trusted_base=artifacts.work_root)
        assert model.metadata.seed == 99


def test_hard_scenarios_remain_labeled() -> None:
    assert EXPECTED_ALERT_FAMILY["mixed_low_slow_deauth"] == "deauth_disassoc_anomaly"
    assert EXPECTED_ALERT_FAMILY["mixed_evil_twin_matching_oui"] == "evil_twin_rogue_ap"

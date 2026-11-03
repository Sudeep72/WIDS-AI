from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from wids_ai.capture.base import PcapSource
from wids_ai.features.extractors import FeatureRow
from wids_ai.inventory import APInventory, KnownAP
from wids_ai.parser.dot11 import parse_frame
from wids_ai.parser.models import Frame
from wids_ai.rules.engine import (
    RuleValidationError,
    deduplicate,
    evaluate_rule,
    evaluate_rules,
    load_rules,
)

pytestmark = pytest.mark.slow

BASE = datetime(2025, 1, 1, tzinfo=UTC)
RULES = Path(__file__).resolve().parent.parent / "wids_ai" / "rules" / "rules"


def _inventory() -> APInventory:
    return APInventory(
        aps={
            "00:11:22:33:44:55": KnownAP(
                bssid="00:11:22:33:44:55",
                ssid="LabNet",
                oui="001122",
                channels=(6,),
                security="open",
                mean_rssi=-42,
            )
        }
    )


def _row(
    *,
    scope: str = "ssid",
    group: str = "LabNet",
    **updates: object,
) -> FeatureRow:
    values: dict[str, object] = {
        "window_start": BASE,
        "window_end": BASE + timedelta(seconds=10),
        "scope": scope,
        "group": group,
        "frame_count": 10,
    }
    values.update(updates)
    return FeatureRow.model_validate(values)


def _rules() -> list:
    return load_rules(RULES)


def _loaded_frames(pcap: Path) -> list[Frame]:
    return [
        frame for packet in PcapSource(pcap).packets() if (frame := parse_frame(packet)) is not None
    ]


@pytest.fixture(scope="session")
def parsed(synthetic: Path, parsed_synthetic) -> dict[str, tuple[list[Frame], list[FeatureRow]]]:
    cached_dataset, result = parsed_synthetic
    assert cached_dataset == synthetic
    return result


def _detections(
    pcap: Path,
    inventory: APInventory,
    parsed: dict[str, tuple[list[Frame], list[FeatureRow]]],
) -> list:
    frames, rows = parsed[pcap.stem]
    return evaluate_rules(rows, _rules(), frames, inventory)


@pytest.fixture(scope="session")
def synthetic(synthetic_dataset) -> Path:
    return synthetic_dataset(42)


@pytest.fixture(scope="session")
def inventory(synthetic: Path) -> APInventory:
    frames = [
        frame
        for packet in PcapSource(synthetic / "benign_baseline.pcap").packets()
        if (frame := parse_frame(packet)) is not None
    ]
    return APInventory.from_frames(frames)


def test_rule_schema_loads_all_families() -> None:
    rules = _rules()
    assert 2 <= sum(rule.family == "evil_twin_rogue_ap" for rule in rules) <= 4
    assert 2 <= sum(rule.family == "deauth_disassoc_anomaly" for rule in rules) <= 6
    assert 2 <= sum(rule.family == "probe_response_karma" for rule in rules) <= 4
    assert 2 <= sum(rule.family == "beacon_management_anomaly" for rule in rules) <= 4


def test_rule_schema_rejects_invalid_condition(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yml"
    bad.write_text(
        "id: WIDS-BAD-001\ntitle: bad\nfamily: x\ndescription: x\n"
        "severity: low\nscope: bssid\nconditions: {}\nthreshold: 1\n"
        "window: 10\ncooldown: 0\nattack_ref: x\nfalse_positive_notes: x\n",
        encoding="utf-8",
    )
    with pytest.raises(RuleValidationError):
        load_rules(tmp_path)


def test_benign_has_zero_detections(
    synthetic: Path,
    inventory: APInventory,
    parsed: dict[str, tuple[list[Frame], list[FeatureRow]]],
) -> None:
    assert _detections(synthetic / "benign_baseline.pcap", inventory, parsed) == []


def test_evil_twin_rules_fire(
    synthetic: Path,
    inventory: APInventory,
    parsed: dict[str, tuple[list[Frame], list[FeatureRow]]],
) -> None:
    detections = _detections(synthetic / "mixed_evil_twin.pcap", inventory, parsed)
    ids = {detection.rule_id for detection in detections}
    assert {"WIDS-EVIL-001", "WIDS-EVIL-002"} <= ids
    assert any(
        detection.bssids == ("02:de:ad:be:ef:01", "00:11:22:33:44:55")
        or "02:de:ad:be:ef:01" in detection.bssids
        for detection in detections
    )


def test_deauth_rules_fire(
    synthetic: Path,
    inventory: APInventory,
    parsed: dict[str, tuple[list[Frame], list[FeatureRow]]],
) -> None:
    detections = _detections(synthetic / "mixed_deauth_burst.pcap", inventory, parsed)
    ids = {detection.rule_id for detection in detections}
    assert {"WIDS-DEAUTH-001", "WIDS-DEAUTH-002", "WIDS-DEAUTH-003"} <= ids


def test_karma_rule_fires(
    synthetic: Path,
    inventory: APInventory,
    parsed: dict[str, tuple[list[Frame], list[FeatureRow]]],
) -> None:
    detections = _detections(synthetic / "mixed_karma_probe_responses.pcap", inventory, parsed)
    assert {detection.rule_id for detection in detections} >= {"WIDS-KARMA-001", "WIDS-KARMA-002"}


def test_beacon_rules_fire(
    synthetic: Path,
    inventory: APInventory,
    parsed: dict[str, tuple[list[Frame], list[FeatureRow]]],
) -> None:
    detections = _detections(synthetic / "mixed_beacon_sequence_anomaly.pcap", inventory, parsed)
    ids = {detection.rule_id for detection in detections}
    assert {"WIDS-BEACON-001", "WIDS-BEACON-002"} <= ids


def test_threshold_boundary_and_empty_window(inventory: APInventory) -> None:
    rules = {rule.id: rule for rule in _rules()}
    at_threshold = evaluate_rule(
        rules["WIDS-KARMA-001"],
        _row(
            scope="bssid",
            group="02:00:00:00:10:01",
            distinct_ssids_answered=3,
            probe_response_count=3,
        ),
        [],
        inventory,
    )
    below_threshold = evaluate_rule(
        rules["WIDS-KARMA-001"],
        _row(
            scope="bssid",
            group="02:00:00:00:10:01",
            distinct_ssids_answered=2,
            probe_response_count=2,
        ),
        [],
        inventory,
    )
    empty = evaluate_rule(rules["WIDS-DEAUTH-001"], _row(scope="bssid"), [], inventory)
    assert at_threshold is not None
    assert below_threshold is None
    assert empty is None


def test_unknown_ap_oui_mismatch(inventory: APInventory) -> None:
    rule = next(rule for rule in _rules() if rule.id == "WIDS-EVIL-002")
    row = _row(
        distinct_bssids=2,
        observed_bssids="00:11:22:33:44:55,02:de:ad:be:ef:01",
        observed_security_modes="open",
    )
    detection = evaluate_rule(rule, row, [], inventory)
    assert detection is not None
    assert detection.evidence[0].field in {"unknown_bssid_count", "oui_mismatch"}


def test_known_oui_format_does_not_trigger_mismatch() -> None:
    rule = next(rule for rule in _rules() if rule.id == "WIDS-EVIL-002")
    inventory = APInventory(
        aps={
            "00:11:22:33:44:55": KnownAP(
                bssid="00:11:22:33:44:55",
                ssid="LabNet",
                oui="001122",
                channels=(6,),
                security="open",
                mean_rssi=-42,
            )
        }
    )
    row = _row(
        distinct_bssids=2,
        observed_bssids="00:11:22:33:44:55,00:11:22:aa:bb:01",
        observed_security_modes="open",
    )
    assert evaluate_rule(rule, row, [], inventory) is None


def test_trusted_sequence_gap_only_does_not_fire() -> None:
    rule = next(rule for rule in _rules() if rule.id == "WIDS-BEACON-002")
    row = _row(
        scope="bssid",
        group="00:11:22:33:44:55",
        seq_gap_count=2,
        seq_duplicate_count=0,
        beacon_interval_std=4.0,
        beacon_interval_jitter=3.0,
        observed_bssids="00:11:22:33:44:55",
    )
    assert evaluate_rule(rule, row, [], _inventory()) is None


def test_unknown_sequence_gap_still_fires() -> None:
    rule = next(rule for rule in _rules() if rule.id == "WIDS-BEACON-002")
    row = _row(
        scope="bssid",
        group="02:aa:bb:cc:dd:ee",
        seq_gap_count=2,
        seq_duplicate_count=0,
        beacon_interval_std=4.0,
        beacon_interval_jitter=3.0,
        observed_bssids="02:aa:bb:cc:dd:ee",
    )
    detection = evaluate_rule(rule, row, [], _inventory())
    assert detection is not None
    assert detection.evidence[0].field == "seq_gap_count"


def test_interleaved_duplicate_streams_still_fire() -> None:
    rule = next(rule for rule in _rules() if rule.id == "WIDS-BEACON-002")
    row = _row(
        scope="bssid",
        group="00:11:22:33:44:55",
        seq_gap_count=0,
        seq_duplicate_count=2,
        beacon_interval_std=4.0,
        beacon_interval_jitter=3.0,
        observed_bssids="00:11:22:33:44:55",
    )
    detection = evaluate_rule(rule, row, [], _inventory())
    assert detection is not None
    assert detection.evidence[0].field == "seq_duplicate_count"


def test_rolling_deauth_rules_detect_spread_activity() -> None:
    rules = {rule.id: rule for rule in _rules()}
    frames = [
        Frame(
            timestamp=BASE + timedelta(seconds=index * 12),
            frame_type="management",
            subtype="deauthentication",
            type_code=0,
            subtype_code=12,
            addr1="de:ad:cc:00:00:02",
            addr2="02:de:ad:de:02:02",
            addr3="02:de:ad:de:02:02",
            bssid="02:de:ad:de:02:02",
            reason_code=7,
        )
        for index in range(12)
    ]
    detections = evaluate_rules(
        [],
        [rules["WIDS-DEAUTH-005"], rules["WIDS-DEAUTH-006"]],
        frames,
        _inventory(),
    )
    assert {item.rule_id for item in detections} == {"WIDS-DEAUTH-005", "WIDS-DEAUTH-006"}
    assert all(item.evidence[0].observed == 6 for item in detections)


def test_hits_merge_into_one_incident() -> None:
    rule = next(rule for rule in _rules() if rule.id == "WIDS-DEAUTH-001")
    frames = []
    for second in range(0, 20):
        frames.append(
            Frame(
                timestamp=BASE + timedelta(seconds=second),
                frame_type="management",
                subtype="deauthentication",
                type_code=0,
                subtype_code=12,
                addr1="aa:bb:cc:00:00:01",
                addr2="00:11:22:33:44:55",
                addr3="00:11:22:33:44:55",
                bssid="00:11:22:33:44:55",
                reason_code=7,
            )
        )
    row1 = _row(
        scope="bssid",
        group="00:11:22:33:44:55",
        deauth_count=10,
        deauth_received_rate=1.0,
        observed_bssids="00:11:22:33:44:55",
    )
    row2 = row1.model_copy(
        update={
            "window_start": BASE + timedelta(seconds=5),
            "window_end": BASE + timedelta(seconds=15),
        }
    )
    detections = [
        evaluate_rule(rule, row1, frames, _inventory()),
        evaluate_rule(rule, row2, frames, _inventory()),
    ]
    assert all(item is not None for item in detections)
    incidents = deduplicate([item for item in detections if item is not None])
    assert len(incidents) == 1
    assert incidents[0].hit_count == 2


def test_detection_starts_in_labeled_attack_window(
    synthetic: Path,
    inventory: APInventory,
    parsed: dict[str, tuple[list[Frame], list[FeatureRow]]],
) -> None:
    labels = json.loads((synthetic / "labels.json").read_text(encoding="utf-8"))
    metadata = next(
        item for item in labels["scenarios"] if item["scenario"] == "mixed_deauth_burst"
    )
    detections = _detections(synthetic / "mixed_deauth_burst.pcap", inventory, parsed)
    incidents = deduplicate(detections)
    first = min(incident.first_seen for incident in incidents)
    start = datetime.fromisoformat(metadata["details"]["attack_start"])
    end = datetime.fromisoformat(metadata["details"]["attack_end"])
    tolerance = timedelta(seconds=10)
    assert start - tolerance <= first <= end + tolerance


@pytest.mark.slow
def test_inventory_oui_and_json_round_trip(tmp_path: Path, synthetic: Path) -> None:
    frames = [
        frame
        for packet in PcapSource(synthetic / "benign_baseline.pcap").packets()
        if (frame := parse_frame(packet)) is not None
    ]
    inventory = APInventory.from_frames(frames)
    assert inventory.get("00:11:22:33:44:55").oui == "00:11:22"
    path = tmp_path / "inventory.json"
    inventory.save(path)
    loaded = APInventory.load(path)
    assert loaded.aps["00:11:22:33:44:55"].ssid == "LabNet"
    assert 0 <= loaded.aps["00:11:22:33:44:55"].trust_score <= 100


def test_every_rule_attack_ref_resolves() -> None:
    from wids_ai.rules.engine import load_attack_mapping

    mapping = load_attack_mapping()
    assert all(rule.attack_ref in mapping["refs"] for rule in _rules())


def test_inventory_trust_is_bounded_and_updated() -> None:
    inventory = _inventory()
    rule = next(rule for rule in _rules() if rule.id == "WIDS-BEACON-001")
    row = _row(
        scope="bssid",
        group="00:11:22:33:44:55",
        beacon_count=4,
        beacon_interval_std=60,
        observed_bssids="00:11:22:33:44:55",
    )
    assert inventory.aps["00:11:22:33:44:55"].trust_score == 90
    detections = evaluate_rules([row], [rule], [], inventory)
    assert detections
    assert inventory.aps["00:11:22:33:44:55"].trust_score == 90
    inventory.adjust_trust("00:11:22:33:44:55", -500)
    assert inventory.aps["00:11:22:33:44:55"].trust_score == 0


RULE_SCENARIOS = {
    "WIDS-EVIL-001": "mixed_evil_twin",
    "WIDS-EVIL-002": "mixed_evil_twin",
    "WIDS-EVIL-003": "mixed_evil_twin",
    "WIDS-EVIL-004": "mixed_evil_twin",
    "WIDS-DEAUTH-001": "mixed_deauth_burst",
    "WIDS-DEAUTH-002": "mixed_deauth_burst",
    "WIDS-DEAUTH-003": "mixed_deauth_burst",
    "WIDS-DEAUTH-004": "mixed_deauth_burst",
    "WIDS-DEAUTH-005": "mixed_low_slow_deauth",
    "WIDS-DEAUTH-006": "mixed_low_slow_deauth",
    "WIDS-KARMA-001": "mixed_karma_probe_responses",
    "WIDS-KARMA-002": "mixed_karma_probe_responses",
    "WIDS-BEACON-001": "mixed_beacon_sequence_anomaly",
    "WIDS-BEACON-002": "mixed_beacon_sequence_anomaly",
    "WIDS-BEACON-003": "mixed_beacon_sequence_anomaly",
}


@pytest.mark.slow
@pytest.mark.parametrize("rule_id,scenario", sorted(RULE_SCENARIOS.items()))
def test_each_rule_true_positive(
    rule_id: str,
    scenario: str,
    synthetic: Path,
    inventory: APInventory,
    parsed: dict[str, tuple[list[Frame], list[FeatureRow]]],
) -> None:
    detections = _detections(synthetic / f"{scenario}.pcap", inventory, parsed)
    assert rule_id in {detection.rule_id for detection in detections}


@pytest.mark.slow
@pytest.mark.parametrize("rule_id", sorted(RULE_SCENARIOS))
def test_each_rule_does_not_fire_on_benign(
    rule_id: str,
    synthetic: Path,
    inventory: APInventory,
    parsed: dict[str, tuple[list[Frame], list[FeatureRow]]],
) -> None:
    detections = _detections(synthetic / "benign_baseline.pcap", inventory, parsed)
    assert rule_id not in {detection.rule_id for detection in detections}


@pytest.mark.slow
@pytest.mark.parametrize("seed", [1, 2, 3, 42, 99])
def test_seed_robustness(seed: int, evaluated_seed) -> None:
    artifacts = evaluated_seed(seed)
    assert artifacts.results["benign_baseline"].incidents == ()
    for name in (
        "mixed_evil_twin",
        "mixed_deauth_burst",
        "mixed_karma_probe_responses",
        "mixed_beacon_sequence_anomaly",
    ):
        incidents = artifacts.results[name].incidents
        start = datetime.fromisoformat(artifacts.labels[name]["details"]["attack_start"])
        end = datetime.fromisoformat(artifacts.labels[name]["details"]["attack_end"])
        tolerance = timedelta(seconds=10)
        assert incidents, f"{name} produced no incidents for seed {seed}"
        assert any(
            start - tolerance <= incident.first_seen <= end + tolerance for incident in incidents
        ), f"{name} produced no in-window incident for seed {seed}"

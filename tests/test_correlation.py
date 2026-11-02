from __future__ import annotations

from datetime import UTC, datetime, timedelta

from wids_ai.correlation.scorer import (
    CorrelationConfig,
    correlate,
    group_incidents,
    score_group,
)
from wids_ai.inventory import APInventory, KnownAP
from wids_ai.rules.schema import Evidence, Incident

BASE = datetime(2025, 1, 1, tzinfo=UTC)


def _incident(
    rule_id: str = "WIDS-EVIL-001",
    family: str = "evil_twin_rogue_ap",
    bssids: tuple[str, ...] = ("02:de:ad:be:ef:01",),
    *,
    start: datetime = BASE,
    hits: int = 1,
    severity: str = "high",
) -> Incident:
    return Incident(
        id=f"INC-{rule_id}",
        rule_id=rule_id,
        family=family,
        severity=severity,  # type: ignore[arg-type]
        title="test incident",
        first_seen=start,
        last_seen=start + timedelta(seconds=10),
        hit_count=hits,
        bssids=bssids,
        ssids=("LabNet",),
        clients=(),
        evidence=(
            Evidence(
                field="distinct_bssids",
                observed=2,
                threshold=2,
                text="distinct_bssids was 2, expected ge 2",
            ),
        ),
        confidence=0.85,
        attack_ref="evil_twin",
        false_positive_notes="test",
    )


def _inventory() -> APInventory:
    return APInventory(
        aps={
            "00:11:22:33:44:55": KnownAP(
                bssid="00:11:22:33:44:55",
                ssid="LabNet",
                oui="00:11:22",
                channels=(6,),
                security=("open",),
                trust_score=50,
            )
        }
    )


def test_scorer_risk_is_bounded_and_rule_weighted() -> None:
    incident = _incident()
    alert = score_group([incident], 0.5, _inventory())
    assert 0 <= alert.risk_score <= 100
    assert alert.risk_score >= 55
    assert alert.reasons
    assert alert.reasons[0].source == "rules"


def test_ml_only_alert_is_informational_and_capped() -> None:
    alert = score_group([], 1.0, _inventory(), CorrelationConfig(ml_only_cap=20), ml_only=True)
    assert alert.informational is True
    assert alert.severity == "informational"
    assert alert.risk_score <= 20
    assert alert.mitre_attack is None


def test_family_grouping_merges_related_windows() -> None:
    incidents = [
        _incident(start=BASE),
        _incident(rule_id="WIDS-EVIL-002", start=BASE + timedelta(seconds=5)),
        _incident(rule_id="WIDS-EVIL-003", start=BASE + timedelta(seconds=10)),
    ]
    groups = group_incidents(incidents)
    assert len(groups) == 1
    alert = score_group(groups[0], 0.4, _inventory())
    assert set(alert.rule_ids) == {"WIDS-EVIL-001", "WIDS-EVIL-002", "WIDS-EVIL-003"}


def test_different_families_do_not_merge() -> None:
    groups = group_incidents(
        [
            _incident(),
            _incident(rule_id="WIDS-BEACON-001", family="beacon_management_anomaly"),
        ]
    )
    assert len(groups) == 2


def test_alert_id_is_stable_for_same_incidents() -> None:
    incidents = [_incident()]
    first = score_group(incidents, 0.3, _inventory())
    second = score_group(incidents, 0.3, _inventory())
    assert first.id == second.id
    assert first.id.startswith("ALT-")


def test_explanation_uses_only_evidence_fields() -> None:
    alert = score_group([_incident()], 0.2, _inventory())
    assert alert.why
    assert alert.indicators_found
    assert alert.indicators_not_found
    assert "distinct_bssids" in alert.why
    assert "not a standalone verdict" in alert.why


def test_ml_only_alert_in_correlate() -> None:
    alerts = correlate([], [0.99], _inventory(), CorrelationConfig(ml_only_cap=10))
    assert len(alerts) == 1
    assert alerts[0].informational
    assert alerts[0].risk_score <= 10

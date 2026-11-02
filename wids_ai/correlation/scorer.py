"""Rule-first ensemble correlation and alert grouping."""

from __future__ import annotations

import hashlib
from collections import Counter
from collections.abc import Iterable
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, model_validator

from wids_ai.attack.mapper import map_family
from wids_ai.correlation.explain import build_explanation
from wids_ai.correlation.schema import Alert, CorrelationReason
from wids_ai.inventory import APInventory
from wids_ai.rules.schema import Evidence, Incident


class CorrelationConfig(BaseModel):
    """Documented ensemble weights and caps."""

    model_config = ConfigDict(extra="forbid")

    rule_weight: float = Field(default=55.0, ge=0.0, le=100.0)
    ml_weight: float = Field(default=15.0, ge=0.0, le=100.0)
    trust_weight: float = Field(default=10.0, ge=0.0, le=100.0)
    repeat_weight: float = Field(default=10.0, ge=0.0, le=100.0)
    family_weight: float = Field(default=10.0, ge=0.0, le=100.0)
    ml_only_cap: int = Field(default=25, ge=0, le=100)

    @model_validator(mode="after")
    def validate_total(self) -> CorrelationConfig:
        total = (
            self.rule_weight
            + self.ml_weight
            + self.trust_weight
            + self.repeat_weight
            + self.family_weight
        )
        if total > 100.0 + 1e-9:
            raise ValueError("Correlation weights must sum to 100 or less")
        return self


def _clamp(value: float, low: float = 0.0, high: float = 100.0) -> float:
    return max(low, min(high, value))


def _merge_evidence(evidence: Iterable[Evidence]) -> list[Evidence]:
    merged: dict[str, Evidence] = {}
    rule_ids: dict[str, set[str]] = {}
    for item in evidence:
        rule_ids.setdefault(item.field, set()).update(item.rule_ids)
        merged.setdefault(item.field, item)
    return [
        merged[field].model_copy(update={"rule_ids": tuple(sorted(rule_ids[field]))})
        for field in sorted(merged)
    ]


def _entity_key(incident: Incident) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    return incident.bssids, incident.ssids, incident.clients


def _stable_id(incidents: list[Incident]) -> str:
    payload = "|".join(
        f"{item.rule_id}:{item.first_seen.isoformat()}:{','.join(item.bssids)}"
        for item in sorted(incidents, key=lambda item: (item.first_seen, item.rule_id))
    )
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
    return f"ALT-{digest}"


def _merge_entities(
    incidents: list[Incident],
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    return (
        tuple(dict.fromkeys(value for item in incidents for value in item.bssids)),
        tuple(dict.fromkeys(value for item in incidents for value in item.ssids)),
        tuple(dict.fromkeys(value for item in incidents for value in item.clients)),
    )


def group_incidents(
    incidents: Iterable[Incident], gap_seconds: float = 30.0
) -> list[list[Incident]]:
    """Group related incidents by overlapping entity sets and time span."""
    groups: list[list[Incident]] = []
    for incident in sorted(
        incidents, key=lambda item: (item.family, item.first_seen, item.rule_id)
    ):
        placed = False
        for group in groups:
            if group[0].family != incident.family:
                continue
            shared = set(_merge_entities(group)[0]) & set(incident.bssids)
            time_gap = (incident.first_seen - max(item.last_seen for item in group)).total_seconds()
            if shared and time_gap <= gap_seconds:
                group.append(incident)
                placed = True
                break
        if not placed:
            groups.append([incident])
    return groups


def score_group(
    incidents: list[Incident],
    ml_score: float,
    inventory: APInventory,
    config: CorrelationConfig | None = None,
    *,
    ml_only: bool = False,
) -> Alert:
    """Turn one incident group into a risk-scored alert."""
    config = config or CorrelationConfig()
    rule_evidence = _merge_evidence(
        item.model_copy(update={"rule_ids": tuple(sorted({*item.rule_ids, incident.rule_id}))})
        for incident in incidents
        for item in incident.evidence
    )
    bssids, ssids, clients = _merge_entities(incidents)
    families = {incident.family for incident in incidents}
    families.discard("")
    severity_order = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    severity = max(
        (item.severity for item in incidents),
        key=lambda value: severity_order[value],
        default="informational",
    )
    if ml_only:
        risk = min(config.ml_only_cap, round(_clamp(ml_score * config.ml_only_cap)))
        severity = "informational"
    else:
        rule_component = config.rule_weight if rule_evidence else 0.0
        ml_component = config.ml_weight * float(ml_score)
        trust_component = 0.0
        if bssids:
            scores = [
                inventory.get(bssid).trust_score
                for bssid in bssids
                if inventory.get(bssid) is not None
            ]
            trust_component = config.trust_weight * (1.0 - (min(scores) / 100.0)) if scores else 0.0
        repeat_component = min(
            config.repeat_weight, float(max(item.hit_count for item in incidents) - 1) * 2.0
        )
        family_component = min(
            config.family_weight, float(len(families) - 1) * config.family_weight / 2.0
        )
        risk = round(
            _clamp(
                rule_component
                + ml_component
                + trust_component
                + repeat_component
                + family_component
            )
        )
    reasons = [
        CorrelationReason(
            source="rules",
            contribution=config.rule_weight if rule_evidence else 0.0,
            explanation="Rule evidence carries the highest weight.",
        ),
        CorrelationReason(
            source="ml",
            contribution=config.ml_weight * ml_score,
            explanation=f"ML anomaly score {ml_score:.3f} is a low-weight supporting signal.",
        ),
    ]
    if bssids:
        scores = [
            inventory.get(bssid).trust_score for bssid in bssids if inventory.get(bssid) is not None
        ]
        if scores:
            reasons.append(
                CorrelationReason(
                    source="trust",
                    contribution=config.trust_weight * (1.0 - min(scores) / 100.0),
                    explanation=f"Lowest AP trust score is {min(scores)}.",
                )
            )
    reasons.append(
        CorrelationReason(
            source="repeat",
            contribution=min(
                config.repeat_weight,
                float(max((item.hit_count for item in incidents), default=1) - 1) * 2.0,
            ),
            explanation="Repeated window hits add bounded context.",
        )
    )
    reasons.append(
        CorrelationReason(
            source="families",
            contribution=min(
                config.family_weight,
                float(len(families) - 1) * config.family_weight / 2.0 if families else 0.0,
            ),
            explanation="Additional rule families add bounded context.",
        )
    )
    first = min(item.first_seen for item in incidents) if incidents else datetime.now().astimezone()
    last = max(item.last_seen for item in incidents) if incidents else first
    primary_family = sorted(families)[0] if families else "ml_anomaly"
    not_fired = _merge_evidence(
        item for incident in incidents for item in incident.not_fired_evidence
    )
    why, found, missing, recommended = build_explanation(
        primary_family,
        rule_evidence,
        not_fired,
        bssids,
        ssids,
        clients,
        ml_score,
    )
    raw_counts = Counter(item.rule_id for item in incidents)
    return Alert(
        id=_stable_id(incidents) if incidents else f"ALT-ML-{int(first.timestamp())}",
        timestamp=first,
        family=", ".join(sorted(families)) if families else "ml_anomaly",
        severity=severity,  # type: ignore[arg-type]
        risk_score=risk,
        rule_evidence=rule_evidence,
        evidence=rule_evidence,
        ml_anomaly_score=ml_score,
        why=why,
        reasons=reasons,
        indicators_found=found,
        indicators_not_found=missing,
        recommended_check=recommended,
        bssids=bssids,
        ssids=ssids,
        clients=clients,
        mitre_attack=(map_family(primary_family) if families and not ml_only else None),
        rule_ids=tuple(sorted({item.rule_id for item in incidents})),
        raw_frame_counts=dict(raw_counts),
        first_seen=first,
        last_seen=last,
        hit_count=sum(item.hit_count for item in incidents),
        informational=ml_only,
    )


def correlate(
    incidents: Iterable[Incident],
    ml_scores: Iterable[float],
    inventory: APInventory,
    config: CorrelationConfig | None = None,
) -> list[Alert]:
    """Group incidents and attach ML context. ML-only rows become informational."""
    incident_list = list(incidents)
    scores = list(ml_scores)
    max_ml = max(scores, default=0.0)
    alerts: list[Alert] = []
    for group in group_incidents(incident_list):
        alerts.append(score_group(group, max_ml, inventory, config))
    if not incident_list and scores:
        alerts.append(score_group([], max_ml, inventory, config, ml_only=True))
    return alerts

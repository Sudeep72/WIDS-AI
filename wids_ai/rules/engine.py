"""YAML rule loading, evaluation, and cross-window deduplication."""

from __future__ import annotations

import json
from bisect import bisect_left
from collections import Counter
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

import yaml

from wids_ai.features.extractors import FeatureRow
from wids_ai.inventory import APInventory
from wids_ai.parser.models import Frame
from wids_ai.rules.schema import (
    Condition,
    Detection,
    Evidence,
    Incident,
    RuleDefinition,
)

SEVERITY_CONFIDENCE = {
    "low": 0.55,
    "medium": 0.7,
    "high": 0.85,
    "critical": 0.95,
}


ATTACK_MAPPING_PATH = Path(__file__).resolve().parent.parent / "attack" / "mapping.yml"


class RuleValidationError(ValueError):
    """Raised when a rule file is malformed or inconsistent."""


def _parse_condition_list(value: object, key: str, path: Path) -> tuple[Condition, ...]:
    if not isinstance(value, list) or not value:
        raise RuleValidationError(f"{path}: {key} must be a non-empty list")
    try:
        return tuple(Condition.model_validate(item) for item in value)
    except ValueError as exc:
        raise RuleValidationError(f"{path}: invalid {key}: {exc}") from exc


def _parse_condition(value: object, path: Path) -> Condition:
    if not isinstance(value, dict):
        raise RuleValidationError(f"{path}: conditions must be a mapping")
    payload = dict(value)
    if "all" in payload:
        payload["all"] = _parse_condition_list(payload["all"], "all", path)
    if "any" in payload:
        payload["any"] = _parse_condition_list(payload["any"], "any", path)
    try:
        return Condition.model_validate(payload)
    except ValueError as exc:
        raise RuleValidationError(f"{path}: invalid conditions: {exc}") from exc


def load_rules(directory: str | Path) -> list[RuleDefinition]:
    """Load and validate all YAML rule files in a directory."""
    root = Path(directory)
    if not root.is_dir():
        raise FileNotFoundError(f"Rules directory not found: {root}")
    rules: list[RuleDefinition] = []
    for path in sorted(root.glob("*.yml")):
        try:
            payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise RuleValidationError(f"{path}: invalid YAML: {exc}") from exc
        if not isinstance(payload, dict):
            raise RuleValidationError(f"{path}: rule root must be a mapping")
        payload = dict(payload)
        payload["conditions"] = _parse_condition(payload.get("conditions"), path)
        try:
            rule = RuleDefinition.model_validate(payload)
        except ValueError as exc:
            raise RuleValidationError(f"{path}: {exc}") from exc
        rules.append(rule)
    ids = [rule.id for rule in rules]
    if len(ids) != len(set(ids)):
        raise RuleValidationError("Duplicate rule ids across rule files")
    return rules


def _compare(operator: str, observed: Any, expected: Any) -> bool:
    if operator == "eq":
        return observed == expected
    if operator == "ne":
        return observed != expected
    if operator == "gt":
        return observed > expected
    if operator == "ge":
        return observed >= expected
    if operator == "lt":
        return observed < expected
    if operator == "le":
        return observed <= expected
    if operator == "in":
        return observed in expected
    if operator == "not_in":
        return observed not in expected
    if operator == "contains":
        return expected in observed
    if operator == "not_contains":
        return expected not in observed
    return False


def _condition_matches(condition: Condition, values: Mapping[str, Any]) -> bool:
    if condition.all is not None:
        return all(_condition_matches(item, values) for item in condition.all)
    if condition.any is not None:
        return any(_condition_matches(item, values) for item in condition.any)
    assert condition.field is not None
    assert condition.operator is not None
    return _compare(condition.operator, values.get(condition.field), condition.value)


def _split(value: str) -> tuple[str, ...]:
    return tuple(item for item in value.split(",") if item)


def _rssi_map(value: str) -> dict[str, float]:
    result: dict[str, float] = {}
    for item in value.split(";"):
        if "=" not in item:
            continue
        key, raw = item.split("=", maxsplit=1)
        try:
            result[key] = float(raw)
        except ValueError:
            continue
    return result


def _frame_values(
    row: FeatureRow,
    frames: Iterable[Frame],
    inventory: APInventory,
) -> dict[str, Any]:
    values: dict[str, Any] = row.model_dump()
    selected = [frame for frame in frames if row.window_start <= frame.timestamp < row.window_end]
    if row.scope == "bssid":
        selected = [frame for frame in selected if frame.bssid == row.group]
    elif row.scope == "client":
        selected = [
            frame for frame in selected if row.group in {frame.addr1, frame.addr2, frame.bssid}
        ]
    elif row.scope == "ssid":
        selected = [frame for frame in selected if frame.ssid == row.group]
    elif row.scope == "channel":
        selected = [
            frame
            for frame in selected
            if frame.channel is not None and str(frame.channel) == row.group
        ]

    bssids = _split(row.observed_bssids)
    ssids = _split(row.observed_ssids)
    channels = tuple(int(item) for item in _split(row.observed_beacon_channels))
    security = _split(row.observed_security_modes)
    rssi_by_bssid = _rssi_map(row.rssi_by_bssid)
    known = tuple(bssid for bssid in bssids if inventory.is_known(bssid))
    unknown = tuple(bssid for bssid in bssids if not inventory.is_known(bssid))
    known_bssid = next((bssid for bssid in known), None)
    known_ap = inventory.get(known_bssid)
    known_oui = known_ap.oui if known_ap is not None else None
    security_mismatch = int(
        bool(known_ap and known_ap.security)
        and any(mode not in known_ap.security for mode in security)
    )
    unknown_ouis = tuple(bssid.split(":", maxsplit=3)[0] for bssid in unknown)
    known_channels = sorted(known_ap.channels) if known_ap is not None else []
    reasons = Counter(
        frame.reason_code
        for frame in selected
        if frame.subtype == "deauthentication" and frame.reason_code is not None
    )
    values.update(
        {
            "known_bssid_count": len(known),
            "unknown_bssid_count": len(unknown),
            "inventory_bssid_count": len(inventory.bssids_for_ssid(row.group))
            if row.scope == "ssid"
            else 0,
            "oui_mismatch": int(bool(known_oui) and any(oui != known_oui for oui in unknown_ouis)),
            "rsn_security_mismatch": security_mismatch,
            "channel_mismatch": int(
                bool(known_channels) and any(channel not in known_channels for channel in channels)
            ),
            "known_rssi_delta": (
                max(
                    (
                        abs(rssi_by_bssid[bssid] - (inventory.get(bssid).mean_rssi or 0.0))
                        for bssid in known
                        if bssid in rssi_by_bssid
                    ),
                    default=0.0,
                )
            ),
            "distinct_reason_codes": len(reasons),
            "reason_code_skew": (max(reasons.values()) / sum(reasons.values()) if reasons else 0.0),
            "broadcast_deauth_count": row.broadcast_deauth_count,
            "observed_bssid_count": len(bssids),
            "known_inventory_ssids": tuple(
                ssid for ssid in ssids if inventory.bssids_for_ssid(ssid)
            ),
        }
    )
    return values


def _not_fired_evidence(
    condition: Condition,
    values: Mapping[str, Any],
) -> list[Evidence]:
    evidence: list[Evidence] = []
    if condition.all is not None:
        for item in condition.all:
            if not _condition_matches(item, values):
                evidence.extend(_not_fired_evidence(item, values))
        return evidence
    if condition.any is not None:
        matched = [item for item in condition.any if _condition_matches(item, values)]
        if not matched:
            for item in condition.any:
                evidence.extend(_not_fired_evidence(item, values))
        return evidence
    if condition.field is None or condition.operator is None:
        return evidence
    observed = values.get(condition.field)
    if _compare(condition.operator, observed, condition.value):
        return evidence
    return [
        Evidence(
            field=condition.field,
            observed=observed,
            threshold=condition.value,
            text=f"{condition.field} was {observed!r}, expected {condition.operator} {condition.value!r}",
        )
    ]


def _evidence_for(
    condition: Condition,
    values: Mapping[str, Any],
    threshold: float,
    *,
    prefix: str = "",
) -> list[Evidence]:
    evidence: list[Evidence] = []
    if condition.all is not None:
        for item in condition.all:
            evidence.extend(_evidence_for(item, values, threshold, prefix=prefix))
        return evidence
    if condition.any is not None:
        matched = [item for item in condition.any if _condition_matches(item, values)]
        for item in matched:
            evidence.extend(_evidence_for(item, values, threshold, prefix=prefix))
        return evidence
    if condition.field is None:
        return evidence
    observed = values.get(condition.field)
    if condition.operator and not _compare(condition.operator, observed, condition.value):
        return evidence
    label = f"{prefix}{condition.field}"
    return [
        Evidence(
            field=label,
            observed=observed,
            threshold=condition.value,
            text=f"{label} was {observed!r}, expected {condition.operator} {condition.value!r}",
        )
    ]


def _identity_from_row(row: FeatureRow) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    bssids = _split(row.observed_bssids)
    ssids = _split(row.observed_ssids)
    clients = tuple(
        client
        for client in _split(row.observed_clients)
        if client != "ff:ff:ff:ff:ff:ff" and client not in set(bssids)
    )
    if row.scope == "bssid":
        bssids = (row.group,)
    elif row.scope == "client":
        clients = (row.group,) if row.group not in set(bssids) else ()
    elif row.scope == "ssid":
        ssids = (row.group,)
    elif row.scope == "channel":
        bssids = tuple(bssid for bssid in bssids if bssid)
    return bssids, ssids, clients


def evaluate_rule(
    rule: RuleDefinition,
    row: FeatureRow,
    frames: Iterable[Frame],
    inventory: APInventory,
) -> Detection | None:
    """Evaluate one rule against one feature row."""
    if rule.scope != row.scope:
        return None
    values = _frame_values(row, frames, inventory)
    if not _condition_matches(rule.conditions, values):
        return None
    threshold_field = rule.threshold_field or rule.conditions.field or "frame_count"
    threshold_value = values.get(threshold_field, 0.0)
    composite = rule.conditions.any is not None and len(rule.conditions.any) > 1
    if not composite and (threshold_value is None or float(threshold_value) < rule.threshold):
        return None
    evidence = _evidence_for(rule.conditions, values, rule.threshold)
    bssids, ssids, clients = _identity_from_row(row)
    return Detection(
        rule_id=rule.id,
        family=rule.family,
        severity=rule.severity,
        title=rule.title,
        scope=rule.scope,
        window_start=row.window_start,
        window_end=row.window_end,
        bssids=bssids,
        ssids=ssids,
        clients=clients,
        evidence=tuple(item.model_copy(update={"rule_ids": (rule.id,)}) for item in evidence),
        confidence=SEVERITY_CONFIDENCE[rule.severity],
        attack_ref=rule.attack_ref,
        false_positive_notes=rule.false_positive_notes,
        not_fired_evidence=tuple(
            item.model_copy(update={"rule_ids": (rule.id,)})
            for item in _not_fired_evidence(rule.conditions, values)
        ),
    )


def evaluate_rules(
    rows: Iterable[FeatureRow],
    rules: Iterable[RuleDefinition],
    frames: Iterable[Frame],
    inventory: APInventory,
) -> list[Detection]:
    """Evaluate all rules over all feature rows."""
    frame_list = sorted(frames, key=lambda frame: frame.timestamp)
    timestamps = [frame.timestamp for frame in frame_list]
    rule_list = list(rules)
    mapping = load_attack_mapping()
    refs = mapping.get("refs", {})
    unknown_refs = {rule.attack_ref for rule in rule_list if rule.attack_ref not in refs}
    if unknown_refs:
        raise RuleValidationError(f"Unknown attack_ref values: {sorted(unknown_refs)}")
    detections: list[Detection] = []
    rules_by_scope: dict[str, list[RuleDefinition]] = {}
    for rule in rule_list:
        rules_by_scope.setdefault(rule.scope, []).append(rule)
    for row in rows:
        scope_rules = rules_by_scope.get(row.scope, [])
        if not scope_rules:
            continue
        left = bisect_left(timestamps, row.window_start)
        right = bisect_left(timestamps, row.window_end)
        window_frames = frame_list[left:right]
        for rule in scope_rules:
            detection = evaluate_rule(rule, row, window_frames, inventory)
            if detection is not None:
                detections.append(detection)

    return detections


def deduplicate(
    detections: Iterable[Detection],
    *,
    merge_gap_seconds: float = 10.0,
) -> list[Incident]:
    """Merge detections for the same rule and entities across windows."""
    grouped: dict[
        tuple[str, tuple[str, ...], tuple[str, ...], tuple[str, ...]], list[Detection]
    ] = {}
    for detection in detections:
        key = (
            detection.rule_id,
            detection.bssids,
            detection.ssids,
            detection.clients,
        )
        grouped.setdefault(key, []).append(detection)
    incidents: list[Incident] = []
    for key, group in sorted(grouped.items()):
        ordered = sorted(group, key=lambda item: item.window_start)
        current: list[Detection] = []
        for detection in ordered:
            if not current:
                current = [detection]
                continue
            gap = (detection.window_start - current[-1].window_end).total_seconds()
            if gap <= merge_gap_seconds:
                current.append(detection)
            else:
                incidents.append(_incident_from(key, current))
                current = [detection]
        if current:
            incidents.append(_incident_from(key, current))
    return sorted(incidents, key=lambda item: (item.first_seen, item.rule_id))


def _incident_from(
    key: tuple[str, tuple[str, ...], tuple[str, ...], tuple[str, ...]],
    detections: list[Detection],
) -> Incident:
    first = detections[0]
    merged_evidence = []
    seen_evidence: set[tuple[str, str]] = set()
    for detection in detections:
        for evidence in detection.evidence:
            marker = (evidence.field, evidence.text)
            if marker in seen_evidence:
                continue
            seen_evidence.add(marker)
            merged_evidence.append(evidence)
    return Incident(
        id=f"INC-{first.rule_id}-{first.window_start.timestamp():.0f}",
        rule_id=key[0],
        family=first.family,
        severity=first.severity,
        title=first.title,
        first_seen=first.window_start,
        last_seen=max(item.window_end for item in detections),
        hit_count=len(detections),
        bssids=key[1],
        ssids=key[2],
        clients=key[3],
        evidence=tuple(merged_evidence),
        confidence=max(item.confidence for item in detections),
        attack_ref=first.attack_ref,
        false_positive_notes=first.false_positive_notes,
    )


def load_attack_mapping(path: str | Path = ATTACK_MAPPING_PATH) -> dict[str, object]:
    """Load ATT&CK family and rule mappings from the single mapping file."""
    payload = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise RuleValidationError(f"{path}: attack mapping must be a mapping")
    return payload


def write_detections(incidents: Iterable[Incident], path: str | Path) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    mapping = load_attack_mapping()
    families = mapping.get("families", {})
    payload = []
    for item in incidents:
        record = item.model_dump(mode="json")
        record["mitre_attack"] = families.get(item.family)
        payload.append(record)
    destination.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

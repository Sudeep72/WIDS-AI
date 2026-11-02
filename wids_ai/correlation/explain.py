"""Deterministic template-based alert explanations."""

from __future__ import annotations

from wids_ai.correlation.schema import Indicator
from wids_ai.rules.schema import Evidence


def build_explanation(
    family: str,
    evidence: list[Evidence],
    not_fired_evidence: list[Evidence],
    bssids: tuple[str, ...],
    ssids: tuple[str, ...],
    clients: tuple[str, ...],
    ml_score: float,
) -> tuple[str, list[Indicator], list[Indicator], str]:
    """Build an explanation from deduplicated evaluated evidence only."""
    found = [
        Indicator(
            field=item.field,
            observed=str(item.observed),
            expected=str(item.threshold),
            meaning=item.text,
        )
        for item in evidence
    ]
    not_found = [
        Indicator(
            field=item.field,
            observed=str(item.observed),
            expected=str(item.threshold),
            meaning=item.text,
        )
        for item in not_fired_evidence
        if item.field not in {found_item.field for found_item in found}
    ]
    entities = []
    if bssids:
        entities.append("BSSIDs " + ", ".join(bssids))
    if ssids:
        entities.append("SSIDs " + ", ".join(ssids))
    if clients:
        entities.append("clients " + ", ".join(clients))
    entity_text = "; ".join(entities) if entities else "no specific entities"
    evidence_text = "; ".join(item.text for item in evidence) if evidence else "no rule evidence"
    why = (
        f"{family} evidence was observed for {entity_text}. "
        f"Rule evidence: {evidence_text}. "
        f"The anomaly model contributes a supporting score of {ml_score:.3f}; "
        "it is not a standalone verdict."
    )
    recommended = {
        "evil_twin_rogue_ap": "Verify the BSSID and OUI against the trusted inventory and inspect the nearby radio environment.",
        "deauth_disassoc_anomaly": "Check whether the affected client or access point initiated a legitimate reconnect or maintenance event.",
        "probe_response_karma": "Confirm whether the responding BSSID is authorized to advertise every observed SSID.",
        "beacon_management_anomaly": "Inspect the beacon stream for firmware reset, packet loss, or unauthorized management activity.",
    }.get(
        family,
        "Validate the observed entities against the trusted baseline and local change records.",
    )
    return why, found, not_found, recommended

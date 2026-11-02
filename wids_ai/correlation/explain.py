"""Deterministic template-based alert explanations."""

from __future__ import annotations

from wids_ai.correlation.schema import Indicator
from wids_ai.rules.schema import Evidence


def build_explanation(
    family: str,
    evidence: list[Evidence],
    bssids: tuple[str, ...],
    ssids: tuple[str, ...],
    clients: tuple[str, ...],
    ml_score: float,
) -> tuple[str, list[Indicator], list[Indicator], str]:
    """Build a plain-English explanation strictly from supplied evidence."""
    found = [
        Indicator(
            field=item.field,
            observed=str(item.observed),
            expected=str(item.threshold),
            meaning=item.text,
        )
        for item in evidence
    ]
    expected_checks = {
        "evil_twin_rogue_ap": ("inventory_match", "channel_match", "rsn_match"),
        "deauth_disassoc_anomaly": ("normal_deauth_rate", "unicast_only"),
        "probe_response_karma": ("single_ssid_response", "stable_oui"),
        "beacon_management_anomaly": ("stable_interval", "monotonic_sequence"),
    }
    found_fields = {item.field for item in evidence}
    not_found = [
        Indicator(
            field=field,
            observed="not established",
            expected="expected baseline",
            meaning="This indicator was not established by the rule evidence.",
        )
        for field in expected_checks.get(family, ())
        if field not in found_fields
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

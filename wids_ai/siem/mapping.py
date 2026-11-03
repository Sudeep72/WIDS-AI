"""NanoSIEM field mapping for WIDS-AI alerts."""

from __future__ import annotations

import json
import re
import socket
import unicodedata
import uuid
from datetime import UTC, datetime
from typing import Any

from wids_ai.correlation.schema import Alert
from wids_ai.siem.schema import NANOSIEM_FIELD_KEYS, NormalizedEvent

SYSLOG_SEVERITY = {
    "critical": "crit",
    "high": "err",
    "medium": "warning",
    "low": "notice",
    "informational": "info",
}
CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029]")
SENTENCE_END = re.compile(r"[.!?](?=\s|$)")
MAX_MESSAGE = 500
MAX_RAW = 8192


def clean_text(value: Any, limit: int = 1000) -> str:
    """Strip control characters and normalize attacker-controlled text."""
    if value is None:
        return ""
    text = unicodedata.normalize("NFC", str(value))
    return CONTROL_CHARS.sub("", text)[:limit]


def clean_value(
    value: Any,
    depth: int = 0,
    *,
    string_limit: int = 4000,
    list_limit: int = 200,
) -> Any:
    """Recursively sanitize JSON-compatible values."""
    if depth > 8:
        return "[truncated]"
    if isinstance(value, dict):
        return {
            clean_text(key, 128): clean_value(
                item,
                depth + 1,
                string_limit=string_limit,
                list_limit=list_limit,
            )
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [
            clean_value(
                item,
                depth + 1,
                string_limit=string_limit,
                list_limit=list_limit,
            )
            for item in value[:list_limit]
        ]
    if isinstance(value, str):
        return clean_text(value, string_limit)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return clean_text(value, string_limit)


def _clean_list(values: Any, limit: int, count: int = 200) -> list[str]:
    if values is None:
        return []
    return [clean_text(item, limit) for item in list(values)[:count]]


def _timestamp(value: datetime | None, fallback: datetime) -> str:
    selected = value or fallback
    if selected.tzinfo is None:
        selected = selected.replace(tzinfo=UTC)
    return selected.astimezone(UTC).isoformat()


def _finish_sentence(text: str) -> str:
    return text if text.endswith((".", "!", "?")) else f"{text}."


def _sentence_message(alert: Alert) -> str:
    prefix = f"WIDS-AI {clean_text(alert.family, 128)} (risk {alert.risk_score}): "
    why = clean_text(alert.why, 4000).strip()
    if not why:
        why = "Rule evidence requires analyst review."
    first = SENTENCE_END.search(why)
    sentence = why[: first.end()] if first else why
    full = prefix + sentence
    if len(full) <= MAX_MESSAGE:
        return _finish_sentence(full)
    available = MAX_MESSAGE - len(prefix)
    segment = sentence[:available]
    boundaries = list(SENTENCE_END.finditer(segment))
    if boundaries:
        return prefix + segment[: boundaries[-1].end()]
    candidate = sentence[: max(1, available - 3)].rstrip()
    word_boundary = candidate.rfind(" ")
    if word_boundary > 0:
        candidate = candidate[:word_boundary].rstrip()
    return f"{prefix}{candidate}..."


def _truncate_strings(value: Any, limit: int, depth: int = 0) -> Any:
    if depth > 8:
        return "[truncated]"
    if isinstance(value, dict):
        result = {
            clean_text(key, 128): _truncate_strings(item, limit, depth + 1)
            for key, item in value.items()
        }
        result["_truncated"] = True
        return result
    if isinstance(value, list):
        return [_truncate_strings(item, limit, depth + 1) for item in value[:10]]
    if isinstance(value, str):
        if len(value) <= limit:
            return value
        return value[:limit].rstrip() + "..."
    return value


def _bounded_raw(value: Any) -> str:
    """Return compact valid JSON no larger than 8 KB."""
    candidate = json.dumps(value, separators=(",", ":"), ensure_ascii=False)
    if len(candidate.encode("utf-8")) <= MAX_RAW:
        return candidate
    for string_limit in (2048, 1024, 512, 256, 128, 64, 32):
        candidate = json.dumps(
            _truncate_strings(value, string_limit),
            separators=(",", ":"),
            ensure_ascii=False,
        )
        if len(candidate.encode("utf-8")) <= MAX_RAW:
            return candidate
    fallback = {
        "_truncated": True,
        "id": clean_text(value.get("id"), 128) if isinstance(value, dict) else "",
        "family": clean_text(value.get("family"), 256) if isinstance(value, dict) else "",
        "severity": clean_text(value.get("severity"), 32) if isinstance(value, dict) else "",
        "risk_score": value.get("risk_score") if isinstance(value, dict) else None,
        "why": clean_text(value.get("why"), 1024) if isinstance(value, dict) else "",
    }
    return json.dumps(fallback, separators=(",", ":"), ensure_ascii=False)


def alert_to_event(
    alert: Alert,
    *,
    host: str | None = None,
    ingested_at: datetime | None = None,
) -> NormalizedEvent:
    """Map one correlated alert to a NanoSIEM NormalizedEvent."""
    exported = alert.model_dump(mode="json")
    sanitized = clean_value(exported)
    raw = _bounded_raw(sanitized)
    first_seen = alert.first_seen or alert.timestamp
    technique = alert.mitre_attack.technique if alert.mitre_attack else None
    family = clean_text(alert.family, 128)
    fields = {
        "wids_alert_id": clean_text(alert.id, 128),
        "wids_family": family,
        "wids_rule_ids": _clean_list(alert.rule_ids, 64),
        "wids_risk_score": int(alert.risk_score),
        "wids_severity": clean_text(alert.severity, 32),
        "wids_ml_score": float(alert.ml_anomaly_score),
        "wids_bssids": _clean_list(alert.bssids, 64),
        "wids_ssids": _clean_list(alert.ssids, 256),
        "wids_clients": _clean_list(alert.clients, 64),
        "wids_hit_count": int(alert.hit_count),
        "wids_first_seen": _timestamp(first_seen, alert.timestamp),
        "wids_last_seen": _timestamp(alert.last_seen, first_seen),
        "mitre_tactic": clean_text(alert.mitre_attack.tactic, 128)
        if alert.mitre_attack and alert.mitre_attack.tactic
        else None,
        "mitre_technique": clean_text(technique, 32) if technique else None,
        "mitre_technique_name": clean_text(alert.mitre_attack.technique_name, 256)
        if alert.mitre_attack
        else None,
        "wids_recommended_check": clean_text(alert.recommended_check, 1000),
        "wids_schema_version": 1,
    }
    if tuple(fields) != NANOSIEM_FIELD_KEYS:
        raise RuntimeError("SIEM field mapping order and names changed")
    tags = [
        "wids",
        f"wids:family:{family}",
        f"wids:severity:{clean_text(alert.severity, 32)}",
    ]
    if technique:
        tags.append(f"attack:{clean_text(technique, 32)}")
    now = ingested_at or datetime.now(tz=UTC)
    sensor = clean_text(host, 255) if host else clean_text(socket.gethostname(), 255)
    return NormalizedEvent(
        event_id=str(uuid.uuid5(uuid.NAMESPACE_URL, f"{alert.id}:{alert.hit_count}")),
        timestamp=_timestamp(first_seen, alert.timestamp),
        ingested_at=_timestamp(now, now),
        host=sensor or "wids-ai",
        severity=SYSLOG_SEVERITY[alert.severity],
        message=_sentence_message(alert),
        raw=raw,
        fields=fields,
        tags=tags,
    )

"""Strict NanoSIEM NormalizedEvent export schema."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

NANOSIEM_EVENT_KEYS: tuple[str, ...] = (
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

NANOSIEM_FIELD_KEYS: tuple[str, ...] = (
    "wids_alert_id",
    "wids_family",
    "wids_rule_ids",
    "wids_risk_score",
    "wids_severity",
    "wids_ml_score",
    "wids_bssids",
    "wids_ssids",
    "wids_clients",
    "wids_hit_count",
    "wids_first_seen",
    "wids_last_seen",
    "mitre_tactic",
    "mitre_technique",
    "mitre_technique_name",
    "wids_recommended_check",
    "wids_schema_version",
)


class NormalizedEvent(BaseModel):
    """One NanoSIEM normalized event with the required export keys."""

    model_config = ConfigDict(extra="forbid")

    event_id: str
    timestamp: str
    ingested_at: str
    host: str
    source_ip: None = None
    dest_ip: None = None
    source_port: None = None
    dest_port: None = None
    log_source: Literal["json"] = "json"
    facility: None = None
    severity: Literal["crit", "err", "warning", "notice", "info"]
    program: Literal["wids-ai"] = "wids-ai"
    pid: None = None
    message: str = Field(max_length=500)
    raw: str = Field(max_length=8192)
    fields: dict[str, Any]
    tags: list[str]
    anomaly_score: None = None
    sigma_matches: list[Any] = Field(default_factory=list)
    alert_id: None = None

    @field_validator("host")
    @classmethod
    def host_must_not_be_empty(cls, value: str) -> str:
        if not value:
            raise ValueError("host must not be empty")
        return value

    @field_validator("fields")
    @classmethod
    def fields_must_be_flat(cls, value: dict[str, Any]) -> dict[str, Any]:
        collisions = set(value) & set(NANOSIEM_EVENT_KEYS)
        if collisions:
            raise ValueError(f"fields collide with top-level keys: {sorted(collisions)}")
        if any(isinstance(item, dict) for item in value.values()):
            raise ValueError("fields values must be flat, not nested objects")
        return value

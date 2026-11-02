"""Correlated alert models and evidence structures."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from wids_ai.rules.schema import Evidence

Severity = Literal["informational", "low", "medium", "high", "critical"]


class Indicator(BaseModel):
    """One observed or expected indicator in an explanation."""

    model_config = ConfigDict(extra="forbid")

    field: str
    observed: str
    expected: str
    meaning: str


class AttackMapping(BaseModel):
    """Best-fit ATT&CK mapping attached to an alert."""

    model_config = ConfigDict(extra="forbid")

    tactic: str | None = None
    technique: str | None = None
    technique_name: str
    matrix: str | None = None
    verified: bool = False
    verification_url: str | None = None


class CorrelationReason(BaseModel):
    """One numeric contribution to the final risk score."""

    model_config = ConfigDict(extra="forbid")

    source: str
    contribution: float
    explanation: str


class Alert(BaseModel):
    """Final correlated alert."""

    model_config = ConfigDict(extra="forbid")

    id: str
    timestamp: datetime
    family: str
    severity: Severity
    risk_score: int = Field(ge=0, le=100)
    rule_evidence: list[Evidence] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    ml_anomaly_score: float = Field(ge=0.0, le=1.0)
    why: str
    reasons: list[CorrelationReason] = Field(default_factory=list)
    indicators_found: list[Indicator] = Field(default_factory=list)
    indicators_not_found: list[Indicator] = Field(default_factory=list)
    recommended_check: str
    bssids: tuple[str, ...] = ()
    ssids: tuple[str, ...] = ()
    clients: tuple[str, ...] = ()
    mitre_attack: AttackMapping | None = None
    rule_ids: tuple[str, ...] = ()
    raw_frame_counts: dict[str, int] = Field(default_factory=dict)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    hit_count: int = 0
    informational: bool = False

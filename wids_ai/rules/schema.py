"""Validated YAML rule schema and rule result models."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

Severity = Literal["low", "medium", "high", "critical"]
Operator = Literal[
    "eq",
    "ne",
    "gt",
    "ge",
    "lt",
    "le",
    "in",
    "not_in",
    "contains",
    "not_contains",
]
Composite = Literal["all", "any"]


class Condition(BaseModel):
    """One field comparison or nested all/any group."""

    model_config = ConfigDict(extra="forbid")

    field: str | None = None
    operator: Operator | None = None
    value: Any = None
    all: tuple[Condition, ...] | None = None
    any: tuple[Condition, ...] | None = None

    @model_validator(mode="after")
    def validate_shape(self) -> Condition:
        has_group = self.all is not None or self.any is not None
        has_leaf = self.field is not None or self.operator is not None
        if has_group and has_leaf:
            raise ValueError("Condition cannot mix a group with field/operator")
        if not has_group and (self.field is None or self.operator is None):
            raise ValueError("Leaf condition requires field and operator")
        if self.all is not None and not self.all:
            raise ValueError("all group cannot be empty")
        if self.any is not None and not self.any:
            raise ValueError("any group cannot be empty")
        return self


class RuleDefinition(BaseModel):
    """Validated detection rule loaded from YAML."""

    model_config = ConfigDict(extra="forbid")

    id: str
    title: str
    family: str
    description: str
    severity: Severity
    scope: Literal["bssid", "client", "ssid", "channel", "inventory"]
    conditions: Condition
    threshold: float = Field(ge=0)
    threshold_field: str | None = None
    window: int = Field(gt=0)
    cooldown: int = Field(ge=0)
    attack_ref: str
    false_positive_notes: str

    @model_validator(mode="after")
    def validate_identity(self) -> RuleDefinition:
        if not self.id.startswith(("WIDS-", "wids-")):
            raise ValueError("Rule id must start with WIDS-")
        if not self.attack_ref:
            raise ValueError("attack_ref is required")
        return self


class Evidence(BaseModel):
    """Deterministic evidence item attached to a detection."""

    model_config = ConfigDict(frozen=True)

    field: str
    observed: Any
    threshold: Any
    text: str
    rule_ids: tuple[str, ...] = ()


class Detection(BaseModel):
    """A rule hit before cross-window incident merging."""

    model_config = ConfigDict(extra="forbid")

    rule_id: str
    family: str
    severity: Severity
    title: str
    scope: str
    window_start: datetime
    window_end: datetime
    bssids: tuple[str, ...] = ()
    ssids: tuple[str, ...] = ()
    clients: tuple[str, ...] = ()
    evidence: tuple[Evidence, ...] = ()
    confidence: float = Field(ge=0.0, le=1.0)
    attack_ref: str
    false_positive_notes: str
    not_fired_evidence: tuple[Evidence, ...] = ()


class Incident(BaseModel):
    """Deduplicated detection across overlapping windows."""

    model_config = ConfigDict(extra="forbid")

    id: str
    rule_id: str
    family: str
    severity: Severity
    title: str
    first_seen: datetime
    last_seen: datetime
    hit_count: int
    bssids: tuple[str, ...] = ()
    ssids: tuple[str, ...] = ()
    clients: tuple[str, ...] = ()
    evidence: tuple[Evidence, ...] = ()
    confidence: float = Field(ge=0.0, le=1.0)
    attack_ref: str
    false_positive_notes: str
    not_fired_evidence: tuple[Evidence, ...] = ()

"""ATT&CK mapping lookup with a single source of truth."""

from __future__ import annotations

from pathlib import Path

import yaml

from wids_ai.correlation.schema import AttackMapping

MAPPING_PATH = Path(__file__).resolve().parent / "mapping.yml"


class AttackMappingError(ValueError):
    """Raised for missing or invalid ATT&CK mapping data."""


def load_mapping(path: str | Path = MAPPING_PATH) -> dict[str, object]:
    payload = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise AttackMappingError("ATT&CK mapping must be a mapping")
    return payload


def map_family(family: str, path: str | Path = MAPPING_PATH) -> AttackMapping | None:
    """Return the best-fit ATT&CK mapping for a family."""
    payload = load_mapping(path)
    families = payload.get("families", {})
    if not isinstance(families, dict):
        return None
    item = families.get(family)
    if not isinstance(item, dict):
        return None
    return AttackMapping.model_validate(item)


def map_rule(rule_id: str, path: str | Path = MAPPING_PATH) -> AttackMapping | None:
    """Resolve a rule to its family, then to its best-fit ATT&CK mapping."""
    payload = load_mapping(path)
    rules = payload.get("rules", {})
    if not isinstance(rules, dict):
        return None
    family = rules.get(rule_id)
    return map_family(str(family), path) if family else None

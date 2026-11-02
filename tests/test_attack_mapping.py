from __future__ import annotations

from pathlib import Path

import yaml


def test_attack_mapping_preserves_project_rules(project_root: Path) -> None:
    payload = yaml.safe_load((project_root / "wids_ai" / "attack" / "mapping.yml").read_text())
    assert payload["families"] == {}
    assert payload["rules"] == {}

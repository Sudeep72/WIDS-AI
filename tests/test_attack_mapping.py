from __future__ import annotations

from pathlib import Path

import yaml


def test_attack_mapping_covers_all_rules(project_root: Path) -> None:
    payload = yaml.safe_load((project_root / "wids_ai" / "attack" / "mapping.yml").read_text())
    families = payload["families"]
    rules = payload["rules"]
    assert len(families) == 4
    assert len(rules) == 13
    assert set(rules.values()) == set(families)
    for mapping in families.values():
        assert set(mapping) == {"tactic", "technique", "technique_name"}
        assert mapping["technique"].startswith("T")

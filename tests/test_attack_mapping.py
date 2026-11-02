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
        assert set(mapping) == {
            "tactic",
            "technique",
            "technique_name",
            "matrix",
            "verified",
            "verification_url",
        }
        if mapping["technique"] is not None:
            assert mapping["technique"].startswith("T")
            assert mapping["matrix"] in {"Enterprise", "Mobile"}
            assert "attack.mitre.org/techniques/" in mapping["verification_url"]


def test_beacon_mapping_is_explicitly_no_technique(project_root: Path) -> None:
    payload = yaml.safe_load((project_root / "wids_ai" / "attack" / "mapping.yml").read_text())
    beacon = payload["families"]["beacon_management_anomaly"]
    assert beacon["technique"] is None
    assert beacon["tactic"] is None
    assert beacon["technique_name"] == "none, spoofing or evasion indicator"

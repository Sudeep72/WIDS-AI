from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from wids_ai.config import Settings, load_config


def test_default_config_loads(project_root: Path) -> None:
    settings = load_config(project_root / "config" / "wids.yml")
    assert settings.app.name == "WIDS-AI"
    assert settings.capture.live.enabled is False
    assert settings.siem.enabled is False


def test_config_rejects_out_of_range_contamination(tmp_path: Path) -> None:
    payload = "ml:\n  contamination: 0\n"
    path = tmp_path / "invalid.yml"
    path.write_text(payload, encoding="utf-8")
    with pytest.raises(ValidationError):
        load_config(path)


def test_config_requires_existing_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_config(tmp_path / "missing.yml")


def test_environment_selects_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "environment.yml"
    path.write_text("app:\n  environment: test\n", encoding="utf-8")
    monkeypatch.setenv("WIDS_CONFIG", str(path))
    assert load_config().app.environment == "test"


def test_defaults_are_valid() -> None:
    settings = Settings()
    assert settings.ml.random_seed == 42
    assert settings.api.port == 8000

from __future__ import annotations

import importlib.metadata
from pathlib import Path

import pytest
from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet

RUNTIME_PACKAGES = {
    "fastapi",
    "joblib",
    "numpy",
    "pandas",
    "pydantic",
    "pyyaml",
    "scapy",
    "scikit-learn",
    "uvicorn",
}


def _normalize(name: str) -> str:
    return name.lower().replace("_", "-")


def _requirements(path: Path) -> dict[str, str]:
    pins: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", "-r ")):
            continue
        requirement = Requirement(line)
        assert list(requirement.specifier) and all(
            spec.operator == "==" for spec in requirement.specifier
        )
        pins[_normalize(requirement.name)] = line
    return pins


def test_requires_python_covers_supported_versions(project_root: Path) -> None:
    text = (project_root / "pyproject.toml").read_text(encoding="utf-8")
    assert 'requires-python = ">=3.11"' in text


def test_declared_dependencies_match_requirements(project_root: Path) -> None:
    text = (project_root / "pyproject.toml").read_text(encoding="utf-8")
    pins = _requirements(project_root / "requirements.txt")
    for name in RUNTIME_PACKAGES:
        assert f'"{pins[name]}"' in text


@pytest.mark.parametrize("python_version", ["3.11", "3.12", "3.13", "3.14"])
def test_runtime_pins_support_python_versions(project_root: Path, python_version: str) -> None:
    pins = _requirements(project_root / "requirements.txt")
    for name in RUNTIME_PACKAGES:
        assert Requirement(pins[name]).marker is None
        requires_python = importlib.metadata.metadata(name).get("Requires-Python")
        assert requires_python, f"{name} has no Requires-Python metadata"
        assert SpecifierSet(requires_python).contains(python_version), (
            f"{name} {pins[name]} does not support Python {python_version}"
        )


@pytest.mark.parametrize("python_version", ["3.11", "3.12", "3.13", "3.14"])
def test_development_pins_support_python_versions(project_root: Path, python_version: str) -> None:
    pins = _requirements(project_root / "requirements-dev.txt")
    for name in ("pytest", "pytest-xdist", "ruff", "httpx"):
        assert Requirement(pins[name]).marker is None
        requires_python = importlib.metadata.metadata(name).get("Requires-Python")
        assert requires_python, f"{name} has no Requires-Python metadata"
        assert SpecifierSet(requires_python).contains(python_version), (
            f"{name} {pins[name]} does not support Python {python_version}"
        )


def test_runtime_pins_match_installed_versions(project_root: Path) -> None:
    pins = _requirements(project_root / "requirements.txt")
    for name, line in pins.items():
        installed = importlib.metadata.version(name)
        assert line.endswith(f"=={installed}"), f"{name}: {line} but installed {installed}"

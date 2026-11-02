"""YAML configuration loading and validation."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, PositiveInt, field_validator

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config" / "wids.yml"


class AppConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = "WIDS-AI"
    environment: Literal["development", "test", "production"] = "development"
    timezone: str = "UTC"


class LoggingConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    format: str = "%(asctime)s %(levelname)s %(name)s %(message)s"


class LiveCaptureConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    interface: str = "wlan0mon"
    channel: PositiveInt = 6


class CaptureConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pcap_directory: Path = Path("data/pcaps")
    live: LiveCaptureConfig = Field(default_factory=LiveCaptureConfig)


class StorageConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    database_path: Path = Path("data/wids.db")


class MLConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    model_path: Path = Path("artifacts/isolation_forest.joblib")
    contamination: float = Field(default=0.05, gt=0.0, le=0.5)
    random_seed: int = 42


class SIEMConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    file_path: Path = Path("data/siem/events.jsonl")
    http_endpoint: str | None = None
    timeout_seconds: PositiveInt = 5

    @field_validator("http_endpoint")
    @classmethod
    def validate_http_endpoint(cls, value: str | None) -> str | None:
        if value is not None and not value.startswith(("http://", "https://")):
            raise ValueError("http_endpoint must start with http:// or https://")
        return value


class APIConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    host: str = "127.0.0.1"
    port: int = Field(default=8000, ge=1, le=65535)


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    app: AppConfig = Field(default_factory=AppConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    capture: CaptureConfig = Field(default_factory=CaptureConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)
    ml: MLConfig = Field(default_factory=MLConfig)
    siem: SIEMConfig = Field(default_factory=SIEMConfig)
    api: APIConfig = Field(default_factory=APIConfig)


def load_config(path: str | Path | None = None) -> Settings:
    """Load settings from YAML, with WIDS_CONFIG overriding the default path."""
    selected = path or os.environ.get("WIDS_CONFIG") or DEFAULT_CONFIG_PATH
    config_path = Path(selected)
    if not config_path.is_absolute():
        config_path = PROJECT_ROOT / config_path
    if not config_path.is_file():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    with config_path.open("r", encoding="utf-8") as handle:
        payload = yaml.safe_load(handle) or {}
    if not isinstance(payload, dict):
        raise ValueError("Configuration root must be a mapping")
    return Settings.model_validate(payload)

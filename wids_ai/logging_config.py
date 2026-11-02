"""Application logging setup."""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from wids_ai.config import Settings


def configure_logging(settings: Settings, log_file: Path | None = None) -> None:
    """Configure root logging once with console and optional rotating file output."""
    root = logging.getLogger()
    root.setLevel(settings.logging.level)
    root.handlers.clear()

    formatter = logging.Formatter(settings.logging.format)
    console = logging.StreamHandler()
    console.setFormatter(formatter)
    root.addHandler(console)

    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=5 * 1024 * 1024,
            backupCount=3,
            encoding="utf-8",
        )
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)

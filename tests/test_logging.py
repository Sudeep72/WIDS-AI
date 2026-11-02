from __future__ import annotations

import logging
from pathlib import Path

from wids_ai.config import Settings
from wids_ai.logging_config import configure_logging


def test_logging_writes_to_file(tmp_path: Path) -> None:
    log_file = tmp_path / "logs" / "wids.log"
    configure_logging(Settings(), log_file)
    logging.getLogger("wids_ai.test").info("milestone-one")
    for handler in logging.getLogger().handlers:
        handler.flush()
    assert "milestone-one" in log_file.read_text(encoding="utf-8")

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from wids_ai.cli import main


def test_cli_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "0.1.0" in capsys.readouterr().out


def test_cli_help_without_command(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == 0
    assert "analyze" in capsys.readouterr().out


def test_cli_analyze_is_scaffolded(tmp_path: Path) -> None:
    pcap = tmp_path / "sample.pcap"
    pcap.write_bytes(b"")
    assert main(["analyze", str(pcap)]) == 0


@pytest.mark.skipif(sys.platform == "linux", reason="Checks non-Linux guard behavior")
def test_live_is_refused_off_linux() -> None:
    with pytest.raises(RuntimeError, match="requires Linux"):
        main(["live", "--iface", "wlan0mon"])

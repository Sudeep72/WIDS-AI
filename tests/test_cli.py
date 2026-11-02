from __future__ import annotations

import sys
from pathlib import Path

import pytest
from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap, wrpcap

from wids_ai.cli import main


def test_cli_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "0.1.0" in capsys.readouterr().out


def test_cli_help_without_command(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == 0
    assert "analyze" in capsys.readouterr().out


def test_cli_analyze_reads_pcap(tmp_path: Path) -> None:
    pcap = tmp_path / "sample.pcap"
    packet = (
        RadioTap(present="Channel+dBm_AntSignal", ChannelFrequency=2437, dBm_AntSignal=-45)
        / Dot11(
            type=0,
            subtype=8,
            addr1="ff:ff:ff:ff:ff:ff",
            addr2="00:11:22:33:44:55",
            addr3="00:11:22:33:44:55",
        )
        / Dot11Beacon(cap=0x0401, beacon_interval=100)
        / Dot11Elt(ID="SSID", info=b"lab")
    )
    wrpcap(str(pcap), [packet])
    assert main(["analyze", str(pcap)]) == 0


@pytest.mark.skipif(sys.platform == "linux", reason="Checks non-Linux guard behavior")
def test_live_is_refused_off_linux() -> None:
    with pytest.raises(RuntimeError, match="requires Linux"):
        main(["live", "--iface", "wlan0mon"])

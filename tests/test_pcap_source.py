from __future__ import annotations

from pathlib import Path

import pytest
from scapy.all import Dot11, Dot11Deauth, RadioTap, wrpcap

from wids_ai.capture.base import PcapSource
from wids_ai.parser.dot11 import parse_frame


def _pcap(path: Path) -> Path:
    packet = (
        RadioTap(
            present="Channel+dBm_AntSignal",
            ChannelFrequency=2437,
            ChannelFlags=0x00A0,
            dBm_AntSignal=-50,
        )
        / Dot11(
            type=0,
            subtype=12,
            addr1="ff:ff:ff:ff:ff:ff",
            addr2="00:11:22:33:44:55",
            addr3="00:11:22:33:44:55",
        )
        / Dot11Deauth(reason=7)
    )
    packet.time = 1_700_000_000
    wrpcap(str(path), [packet])
    return path


def test_pcap_source_reads_offline(tmp_path: Path) -> None:
    path = _pcap(tmp_path / "deauth.pcap")
    packets = list(PcapSource(path).packets())
    assert len(packets) == 1
    assert packets[0].haslayer(Dot11)


def test_pcap_source_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="PCAP file not found"):
        list(PcapSource(tmp_path / "missing.pcap").packets())


def test_pcap_source_rejects_invalid_bytes(tmp_path: Path) -> None:
    path = tmp_path / "invalid.pcap"
    path.write_bytes(b"not a pcap")
    with pytest.raises(ValueError, match="Unable to read PCAP"):
        list(PcapSource(path).packets())


def test_pcap_source_preserves_capture_timestamp(tmp_path: Path) -> None:
    path = _pcap(tmp_path / "timestamp.pcap")
    kept = next(iter(PcapSource(path).packets()))
    frame = parse_frame(kept)
    assert frame is not None
    assert frame.timestamp.year == 2023

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap

from wids_ai.capture.live_source import LiveCaptureUnavailable, LiveSource, preflight
from wids_ai.live import build_live_inventory, capture_frames, run_live
from wids_ai.pipeline import parse_live_packet
from wids_ai.storage.db import Database

pytestmark = pytest.mark.slow


def _packet(second: float = 0.0) -> object:
    packet = (
        RadioTap(present="Channel+dBm_AntSignal", ChannelFrequency=2437, dBm_AntSignal=-42)
        / Dot11(
            type=0,
            subtype=8,
            addr1="ff:ff:ff:ff:ff:ff",
            addr2="00:11:22:33:44:55",
            addr3="00:11:22:33:44:55",
        )
        / Dot11Beacon(cap=0x0401, beacon_interval=100)
        / Dot11Elt(ID="SSID", info=b"LabNet")
    )
    packet.time = 1_700_000_000 + second
    return packet


def test_live_uses_arrival_time_not_radiotap_timestamp() -> None:
    frame = parse_live_packet(_packet(second=500), 1_800_000_000.25)
    assert frame is not None
    assert frame.timestamp == datetime.fromtimestamp(1_800_000_000.25, tz=UTC)
    assert frame.timestamp.year == 2027


def test_fake_source_capture_writes_radio_tap_pcap(tmp_path: Path) -> None:
    packets = [_packet(index) for index in range(3)]
    source = LiveSource("fake0", packet_source=lambda: packets)
    frames, errors, sink = capture_frames(source, write_pcap=tmp_path / "capture.pcap")
    sink.close()
    assert len(frames) == 3
    assert errors == 0
    assert (tmp_path / "capture.pcap").is_file()
    raw = (tmp_path / "capture.pcap").read_bytes()
    assert raw


def test_live_run_persists_capture_stats(tmp_path: Path) -> None:
    packets = [_packet(index) for index in range(4)]
    source = LiveSource("fake0", packet_source=lambda: packets)
    inventory = build_live_inventory(
        LiveSource("fake0", packet_source=lambda: packets),
        duration=1,
        yes=True,
    )
    database = Database(tmp_path / "live.db")
    try:
        result = run_live(
            source,
            database=database,
            inventory=inventory,
            model_root=tmp_path / "missing",
            trusted_model_root=tmp_path,
            duration=1,
        )
        stats = database.get_stats()
        assert result.frames == 4
        assert stats["frames_processed"] == 4
        assert stats["frames_per_second"] >= 0
        assert stats["parse_errors"] == 0
        assert stats["dropped"] == 0
    finally:
        database.close()


def test_live_source_rejects_packet_without_radiotap(monkeypatch: pytest.MonkeyPatch) -> None:
    import wids_ai.capture.live_source as live_source

    def fake_sniff(**kwargs):
        kwargs["prn"](Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff"))
        return []

    monkeypatch.setitem(
        __import__("sys").modules, "scapy.all", type("S", (), {"sniff": fake_sniff})
    )
    source = live_source.LiveSource("wlan0mon")
    monkeypatch.setattr(live_source, "preflight", lambda interface: None)
    with pytest.raises(LiveCaptureUnavailable, match="RadioTap"):
        list(source.packets())


def test_live_preflight_rejects_off_linux(monkeypatch: pytest.MonkeyPatch) -> None:
    import wids_ai.capture.live_source as live_source

    monkeypatch.setattr(live_source.sys, "platform", "win32")
    with pytest.raises(LiveCaptureUnavailable, match="Linux"):
        preflight("wlan0mon")


def test_live_source_refuses_off_linux() -> None:
    source = LiveSource("wlan0mon")
    with pytest.raises(LiveCaptureUnavailable, match="Linux"):
        list(source.packets())

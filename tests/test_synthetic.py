from __future__ import annotations

import json
from pathlib import Path

from scapy.all import rdpcap

from wids_ai.capture.base import PcapSource
from wids_ai.parser.dot11 import parse_frame
from wids_ai.synthetic.generator import generate_dataset


def _generate(tmp_path: Path, seed: int = 42) -> tuple[Path, dict[str, dict[str, object]]]:
    out = tmp_path / "synthetic"
    generate_dataset(out, seed=seed)
    labels = json.loads((out / "labels.json").read_text(encoding="utf-8"))
    by_name = {item["scenario"]: item for item in labels["scenarios"]}
    return out, by_name


def test_same_seed_is_byte_deterministic(tmp_path: Path) -> None:
    first, _ = _generate(tmp_path / "first")
    second, _ = _generate(tmp_path / "second")
    first_files = sorted(first.glob("*.pcap"))
    second_files = sorted(second.glob("*.pcap"))
    assert [path.name for path in first_files] == [path.name for path in second_files]
    for left, right in zip(first_files, second_files, strict=True):
        assert left.read_bytes() == right.read_bytes()


def test_different_seed_changes_benign_packets(tmp_path: Path) -> None:
    first, _ = _generate(tmp_path / "first", seed=42)
    second, _ = _generate(tmp_path / "second", seed=43)
    assert (first / "benign_baseline.pcap").read_bytes() != (
        second / "benign_baseline.pcap"
    ).read_bytes()


def test_parser_round_trip_counts(tmp_path: Path) -> None:
    out, labels = _generate(tmp_path)
    for path in sorted(out.glob("*.pcap")):
        frames = [
            frame
            for packet in PcapSource(path).packets()
            if (frame := parse_frame(packet)) is not None
        ]
        scenario = path.stem
        assert len(frames) == labels[scenario]["packet_count"]
        assert all(frame.channel in {1, 6, 11} for frame in frames)
        assert all(frame.rssi is not None for frame in frames)


def test_benign_baseline_is_long_enough(tmp_path: Path) -> None:
    out, labels = _generate(tmp_path)
    frames = [
        frame
        for packet in rdpcap(str(out / "benign_baseline.pcap"))
        if (frame := parse_frame(packet)) is not None
    ]
    duration = (frames[-1].timestamp - frames[0].timestamp).total_seconds()
    assert duration >= 10 * 60
    assert len(labels["benign_baseline"]["bssids"]) >= 3


def test_labels_match_pcap_contents(tmp_path: Path) -> None:
    out, labels = _generate(tmp_path)
    for path in sorted(out.glob("*.pcap")):
        frames = [
            frame
            for packet in PcapSource(path).packets()
            if (frame := parse_frame(packet)) is not None
        ]
        metadata = labels[path.stem]
        assert len(frames) == metadata["packet_count"]
        assert {frame.bssid for frame in frames if frame.bssid} >= set(metadata["bssids"])
        assert {frame.ssid for frame in frames if frame.ssid} >= set(metadata["ssids"])
        observed_clients = {
            address
            for frame in frames
            for address in (frame.transmitter, frame.receiver)
            if address and address in metadata["clients"]
        }
        assert observed_clients >= set(metadata["clients"]) - {"ff:ff:ff:ff:ff:ff"}
        for frame in frames:
            if frame.timestamp:
                assert metadata["start"] <= frame.timestamp.isoformat() <= metadata["end"]


def test_evil_twin_and_deauth_are_labeled(tmp_path: Path) -> None:
    _, labels = _generate(tmp_path)
    assert labels["evil_twin"]["attack_family"] == "evil_twin_rogue_ap"
    assert labels["deauth_burst"]["attack_family"] == "deauth_disassoc_anomaly"
    assert labels["karma_probe_responses"]["attack_family"] == "probe_response_karma"
    assert labels["beacon_sequence_anomaly"]["attack_family"] == "beacon_management_anomaly"


def test_benign_timestamps_sequences_and_jitter_are_varied(tmp_path: Path) -> None:
    out, _ = _generate(tmp_path)
    frames = [
        frame
        for packet in PcapSource(out / "benign_baseline.pcap").packets()
        if (frame := parse_frame(packet)) is not None and frame.subtype == "beacon"
    ]
    assert len({frame.timestamp for frame in frames}) > 100
    assert len({(frame.bssid, frame.seq_num) for frame in frames}) > 100
    intervals = {frame.beacon_interval for frame in frames}
    assert len(intervals) > 1
    assert min(intervals) >= 990
    assert max(intervals) <= 1010

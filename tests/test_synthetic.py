from __future__ import annotations

import json
from pathlib import Path

import pytest

from wids_ai.capture.base import PcapSource
from wids_ai.parser.dot11 import parse_frame
from wids_ai.parser.models import Frame
from wids_ai.synthetic.generator import generate_dataset


def _generate(tmp_path: Path, seed: int = 42) -> tuple[Path, dict[str, dict[str, object]]]:
    out = tmp_path / "synthetic"
    generate_dataset(out, seed=seed)
    labels = json.loads((out / "labels.json").read_text(encoding="utf-8"))
    by_name = {item["scenario"]: item for item in labels["scenarios"]}
    return out, by_name


@pytest.fixture(scope="session")
def generated(synthetic_dataset) -> tuple[Path, dict[str, dict[str, object]]]:
    return _generate(synthetic_dataset(42))


@pytest.fixture(scope="session")
def parsed_frames(
    generated: tuple[Path, dict[str, dict[str, object]]],
) -> dict[str, tuple[Frame, ...]]:
    out, _ = generated
    result: dict[str, tuple[Frame, ...]] = {}
    for path in sorted(out.glob("*.pcap")):
        result[path.stem] = tuple(
            frame
            for packet in PcapSource(path).packets()
            if (frame := parse_frame(packet)) is not None
        )
    return result


@pytest.mark.slow
def test_same_seed_is_byte_deterministic(
    generated: tuple[Path, dict[str, dict[str, object]]], tmp_path: Path
) -> None:
    first, _ = generated
    second, _ = _generate(tmp_path / "second")
    first_files = sorted(first.glob("*.pcap"))
    second_files = sorted(second.glob("*.pcap"))
    assert [path.name for path in first_files] == [path.name for path in second_files]
    for left, right in zip(first_files, second_files, strict=True):
        assert left.read_bytes() == right.read_bytes()


@pytest.mark.slow
def test_different_seed_changes_benign_packets(
    generated: tuple[Path, dict[str, dict[str, object]]], tmp_path: Path
) -> None:
    first, _ = generated
    second, _ = _generate(tmp_path / "second", seed=43)
    assert (first / "benign_baseline.pcap").read_bytes() != (
        second / "benign_baseline.pcap"
    ).read_bytes()


def test_parser_round_trip_counts(
    generated: tuple[Path, dict[str, dict[str, object]]],
    parsed_frames: dict[str, tuple[Frame, ...]],
) -> None:
    _, labels = generated
    for scenario, frames in parsed_frames.items():
        assert len(frames) == labels[scenario]["packet_count"]
        assert all(frame.channel in {1, 6, 11} for frame in frames)
        assert all(frame.rssi is not None for frame in frames)


def test_benign_baseline_is_long_enough(
    generated: tuple[Path, dict[str, dict[str, object]]],
    parsed_frames: dict[str, tuple[Frame, ...]],
) -> None:
    _, labels = generated
    frames = list(parsed_frames["benign_baseline"])
    duration = (frames[-1].timestamp - frames[0].timestamp).total_seconds()
    assert duration >= 10 * 60
    assert len(labels["benign_baseline"]["bssids"]) >= 3


def test_labels_match_pcap_contents(
    generated: tuple[Path, dict[str, dict[str, object]]],
    parsed_frames: dict[str, tuple[Frame, ...]],
) -> None:
    _, labels = generated
    for scenario, frames in parsed_frames.items():
        metadata = labels[scenario]
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
        if metadata["details"].get("mixed"):
            attack_start = metadata["details"]["attack_start"]
            attack_end = metadata["details"]["attack_end"]
            attack_frames = [
                frame
                for frame in frames
                if attack_start <= frame.timestamp.isoformat() <= attack_end
            ]
            assert attack_frames
            assert len(attack_frames) < len(frames)
            assert metadata["details"]["background"] == "benign_baseline"


def test_evil_twin_and_deauth_are_labeled(
    generated: tuple[Path, dict[str, dict[str, object]]],
) -> None:
    _, labels = generated
    assert labels["evil_twin"]["attack_family"] == "evil_twin_rogue_ap"
    assert labels["deauth_burst"]["attack_family"] == "deauth_disassoc_anomaly"
    assert labels["karma_probe_responses"]["attack_family"] == "probe_response_karma"
    assert labels["beacon_sequence_anomaly"]["attack_family"] == "beacon_management_anomaly"


def test_benign_timestamps_sequences_and_jitter_are_varied(
    parsed_frames: dict[str, tuple[Frame, ...]],
) -> None:
    frames = [frame for frame in parsed_frames["benign_baseline"] if frame.subtype == "beacon"]
    assert len({frame.timestamp for frame in frames}) > 100
    assert len({(frame.bssid, frame.seq_num) for frame in frames}) > 100
    assert len({(frame.bssid, frame.seq_num) for frame in frames}) == len(frames)
    intervals = {frame.beacon_interval for frame in frames}
    assert len(intervals) > 1
    assert min(intervals) >= 990
    assert max(intervals) <= 1010


def test_mixed_scenarios_include_benign_background_and_attacks(
    generated: tuple[Path, dict[str, dict[str, object]]],
) -> None:
    out, labels = generated
    mixed = {name: labels[name] for name in labels if name.startswith("mixed_")}
    assert set(mixed) == {
        "mixed_evil_twin",
        "mixed_deauth_burst",
        "mixed_karma_probe_responses",
        "mixed_beacon_sequence_anomaly",
    }
    benign_count = labels["benign_baseline"]["packet_count"]
    for name, metadata in mixed.items():
        assert metadata["details"]["mixed"] is True
        assert metadata["details"]["background"] == "benign_baseline"
        assert metadata["packet_count"] > benign_count
        assert (out / f"{name}.pcap").is_file()
        assert metadata["details"]["attack_start"] < metadata["details"]["attack_end"]
        attack_start = metadata["details"]["attack_start"]
        assert metadata["start"] < attack_start < metadata["end"]


def test_mixed_attack_is_overlaid_mid_capture(
    generated: tuple[Path, dict[str, dict[str, object]]],
    parsed_frames: dict[str, tuple[Frame, ...]],
) -> None:
    _, labels = generated
    benign_frames = list(parsed_frames["benign_baseline"])
    mixed_frames = list(parsed_frames["mixed_evil_twin"])
    assert len(mixed_frames) == labels["mixed_evil_twin"]["packet_count"]
    assert len(mixed_frames) > len(benign_frames)
    assert min(frame.timestamp for frame in mixed_frames) == min(
        frame.timestamp for frame in benign_frames
    )
    assert max(frame.timestamp for frame in mixed_frames) == max(
        frame.timestamp for frame in benign_frames
    )
    attack_bssid = next(
        bssid for bssid in labels["mixed_evil_twin"]["bssids"] if bssid.startswith("02:")
    )
    first_twin = min(frame.timestamp for frame in mixed_frames if frame.bssid == attack_bssid)
    assert first_twin > min(frame.timestamp for frame in mixed_frames)
    assert first_twin.year == 2025


MIXED_NAMES = (
    "mixed_evil_twin",
    "mixed_deauth_burst",
    "mixed_karma_probe_responses",
    "mixed_beacon_sequence_anomaly",
)


def _benign_sequence_streams(
    frames: list[Frame],
) -> dict[str, tuple[tuple[float, int | None], ...]]:
    streams: dict[str, list[tuple[float, int | None]]] = {}
    for frame in frames:
        if frame.bssid in {"00:11:22:33:44:55", "00:11:22:33:44:66", "00:11:22:33:44:77"}:
            streams.setdefault(frame.bssid, []).append((frame.timestamp.timestamp(), frame.seq_num))
    return {bssid: tuple(values) for bssid, values in streams.items()}


def test_mixed_sequence_streams_match_benign(
    parsed_frames: dict[str, tuple[Frame, ...]],
) -> None:
    benign_streams = _benign_sequence_streams(list(parsed_frames["benign_baseline"]))
    for name in MIXED_NAMES:
        mixed_streams = _benign_sequence_streams(list(parsed_frames[name]))
        assert mixed_streams == benign_streams


def test_mixed_attack_sources_are_distinct_from_benign(
    generated: tuple[Path, dict[str, dict[str, object]]],
) -> None:
    _, labels = generated
    benign_bssids = set(labels["benign_baseline"]["bssids"])
    for name in MIXED_NAMES:
        attack_bssids = set(labels[name]["bssids"]) - benign_bssids
        assert attack_bssids
        assert all(not bssid.startswith("00:11:22:33") for bssid in attack_bssids)

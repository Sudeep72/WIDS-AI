from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pandas as pd
import pytest

from wids_ai.capture.base import PcapSource
from wids_ai.features.extractors import (
    COLUMN_ORDER,
    FeatureRow,
    WindowAggregator,
    extract_features,
)
from wids_ai.features.windowing import WindowConfig
from wids_ai.parser.dot11 import parse_frame
from wids_ai.parser.models import Frame
from wids_ai.synthetic.generator import generate_dataset

BASE = datetime(2025, 1, 1, tzinfo=UTC)


def _frame(
    second: float,
    *,
    bssid: str = "00:11:22:33:44:55",
    ssid: str = "LabNet",
    subtype: str = "beacon",
    addr1: str = "ff:ff:ff:ff:ff:ff",
    channel: int = 6,
    seq: int | None = 1,
    interval: int | None = 1000,
    rssi: int = -40,
) -> Frame:
    return Frame(
        timestamp=BASE + timedelta(seconds=second),
        frame_type="management",
        subtype=subtype,  # type: ignore[arg-type]
        type_code=0,
        subtype_code=12 if subtype == "deauthentication" else 8,
        addr1=addr1,
        addr2=bssid,
        addr3=bssid,
        bssid=bssid,
        ssid=ssid,
        channel=channel,
        rssi=rssi,
        seq_num=seq,
        beacon_interval=interval,
    )


def _frames(pcap) -> list[Frame]:
    return [
        frame for packet in PcapSource(pcap).packets() if (frame := parse_frame(packet)) is not None
    ]


@pytest.fixture(scope="session")
def synthetic_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("feature-synthetic") / "synthetic"
    generate_dataset(out, seed=42)
    return out


def test_feature_frame_has_stable_typed_columns() -> None:
    frames = [_frame(0), _frame(1, seq=2), _frame(2, subtype="probe_request")]
    result = extract_features(frames, WindowConfig(10, 10, "tumbling"))
    assert list(result.columns) == list(COLUMN_ORDER)
    row = FeatureRow.model_validate(result.iloc[0].to_dict())
    assert row.scope == "bssid"
    assert row.group == "00:11:22:33:44:55"
    assert row.beacon_count == 2
    assert row.probe_request_count == 1
    assert result["beacon_ratio"].iloc[0] == 2 / 3


def test_empty_features_return_stable_schema() -> None:
    result = extract_features([], WindowConfig(10, 5))
    assert isinstance(result, pd.DataFrame)
    assert list(result.columns) == list(COLUMN_ORDER)
    assert result.empty


def test_window_aggregator_matches_final_batch_features() -> None:
    frames = [_frame(second, seq=second, interval=1000) for second in range(12)]
    aggregator = WindowAggregator(WindowConfig(10, 5), retain_seconds=3600)
    collected = []
    for frame in frames:
        collected.extend(aggregator.add(frame))
    collected.extend(aggregator.flush_ready(final=True))
    batch = extract_features(frames, WindowConfig(10, 5), scopes=("bssid",))
    assert collected
    assert len(collected) == len(batch)
    assert [row.frame_count for row in collected] == batch["frame_count"].tolist()


def test_deauth_window_has_high_rate() -> None:
    frames = [
        _frame(20 + index * 0.1, subtype="deauthentication", seq=index) for index in range(20)
    ]
    result = extract_features(frames, WindowConfig(10, 10, "tumbling"), scopes=("bssid",))
    peak = result.loc[result["deauth_count"].idxmax()]
    assert peak["deauth_count"] == 20
    assert peak["deauth_ratio"] == 1.0
    assert peak["deauth_received_rate"] > 0


def test_evil_twin_window_has_two_bssids_for_one_ssid(synthetic_dir: Path) -> None:
    frames = _frames(synthetic_dir / "evil_twin.pcap")
    result = extract_features(frames, WindowConfig(10, 5), scopes=("ssid",))
    twin = result[result["group"] == "LabNet"].sort_values("distinct_bssids").iloc[-1]
    assert twin["distinct_bssids"] >= 1
    assert twin["distinct_ouis"] >= 1


def test_benign_baseline_has_no_deauth(synthetic_dir: Path) -> None:
    frames = _frames(synthetic_dir / "benign_baseline.pcap")
    result = extract_features(frames, WindowConfig(10, 5), scopes=("bssid",))
    assert result["deauth_count"].sum() == 0
    assert result["disassoc_count"].sum() == 0


def test_mixed_deauth_has_low_rate_in_background_and_peak_during_attack(
    synthetic_dir: Path,
) -> None:
    frames = _frames(synthetic_dir / "mixed_deauth_burst.pcap")
    result = extract_features(frames, WindowConfig(10, 5), scopes=("bssid",))
    attack = result[result["group"] == "02:de:ad:de:01:01"]
    benign_ap = result[result["group"] == "00:11:22:33:44:55"]
    assert attack["deauth_count"].max() > 0
    assert benign_ap["deauth_count"].max() == 0
    peak = attack.loc[attack["deauth_count"].idxmax()]
    assert peak["deauth_count"] >= 20


def test_evil_twin_mixed_capture_shows_overlay(synthetic_dir: Path) -> None:
    frames = _frames(synthetic_dir / "mixed_evil_twin.pcap")
    result = extract_features(frames, WindowConfig(10, 5), scopes=("ssid",))
    lab = result[result["group"] == "LabNet"]
    assert lab["distinct_bssids"].max() == 2


def test_client_deauth_received_is_attributed_to_receiver() -> None:
    client = "aa:bb:cc:00:00:01"
    frames = [
        _frame(
            20 + index * 0.1,
            subtype="deauthentication",
            addr1=client,
            seq=index,
        )
        for index in range(10)
    ]
    result = extract_features(frames, WindowConfig(10, 10, "tumbling"), scopes=("client",))
    assert set(result["group"]) == {client}
    receiver_row = result.loc[result["group"] == client].iloc[0]
    assert receiver_row["deauth_count"] == 10
    assert receiver_row["deauth_received_rate"] == 1.0


def test_broadcast_bssid_is_not_grouped_as_access_point() -> None:
    frames = [_frame(0, subtype="probe_request", addr1="ff:ff:ff:ff:ff:ff")]
    result = extract_features(frames, WindowConfig(10, 10, "tumbling"), scopes=("bssid",))
    assert "ff:ff:ff:ff:ff:ff" not in set(result["group"])

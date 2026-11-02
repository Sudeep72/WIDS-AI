from __future__ import annotations

from datetime import UTC, datetime, timedelta

from wids_ai.features.windowing import (
    WindowConfig,
    assign_windows,
    group_frames,
    grouped_windows,
    window_bounds,
)
from wids_ai.parser.models import Frame

BASE = datetime(2025, 1, 1, tzinfo=UTC)


def _frame(second: float, *, bssid: str = "00:11:22:33:44:55", subtype: str = "beacon") -> Frame:
    return Frame(
        timestamp=BASE + timedelta(seconds=second),
        frame_type="management",
        subtype=subtype,  # type: ignore[arg-type]
        type_code=0,
        subtype_code=8,
        addr1="ff:ff:ff:ff:ff:ff",
        addr2=bssid,
        addr3=bssid,
        bssid=bssid,
        beacon_interval=100,
    )


def test_window_bounds_are_half_open_and_sliding() -> None:
    frames = [_frame(0), _frame(9.999), _frame(10), _frame(12)]
    config = WindowConfig(size_seconds=10, step_seconds=5)
    bounds = list(window_bounds(frames, config))
    assert bounds[0] == (BASE, BASE + timedelta(seconds=10))
    assert bounds[1][0] == BASE + timedelta(seconds=5)
    windows = list(assign_windows(frames, config))
    assert [len(window.frames) for window in windows[:3]] == [2, 3, 2]
    assert windows[0].frames[0].timestamp == BASE
    assert windows[0].frames[-1].timestamp == BASE + timedelta(seconds=9.999)


def test_tumbling_windows_do_not_overlap() -> None:
    frames = [_frame(second) for second in (0, 4, 9, 10, 19, 20)]
    config = WindowConfig(size_seconds=10, step_seconds=10, mode="tumbling")
    windows = list(assign_windows(frames, config))
    assert [len(window.frames) for window in windows[:3]] == [3, 2, 1]
    assert windows[0].end == windows[1].start
    assert windows[1].end == windows[2].start


def test_tumbling_requires_equal_step_and_size() -> None:
    import pytest

    with pytest.raises(ValueError, match="step_seconds"):
        WindowConfig(size_seconds=10, step_seconds=5, mode="tumbling")


def test_empty_frame_input_produces_no_windows() -> None:
    config = WindowConfig(size_seconds=10, step_seconds=5)
    assert list(assign_windows([], config)) == []
    assert list(window_bounds([], config)) == []


def test_explicit_empty_window_bounds_are_supported() -> None:
    config = WindowConfig(size_seconds=10, step_seconds=10, mode="tumbling")
    start = BASE
    end = BASE + timedelta(seconds=10)
    windows = list(window_bounds([], config, start=start, end=end))
    assert windows == [(start, end), (end, end + timedelta(seconds=10))]


def test_groups_are_per_bssid_client_channel_and_ssid() -> None:
    frames = [
        _frame(0, bssid="00:11:22:33:44:55"),
        _frame(1, bssid="00:11:22:33:44:66", subtype="probe_response"),
    ]
    frames[0] = frames[0].model_copy(update={"channel": 6, "ssid": "Lab"})
    frames[1] = frames[1].model_copy(update={"channel": 1, "ssid": "Guest"})
    config = WindowConfig(size_seconds=10, step_seconds=10, mode="tumbling")
    assert set(group_frames(frames, "bssid")) == {"00:11:22:33:44:55", "00:11:22:33:44:66"}
    assert set(group_frames(frames, "client")) == {"00:11:22:33:44:55", "00:11:22:33:44:66"}
    assert set(group_frames(frames, "channel")) == {"1", "6"}
    assert set(group_frames(frames, "ssid")) == {"Guest", "Lab"}
    grouped = list(grouped_windows(frames, config, "ssid"))
    assert {window.group for window in grouped} == {"Guest", "Lab"}
    assert all(window.scope == "ssid" for window in grouped)

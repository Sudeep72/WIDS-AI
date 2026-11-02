"""Deterministic per-window feature extraction."""

from __future__ import annotations

import itertools
from collections import Counter
from collections.abc import Iterable, Sequence
from datetime import datetime, timedelta
from statistics import fmean, pstdev
from typing import Literal

import pandas as pd
from pydantic import BaseModel, ConfigDict

from wids_ai.features.windowing import (
    GroupScope,
    Window,
    WindowConfig,
    group_frames,
    grouped_windows,
    window_bounds,
)
from wids_ai.parser.models import Frame

FeatureScope = Literal["bssid", "client", "ssid", "channel"]
SUB_TYPES = (
    "beacon",
    "probe_request",
    "probe_response",
    "deauthentication",
    "disassociation",
    "authentication",
    "association_request",
    "association_response",
    "action",
)


class FeatureRow(BaseModel):
    """One typed feature row for a group and window."""

    model_config = ConfigDict(frozen=True)

    window_start: datetime
    window_end: datetime
    scope: FeatureScope
    group: str
    frame_count: int = 0
    beacon_count: int = 0
    beacon_interval_mean: float = 0.0
    beacon_interval_std: float = 0.0
    beacon_interval_jitter: float = 0.0
    seq_gap_count: int = 0
    seq_duplicate_count: int = 0
    probe_response_count: int = 0
    distinct_ssids_answered: int = 0
    deauth_count: int = 0
    disassoc_count: int = 0
    rssi_mean: float = 0.0
    rssi_std: float = 0.0
    channel_change_count: int = 0
    deauth_received_rate: float = 0.0
    probe_request_count: int = 0
    distinct_ssids_probed: int = 0
    distinct_bssids: int = 0
    distinct_ouis: int = 0
    distinct_channels: int = 0
    rsn_mismatch: int = 0
    rssi_spread: float = 0.0
    beacon_ratio: float = 0.0
    probe_request_ratio: float = 0.0
    probe_response_ratio: float = 0.0
    deauth_ratio: float = 0.0
    disassoc_ratio: float = 0.0
    authentication_ratio: float = 0.0
    association_ratio: float = 0.0
    action_ratio: float = 0.0

    def to_series(self) -> pd.Series:
        return pd.Series(self.model_dump(), dtype=object)


COLUMN_ORDER: tuple[str, ...] = tuple(FeatureRow.model_fields)


def _mean(values: Sequence[float]) -> float:
    return float(fmean(values)) if values else 0.0


def _std(values: Sequence[float]) -> float:
    return float(pstdev(values)) if len(values) > 1 else 0.0


def _interval_series(frames: Iterable[Frame]) -> list[float]:
    beacons = sorted(
        (
            frame
            for frame in frames
            if frame.subtype == "beacon" and frame.beacon_interval is not None
        ),
        key=lambda frame: frame.timestamp,
    )
    values: list[float] = []
    for previous, current in itertools.pairwise(beacons):
        delta_ms = (current.timestamp - previous.timestamp).total_seconds() * 1000.0
        values.append(float(current.beacon_interval or delta_ms))
    if not values and beacons:
        values.append(float(beacons[0].beacon_interval or 0))
    return values


def _seq_stats(frames: Iterable[Frame]) -> tuple[int, int]:
    gaps = 0
    duplicates = 0
    seen: set[tuple[str | None, int]] = set()
    per_sender: dict[str | None, int] = {}
    for frame in sorted(frames, key=lambda item: item.timestamp):
        if frame.seq_num is None:
            continue
        key = (frame.addr2, frame.seq_num)
        if key in seen:
            duplicates += 1
        seen.add(key)
        previous = per_sender.get(frame.addr2)
        if previous is not None:
            delta = (frame.seq_num - previous) % 4096
            if delta not in {0, 1}:
                gaps += 1
        per_sender[frame.addr2] = frame.seq_num
    return gaps, duplicates


def _oui(mac: str | None) -> str | None:
    return mac.split(":", maxsplit=3)[0] if mac else None


def _is_unicast(mac: str | None) -> bool:
    if not mac:
        return False
    try:
        first_octet = int(mac.split(":", maxsplit=1)[0], 16)
    except ValueError:
        return False
    return not bool(first_octet & 0x01)


def _channel_changes(frames: Sequence[Frame]) -> int:
    channels = [frame.channel for frame in frames if frame.channel is not None]
    return sum(1 for left, right in itertools.pairwise(channels) if left != right)


def _rsn_signature(frame: Frame) -> tuple[object, ...]:
    return (
        frame.rsn.present,
        frame.rsn.group_cipher,
        frame.rsn.pairwise_ciphers,
        frame.rsn.akm_suites,
        frame.security,
    )


def _rsn_mismatch(frames: Sequence[Frame]) -> int:
    signatures = {_rsn_signature(frame) for frame in frames if frame.subtype == "beacon"}
    return int(len(signatures) > 1)


def _ratio(count: int, total: int) -> float:
    return float(count / total) if total else 0.0


def extract_window_features(window: Window) -> FeatureRow:
    """Extract deterministic features for one window."""
    frames = list(window.frames)
    scope = window.scope or "bssid"
    group = window.group or ""
    interval_values = _interval_series(frames)
    rssi = [float(frame.rssi) for frame in frames if frame.rssi is not None]
    seq_gaps, seq_duplicates = _seq_stats(frames)
    ssids_answered = {
        frame.ssid for frame in frames if frame.subtype == "probe_response" and frame.ssid
    }
    ssids_probed = {
        frame.ssid for frame in frames if frame.subtype == "probe_request" and frame.ssid
    }
    bssids = {frame.bssid for frame in frames if frame.bssid and _is_unicast(frame.bssid)}
    ouis = {_oui(frame.bssid) for frame in frames if frame.bssid and _is_unicast(frame.bssid)}
    channels = {frame.channel for frame in frames if frame.channel is not None}
    rssi_spread = max(rssi) - min(rssi) if rssi else 0.0
    deauth_received = sum(
        1
        for frame in frames
        if frame.subtype == "deauthentication"
        and (
            scope != "client"
            or frame.addr1 == group
            or (frame.addr2 == group and frame.addr1 in {"ff:ff:ff:ff:ff:ff", None})
        )
    )
    counters = Counter(frame.subtype for frame in frames)
    total = len(frames)
    durations = window.duration_seconds or 1.0
    return FeatureRow(
        window_start=window.start,
        window_end=window.end,
        scope=scope,
        group=group,
        frame_count=total,
        beacon_count=counters["beacon"],
        beacon_interval_mean=_mean(interval_values),
        beacon_interval_std=_std(interval_values),
        beacon_interval_jitter=_std(
            [abs(right - left) for left, right in itertools.pairwise(interval_values)]
        ),
        seq_gap_count=seq_gaps,
        seq_duplicate_count=seq_duplicates,
        probe_response_count=counters["probe_response"],
        distinct_ssids_answered=len(ssids_answered),
        deauth_count=counters["deauthentication"],
        disassoc_count=counters["disassociation"],
        rssi_mean=_mean(rssi),
        rssi_std=_std(rssi),
        channel_change_count=_channel_changes(frames),
        deauth_received_rate=deauth_received / durations,
        probe_request_count=counters["probe_request"],
        distinct_ssids_probed=len(ssids_probed),
        distinct_bssids=len(bssids),
        distinct_ouis=len(ouis),
        distinct_channels=len(channels),
        rsn_mismatch=_rsn_mismatch(frames),
        rssi_spread=rssi_spread,
        beacon_ratio=_ratio(counters["beacon"], total),
        probe_request_ratio=_ratio(counters["probe_request"], total),
        probe_response_ratio=_ratio(counters["probe_response"], total),
        deauth_ratio=_ratio(counters["deauthentication"], total),
        disassoc_ratio=_ratio(counters["disassociation"], total),
        authentication_ratio=_ratio(counters["authentication"], total),
        association_ratio=_ratio(
            counters["association_request"] + counters["association_response"], total
        ),
        action_ratio=_ratio(counters["action"] + counters["action_no_ack"], total),
    )


def extract_features(
    frames: Iterable[Frame],
    config: WindowConfig | None = None,
    scopes: Sequence[GroupScope] = ("bssid", "client", "channel", "ssid"),
    *,
    include_empty: bool = False,
) -> pd.DataFrame:
    """Return a stable-order feature DataFrame for multiple group scopes."""
    ordered = sorted(frames, key=lambda frame: frame.timestamp)
    config = config or WindowConfig()
    rows: list[FeatureRow] = []
    if include_empty:
        from wids_ai.features.windowing import assign_windows

        for window in assign_windows(ordered, config):
            rows.append(extract_window_features(window))
    for scope in scopes:
        for window in grouped_windows(ordered, config, scope):
            rows.append(extract_window_features(window))
    if not rows:
        return pd.DataFrame(columns=COLUMN_ORDER)
    frame = pd.DataFrame([row.model_dump() for row in rows], columns=COLUMN_ORDER)
    return frame.sort_values(["window_start", "scope", "group"], kind="stable").reset_index(
        drop=True
    )


def batch_extract(
    frames: Iterable[Frame],
    config: WindowConfig | None = None,
    scopes: Sequence[GroupScope] = ("bssid", "client", "channel", "ssid"),
) -> pd.DataFrame:
    """Batch helper for offline PCAP frame collections."""
    return extract_features(frames, config=config, scopes=scopes)


class WindowAggregator:
    """Incremental state for timestamp-driven live windows."""

    def __init__(
        self, config: WindowConfig | None = None, retain_seconds: float | None = None
    ) -> None:
        self.config = config or WindowConfig()
        self.retain_seconds = retain_seconds
        self._frames: list[Frame] = []
        self._emitted: set[tuple[str, datetime, datetime]] = set()
        self._first_timestamp: datetime | None = None

    def add(self, frame: Frame) -> list[FeatureRow]:
        """Add one frame and return features for newly closed windows."""
        self._frames.append(frame)
        if self._first_timestamp is None:
            self._first_timestamp = frame.timestamp
        return self.flush_ready(final=False)

    def flush_ready(self, *, final: bool) -> list[FeatureRow]:
        """Extract completed windows up to the latest frame time."""
        if not self._frames:
            return []
        latest = max(frame.timestamp for frame in self._frames)
        closed_end = latest + self.config.size if final else latest - self.config.size
        first = self._first_timestamp or min(frame.timestamp for frame in self._frames)
        ready: list[FeatureRow] = []
        for group, members in group_frames(self._frames, "bssid").items():
            for start, end in window_bounds(
                members,
                self.config,
                start=first,
                end=latest,
                include_empty=False,
            ):
                key = (group, start, end)
                if end <= closed_end and key not in self._emitted:
                    selected = tuple(frame for frame in members if start <= frame.timestamp < end)
                    ready.append(
                        extract_window_features(
                            Window(
                                start=start, end=end, frames=selected, group=group, scope="bssid"
                            )
                        )
                    )
                    self._emitted.add(key)
        if self.retain_seconds is not None:
            keep_after = latest - timedelta(seconds=self.retain_seconds)
            self._frames = [frame for frame in self._frames if frame.timestamp >= keep_after]
        return ready

    @property
    def buffered_frames(self) -> int:
        return len(self._frames)

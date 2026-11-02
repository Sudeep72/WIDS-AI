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
    broadcast_deauth_count: int = 0
    deauth_reason_distinct: int = 0
    deauth_reason_skew: float = 0.0
    seq_backward_count: int = 0
    observed_bssids: str = ""
    observed_ssids: str = ""
    observed_clients: str = ""
    observed_beacon_channels: str = ""
    observed_security_modes: str = ""
    rssi_by_bssid: str = ""

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


def _seq_stats(frames: Iterable[Frame]) -> tuple[int, int, int]:
    gaps = 0
    duplicates = 0
    backward = 0
    seen: set[tuple[str | None, int | None, int]] = set()
    per_stream: dict[tuple[str | None, int | None], int] = {}
    for frame in sorted(frames, key=lambda item: item.timestamp):
        if frame.seq_num is None:
            continue
        stream = (frame.addr2, frame.channel)
        key = (frame.addr2, frame.channel, frame.seq_num)
        if key in seen:
            duplicates += 1
        seen.add(key)
        previous = per_stream.get(stream)
        if previous is not None:
            delta = (frame.seq_num - previous) % 4096
            if 1 < delta < 2048:
                gaps += 1
            if frame.seq_num < previous and previous - frame.seq_num < 2048:
                backward += 1
        per_stream[stream] = frame.seq_num
    return gaps, duplicates, backward


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
    seq_gaps, seq_duplicates, seq_backward = _seq_stats(frames)
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
    beacon_frames = [frame for frame in frames if frame.subtype == "beacon"]
    observed_bssids = sorted(bssids)
    observed_ssids = sorted({frame.ssid for frame in frames if frame.ssid})
    observed_clients = sorted(
        {
            address
            for frame in frames
            for address in (frame.addr1, frame.addr2)
            if _is_unicast(address) and address not in bssids
        }
    )
    beacon_channels = sorted(
        {frame.channel for frame in beacon_frames if frame.channel is not None}
    )
    security_modes = sorted(
        {frame.security for frame in frames if frame.subtype in {"beacon", "probe_response"}}
    )
    rssi_by_bssid: dict[str, list[float]] = {}
    for frame in frames:
        if frame.bssid and _is_unicast(frame.bssid) and frame.rssi is not None:
            rssi_by_bssid.setdefault(frame.bssid, []).append(float(frame.rssi))
    rssi_by_bssid_text = ";".join(
        f"{bssid}={_mean(values):.3f}" for bssid, values in sorted(rssi_by_bssid.items())
    )
    deauth_count = (
        deauth_received
        if scope == "client"
        else sum(1 for frame in frames if frame.subtype == "deauthentication")
    )
    counters = Counter(frame.subtype for frame in frames)
    deauth_reasons = Counter(
        frame.reason_code
        for frame in frames
        if frame.subtype == "deauthentication" and frame.reason_code is not None
    )
    broadcast_deauths = sum(
        1
        for frame in frames
        if frame.subtype == "deauthentication" and frame.addr1 == "ff:ff:ff:ff:ff:ff"
    )
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
        deauth_count=deauth_count,
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
        broadcast_deauth_count=broadcast_deauths,
        deauth_reason_distinct=len(deauth_reasons),
        deauth_reason_skew=(
            max(deauth_reasons.values()) / sum(deauth_reasons.values()) if deauth_reasons else 0.0
        ),
        seq_backward_count=seq_backward,
        observed_bssids=",".join(observed_bssids),
        observed_ssids=",".join(observed_ssids),
        observed_clients=",".join(observed_clients),
        observed_beacon_channels=",".join(str(channel) for channel in beacon_channels),
        observed_security_modes=",".join(security_modes),
        rssi_by_bssid=rssi_by_bssid_text,
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

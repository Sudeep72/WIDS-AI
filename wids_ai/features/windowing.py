"""Timestamp-driven sliding and tumbling windows."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal

from wids_ai.parser.models import Frame

BROADCAST = "ff:ff:ff:ff:ff:ff"

WindowMode = Literal["sliding", "tumbling"]
GroupScope = Literal["bssid", "client", "channel", "ssid"]


@dataclass(frozen=True)
class Window:
    """A half-open frame window: start <= timestamp < end."""

    start: datetime
    end: datetime
    frames: tuple[Frame, ...]
    group: str | None = None
    scope: GroupScope | None = None

    @property
    def is_empty(self) -> bool:
        return not self.frames

    @property
    def duration_seconds(self) -> float:
        return (self.end - self.start).total_seconds()


@dataclass(frozen=True)
class WindowConfig:
    size_seconds: float = 10.0
    step_seconds: float = 5.0
    mode: WindowMode = "sliding"

    def __post_init__(self) -> None:
        if self.size_seconds <= 0:
            raise ValueError("Window size must be positive")
        if self.step_seconds <= 0:
            raise ValueError("Window step must be positive")
        if self.mode == "tumbling" and self.step_seconds != self.size_seconds:
            raise ValueError("Tumbling windows require step_seconds == size_seconds")

    @property
    def size(self) -> timedelta:
        return timedelta(seconds=self.size_seconds)

    @property
    def step(self) -> timedelta:
        return timedelta(seconds=self.step_seconds)


def window_bounds(
    frames: Iterable[Frame],
    config: WindowConfig,
    *,
    start: datetime | None = None,
    end: datetime | None = None,
    include_empty: bool = True,
) -> Iterator[tuple[datetime, datetime]]:
    """Yield half-open window bounds from frame timestamps."""
    ordered = list(frames)
    if not ordered and start is None:
        return
    first = start or min(frame.timestamp for frame in ordered)
    last = end or max(frame.timestamp for frame in ordered)
    if first.tzinfo is None:
        first = first.replace(tzinfo=UTC)
    if last.tzinfo is None:
        last = last.replace(tzinfo=UTC)
    if last < first:
        raise ValueError("Window end must not precede window start")
    cursor = first
    while cursor < last or (include_empty and cursor == last):
        window_end = cursor + config.size
        yield cursor, window_end
        if config.mode == "tumbling":
            cursor = window_end
        else:
            cursor += config.step


def assign_windows(frames: Iterable[Frame], config: WindowConfig) -> Iterator[Window]:
    """Assign frames to sliding or tumbling windows."""
    ordered = sorted(frames, key=lambda frame: frame.timestamp)
    if not ordered:
        return
    first = ordered[0].timestamp
    last = ordered[-1].timestamp
    for start, end in window_bounds(ordered, config, start=first, end=last):
        selected = tuple(frame for frame in ordered if start <= frame.timestamp < end)
        yield Window(start=start, end=end, frames=selected)


def _is_unicast(mac: str | None) -> bool:
    if not mac or mac == BROADCAST:
        return False
    try:
        return not bool(int(mac.split(":", maxsplit=1)[0], 16) & 0x01)
    except ValueError:
        return False


def _group_keys(frame: Frame, scope: GroupScope) -> tuple[str, ...]:
    if scope == "bssid":
        return (frame.bssid,) if _is_unicast(frame.bssid) else ()
    if scope == "client":
        if frame.subtype == "deauthentication":
            return (frame.addr1,) if _is_unicast(frame.addr1) else ()
        return tuple(
            dict.fromkeys(address for address in (frame.addr1, frame.addr2) if _is_unicast(address))
        )
    if scope == "channel":
        return (str(frame.channel),) if frame.channel is not None else ()
    return (frame.ssid,) if frame.ssid else ()


def group_frames(frames: Iterable[Frame], scope: GroupScope) -> dict[str, tuple[Frame, ...]]:
    """Group frames by BSSID, client participant, channel, or SSID."""
    grouped: dict[str, list[Frame]] = {}
    seen: dict[str, set[int]] = {}
    for frame in frames:
        for value in _group_keys(frame, scope):
            identities = seen.setdefault(value, set())
            if id(frame) in identities:
                continue
            identities.add(id(frame))
            grouped.setdefault(value, []).append(frame)
    return {key: tuple(value) for key, value in sorted(grouped.items())}


def grouped_windows(
    frames: Iterable[Frame], config: WindowConfig, scope: GroupScope
) -> Iterator[Window]:
    """Yield windows for each group, preserving group identity."""
    for group, members in group_frames(frames, scope).items():
        for window in assign_windows(members, config):
            yield Window(
                start=window.start,
                end=window.end,
                frames=window.frames,
                group=group,
                scope=scope,
            )

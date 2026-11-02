"""In-memory and JSON-backed trusted access point inventory."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, field_validator

from wids_ai.parser.models import Frame

BROADCAST = "ff:ff:ff:ff:ff:ff"


def _is_unicast(mac: str | None) -> bool:
    if not mac or mac == BROADCAST:
        return False
    try:
        return not bool(int(mac.split(":", maxsplit=1)[0], 16) & 0x01)
    except ValueError:
        return False


class KnownAP(BaseModel):
    """A trusted access point learned from baseline traffic."""

    model_config = ConfigDict(extra="forbid")

    bssid: str
    ssid: str | None = None
    oui: str | None = None
    channels: tuple[int, ...] = ()
    security: str = "unknown"
    beacon_interval: float | None = None
    mean_rssi: float | None = None
    trust_score: int = Field(default=90, ge=0, le=100)
    observations: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    @property
    @field_validator("security", mode="before")
    @classmethod
    def normalize_security(cls, value: object) -> str:
        if isinstance(value, (list, tuple)):
            modes = [str(item) for item in value if item and item != "unknown"]
            return modes[-1] if modes else "unknown"
        return str(value) if value else "unknown"

    @property
    def channel_set(self) -> set[int]:
        return set(self.channels)


class APInventory(BaseModel):
    """Trusted AP inventory with no database dependency."""

    model_config = ConfigDict(extra="forbid")

    aps: dict[str, KnownAP] = Field(default_factory=dict)
    updated_at: datetime | None = None

    @classmethod
    def from_frames(cls, frames: Iterable[Frame]) -> APInventory:
        """Learn known-good APs from a trusted baseline capture."""
        grouped: dict[str, list[Frame]] = {}
        for frame in frames:
            if frame.bssid and _is_unicast(frame.bssid):
                grouped.setdefault(frame.bssid, []).append(frame)
        aps: dict[str, KnownAP] = {}
        for bssid, members in sorted(grouped.items()):
            beacons = [frame for frame in members if frame.subtype == "beacon"]
            proxy = beacons or members
            ssid = next((frame.ssid for frame in beacons if frame.ssid), None)
            channels = tuple(
                sorted({frame.channel for frame in proxy if frame.channel is not None})
            )
            security_frames = [
                frame
                for frame in members
                if frame.subtype in {"beacon", "probe_response"} and frame.security != "unknown"
            ]
            security = (
                max(security_frames, key=lambda frame: frame.timestamp).security
                if security_frames
                else "unknown"
            )
            intervals = [
                float(frame.beacon_interval)
                for frame in beacons
                if frame.beacon_interval is not None
            ]
            rssi = [float(frame.rssi) for frame in members if frame.rssi is not None]
            timestamps = [frame.timestamp for frame in members]
            aps[bssid] = KnownAP(
                bssid=bssid,
                ssid=ssid,
                oui=":".join(bssid.split(":")[:3]),
                channels=channels,
                security=security,
                beacon_interval=(sum(intervals) / len(intervals)) if intervals else None,
                mean_rssi=(sum(rssi) / len(rssi)) if rssi else None,
                trust_score=90,
                observations=len(members),
                first_seen=min(timestamps) if timestamps else None,
                last_seen=max(timestamps) if timestamps else None,
            )
        return cls(aps=aps, updated_at=datetime.now(tz=UTC))

    def is_known(self, bssid: str | None) -> bool:
        return bool(bssid and bssid in self.aps)

    def get(self, bssid: str | None) -> KnownAP | None:
        return self.aps.get(bssid) if bssid else None

    def bssids_for_ssid(self, ssid: str) -> tuple[str, ...]:
        return tuple(bssid for bssid, ap in sorted(self.aps.items()) if ap.ssid == ssid)

    def adjust_trust(self, bssid: str, delta: int) -> None:
        """Adjust trust score without leaving the 0 to 100 range."""
        ap = self.aps.get(bssid)
        if ap is None:
            return
        ap.trust_score = max(0, min(100, ap.trust_score + delta))
        self.updated_at = datetime.now(tz=UTC)

    def observe_frames(self, frames: Iterable[Frame]) -> None:
        """Materialize every observed BSSID, including unknown APs."""
        grouped: dict[str, list[Frame]] = {}
        for frame in frames:
            if frame.bssid and _is_unicast(frame.bssid):
                grouped.setdefault(frame.bssid, []).append(frame)
        for bssid, members in grouped.items():
            beacons = [frame for frame in members if frame.subtype == "beacon"]
            proxy = beacons or members
            security_frames = [
                frame
                for frame in members
                if frame.subtype in {"beacon", "probe_response"} and frame.security != "unknown"
            ]
            latest_security = (
                max(security_frames, key=lambda frame: frame.timestamp).security
                if security_frames
                else "unknown"
            )
            rssi = [float(frame.rssi) for frame in members if frame.rssi is not None]
            known = self.aps.get(bssid)
            if known is None:
                self.aps[bssid] = KnownAP(
                    bssid=bssid,
                    ssid=next((frame.ssid for frame in beacons if frame.ssid), None),
                    oui=":".join(bssid.split(":")[:3]),
                    channels=tuple(
                        sorted({frame.channel for frame in proxy if frame.channel is not None})
                    ),
                    security=latest_security,
                    beacon_interval=(
                        max(
                            (
                                float(frame.beacon_interval)
                                for frame in beacons
                                if frame.beacon_interval is not None
                            ),
                            default=None,
                        )
                    ),
                    mean_rssi=(sum(rssi) / len(rssi)) if rssi else None,
                    trust_score=10,
                    observations=len(members),
                    first_seen=min(frame.timestamp for frame in members),
                    last_seen=max(frame.timestamp for frame in members),
                )
                continue
            known.ssid = known.ssid or next((frame.ssid for frame in beacons if frame.ssid), None)
            known.channels = tuple(
                sorted(
                    {
                        *known.channels,
                        *(frame.channel for frame in proxy if frame.channel is not None),
                    }
                )
            )
            known.security = latest_security if latest_security != "unknown" else known.security
            known.mean_rssi = (sum(rssi) / len(rssi)) if rssi else known.mean_rssi
            known.observations += len(members)
            known.first_seen = min(
                filter(None, [known.first_seen, min(frame.timestamp for frame in members)])
            )
            known.last_seen = max(frame.timestamp for frame in members)
        self.updated_at = datetime.now(tz=UTC)

    def save(self, path: str | Path) -> None:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(self.model_dump_json(indent=2) + "\n", encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> APInventory:
        return cls.model_validate_json(Path(path).read_text(encoding="utf-8"))

    def to_json(self) -> str:
        return self.model_dump_json(indent=2)

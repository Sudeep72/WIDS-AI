"""Linux monitor-mode capture with an injectable packet source for tests."""

from __future__ import annotations

import logging
import os
import queue
import shutil
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

from scapy.packet import Packet

from wids_ai.capture.base import Source

LOGGER = logging.getLogger(__name__)
_NO_RADIOTAP = object()


class LiveCaptureUnavailable(RuntimeError):
    """Raised when live capture cannot run on this platform or interface."""


@dataclass(frozen=True)
class CaptureStats:
    frames: int = 0
    parse_errors: int = 0
    dropped: int = 0
    started_at: float = 0.0

    @property
    def duration_seconds(self) -> float:
        return max(0.0, time.monotonic() - self.started_at)


def _run_iw(arguments: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["iw", *arguments],
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )


def _cap_net_raw() -> bool:
    """Check effective CAP_NET_RAW without relying on a privileged child."""
    try:
        with Path("/proc/self/status").open(encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("CapEff:"):
                    effective = int(line.split()[1], 16)
                    return bool(effective & (1 << 13))
    except (OSError, ValueError):
        return False
    return False


def preflight(interface: str) -> None:
    """Fail early with actionable guidance before opening a live source."""
    if sys.platform != "linux":
        raise LiveCaptureUnavailable(
            "Live capture requires Linux. Use offline PCAP replay on Windows. "
            "Fix: boot Kali Linux with a monitor-mode wireless adapter."
        )
    if os.geteuid() != 0 and not _cap_net_raw():
        raise LiveCaptureUnavailable(
            "Live capture requires root or CAP_NET_RAW. "
            "Fix: sudo -E .venv/bin/python -m wids_ai live --iface wlan0mon"
        )
    if not interface or interface == "lo":
        raise LiveCaptureUnavailable(
            "A monitor-mode wireless interface is required. "
            "Fix: sudo airmon-ng start wlan0, then use the resulting wlan0mon name."
        )
    if shutil.which("iw") is None:
        raise LiveCaptureUnavailable(
            "The iw command is required for monitor-mode checks. "
            "Fix: sudo apt install iw aircrack-ng"
        )
    check = _run_iw(["dev", interface, "info"])
    if check.returncode != 0:
        raise LiveCaptureUnavailable(
            f"Wireless interface {interface} was not found. "
            "Fix: run `iw dev` and pass the monitor interface name."
        )
    if "type monitor" not in check.stdout.lower():
        raise LiveCaptureUnavailable(
            f"Interface {interface} is not in monitor mode. "
            f"Fix: sudo airmon-ng start {interface.removesuffix('mon')}"
        )


class LiveSource(Source):
    """Yield RadioTap packets from a Linux monitor-mode interface."""

    def __init__(
        self,
        interface: str,
        channel: int = 6,
        packet_count: int = 0,
        *,
        packet_source: Callable[[], list[Packet]] | None = None,
    ) -> None:
        self.interface = interface
        self.channel = channel
        self.packet_count = packet_count
        self._packet_source = packet_source
        self.stats = CaptureStats(started_at=time.monotonic())
        self.dropped = 0
        self._stop = threading.Event()

    def _validate(self) -> None:
        if self._packet_source is not None:
            if not 1 <= self.channel <= 233:
                raise LiveCaptureUnavailable("Channel must be between 1 and 233")
            return
        preflight(self.interface)
        if not 1 <= self.channel <= 233:
            raise LiveCaptureUnavailable(
                "Channel must be between 1 and 233. Fix: pass --channel N."
            )

    def stop(self) -> None:
        """Request capture shutdown without transmitting anything."""
        self._stop.set()

    def packets(self) -> Iterator[Packet]:
        self._validate()
        if self._packet_source is not None:
            for packet in self._packet_source():
                yield packet
            return
        try:
            from scapy.all import sniff
        except ImportError as exc:
            raise LiveCaptureUnavailable(
                "Scapy live capture is unavailable. Fix: .venv/bin/pip install -r requirements.txt"
            ) from exc
        packets: queue.Queue[Packet | object | None] = queue.Queue(maxsize=4096)
        stop = self._stop

        def receive(packet: Packet) -> None:
            if not packet.haslayer("RadioTap"):
                packets.put(_NO_RADIOTAP)
                stop.set()
                return
            packet.time = time.time()
            try:
                packets.put_nowait(packet)
            except queue.Full:
                self.dropped += 1

        def capture() -> None:
            try:
                sniff(
                    monitor=True,
                    store=False,
                    prn=receive,
                    stop_filter=lambda _packet: stop.is_set(),
                    iface=self.interface,
                )
            except (OSError, PermissionError) as exc:
                LOGGER.error("Live capture stopped: %s", type(exc).__name__)
            finally:
                packets.put(None)

        thread = threading.Thread(target=capture, daemon=True, name="wids-live")
        thread.start()
        yielded = 0
        try:
            while True:
                packet = packets.get(timeout=1.0)
                if packet is None:
                    return
                if packet is _NO_RADIOTAP:
                    raise LiveCaptureUnavailable(
                        "Captured packet has no RadioTap header. "
                        "Fix: use a monitor-mode adapter and verify with "
                        f"`tshark -i {self.interface} -c 1 -V`."
                    )
                yielded += 1
                yield packet
                if self.packet_count and yielded >= self.packet_count:
                    return
        except queue.Empty:
            if not thread.is_alive():
                return
        finally:
            stop.set()
            thread.join(timeout=2.0)


class LivePacketSink:
    """Write captured RadioTap packets to a PCAP without transmitting."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else None
        self._packets: list[Packet] = []

    def append(self, packet: Packet) -> None:
        if self.path is not None:
            self._packets.append(packet)

    def close(self) -> None:
        if self.path is None:
            return
        from scapy.utils import wrpcap

        self.path.parent.mkdir(parents=True, exist_ok=True)
        wrpcap(str(self.path), self._packets)

    def __enter__(self) -> LivePacketSink:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


def set_channel(interface: str, channel: int) -> None:
    """Set one monitor-mode channel through a fixed iw argument list."""
    check = subprocess.run(
        ["iw", "dev", interface, "set", "channel", str(channel)],
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )
    if check.returncode != 0:
        raise LiveCaptureUnavailable(
            f"Unable to set {interface} to channel {channel}. "
            f"Fix: sudo iw dev {interface} set channel {channel}"
        )

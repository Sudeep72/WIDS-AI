"""Linux monitor-mode capture isolated from offline analysis."""

from __future__ import annotations

import logging
import sys
from collections.abc import Iterator

from scapy.packet import Packet

from wids_ai.capture.base import Source

LOGGER = logging.getLogger(__name__)


class LiveCaptureUnavailable(RuntimeError):
    """Raised when live capture cannot run on this platform or interface."""


class LiveSource(Source):
    """Yield packets from a Linux monitor-mode interface."""

    def __init__(self, interface: str, channel: int = 6, packet_count: int = 0) -> None:
        self.interface = interface
        self.channel = channel
        self.packet_count = packet_count

    def _validate(self) -> None:
        if sys.platform != "linux":
            raise LiveCaptureUnavailable(
                "Live capture requires Linux with a monitor-mode interface. "
                "Use offline PCAP analysis on Windows."
            )
        if not self.interface or self.interface == "lo":
            raise LiveCaptureUnavailable("A monitor-mode wireless interface is required")
        if not 1 <= self.channel <= 233:
            raise LiveCaptureUnavailable("Channel must be between 1 and 233")

    def packets(self) -> Iterator[Packet]:
        self._validate()
        try:
            from scapy.all import sniff
        except ImportError as exc:
            raise LiveCaptureUnavailable(
                "Scapy live capture is unavailable. Install requirements.txt in the Kali venv."
            ) from exc

        try:
            packets = sniff(
                iface=self.interface,
                monitor=True,
                count=self.packet_count or 0,
                store=True,
            )
        except (OSError, PermissionError) as exc:
            raise LiveCaptureUnavailable(
                f"Unable to capture on {self.interface}. Check monitor mode and privileges: {exc}"
            ) from exc
        yield from packets


def require_linux_live_capture() -> None:
    """Fail clearly when live capture is requested outside Linux."""
    LiveSource("wlan0mon")._validate()

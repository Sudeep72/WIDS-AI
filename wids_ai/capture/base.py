"""Capture source contract shared by offline and live sources."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from pathlib import Path

from scapy.packet import Packet


class Source(ABC):
    """A source that yields parsed-ready Scapy packets."""

    @abstractmethod
    def packets(self) -> Iterator[Packet]:
        """Yield packets until the source is exhausted."""


class PcapSource(Source):
    """Offline PCAP source that works on Windows without a wireless adapter."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def packets(self) -> Iterator[Packet]:
        if not self.path.is_file():
            raise FileNotFoundError(f"PCAP file not found: {self.path}")
        from scapy.error import Scapy_Exception
        from scapy.utils import rdpcap

        try:
            packets = rdpcap(str(self.path))
        except (OSError, ValueError, Scapy_Exception) as exc:
            raise ValueError(f"Unable to read PCAP file {self.path}: {exc}") from exc
        yield from packets

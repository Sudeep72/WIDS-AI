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
    """Offline PCAP source. The implementation lands in milestone M2."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def packets(self) -> Iterator[Packet]:
        raise NotImplementedError("Offline PCAP reading is implemented in milestone M2")

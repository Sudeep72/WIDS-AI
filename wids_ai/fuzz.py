"""Bounded parser fuzzing helpers."""

from __future__ import annotations

import random

from scapy.packet import Raw

from wids_ai.capture.base import PcapSource
from wids_ai.parser.dot11 import parse_frame
from wids_ai.parser.models import Frame


def fuzz_cases(seed: int, count: int) -> list[bytes]:
    """Return deterministic truncated, malformed, and random byte strings."""
    rng = random.Random(seed)
    cases: list[bytes] = []
    for index in range(count):
        length = rng.randint(1, 256)
        kind = index % 3
        if kind == 0:
            cases.append(bytes(rng.randrange(256) for _ in range(length)))
        elif kind == 1:
            cases.append(b"\x00\x00" + bytes(rng.randrange(256) for _ in range(length)))
        else:
            cases.append(bytes(rng.randrange(256) for _ in range(max(1, length // 3))))
    return cases


def parse_fuzz_cases(cases: list[bytes]) -> int:
    """Parse fuzz payloads and return the number of accepted frames."""
    accepted = 0
    for payload in cases:
        frame = parse_frame(Raw(load=payload))
        if isinstance(frame, Frame):
            accepted += 1
    return accepted


def fuzz_pcap(path, seed: int = 7, count: int = 200) -> None:
    """Write a fuzz PCAP for optional offline stress testing."""
    from scapy.all import wrpcap

    packets = [Raw(load=payload) for payload in fuzz_cases(seed, count)]
    wrpcap(str(path), packets)


def read_fuzz_pcap(path) -> int:
    accepted = 0
    for packet in PcapSource(path).packets():
        frame = parse_frame(packet)
        if isinstance(frame, Frame):
            accepted += 1
    return accepted

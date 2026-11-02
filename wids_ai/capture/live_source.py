"""Guarded live capture entry point.

Live capture is Linux-only. The actual monitor-mode implementation lands in M2.
"""

from __future__ import annotations

import sys


def require_linux_live_capture() -> None:
    """Fail clearly when live capture is requested outside Linux."""
    if sys.platform != "linux":
        raise RuntimeError(
            "Live capture requires Linux with a monitor-mode interface. "
            "Use offline PCAP analysis on Windows."
        )
    raise NotImplementedError("Linux live capture is implemented in milestone M2")

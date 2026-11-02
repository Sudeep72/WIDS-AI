"""Compatibility wrapper for the M3 synthetic PCAP generator."""

from __future__ import annotations

import runpy
from pathlib import Path


def main() -> None:
    tool = Path(__file__).resolve().parent.parent / "tools" / "make_synthetic_pcaps.py"
    runpy.run_path(str(tool), run_name="__main__")


if __name__ == "__main__":
    main()

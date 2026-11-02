"""Generate labeled synthetic wireless PCAP files.

Usage:
    python tools/make_synthetic_pcaps.py --out data/synthetic --seed 42

This tool writes capture files only. It never transmits frames.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from wids_ai.synthetic.generator import generate_dataset  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate synthetic 802.11 PCAP fixtures")
    parser.add_argument("--out", type=Path, default=Path("data/synthetic"))
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    generated = generate_dataset(args.out, args.seed)
    for item in generated:
        print(f"{item.name}: {item.labels.packet_count} packets -> {item.path}")
    print(f"labels -> {args.out / 'labels.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

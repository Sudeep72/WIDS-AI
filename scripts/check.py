"""Portable CI-equivalent checks. Run with the project virtual environment."""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TMP_ROOT = ROOT / ".tmp"


SOURCE_FORBIDDEN = (
    "from scapy.all import send",
    "from scapy.all import sendp",
    "scapy.send",
    "sendp(",
    "sendpfast(",
    "srp(",
    "srp1(",
    ".send(",
)


def scan_transmit_apis() -> None:
    hits = []
    for root in (ROOT / "wids_ai", ROOT / "tools", ROOT / "scripts"):
        for path in root.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in {".py", ".sh", ".ps1"}:
                continue
            if path.resolve() == Path(__file__).resolve():
                continue
            text = path.read_text(encoding="utf-8")
            for token in SOURCE_FORBIDDEN:
                if token in text:
                    hits.append(f"{path}: {token}")
    if hits:
        raise RuntimeError("Transmit API scan failed: " + "; ".join(hits))
    print("Transmit API scan passed", flush=True)


def run(*args: str) -> None:
    print(f"+ {' '.join(args)}", flush=True)
    subprocess.run(args, cwd=ROOT, check=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--slow", action="store_true")
    args = parser.parse_args()
    TMP_ROOT.mkdir(exist_ok=True)
    basetemp = TMP_ROOT / f"pytest-{time.time_ns()}"
    run(sys.executable, "-m", "ruff", "check", ".")
    run(sys.executable, "-m", "ruff", "format", "--check", ".")
    scan_transmit_apis()
    cache_dir = TMP_ROOT / f"pytest-cache-{time.time_ns()}"
    if args.slow:
        run(
            sys.executable,
            "-m",
            "pytest",
            "-m",
            "slow or not slow",
            "-n",
            "auto",
            "--dist",
            "loadscope",
            f"--basetemp={basetemp}",
            "-o",
            f"cache_dir={cache_dir}",
        )
    else:
        run(
            sys.executable,
            "-m",
            "pytest",
            f"--basetemp={basetemp}",
            "-o",
            f"cache_dir={cache_dir}",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

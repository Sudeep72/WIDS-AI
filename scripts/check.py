"""Portable CI-equivalent checks. Run with the project virtual environment."""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TMP_ROOT = ROOT / ".tmp"


def run(*args: str) -> None:
    print(f"+ {' '.join(args)}", flush=True)
    subprocess.run(args, cwd=ROOT, check=True)


def main() -> int:
    TMP_ROOT.mkdir(exist_ok=True)
    basetemp = TMP_ROOT / f"pytest-{time.time_ns()}"
    run(sys.executable, "-m", "ruff", "check", ".")
    run(sys.executable, "-m", "ruff", "format", "--check", ".")
    run(sys.executable, "-m", "pytest", f"--basetemp={basetemp}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

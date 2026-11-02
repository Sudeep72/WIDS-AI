"""Portable CI-equivalent checks. Run with the project virtual environment."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def run(*args: str) -> None:
    print(f"+ {' '.join(args)}", flush=True)
    subprocess.run(args, cwd=ROOT, check=True)


def main() -> int:
    run(sys.executable, "-m", "ruff", "check", ".")
    run(sys.executable, "-m", "ruff", "format", "--check", ".")
    run(sys.executable, "-m", "pytest")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

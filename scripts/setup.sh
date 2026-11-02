#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
if [[ ! -x .venv/bin/python ]]; then
  python3 -m venv .venv
fi
.venv/bin/python -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' || {
  echo "Python 3.11 or newer is required." >&2
  exit 1
}
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m pip install --no-deps -e .
echo "WIDS-AI environment ready."

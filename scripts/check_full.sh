#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
PYTHON="${PYTHON:-$ROOT/.venv/bin/python}"
if [[ ! -x "$PYTHON" ]]; then
  echo "Missing .venv. Run scripts/setup.sh first." >&2
  exit 1
fi
export PYTEST_ADDOPTS="--basetemp=.tmp/pytest-full -m 'slow or not slow'"
exec "$PYTHON" scripts/check.py
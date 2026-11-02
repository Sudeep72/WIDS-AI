#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
PYTHON="${PYTHON:-$ROOT/.venv/bin/python}"
if [[ ! -f data/synthetic/mixed_evil_twin.pcap ]]; then
  "$PYTHON" tools/make_synthetic_pcaps.py --out data/synthetic --seed 42
fi
if [[ ! -f .tmp/inventory.json ]]; then
  "$PYTHON" -m wids_ai.cli baseline data/synthetic/benign_baseline.pcap --out .tmp/inventory.json
fi
if [[ ! -f models/default/bssid/isolation_forest.joblib ]]; then
  "$PYTHON" -m wids_ai.cli train data/synthetic/benign_baseline.pcap --out models/default --seed 42
fi
echo "Dashboard: http://127.0.0.1:8000"
exec "$PYTHON" -m wids_ai.cli serve --replay data/synthetic/mixed_evil_twin.pcap --speed 20 --inventory .tmp/inventory.json --model models/default --rules wids_ai/rules/rules
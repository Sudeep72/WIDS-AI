$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Python = Join-Path $Root ".venv\Scripts\python.exe"
Set-Location -LiteralPath $Root
if (-not (Test-Path -LiteralPath "data\synthetic\mixed_evil_twin.pcap")) {
    & $Python tools\make_synthetic_pcaps.py --out data\synthetic --seed 42
}
if (-not (Test-Path -LiteralPath ".tmp\inventory.json")) {
    & $Python -m wids_ai.cli baseline data\synthetic\benign_baseline.pcap --out .tmp\inventory.json
}
if (-not (Test-Path -LiteralPath "models\default\bssid\isolation_forest.joblib")) {
    & $Python -m wids_ai.cli train data\synthetic\benign_baseline.pcap --out models\default --seed 42
}
Write-Output "Dashboard: http://127.0.0.1:8000"
& $Python -m wids_ai.cli serve --replay data\synthetic\mixed_evil_twin.pcap --speed 20 --inventory .tmp\inventory.json --model models\default --rules wids_ai\rules\rules
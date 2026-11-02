$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Python = Join-Path $Root ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $Python)) {
    throw "Missing .venv. Run scripts\setup.ps1 first."
}
Set-Location -LiteralPath $Root
$env:PYTEST_ADDOPTS = "--basetemp=.tmp/pytest-full -m ''slow or not slow''"
& $Python scripts\check.py
exit $LASTEXITCODE
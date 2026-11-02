$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$VenvPython = Join-Path $Root ".venv\Scripts\python.exe"
Set-Location -LiteralPath $Root

if (-not (Test-Path -LiteralPath $VenvPython)) {
    python -m venv .venv
}

$Version = & $VenvPython -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
$Parts = $Version.Split(".")
if ([int]$Parts[0] -lt 3 -or ([int]$Parts[0] -eq 3 -and [int]$Parts[1] -lt 11)) {
    throw "Python 3.11 or newer is required. Found $Version."
}

& $VenvPython -m pip install -r requirements.txt
& $VenvPython -m pip install -r requirements-dev.txt
& $VenvPython -m pip install --no-deps -e .
Write-Output "WIDS-AI environment ready with Python $Version."

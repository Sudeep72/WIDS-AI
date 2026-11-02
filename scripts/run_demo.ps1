$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $Root
Write-Output "Demo is staged for milestone M10. Run scripts\check.ps1 to validate M1."

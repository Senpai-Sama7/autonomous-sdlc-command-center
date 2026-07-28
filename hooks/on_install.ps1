param(
  [Parameter(Mandatory = $true)][string]$PluginPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Write-Host "[autonomous-sdlc-command-center] Verifying plugin integrity..." -ForegroundColor Cyan

$preflight = Join-Path $PluginPath 'scripts\commands\plugin_preflight.ps1'
if (-not (Test-Path -LiteralPath $preflight -PathType Leaf)) {
  Write-Host "[ERROR] Preflight script not found; installation may be incomplete." -ForegroundColor Red
  exit 1
}

$result = & $preflight -PluginPath $PluginPath | ConvertFrom-Json
if ($result.status -ne 'pass') {
  Write-Host "[ERROR] Plugin preflight failed. Review findings above." -ForegroundColor Red
  exit 1
}

Write-Host "[autonomous-sdlc-command-center] Plugin verified. Run smoke tests with:" -ForegroundColor Green
Write-Host "  .\scripts\tests\smoke.ps1" -ForegroundColor Gray

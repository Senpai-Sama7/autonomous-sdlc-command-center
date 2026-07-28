param(
  [Parameter(Mandatory = $true)][string]$PluginPath,
  [Parameter(Mandatory = $true)][string]$PreviousVersion
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Write-Host "[autonomous-sdlc-command-center] Updating from v$PreviousVersion..." -ForegroundColor Cyan

$preflight = Join-Path $PluginPath 'scripts\commands\plugin_preflight.ps1'
if (Test-Path -LiteralPath $preflight -PathType Leaf) {
  $result = & $preflight -PluginPath $PluginPath | ConvertFrom-Json
  if ($result.status -eq 'pass') {
    Write-Host "[autonomous-sdlc-command-center] Update verified." -ForegroundColor Green
  } else {
    Write-Host "[WARNING] Update completed with preflight warnings." -ForegroundColor Yellow
  }
} else {
  Write-Host "[WARNING] Preflight script not available for verification." -ForegroundColor Yellow
}

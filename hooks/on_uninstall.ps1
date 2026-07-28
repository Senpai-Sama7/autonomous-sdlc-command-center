param(
  [Parameter(Mandatory = $true)][string]$PluginPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Write-Host "[autonomous-sdlc-command-center] Uninstalling. No persistent data to clean up." -ForegroundColor Cyan

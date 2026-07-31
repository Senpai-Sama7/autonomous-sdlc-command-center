# Universal installer for Windows/PowerShell
param(
  [string]$Python = "python"
)

Write-Host "=== Autonomous SDLC Command Center Universal Installer (PowerShell) ==="

$ProjectDir = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Write-Host "Source: $ProjectDir"

# Install pip package
Write-Host "[1/4] Installing Python package..."
& $Python -m pip install -e $ProjectDir --break-system-packages 2>&1 | Select-Object -Last 5
Write-Host "Installed sdlc and sdlc-mcp"

Write-Host "[2/4] Verifying CLI..."
& $Python -m sdlc_cli --version 2>$null
if ($LASTEXITCODE -ne 0) {
  sdlc --version
}
sdlc doctor --format text | Select-Object -First 15

Write-Host "[3/4] Checking rg..."
try { rg --version } catch { Write-Warning "rg not found, install ripgrep for PowerShell commands" }

Write-Host "[4/4] Example MCP configs:"
Write-Host "OpenCode: ~/.config/opencode/opencode.jsonc with command sdlc-mcp"
Write-Host "Claude Desktop: %APPDATA%\Claude\claude_desktop_config.json"
Write-Host "Cursor: ~/.cursor/mcp.json"
Write-Host "Gemini: ~/.gemini/settings.json"

Write-Host "=== Done ==="

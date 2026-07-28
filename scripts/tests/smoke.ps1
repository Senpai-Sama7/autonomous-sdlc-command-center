[CmdletBinding()]
param(
  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string]$PluginPath = (Join-Path $PSScriptRoot '..\..'),
  [Parameter()]
  [string]$TargetRepo = (Get-Location).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$resolvedPlugin = (Get-Item -LiteralPath $PluginPath -Force).FullName
$failed = 0; $passed = 0

function Assert-Pass {
  param([string]$Test, [scriptblock]$ScriptBlock)
  try {
    $null = & $ScriptBlock
    $script:passed++; Write-Host "[PASS] $Test" -ForegroundColor Green
  } catch {
    $script:failed++; Write-Host "[FAIL] $Test`: $_" -ForegroundColor Red
  }
}

function Assert-Json {
  param([string]$Test, [scriptblock]$ScriptBlock)
  try {
    $output = & $ScriptBlock | Out-String
    $output | ConvertFrom-Json -ErrorAction Stop | Out-Null
    $script:passed++; Write-Host "[PASS] $Test" -ForegroundColor Green
  } catch {
    $script:failed++; Write-Host "[FAIL] $Test - not valid JSON: $_" -ForegroundColor Red
  }
}

Write-Host "`n=== autonomous-sdlc-command-center smoke tests ===" -ForegroundColor Cyan
Write-Host "Plugin root: $resolvedPlugin`n"

# --- PowerShell commands ---
$snapshotCmd = Join-Path $resolvedPlugin 'scripts\commands\repo_snapshot.ps1'
$releaseCmd = Join-Path $resolvedPlugin 'scripts\commands\release_readiness.ps1'
$preflightCmd = Join-Path $resolvedPlugin 'scripts\commands\plugin_preflight.ps1'
$cliScript = Join-Path $resolvedPlugin 'mcp\sdlc_cli.py'

Assert-Pass -Test "plugin_preflight.ps1 passes" -ScriptBlock { & $preflightCmd -PluginPath $resolvedPlugin }
Assert-Json -Test "plugin_preflight.ps1 JSON output" -ScriptBlock { & $preflightCmd -PluginPath $resolvedPlugin }
Assert-Pass -Test "repo_snapshot.ps1 runs" -ScriptBlock { & $snapshotCmd -Path $resolvedPlugin -MaxFiles 10 }
Assert-Json -Test "repo_snapshot.ps1 JSON output" -ScriptBlock { & $snapshotCmd -Path $resolvedPlugin -MaxFiles 10 }
Assert-Pass -Test "release_readiness.ps1 runs" -ScriptBlock { & $releaseCmd -Path $resolvedPlugin -MaxFiles 50 }
Assert-Json -Test "release_readiness.ps1 JSON output" -ScriptBlock { & $releaseCmd -Path $resolvedPlugin -MaxFiles 50 }
Assert-Pass -Test "repo_snapshot rejects root" -ScriptBlock {
  $threw = $false
  try { & $snapshotCmd -Path 'C:\' 2>$null } catch { $threw = $true }
  if (-not $threw) { throw "expected rejection of filesystem root" }
}

# --- Python MCP server ---
$mcpServer = Join-Path $resolvedPlugin 'mcp\sdlc_mcp_server.py'
Assert-Pass -Test "MCP server initialize" -ScriptBlock {
  $r = '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}' | python $mcpServer
  $p = $r | ConvertFrom-Json; if ($p.result.protocolVersion -ne '2025-11-25') { throw "bad protocol" }
}
Assert-Json -Test "MCP server tools/list" -ScriptBlock {
  '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' | python $mcpServer
}
Assert-Pass -Test "MCP server calls sdlc_repo_snapshot" -ScriptBlock {
  $req = '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"sdlc_repo_snapshot","arguments":{"path":"' + $resolvedPlugin.Replace('\', '\\') + '","maxFiles":10}}}'
  $r = $req | python $mcpServer; $p = $r | ConvertFrom-Json
  if ($p.result.structuredContent.sampleLimit -ne 10) { throw "bad sample limit" }
}

# --- MCP error paths (E12) ---
Assert-Pass -Test "MCP rejects invalid JSON (-32700)" -ScriptBlock {
  $p = 'not json' | python $mcpServer | ConvertFrom-Json
  if ($p.error.code -ne -32700) { throw "expected -32700, got $($p.error.code)" }
}
Assert-Pass -Test "MCP rejects unknown tool (-32602)" -ScriptBlock {
  $p = '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"nope","arguments":{}}}' | python $mcpServer | ConvertFrom-Json
  if ($p.error.code -ne -32602) { throw "expected -32602, got $($p.error.code)" }
}
Assert-Pass -Test "MCP rejects unknown method (-32601)" -ScriptBlock {
  $p = '{"jsonrpc":"2.0","id":5,"method":"bogus/method","params":{}}' | python $mcpServer | ConvertFrom-Json
  if ($p.error.code -ne -32601) { throw "expected -32601, got $($p.error.code)" }
}
Assert-Pass -Test "MCP rejects batch requests (-32600)" -ScriptBlock {
  $p = '[{"jsonrpc":"2.0","id":6,"method":"ping"}]' | python $mcpServer | ConvertFrom-Json
  if ($p.error.code -ne -32600) { throw "expected -32600, got $($p.error.code)" }
}

# --- CLI error paths (E12) ---
Assert-Pass -Test "CLI rejects maxFiles out of range" -ScriptBlock {
  python $cliScript snapshot --path $resolvedPlugin --max-files 0 2>$null | Out-Null
  if ($LASTEXITCODE -ne 2) { throw "expected exit 2, got $LASTEXITCODE" }
}
Assert-Pass -Test "CLI search rejects invalid regex" -ScriptBlock {
  python $cliScript search --path $resolvedPlugin --pattern '(' 2>$null | Out-Null
  if ($LASTEXITCODE -ne 2) { throw "expected exit 2, got $LASTEXITCODE" }
}

# --- Gated write engine cycle (E12) ---
Assert-Pass -Test "write engine dry-run/confirm/rollback cycle" -ScriptBlock {
  $fixture = Join-Path ([System.IO.Path]::GetTempPath()) "sdlc-smoke-$([Guid]::NewGuid().ToString('N'))"
  New-Item -ItemType Directory -Path $fixture | Out-Null
  try {
    $dry = python $cliScript write --path $fixture --file t.md --content 'alpha' | ConvertFrom-Json
    if ($dry.status -ne 'dry-run') { throw "expected dry-run, got $($dry.status)" }
    if (Test-Path (Join-Path $fixture 't.md')) { throw 'dry-run created a file' }
    $applied = python $cliScript write --path $fixture --file t.md --content 'alpha' --confirm | ConvertFrom-Json
    if ($applied.status -ne 'written') { throw "expected written, got $($applied.status)" }
    $audit = python $cliScript audit --path $fixture | ConvertFrom-Json
    if (-not $audit.chainValid) { throw 'audit chain invalid' }
    $rb = python $cliScript rollback --path $fixture --change-id $applied.changeId --confirm | ConvertFrom-Json
    if ($rb.status -ne 'rolled-back') { throw "expected rolled-back, got $($rb.status)" }
    if (Test-Path (Join-Path $fixture 't.md')) { throw 'rollback did not remove created file' }
  } finally {
    Remove-Item -LiteralPath $fixture -Recurse -Force -ErrorAction SilentlyContinue
  }
}
Assert-Pass -Test "secret-scan redacts planted key" -ScriptBlock {
  $fixture = Join-Path ([System.IO.Path]::GetTempPath()) "sdlc-smoke-$([Guid]::NewGuid().ToString('N'))"
  New-Item -ItemType Directory -Path $fixture | Out-Null
  try {
    $key = 'AKIA' + 'IOSFODNN7EXAMPLE'
    Set-Content -Path (Join-Path $fixture 's.cfg') -Value "aws_key = $key"
    $out = python $cliScript secret-scan --path $fixture | Out-String
    $scan = $out | ConvertFrom-Json
    if ($scan.status -ne 'warning' -or $scan.findingCount -lt 1) { throw 'expected findings' }
    if ($out.Contains($key)) { throw 'raw secret leaked into output' }
  } finally {
    Remove-Item -LiteralPath $fixture -Recurse -Force -ErrorAction SilentlyContinue
  }
}

# --- Python CLI ---
Assert-Pass -Test "Python CLI snapshot" -ScriptBlock { python $cliScript snapshot --path $resolvedPlugin --max-files 10 }
Assert-Pass -Test "Python CLI preflight" -ScriptBlock {
  $r = python $cliScript plugin-preflight --plugin-path $resolvedPlugin
  $p = $r | ConvertFrom-Json; if ($p.status -ne 'pass') { throw "preflight: $($p.status)" }
}

# --- Summary ---
Write-Host "`n=== Results: $passed passed, $failed failed ===" -ForegroundColor $(if ($failed -eq 0) { 'Green' } else { 'Red' })
if ($failed -gt 0) { exit 1 }

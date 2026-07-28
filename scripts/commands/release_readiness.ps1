[CmdletBinding()]
param(
  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string]$Path = (Get-Location).Path,

  [Parameter()]
  [ValidateRange(1, 2000)]
  [int]$MaxFiles = 500
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function New-Check {
  param(
    [Parameter(Mandatory = $true)][string]$Id,
    [Parameter(Mandatory = $true)][ValidateSet('pass', 'warning', 'fail', 'unknown')][string]$Status,
    [Parameter(Mandatory = $true)][string]$Detail
  )

  return [pscustomobject][ordered]@{
    id = $Id
    status = $Status
    detail = $Detail
  }
}

$snapshotScript = Join-Path $PSScriptRoot 'repo_snapshot.ps1'
if (-not (Test-Path -LiteralPath $snapshotScript -PathType Leaf)) {
  throw "Required snapshot command is missing: $snapshotScript"
}

$snapshot = & $snapshotScript -Path $Path -MaxFiles $MaxFiles -IncludeGit | ConvertFrom-Json
$checks = [System.Collections.Generic.List[object]]::new()

if ($snapshot.sampleLimitReached) {
  $checks.Add((New-Check -Id 'inventory-completeness' -Status warning -Detail "The snapshot reached its $($snapshot.sampleLimit)-file sample limit; inspect targeted paths before relying on absence claims."))
} else {
  $checks.Add((New-Check -Id 'inventory-completeness' -Status pass -Detail 'The bounded snapshot did not reach its sample limit.'))
}

if ($snapshot.manifests.Count -gt 0) {
  $checks.Add((New-Check -Id 'build-manifests' -Status pass -Detail "Detected $($snapshot.manifests.Count) build or runtime manifest(s)."))
} else {
  $checks.Add((New-Check -Id 'build-manifests' -Status warning -Detail 'No common build manifest was found in the sampled files.'))
}

if ($snapshot.lockfiles.Count -gt 0) {
  $checks.Add((New-Check -Id 'dependency-lockfiles' -Status pass -Detail "Detected $($snapshot.lockfiles.Count) dependency lockfile(s)."))
} elseif ($snapshot.manifests.Count -gt 0) {
  $checks.Add((New-Check -Id 'dependency-lockfiles' -Status warning -Detail 'A manifest was found but no common lockfile was detected in the sample.'))
} else {
  $checks.Add((New-Check -Id 'dependency-lockfiles' -Status unknown -Detail 'No dependency-manifest evidence was available.'))
}

if ($snapshot.testFiles.Count -gt 0) {
  $checks.Add((New-Check -Id 'test-evidence' -Status pass -Detail "Detected $($snapshot.testFiles.Count) test-related file(s) in the sample."))
} else {
  $checks.Add((New-Check -Id 'test-evidence' -Status warning -Detail 'No test-related files were detected; inspect the test strategy manually.'))
}

if ($snapshot.ciFiles.Count -gt 0) {
  $checks.Add((New-Check -Id 'ci-evidence' -Status pass -Detail "Detected $($snapshot.ciFiles.Count) CI configuration file(s)."))
} else {
  $checks.Add((New-Check -Id 'ci-evidence' -Status warning -Detail 'No CI configuration was detected in the sample.'))
}

$readmePath = Join-Path $snapshot.scanRoot 'README.md'
$changelogPath = Join-Path $snapshot.scanRoot 'CHANGELOG.md'
$checks.Add((New-Check -Id 'documentation' -Status $(if (Test-Path -LiteralPath $readmePath -PathType Leaf) { 'pass' } else { 'warning' }) -Detail $(if (Test-Path -LiteralPath $readmePath -PathType Leaf) { 'README.md is present.' } else { 'README.md was not found at the repository root.' })))
$checks.Add((New-Check -Id 'changelog' -Status $(if (Test-Path -LiteralPath $changelogPath -PathType Leaf) { 'pass' } else { 'warning' }) -Detail $(if (Test-Path -LiteralPath $changelogPath -PathType Leaf) { 'CHANGELOG.md is present.' } else { 'CHANGELOG.md was not found at the repository root.' })))

if ($snapshot.git.available -and $snapshot.git.repository) {
  $worktreeStatus = if ($snapshot.git.workingTreeClean) { 'pass' } else { 'warning' }
  $worktreeDetail = if ($snapshot.git.workingTreeClean) { 'Working tree is clean.' } else { "Working tree has $($snapshot.git.changedFileCount) changed path(s); confirm intended release contents." }
  $checks.Add((New-Check -Id 'working-tree' -Status $worktreeStatus -Detail $worktreeDetail))

  $gitPath = (Get-Command -Name git -CommandType Application -ErrorAction Stop | Select-Object -First 1).Path
  # Capture the exit code locally so a prior native call cannot bleed into this check (E4).
  $global:LASTEXITCODE = $null
  $diffCheckOutput = @(& $gitPath -C $snapshot.scanRoot diff --check 2>$null)
  $diffExitCode = if ($global:LASTEXITCODE -is [int]) { $global:LASTEXITCODE } else { 1 }
  if ($diffExitCode -eq 0) {
    $checks.Add((New-Check -Id 'diff-whitespace' -Status pass -Detail 'git diff --check found no whitespace errors in tracked changes.'))
  } else {
    $checks.Add((New-Check -Id 'diff-whitespace' -Status fail -Detail 'git diff --check found whitespace errors; inspect locally before release.'))
  }
} elseif ($snapshot.git.available) {
  $checks.Add((New-Check -Id 'working-tree' -Status unknown -Detail 'Git is available but the target is not a Git worktree.'))
} else {
  $checks.Add((New-Check -Id 'working-tree' -Status unknown -Detail 'Git is not available; working-tree state was not assessed.'))
}

$failures = @($checks | Where-Object { $_.status -eq 'fail' })
$warnings = @($checks | Where-Object { $_.status -eq 'warning' })
$recommendation = if ($failures.Count -gt 0) {
  'blocked'
} elseif ($warnings.Count -gt 0) {
  'needs-review'
} else {
  'ready-for-verification'
}

[pscustomobject][ordered]@{
  status = $recommendation
  scanRoot = $snapshot.scanRoot
  generatedAtUtc = [DateTime]::UtcNow.ToString('o')
  checks = @($checks)
  summary = [ordered]@{
    pass = @($checks | Where-Object { $_.status -eq 'pass' }).Count
    warnings = $warnings.Count
    failures = $failures.Count
    unknown = @($checks | Where-Object { $_.status -eq 'unknown' }).Count
  }
  note = 'This is read-only evidence collection. It does not run tests, query remote CI, scan vulnerabilities, or authorize a release.'
} | ConvertTo-Json -Depth 6

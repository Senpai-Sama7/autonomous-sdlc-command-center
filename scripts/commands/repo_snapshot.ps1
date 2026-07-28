[CmdletBinding()]
param(
  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string]$Path = (Get-Location).Path,

  [Parameter()]
  [ValidateRange(1, 2000)]
  [int]$MaxFiles = 250,

  [Parameter()]
  [switch]$IncludeGit
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-ApplicationPath {
  param([Parameter(Mandatory = $true)][string]$Name)

  $command = Get-Command -Name $Name -CommandType Application -ErrorAction SilentlyContinue |
    Select-Object -First 1
  if ($null -eq $command) {
    return $null
  }

  return $command.Path
}

function Resolve-RepositoryPath {
  param([Parameter(Mandatory = $true)][string]$Candidate)

  $item = Get-Item -LiteralPath $Candidate -Force
  if (-not $item.PSIsContainer) {
    throw "Path must be a directory: $Candidate"
  }

  $resolved = $item.FullName
  $trimmedPath = $resolved.TrimEnd('\', '/')
  $trimmedRoot = [System.IO.Path]::GetPathRoot($resolved).TrimEnd('\', '/')
  if ($trimmedPath -eq $trimmedRoot) {
    throw "Refusing to scan a filesystem root. Pass a repository directory instead: $resolved"
  }

  return $resolved
}

function Get-GitSummary {
  param(
    [Parameter(Mandatory = $true)][string]$GitPath,
    [Parameter(Mandatory = $true)][string]$RepositoryPath
  )

  $global:LASTEXITCODE = $null
  $insideWorkTree = @(& $GitPath -C $RepositoryPath rev-parse --is-inside-work-tree 2>$null)
  $gitExit = if ($global:LASTEXITCODE -is [int]) { $global:LASTEXITCODE } else { 0 }
  if ($gitExit -ne 0 -or $insideWorkTree.Count -ne 1 -or $insideWorkTree[0].Trim() -ne 'true') {
    return [ordered]@{
      available = $true
      repository = $false
    }
  }

  $branch = @(& $GitPath -C $RepositoryPath branch --show-current 2>$null)
  $status = @(& $GitPath -C $RepositoryPath status --porcelain=v1 2>$null)
  $head = @(& $GitPath -C $RepositoryPath rev-parse --short HEAD 2>$null)

  return [ordered]@{
    available = $true
    repository = $true
    branch = if ($branch.Count -eq 1) { $branch[0].Trim() } else { $null }
    head = if ($head.Count -eq 1) { $head[0].Trim() } else { $null }
    workingTreeClean = ($status.Count -eq 0)
    changedFileCount = $status.Count
  }
}

$resolvedPath = Resolve-RepositoryPath -Candidate $Path
$rgPath = Get-ApplicationPath -Name 'rg'
if ([string]::IsNullOrWhiteSpace($rgPath)) {
  throw 'repo_snapshot.ps1 requires ripgrep (rg) on PATH. Install ripgrep or run this command from a Codex environment that includes it.'
}

$rgArguments = @(
  '--files',
  '--hidden',
  '--glob', '!.git/**',
  '--glob', '!node_modules/**',
  '--glob', '!vendor/**',
  '--glob', '!dist/**',
  '--glob', '!build/**',
  '--glob', '!coverage/**',
  '--glob', '!target/**',
  '--', $resolvedPath
)

$global:LASTEXITCODE = $null
$rgOutput = @(& $rgPath @rgArguments 2>$null)
$rgExitCode = if ($global:LASTEXITCODE -is [int]) { $global:LASTEXITCODE } else { 0 }
$files = $rgOutput | Select-Object -First $MaxFiles
if ($rgExitCode -gt 1) {
  throw "ripgrep failed while scanning '$resolvedPath' (exit code $rgExitCode)."
}

$relativeFiles = @($files | ForEach-Object {
  $_.Substring($resolvedPath.Length).TrimStart('\', '/')
})

$manifestNames = @(
  'package.json', 'pnpm-workspace.yaml', 'pyproject.toml', 'requirements.txt', 'Pipfile',
  'poetry.lock', 'go.mod', 'Cargo.toml', 'pom.xml', 'build.gradle', 'build.gradle.kts',
  'Gemfile', 'composer.json', 'Dockerfile', 'docker-compose.yml', 'compose.yml', 'Makefile'
)
$lockFileNames = @(
  'package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', 'poetry.lock',
  'Pipfile.lock', 'Cargo.lock', 'go.sum', 'Gemfile.lock', 'composer.lock', 'gradle.lockfile'
)

$manifests = @($relativeFiles | Where-Object { $manifestNames -contains (Split-Path -Path $_ -Leaf) })
$lockfiles = @($relativeFiles | Where-Object { $lockFileNames -contains (Split-Path -Path $_ -Leaf) })
$ciFiles = @($relativeFiles | Where-Object {
  $_ -match '(^|[\\/])\.github[\\/]workflows[\\/]|(^|[\\/])\.gitlab-ci|azure-pipelines|Jenkinsfile|(^|[\\/])\.circleci[\\/]|buildkite'
})
$testFiles = @($relativeFiles | Where-Object {
  $_ -match '(^|[\\/])(test|tests|spec|__tests__)([\\/]|$)|\.(test|spec)\.[^.]+$'
} | Select-Object -First 50)
$infrastructureFiles = @($relativeFiles | Where-Object {
  $_ -match '(^|[\\/])(terraform|k8s|kubernetes|helm|ansible|\.github[\\/]workflows)([\\/]|$)|(^|[\\/])(Dockerfile|docker-compose\.ya?ml|compose\.ya?ml)$'
} | Select-Object -First 50)
$sensitivePathIndicators = @($relativeFiles | Where-Object {
  $_ -match '(^|[\\/])\.env($|\.)|(^|[\\/])(secrets?|credentials?)([\\/_.-]|$)' -and
  # Intentional example templates are not sensitive indicators (E15).
  (Split-Path -Path $_ -Leaf) -notmatch '^\.env\.(example|sample|template)$'
} | Select-Object -First 20)

$gitSummary = $null
if ($IncludeGit) {
  $gitPath = Get-ApplicationPath -Name 'git'
  $gitSummary = if ([string]::IsNullOrWhiteSpace($gitPath)) {
    [ordered]@{ available = $false; repository = $false }
  } else {
    Get-GitSummary -GitPath $gitPath -RepositoryPath $resolvedPath
  }
}

[pscustomobject][ordered]@{
  schemaVersion = '1.0'
  generatedAtUtc = [DateTime]::UtcNow.ToString('o')
  scanRoot = $resolvedPath
  fileCountSampled = $relativeFiles.Count
  sampleLimit = $MaxFiles
  sampleLimitReached = ($relativeFiles.Count -ge $MaxFiles)
  manifests = $manifests
  lockfiles = $lockfiles
  ciFiles = $ciFiles
  testFiles = $testFiles
  infrastructureFiles = $infrastructureFiles
  sensitivePathIndicators = $sensitivePathIndicators
  git = $gitSummary
} | ConvertTo-Json -Depth 6

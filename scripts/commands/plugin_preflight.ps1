[CmdletBinding()]
param(
  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string]$PluginPath = (Join-Path $PSScriptRoot '..\..')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Add-Finding {
  param(
    [Parameter(Mandatory = $true)][System.Collections.Generic.List[object]]$Findings,
    [Parameter(Mandatory = $true)][ValidateSet('error', 'warning', 'info')][string]$Severity,
    [Parameter(Mandatory = $true)][string]$Id,
    [Parameter(Mandatory = $true)][string]$Message,
    [string]$File
  )

  $Findings.Add([pscustomobject][ordered]@{
    severity = $Severity
    id = $Id
    message = $Message
    file = $File
  })
}

function Test-JsonFile {
  param([Parameter(Mandatory = $true)][string]$FilePath)

  try {
    Get-Content -LiteralPath $FilePath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop | Out-Null
    return $true
  } catch {
    return $false
  }
}

$findings = [System.Collections.Generic.List[object]]::new()
$resolvedPluginPath = (Get-Item -LiteralPath $PluginPath -Force).FullName
if (-not (Get-Item -LiteralPath $resolvedPluginPath -Force).PSIsContainer) {
  throw "PluginPath must be a directory: $resolvedPluginPath"
}

$manifestPath = Join-Path $resolvedPluginPath '.codex-plugin\plugin.json'
$manifest = $null
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
  Add-Finding -Findings $findings -Severity error -Id 'manifest-missing' -Message 'Required plugin manifest is missing.' -File $manifestPath
} elseif (-not (Test-JsonFile -FilePath $manifestPath)) {
  Add-Finding -Findings $findings -Severity error -Id 'manifest-invalid-json' -Message 'Plugin manifest is not valid JSON.' -File $manifestPath
} else {
  $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
  $expectedName = Split-Path -Path $resolvedPluginPath -Leaf
  if ([string]::IsNullOrWhiteSpace($manifest.name) -or $manifest.name -ne $expectedName) {
    Add-Finding -Findings $findings -Severity error -Id 'manifest-name' -Message "Manifest name must match the plugin directory '$expectedName'." -File $manifestPath
  }
  if ([string]::IsNullOrWhiteSpace($manifest.version) -or $manifest.version -notmatch '^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$') {
    Add-Finding -Findings $findings -Severity error -Id 'manifest-version' -Message 'Manifest version is missing or is not semantic-version compatible.' -File $manifestPath
  }
  if ($null -eq $manifest.interface -or [string]::IsNullOrWhiteSpace($manifest.interface.displayName) -or [string]::IsNullOrWhiteSpace($manifest.interface.shortDescription)) {
    Add-Finding -Findings $findings -Severity error -Id 'manifest-interface' -Message 'Manifest interface metadata is incomplete.' -File $manifestPath
  }
  $prompts = @($manifest.interface.defaultPrompt)
  if ($prompts.Count -gt 3) {
    Add-Finding -Findings $findings -Severity warning -Id 'prompt-count' -Message 'Only the first three default prompts are surfaced by Codex.' -File $manifestPath
  }
  foreach ($prompt in $prompts) {
    if ($prompt -is [string] -and $prompt.Length -gt 128) {
      Add-Finding -Findings $findings -Severity warning -Id 'prompt-length' -Message 'A default prompt exceeds 128 characters and may be truncated.' -File $manifestPath
      break
    }
  }
}

$skillsRoot = Join-Path $resolvedPluginPath 'skills'
if (-not (Test-Path -LiteralPath $skillsRoot -PathType Container)) {
  Add-Finding -Findings $findings -Severity error -Id 'skills-missing' -Message 'The declared skills directory is missing.' -File $skillsRoot
} else {
  $skillFiles = @(Get-ChildItem -LiteralPath $skillsRoot -Filter 'SKILL.md' -File -Recurse -ErrorAction Stop)
  if ($skillFiles.Count -eq 0) {
    Add-Finding -Findings $findings -Severity error -Id 'skills-empty' -Message 'No SKILL.md files were found.' -File $skillsRoot
  }

  $seenSkillNames = @{}
  foreach ($skillFile in $skillFiles) {
    $content = Get-Content -LiteralPath $skillFile.FullName -Raw
    if ($content -match '\[TODO:\s*') {
      Add-Finding -Findings $findings -Severity error -Id 'skill-todo' -Message 'Skill contains an unresolved TODO placeholder.' -File $skillFile.FullName
    }
    $frontMatter = [regex]::Match($content, '(?s)\A---\s*\r?\n(?<body>.*?)\r?\n---')
    if (-not $frontMatter.Success) {
      Add-Finding -Findings $findings -Severity error -Id 'skill-frontmatter' -Message 'Skill is missing YAML frontmatter.' -File $skillFile.FullName
      continue
    }
    $nameMatch = [regex]::Match($frontMatter.Groups['body'].Value, '(?m)^name:\s*["'']?(?<name>[a-z0-9-]+)["'']?\s*$')
    $descriptionMatch = [regex]::Match($frontMatter.Groups['body'].Value, '(?m)^description:\s*["'']?(?<description>.+?)["'']?\s*$')
    if (-not $nameMatch.Success -or -not $descriptionMatch.Success) {
      Add-Finding -Findings $findings -Severity error -Id 'skill-metadata' -Message 'Skill frontmatter requires name and description.' -File $skillFile.FullName
      continue
    }
    $skillName = $nameMatch.Groups['name'].Value
    if ($seenSkillNames.ContainsKey($skillName)) {
      Add-Finding -Findings $findings -Severity error -Id 'skill-duplicate-name' -Message "Skill name '$skillName' is duplicated." -File $skillFile.FullName
    } else {
      $seenSkillNames[$skillName] = $true
    }
    $directoryName = Split-Path -Path (Split-Path -Path $skillFile.FullName -Parent) -Leaf
    if ($skillName -ne $directoryName) {
      Add-Finding -Findings $findings -Severity warning -Id 'skill-directory-name' -Message "Skill name '$skillName' does not match directory '$directoryName'." -File $skillFile.FullName
    }

    # Machine-readable skill contract validation (E13 parity with the Python core).
    $skillDir = Split-Path -Path $skillFile.FullName -Parent
    $contractPath = Join-Path $skillDir 'contract.json'
    if (-not (Test-Path -LiteralPath $contractPath -PathType Leaf)) {
      Add-Finding -Findings $findings -Severity warning -Id 'contract-missing' -Message 'Skill has no machine-readable contract.json.' -File $skillDir
    } elseif (-not (Test-JsonFile -FilePath $contractPath)) {
      Add-Finding -Findings $findings -Severity error -Id 'contract-invalid-json' -Message 'Skill contract is not valid JSON.' -File $contractPath
    } else {
      $contract = Get-Content -LiteralPath $contractPath -Raw | ConvertFrom-Json
      foreach ($field in @('schemaVersion', 'name', 'version', 'summary')) {
        if ($null -eq $contract.PSObject.Properties[$field]) {
          Add-Finding -Findings $findings -Severity error -Id 'contract-field' -Message "Skill contract is missing required field '$field'." -File $contractPath
        }
      }
      if (-not [string]::IsNullOrWhiteSpace($contract.name) -and $contract.name -ne $directoryName) {
        Add-Finding -Findings $findings -Severity error -Id 'contract-name' -Message 'Contract name must match the skill directory.' -File $contractPath
      }
      if (-not [string]::IsNullOrWhiteSpace($contract.name) -and $contract.name -ne $skillName) {
        Add-Finding -Findings $findings -Severity error -Id 'contract-name-mismatch' -Message 'Contract name must match SKILL.md frontmatter name.' -File $contractPath
      }
      if (-not [string]::IsNullOrWhiteSpace($contract.version) -and $contract.version -notmatch '^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$') {
        Add-Finding -Findings $findings -Severity error -Id 'contract-version' -Message 'Contract version is not semantic-version compatible.' -File $contractPath
      }
      if ($null -ne $contract.PSObject.Properties['evalPrompts']) {
        foreach ($relative in @($contract.evalPrompts)) {
          if ($relative -is [string] -and -not (Test-Path -LiteralPath (Join-Path $skillDir $relative) -PathType Leaf)) {
            Add-Finding -Findings $findings -Severity warning -Id 'contract-eval-missing' -Message "Eval prompt file '$relative' is missing." -File $contractPath
          }
        }
      }
    }
  }
}

$codeRoot = Join-Path $resolvedPluginPath 'scripts\commands'
if (Test-Path -LiteralPath $codeRoot -PathType Container) {
  $dangerousPatterns = @(
    @{ id = 'dynamic-code-execution'; pattern = '(?im)\b(Invoke-Expression|iex)\b'; message = 'Dynamic PowerShell evaluation is not allowed in bundled commands.' },
    @{ id = 'encoded-powershell'; pattern = '(?im)-EncodedCommand\b'; message = 'Encoded PowerShell commands obscure behavior.' },
    @{ id = 'pipe-to-shell'; pattern = '(?im)(curl|Invoke-WebRequest|iwr).{0,200}\|\s*(sh|bash|iex|Invoke-Expression)'; message = 'Piping downloaded content into a shell is unsafe.' },
    @{ id = 'force-recursive-delete'; pattern = '(?im)Remove-Item\b[^\r\n]*-Recurse\b[^\r\n]*-Force\b'; message = 'Force-recursive deletion is not allowed in bundled commands.' }
  )
  $secretPatterns = @(
    @{ id = 'private-key'; pattern = '-----BEGIN (?:RSA|EC|OPENSSH|DSA|PGP) PRIVATE KEY-----' },
    @{ id = 'github-token'; pattern = '\bgh[pousr]_[A-Za-z0-9_]{20,}\b' },
    @{ id = 'openai-key'; pattern = '\bsk-[A-Za-z0-9_-]{20,}\b' },
    @{ id = 'aws-access-key'; pattern = '\bAKIA[0-9A-Z]{16}\b' }
  )
  # This command embeds the rule expressions themselves, so audit sibling commands here and
  # validate this self-auditor through the dedicated smoke test instead of false-flagging it.
  foreach ($codeFile in @(Get-ChildItem -LiteralPath $codeRoot -File -Recurse -ErrorAction Stop | Where-Object { $_.Name -ne 'plugin_preflight.ps1' -and $_.Length -le 1048576 })) {
    $content = Get-Content -LiteralPath $codeFile.FullName -Raw
    foreach ($rule in $dangerousPatterns) {
      if ([regex]::IsMatch($content, $rule.pattern)) {
        Add-Finding -Findings $findings -Severity error -Id $rule.id -Message $rule.message -File $codeFile.FullName
      }
    }
    foreach ($rule in $secretPatterns) {
      if ([regex]::IsMatch($content, $rule.pattern)) {
        Add-Finding -Findings $findings -Severity error -Id 'potential-secret' -Message "Potential $($rule.id) signature detected; value intentionally omitted." -File $codeFile.FullName
      }
    }
  }
}

$errors = @($findings | Where-Object { $_.severity -eq 'error' })
$warnings = @($findings | Where-Object { $_.severity -eq 'warning' })
[pscustomobject][ordered]@{
  status = if ($errors.Count -eq 0) { 'pass' } else { 'fail' }
  pluginPath = $resolvedPluginPath
  summary = [ordered]@{
    errors = $errors.Count
    warnings = $warnings.Count
    info = @($findings | Where-Object { $_.severity -eq 'info' }).Count
  }
  findings = @($findings)
} | ConvertTo-Json -Depth 6

[CmdletBinding()]
param(
    [Parameter()]
    [string]$RepositoryRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
    $RepositoryRoot = Join-Path $PSScriptRoot '..'
}
$root = [System.IO.Path]::GetFullPath($RepositoryRoot)
$failures = [System.Collections.Generic.List[string]]::new()

function Add-Failure {
    param([Parameter(Mandatory = $true)][string]$Message)
    $script:failures.Add($Message)
}

if (-not (Test-Path -LiteralPath (Join-Path $root '.git'))) {
    throw "RepositoryRoot must be a Git worktree: $root"
}

$required = @(
    'README.md',
    'CONTRIBUTING.md',
    'docs/README.md',
    'docs/DOCUMENT_GUIDE.md',
    'docs/GLOSSARY.md',
    'docs/installation.md',
    'docs/provider-setup.md',
    'docs/usage.md',
    'docs/troubleshooting.md',
    'docs/onboarding-evidence.md',
    'docs/release-follow-ups.md',
    'docs/architecture/README.md',
    'docs/architecture/pipeline.md',
    'docs/architecture/runtime-and-recovery.md',
    'docs/architecture/agents-and-providers.md',
    'docs/architecture/contracts-and-storage.md',
    'docs/architecture/static-and-dynamic-analysis.md',
    'docs/architecture/gates-chaining-reporting.md',
    'docs/architecture/security-boundaries.md',
    'docs/architecture/implementation-map.md',
    'docs/decisions/README.md'
)

foreach ($relativePath in $required) {
    if (-not (Test-Path -LiteralPath (Join-Path $root $relativePath) -PathType Leaf)) {
        Add-Failure "required current document is missing: $relativePath"
    }
}

$obsolete = @(
    '.superpowers',
    'docs/architecture-v5',
    'docs/governance',
    'docs/handoff',
    'docs/review',
    'docs/superpowers',
    'docs/architecture-to-code.md',
    'scripts/validate-architecture-docs.ps1',
    'scripts/audit-doc-inventory.ps1'
)
foreach ($relativePath in $obsolete) {
    if (Test-Path -LiteralPath (Join-Path $root $relativePath)) {
        Add-Failure "obsolete documentation surface still exists: $relativePath"
    }
}

$markdown = @(& git -C $root ls-files -- '*.md')
if ($LASTEXITCODE -ne 0) {
    throw 'Unable to list Git-tracked Markdown files.'
}

$obsoleteReferences = @(
    'docs/architecture-v5',
    'docs/governance/',
    'docs/handoff/',
    'docs/review/',
    'docs/superpowers/',
    'docs/architecture-to-code.md'
)

$linkCount = 0
foreach ($relativePath in $markdown) {
    $sourcePath = Join-Path $root $relativePath
    if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
        continue
    }
    $text = Get-Content -Raw -Encoding UTF8 -LiteralPath $sourcePath
    foreach ($needle in $obsoleteReferences) {
        if ($text.IndexOf($needle, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
            Add-Failure "obsolete documentation reference in ${relativePath}: $needle"
        }
    }
    foreach ($match in [regex]::Matches($text, '\]\((?<target>[^)]+)\)')) {
        $target = $match.Groups['target'].Value.Trim()
        if ($target.StartsWith('<') -and $target.EndsWith('>')) {
            $target = $target.Substring(1, $target.Length - 2)
        }
        if ($target -match '^[a-zA-Z][a-zA-Z0-9+.-]*:' -or $target.StartsWith('#')) {
            continue
        }
        $target = $target.Split('#')[0].Split('?')[0]
        if ([string]::IsNullOrWhiteSpace($target)) {
            continue
        }
        try {
            $target = [System.Uri]::UnescapeDataString($target)
        }
        catch [System.UriFormatException] {
            Add-Failure "invalid local Markdown link in ${relativePath}: $target"
            continue
        }
        $candidate = if ($target.StartsWith('/')) {
            Join-Path $root $target.TrimStart('/')
        }
        else {
            Join-Path (Split-Path -Parent $sourcePath) $target
        }
        $linkCount += 1
        if (-not (Test-Path -LiteralPath $candidate)) {
            Add-Failure "missing local Markdown link: $relativePath -> $target"
        }
    }
}

$sourceReferenceCount = 0
$architectureFiles = Get-ChildItem -LiteralPath (Join-Path $root 'docs/architecture') -File -Filter '*.md'
foreach ($file in $architectureFiles) {
    $text = Get-Content -Raw -Encoding UTF8 -LiteralPath $file.FullName
    foreach ($match in [regex]::Matches($text, '`(?<path>src/sastsimi/[^`]+\.py)`')) {
        $relativePath = $match.Groups['path'].Value
        $sourceReferenceCount += 1
        if (-not (Test-Path -LiteralPath (Join-Path $root $relativePath) -PathType Leaf)) {
            Add-Failure "architecture references missing source file: $relativePath"
        }
    }
}

$pipelinePath = Join-Path $root 'docs/architecture/pipeline.md'
if (Test-Path -LiteralPath $pipelinePath -PathType Leaf) {
    $pipeline = Get-Content -Raw -Encoding UTF8 -LiteralPath $pipelinePath
    $stages = @(
        'STATIC_DONE',
        'HYPOTHESIS_DONE',
        'PRO_CON_DONE',
        'VERIFICATION_INITIAL_DONE',
        'POC_CANDIDATE_DONE',
        'POC_EXECUTION_DONE',
        'VERIFICATION_FINAL_DONE',
        'CWE_DONE',
        'TECH_GATE_DONE',
        'SCOPE_GATE_DONE',
        'PRIMITIVE_ADMISSION_DONE',
        'CHAINING_DONE',
        'FINDING_DONE',
        'REPORT_DONE'
    )
    $previous = -1
    foreach ($stage in $stages) {
        $position = $pipeline.IndexOf($stage, [System.StringComparison]::Ordinal)
        if ($position -lt 0) {
            Add-Failure "pipeline is missing current stage: $stage"
        }
        elseif ($position -le $previous) {
            Add-Failure "pipeline stage is out of order: $stage"
        }
        $previous = $position
    }
}

$decisions = @(Get-ChildItem -LiteralPath (Join-Path $root 'docs/decisions') -File -Filter 'ADR-*.md')
foreach ($decision in $decisions) {
    $text = Get-Content -Raw -Encoding UTF8 -LiteralPath $decision.FullName
    if ($text.IndexOf('상태: `ACCEPTED`', [System.StringComparison]::Ordinal) -lt 0) {
        Add-Failure "current decision is not ACCEPTED: $($decision.Name)"
    }
}

if ($failures.Count -gt 0) {
    foreach ($failure in $failures) {
        Write-Error $failure
    }
    throw "Current documentation validation failed with $($failures.Count) error(s)."
}

Write-Output "Current documentation: $($required.Count) required files"
Write-Output "Tracked Markdown: $($markdown.Count) files, local links: $linkCount"
Write-Output "Architecture source references: $sourceReferenceCount"
Write-Output "Accepted ADRs: $($decisions.Count)"

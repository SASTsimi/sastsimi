[CmdletBinding()]
param(
    [Parameter()]
    [string]$RepositoryRoot = (Join-Path $PSScriptRoot '..'),

    [Parameter()]
    [string[]]$DeletionAllowlist = @(),

    [Parameter()]
    [switch]$CheckLinks
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-NormalizedRelativePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Root
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $rootWithSeparator = [System.IO.Path]::GetFullPath($Root).TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
    if (-not $fullPath.StartsWith($rootWithSeparator, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $null
    }

    return $fullPath.Substring($rootWithSeparator.Length).Replace('\', '/')
}

function Get-LocalMarkdownTargets {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SourcePath,

        [Parameter(Mandatory = $true)]
        [string]$Root
    )

    $text = Get-Content -Raw -Encoding UTF8 -LiteralPath $SourcePath
    $targets = @()
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
            continue
        }

        if ($target.StartsWith('/')) {
            $candidate = Join-Path $Root $target.TrimStart('/')
        }
        else {
            $candidate = Join-Path (Split-Path -Parent $SourcePath) $target
        }

        $targets += [pscustomobject]@{
            Target = $target
            RelativePath = Get-NormalizedRelativePath -Path $candidate -Root $Root
            Exists = Test-Path -LiteralPath $candidate -PathType Leaf
        }
    }

    return $targets
}

function Find-TextReference {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Text,

        [Parameter(Mandatory = $true)]
        [string]$RelativePath
    )

    $normalized = $RelativePath.Replace('\', '/')
    $fileName = Split-Path -Leaf $normalized
    return $Text.IndexOf($normalized, [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -or
        $Text.IndexOf($fileName, [System.StringComparison]::OrdinalIgnoreCase) -ge 0
}

$repositoryFullPath = [System.IO.Path]::GetFullPath($RepositoryRoot)
if (-not (Test-Path -LiteralPath (Join-Path $repositoryFullPath '.git'))) {
    throw "RepositoryRoot must be a Git worktree: $repositoryFullPath"
}

$trackedMarkdown = @(& git -C $repositoryFullPath ls-files -- '*.md')
if ($LASTEXITCODE -ne 0) {
    throw 'Unable to read Git-tracked Markdown files.'
}
$trackedMarkdown = @($trackedMarkdown | ForEach-Object { $_.Replace('\', '/') } | Sort-Object -Unique)
$trackedMarkdownSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
foreach ($path in $trackedMarkdown) {
    [void]$trackedMarkdownSet.Add($path)
}

$targetsBySource = @{}
$missingLinks = @()
foreach ($relativePath in $trackedMarkdown) {
    $sourcePath = Join-Path $repositoryFullPath $relativePath
    $targets = @(Get-LocalMarkdownTargets -SourcePath $sourcePath -Root $repositoryFullPath)
    $targetsBySource[$relativePath] = $targets
    foreach ($target in $targets) {
        if (-not $target.Exists) {
            $missingLinks += "$relativePath -> $($target.Target)"
        }
    }
}

$validatorPath = Join-Path $repositoryFullPath 'scripts/validate-architecture-docs.ps1'
$validatorText = if (Test-Path -LiteralPath $validatorPath) { Get-Content -Raw -Encoding UTF8 -LiteralPath $validatorPath } else { '' }
$validatorGlobalMarkdownScan = $validatorText -match '(?s)\$markdownFiles\s*=\s*Get-ChildItem.*?-Recurse.*?-Filter\s+''\*\.md'''
$finalApprovalRelativePath = 'docs/review/FINAL_ARCHITECTURE_V5_APPROVAL.md'
$finalApprovalPath = Join-Path $repositoryFullPath $finalApprovalRelativePath
$finalApprovalText = if (Test-Path -LiteralPath $finalApprovalPath) { Get-Content -Raw -Encoding UTF8 -LiteralPath $finalApprovalPath } else { '' }
$provenanceRelativePath = 'docs/review/PROVENANCE.md'
$provenancePath = Join-Path $repositoryFullPath $provenanceRelativePath
$provenanceText = if (Test-Path -LiteralPath $provenancePath) { Get-Content -Raw -Encoding UTF8 -LiteralPath $provenancePath } else { '' }
$adrRelativePaths = @($trackedMarkdown | Where-Object { $_ -like 'docs/review/decisions/ADR-*.md' })
$adrTexts = @{}
foreach ($adrRelativePath in $adrRelativePaths) {
    $adrTexts[$adrRelativePath] = Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $repositoryFullPath $adrRelativePath)
}

$inventory = foreach ($relativePath in $trackedMarkdown) {
    $inboundLinks = @($targetsBySource.GetEnumerator() | Where-Object {
        $_.Value | Where-Object { $_.RelativePath -eq $relativePath }
    } | ForEach-Object { $_.Key } | Sort-Object -Unique)

    $validatorReferences = @()
    if ($validatorGlobalMarkdownScan) {
        $validatorReferences += 'scripts/validate-architecture-docs.ps1 (global Markdown scan; deletion-blocking)'
    }
    if (Find-TextReference -Text $validatorText -RelativePath $relativePath) {
        $validatorReferences += 'scripts/validate-architecture-docs.ps1 (literal path/basename reference)'
    }

    $finalApprovalReferences = @()
    if ($relativePath -eq $finalApprovalRelativePath) {
        $finalApprovalReferences += "$finalApprovalRelativePath (protected final approval)"
    }
    elseif (Find-TextReference -Text $finalApprovalText -RelativePath $relativePath) {
        $finalApprovalReferences += $finalApprovalRelativePath
    }

    $provenanceReferences = @()
    if ($relativePath -eq $provenanceRelativePath) {
        $provenanceReferences += "$provenanceRelativePath (protected provenance)"
    }
    elseif (Find-TextReference -Text $provenanceText -RelativePath $relativePath) {
        $provenanceReferences += $provenanceRelativePath
    }

    $adrReferences = @()
    foreach ($adrRelativePath in $adrRelativePaths) {
        if ($relativePath -eq $adrRelativePath -and $adrTexts[$adrRelativePath] -match '상태:\s*`ACCEPTED`') {
            $adrReferences += "$adrRelativePath (protected ACCEPTED ADR)"
        }
        elseif (Find-TextReference -Text $adrTexts[$adrRelativePath] -RelativePath $relativePath) {
            $adrReferences += $adrRelativePath
        }
    }

    [pscustomobject]@{
        Path = $relativePath
        InboundLinks = @($inboundLinks)
        ValidatorReferences = @($validatorReferences)
        FinalApprovalReferences = @($finalApprovalReferences)
        ProvenanceReferences = @($provenanceReferences)
        AdrReferences = @($adrReferences)
    }
}

Write-Output "Tracked Markdown files: $($inventory.Count)"
Write-Output "Architecture validator global Markdown scan: $validatorGlobalMarkdownScan"
foreach ($record in $inventory) {
    Write-Output "Path: $($record.Path)"
    Write-Output "  InboundLinks: $($record.InboundLinks -join '; ')"
    Write-Output "  ValidatorReferences: $($record.ValidatorReferences -join '; ')"
    Write-Output "  FinalApprovalReferences: $($record.FinalApprovalReferences -join '; ')"
    Write-Output "  ProvenanceReferences: $($record.ProvenanceReferences -join '; ')"
    Write-Output "  AdrReferences: $($record.AdrReferences -join '; ')"
}

$failures = @()
foreach ($allowlistedPath in $DeletionAllowlist) {
    $candidatePath = Get-NormalizedRelativePath -Path (Join-Path $repositoryFullPath $allowlistedPath) -Root $repositoryFullPath
    if ($null -eq $candidatePath -or -not $trackedMarkdownSet.Contains($candidatePath)) {
        $failures += "Deletion allowlist path is not Git-tracked Markdown: $allowlistedPath"
        continue
    }

    $record = @($inventory | Where-Object { $_.Path -eq $candidatePath })[0]
    $requiredReferences = @($record.InboundLinks) + @($record.ValidatorReferences) + @($record.FinalApprovalReferences) + @($record.ProvenanceReferences) + @($record.AdrReferences)
    if ($requiredReferences.Count -gt 0) {
        $failures += "Deletion allowlist path has required references: $candidatePath -> $($requiredReferences -join '; ')"
    }
}

if ($CheckLinks) {
    Write-Output "Missing local Markdown links: $($missingLinks.Count)"
    foreach ($missingLink in $missingLinks) {
        $failures += "Missing local Markdown link: $missingLink"
    }
}

if ($failures.Count -gt 0) {
    $failures | ForEach-Object { Write-Error $_ }
    exit 1
}

Write-Output 'Document inventory audit passed.'

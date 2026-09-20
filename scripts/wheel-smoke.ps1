[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$WorkRoot
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Invoke-Native {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]]$Arguments
    )

    $lines = @(& $FilePath @Arguments)
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code ${LASTEXITCODE}: $FilePath $Arguments"
    }
    return $lines
}

function Invoke-JsonCli {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Cli,
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    $text = (Invoke-Native $Cli @Arguments) -join "`n"
    try {
        return $text | ConvertFrom-Json
    }
    catch {
        throw "CLI did not return JSON for: $Cli $Arguments"
    }
}

$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$requestedRoot = [System.IO.Path]::GetFullPath($WorkRoot)
if (Test-Path -LiteralPath $requestedRoot) {
    throw "WorkRoot must not exist: $requestedRoot"
}

New-Item -ItemType Directory -Path $requestedRoot | Out-Null
$dist = Join-Path $requestedRoot 'dist'
$venv = Join-Path $requestedRoot 'venv'
$data = Join-Path $requestedRoot 'data'

Push-Location $repositoryRoot
try {
    Invoke-Native 'uv' 'build' '--wheel' '--out-dir' $dist | Out-Null
}
finally {
    Pop-Location
}

$wheel = @(Get-ChildItem -LiteralPath $dist -Filter 'sastsimi-*.whl' -File)
if ($wheel.Count -ne 1) {
    throw "Expected exactly one SASTSIMI wheel, found $($wheel.Count)"
}

Invoke-Native 'uv' 'venv' '--python' '3.12' '--seed' $venv | Out-Null
$runningOnWindows = [System.Environment]::OSVersion.Platform -eq 'Win32NT'
if ($runningOnWindows) {
    $python = Join-Path $venv 'Scripts/python.exe'
    $cli = Join-Path $venv 'Scripts/sastsimi.exe'
}
else {
    $python = Join-Path $venv 'bin/python'
    $cli = Join-Path $venv 'bin/sastsimi'
}
Invoke-Native 'uv' 'pip' 'install' '--python' $python $wheel[0].FullName | Out-Null

$savedPythonPath = $env:PYTHONPATH
Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue
Push-Location $requestedRoot
try {
    $help = (Invoke-Native $cli '--help') -join "`n"
    foreach ($command in @(
        'doctor', 'analyze', 'demo', 'status', 'results', 'reports', 'report',
        'onboarding', 'capability'
    )) {
        if ($help -notmatch "\b$command\b") {
            throw "Installed wheel does not expose required command: $command"
        }
    }
    $analyzeHelp = (Invoke-Native $cli 'analyze' '--help') -join "`n"
    foreach ($option in @('--repo', '--commit', '--profile')) {
        if ($analyzeHelp -notmatch [regex]::Escape($option)) {
            throw "Installed wheel production analyze is missing: $option"
        }
    }

    $doctor = Invoke-JsonCli $cli @('doctor', '--format', 'json')
    if ($doctor.status -ne 'ok') {
        throw 'doctor did not return status=ok'
    }

    $upgrade = Invoke-JsonCli $cli @(
        '--data-dir', $data, 'db', 'upgrade', 'head', '--format', 'json'
    )
    $current = Invoke-JsonCli $cli @(
        '--data-dir', $data, 'db', 'current', '--format', 'json'
    )
    if ($upgrade.status -ne 'ok' -or $current.status -ne 'ok') {
        throw 'Database migration smoke failed'
    }

    $analysis = Invoke-JsonCli $cli @(
        '--data-dir', $data, 'demo', 'analyze', '--scenario', 'TRUE',
        '--format', 'json'
    )
    $result = Invoke-JsonCli $cli @(
        '--data-dir', $data, 'demo', 'results', '--format', 'json'
    )
    if ($analysis.status -ne 'ok' -or $result.status -ne 'ok') {
        throw 'Deterministic analysis smoke failed'
    }

    $analysisId = [string]$analysis.data.analysis_id
    $reports = Invoke-JsonCli $cli @(
        '--data-dir', $data, 'reports', $analysisId, '--format', 'json'
    )
    if ($reports.status -ne 'ok' -or @($reports.data.reports).Count -ne 1) {
        throw 'Expected exactly one current report'
    }
    $findingId = [string]$reports.data.reports[0].finding_id
    $displayId = [string]$reports.data.reports[0].display_id
    if ($displayId -notmatch '^F-[0-9]{3,}$') {
        throw "Report list did not return a stable display id: $displayId"
    }
    $shown = (Invoke-Native $cli '--data-dir' $data 'report' 'show' $findingId) -join "`n"
    if ($shown -notmatch '^# ') {
        throw 'Report show did not return Markdown'
    }
    Invoke-Native $cli '--data-dir' $data 'report' 'export' $findingId '--format' 'markdown' | Out-Null
    $reportPath = Join-Path $data "reports/$analysisId/$displayId.md"
    if (-not (Test-Path -LiteralPath $reportPath -PathType Leaf)) {
        throw "Markdown report was not exported to the exact expected path: $reportPath"
    }
}
finally {
    Pop-Location
    if ($null -ne $savedPythonPath) {
        $env:PYTHONPATH = $savedPythonPath
    }
}

Write-Output "Installed wheel smoke passed: $($wheel[0].Name)"

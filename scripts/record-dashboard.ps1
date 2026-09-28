# Explicit, bounded Windows desktop capture for a local dashboard rehearsal.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Url,
    [Parameter(Mandatory = $true)][string]$OutputPath,
    [string]$FfmpegPath,
    [ValidateRange(5, 600)][int]$DurationSeconds = 180,
    [switch]$DryRun,
    [switch]$ConfirmCapture
)

$ErrorActionPreference = 'Stop'

$dashboardUrl = $null
if (-not [Uri]::TryCreate($Url, [UriKind]::Absolute, [ref]$dashboardUrl) -or
    $dashboardUrl.Scheme -ne 'http' -or
    $dashboardUrl.UserInfo -or
    $dashboardUrl.Query -or
    $dashboardUrl.Fragment) {
    throw 'Only a plain http loopback dashboard URL is allowed.'
}
$parsedAddress = $null
$isLoopback = $dashboardUrl.Host -eq 'localhost' -or
    ([Net.IPAddress]::TryParse($dashboardUrl.Host, [ref]$parsedAddress) -and
     [Net.IPAddress]::IsLoopback($parsedAddress))
if (-not $isLoopback) {
    throw 'Recording requires a loopback dashboard URL (localhost or 127.0.0.1).'
}
if (-not [IO.Path]::IsPathRooted($OutputPath) -or
    $OutputPath -match '^[A-Za-z]:[^\\/]' -or
    $OutputPath.StartsWith('\\')) {
    throw 'OutputPath must be an absolute local path.'
}
if ([IO.Path]::GetExtension($OutputPath) -ine '.mp4') {
    throw 'OutputPath must end in .mp4.'
}
$outputFull = [IO.Path]::GetFullPath($OutputPath)
$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..')).TrimEnd(
    [IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar
)
if ($outputFull.StartsWith($repoRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Save the MP4 outside the repository; videos are delivered separately.'
}
if (-not (Test-Path -LiteralPath (Split-Path -Parent $outputFull) -PathType Container)) {
    throw 'The output directory does not exist.'
}
if (Test-Path -LiteralPath $outputFull) {
    throw 'The output MP4 already exists; refusing to overwrite it.'
}

if ($FfmpegPath) {
    if (-not (Test-Path -LiteralPath $FfmpegPath -PathType Leaf)) {
        throw 'ffmpeg executable was not found at FfmpegPath.'
    }
    $ffmpeg = (Resolve-Path -LiteralPath $FfmpegPath).Path
} else {
    $ffmpegCommand = Get-Command ffmpeg.exe -CommandType Application -ErrorAction SilentlyContinue
    if (-not $ffmpegCommand) {
        throw 'ffmpeg executable was not found. Install ffmpeg or pass -FfmpegPath.'
    }
    $ffmpeg = $ffmpegCommand.Source
}

$arguments = @(
    '-hide_banner', '-loglevel', 'error',
    '-f', 'gdigrab', '-framerate', '20', '-i', 'desktop',
    '-t', [string]$DurationSeconds,
    '-c:v', 'libx264', '-preset', 'veryfast', '-pix_fmt', 'yuv420p',
    '-movflags', '+faststart', '-n',
    ('"' + $outputFull + '"')
)
if ($DryRun) {
    Write-Output "DRY RUN: $($dashboardUrl.AbsoluteUri)"
    Write-Output "Desktop capture only; verify this dashboard is visible before recording."
    Write-Output "ffmpeg $($arguments -join ' ')"
    return
}
if (-not $ConfirmCapture) {
    throw 'Screen capture requires explicit -ConfirmCapture. The entire desktop may be recorded.'
}
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'This gdigrab recorder requires Windows.'
}
try {
    $null = Invoke-WebRequest -Uri $dashboardUrl.AbsoluteUri -UseBasicParsing -TimeoutSec 4
} catch {
    throw 'The local dashboard is not responding; open the URL before recording.'
}
Write-Warning 'Recording the entire desktop, including any visible windows or notifications. Hide secrets first.'
$capture = $null
try {
    $capture = Start-Process -FilePath $ffmpeg -ArgumentList $arguments -PassThru -WindowStyle Hidden
    Wait-Process -Id $capture.Id
    $capture.Refresh()
    if ($capture.ExitCode -ne 0) {
        throw "ffmpeg failed with exit code $($capture.ExitCode)."
    }
    Write-Output "Recording saved: $outputFull"
} finally {
    if ($null -ne $capture -and -not $capture.HasExited) {
        Stop-Process -Id $capture.Id -ErrorAction SilentlyContinue
    }
}

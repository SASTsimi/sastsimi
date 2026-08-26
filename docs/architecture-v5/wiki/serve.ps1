param(
    [int]$Port = 8000
)

$wikiRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$architectureRoot = Split-Path -Parent $wikiRoot
Write-Host "Open http://localhost:$Port/wiki/"
python -m http.server $Port --directory $architectureRoot

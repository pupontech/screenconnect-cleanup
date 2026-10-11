# Harmless report-generation regression for an explicit bare output filename.
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$temp=Join-Path ([IO.Path]::GetTempPath()) ('scc-report-path-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $temp
try {
    [IO.File]::WriteAllText((Join-Path $temp 'findings.json'),'{"ComputerName":"Fixture","ScreenConnect":{"Instances":[],"Historical":[],"ParseIssues":[]},"OtherTargets":[]}')
    Push-Location $temp
    try {
        & (Join-Path $repo 'New-InvestigationReport.ps1') -FindingsJson './findings.json' -OutputPath 'report.html'
        if(-not (Test-Path -LiteralPath (Join-Path $temp 'report.html'))){throw 'Bare report filename did not write in the requested directory.'}
    } finally {Pop-Location}
    Write-Host 'PASS: explicit bare relative report path is supported.'
} finally {Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue}

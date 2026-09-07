# Non-destructive diff regression: real JSON files and the production consumer.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('scc-diff-evidence-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $tmp
$failures = 0
function Check {
    param([string]$Name, [bool]$Ok)
    if ($Ok) { Write-Host "PASS: $Name" }
    else { Write-Host "FAIL: $Name"; $script:failures++ }
}
function Invoke-Fixture {
    param($Snapshot)
    $before = Join-Path $tmp 'before.json'
    $after = Join-Path $tmp 'after.json'
    $out = Join-Path $tmp 'diff.json'
    $json = ConvertTo-Json -InputObject $Snapshot -Depth 12
    [IO.File]::WriteAllText($before, $json)
    [IO.File]::WriteAllText($after, $json)
    & (Join-Path $repoRoot 'diff-snapshots.ps1') -BeforeFile $before -AfterFile $after -OutFile $out | Out-Null
    $rc = $LASTEXITCODE
    return @{ Rc = $rc; Diff = (Get-Content -LiteralPath $out -Raw | ConvertFrom-Json) }
}
try {
    $snapshot = [ordered]@{
        ComputerName = 'SYNTHETIC'; Label = 'fixture'; CollectedUtc = '2026-01-01 00:00:00'
        CollectionComplete = $true; CollectionErrors = @(); CollectionWarnings = @()
        Sections = @{ Services = @(); Srum = $null; SystemSettings = @{} }
    }
    $r = Invoke-Fixture $snapshot
    Check 'complete empty fixture is CLEAN with exit zero' ($r.Rc -eq 0 -and $r.Diff.Verdict -eq 'CLEAN')
    foreach ($field in @('BeforeCollectionErrors', 'AfterCollectionErrors', 'BeforeCollectionWarnings', 'AfterCollectionWarnings')) {
        Check "$field remains a flat empty array" ($null -ne $r.Diff.$field -and @($r.Diff.$field).Count -eq 0)
    }
    $snapshot.Remove('CollectionComplete')
    foreach ($shape in @('array', 'object', 'null')) {
        $snapshot.CollectionErrors = switch ($shape) { 'array' { , @() }; 'object' { [pscustomobject]@{} }; 'null' { $null } }
        $r = Invoke-Fixture $snapshot
        Check "legacy empty errors ($shape) are not a phantom failure" ($r.Rc -eq 0 -and $r.Diff.Verdict -eq 'CLEAN')
    }
    foreach ($count in @(1, 2)) {
        $snapshot.CollectionErrors = @(1..$count | ForEach-Object { [pscustomobject]@{ Section = 'Services'; Error = "fixture failure $_" } })
        $r = Invoke-Fixture $snapshot
        Check "$count real errors fail closed" ($r.Rc -eq 1 -and $r.Diff.Verdict -eq 'INCOMPLETE')
        Check "$count real errors remain flat" (@($r.Diff.AfterCollectionErrors).Count -eq $count -and $r.Diff.AfterCollectionErrors[0].Section -eq 'Services')
    }
} finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force
}
if ($failures) { throw "$failures diff evidence regression(s) failed" }
Write-Host 'PASS: diff evidence regressions'

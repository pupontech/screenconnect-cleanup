# =====================================================================
# Test-SelfTests.ps1 -- invoke each module's self-test / verification entry
# points that exist and fail on any failures reported.
#
# Currently discovers:
#   Scc.Detection -> Invoke-SccDetectionSelfTest
#   (future modules may expose Invoke-Scc*SelfTest or Test-Scc* )
#
# Exit codes: 0 = all self-tests passed or no tests found,
#             1 = any self-test reported failures or threw.
#
# PowerShell 5.1 compatible. Pure ASCII, no BOM.
# =====================================================================
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$scriptRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$srcRoot = Join-Path $scriptRoot 'src'
if (-not (Test-Path -LiteralPath $srcRoot)) {
    Write-Host 'src/ not found.'
    exit 1
}

# Make src discoverable
$sep = [System.IO.Path]::PathSeparator
$env:PSModulePath = $srcRoot + $sep + $env:PSModulePath

# Discover module manifests
$manifests = Get-ChildItem -Path $srcRoot -Recurse -Filter '*.psd1' -File -ErrorAction Stop

$selfTests = @(
    @{ Module = 'Scc.Detection'; Function = 'Invoke-SccDetectionSelfTest' }
    @{ Module = 'Scc.Core'; Function = 'Invoke-SccCoreSelfTest' }
    @{ Module = 'Scc.Evidence'; Function = 'Invoke-SccEvidenceSelfTest' }
    @{ Module = 'Scc.Snapshots'; Function = 'Invoke-SccSnapshotsSelfTest' }
    @{ Module = 'Scc.Tools'; Function = 'Invoke-SccToolsSelfTest' }
    @{ Module = 'Scc.Scanners'; Function = 'Invoke-SccScannersSelfTest' }
    @{ Module = 'Scc.Remedy'; Function = 'Invoke-SccRemedySelfTest' }
    @{ Module = 'Scc.Report'; Function = 'Invoke-SccReportSelfTest' }
    @{ Module = 'Scc.UI'; Function = 'Invoke-SccUISelfTest' }
)

$totalFound = 0
$totalFailed = 0
$reports = @()

foreach ($entry in $selfTests) {
    $modName = $entry.Module
    $fn = $entry.Function
    $manifest = Join-Path $srcRoot $modName "$modName.psd1"
    if (-not (Test-Path -LiteralPath $manifest)) { continue }
    try {
        Import-Module -Name $manifest -Force -ErrorAction Stop
    } catch {
        Write-Host ("SELFTEST: failed to import {0}: {1}" -f $modName, $_.Exception.Message) -ForegroundColor Red
        $totalFailed++
        $reports += ("IMPORT-FAIL: {0} ({1})" -f $modName, $_.Exception.Message)
        continue
    }
    $cmd = Get-Command -Name $fn -ErrorAction SilentlyContinue
    if ($null -eq $cmd) { continue }
    $totalFound++
    Write-Host ("Running self-test: {0} -> {1}" -f $modName, $fn)
    try {
        $failures = & $fn -ErrorAction Stop
        $arr = @($failures)
        # Pester style: empty or $null means pass; non-empty array of strings means failures
        # Some self-tests return $null on success, others empty array.
        $realFailures = @()
        foreach ($f in $arr) {
            if ($null -ne $f -and $f -ne '') { $realFailures += $f }
        }
        if (@($realFailures).Count -gt 0) {
            $totalFailed++
            Write-Host ("  FAIL: {0} reported {1} failure(s)" -f $fn, @($realFailures).Count) -ForegroundColor Red
            foreach ($r in $realFailures) { Write-Host ("    {0}" -f $r) -ForegroundColor Red }
            $reports += ("FAIL: {0} ({1} failures)" -f $fn, @($realFailures).Count)
        } else {
            Write-Host ("  PASS: {0}" -f $fn) -ForegroundColor Green
        }
    } catch {
        $totalFailed++
        Write-Host ("  ERROR: {0} threw: {1}" -f $fn, $_.Exception.Message) -ForegroundColor Red
        $reports += ("ERROR: {0} threw ({1})" -f $fn, $_.Exception.Message)
    }
}

if ($totalFound -eq 0) {
    Write-Host 'No self-test entry points found (modules may not expose one yet) - OK.'
    exit 0
}

Write-Host ("Self-tests done: {0} found, {1} failed." -f $totalFound, $totalFailed)
if ($totalFailed -gt 0) {
    Write-Host 'Self-test failures:'
    foreach ($r in $reports) { Write-Host ("  {0}" -f $r) }
    exit 1
}
exit 0

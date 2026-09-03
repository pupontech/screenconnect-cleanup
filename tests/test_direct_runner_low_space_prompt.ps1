# test_direct_runner_low_space_prompt.ps1 - direct runner low-disk confirmation test.
# Exercises sc-cleanup.ps1 through stdin in WhatIf mode; no vendor actions run.
# PowerShell 5.1 compatible. Pure ASCII, no BOM.
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$runnerPath = Join-Path $repoRoot 'sc-cleanup.ps1'
$psHost = $null
if ($PSVersionTable.PSEdition -eq 'Desktop') {
    $psHost = Join-Path $PSHOME 'powershell.exe'
} else {
    $psHost = (Get-Command pwsh -ErrorAction Stop).Source
}

$probeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('scc-direct-prompt-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $probeRoot -Force
$toolDir = Join-Path $repoRoot 'tools'

$failures = @()
function Check {
    param([string]$Name, [bool]$Condition, [string]$Details)
    if ($Condition) {
        Write-Host ("PASS  " + $Name)
    } else {
        $message = "FAIL  " + $Name
        if ($Details) { $message += " - " + $Details }
        Write-Host $message
        $script:failures += $message
    }
}

function Invoke-RunnerProbe {
    param(
        [string]$Name,
        [int]$MinFreeGB,
        [string]$Answer
    )
    $runRoot = Join-Path $probeRoot $Name
    $arguments = @(
        '-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass',
        '-File', $runnerPath,
        '-WhatIf', '-sr', '-sa', '-avu', '-np',
        '-MinFreeGB', [string]$MinFreeGB,
        '-OutRoot', $runRoot,
        '-ToolDir', $toolDir
    )
    try {
        if ($null -eq $Answer) {
            $output = & $psHost @arguments 2>&1
        } else {
            $output = $Answer | & $psHost @arguments 2>&1
        }
        $rc = $LASTEXITCODE
        return [pscustomobject]@{
            ExitCode = $rc
            Text = ($output -join "`n")
        }
    } finally {
        Remove-Item -LiteralPath $runRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

try {
    # An intentionally impossible threshold forces the actual direct-runner
    # disk check into the operator-confirmation branch on both runtimes.
    $yes = Invoke-RunnerProbe -Name 'yes' -MinFreeGB ([int]::MaxValue) -Answer 'Y'
    Check 'yes continues after low-space confirmation' ($yes.ExitCode -eq 0 -and $yes.Text -match 'PIPELINE COMPLETE') $yes.Text
    Check 'direct prompt reports measured free space' ($yes.Text -match 'Only [0-9]+ GB free on') $yes.Text
    Check 'direct prompt asks whether to continue' ($yes.Text -match '(?i)Continue anyway\? \[y/N\]') $yes.Text

    $yesLong = Invoke-RunnerProbe -Name 'yes-long' -MinFreeGB ([int]::MaxValue) -Answer 'Yes'
    Check 'direct Yes alias continues after low-space confirmation' ($yesLong.ExitCode -eq 0 -and $yesLong.Text -match 'PIPELINE COMPLETE') $yesLong.Text

    $invalid = Invoke-RunnerProbe -Name 'invalid' -MinFreeGB ([int]::MaxValue) -Answer 'maybe'
    Check 'direct invalid answer fails closed' ($invalid.ExitCode -ne 0 -and $invalid.Text -notmatch 'PIPELINE COMPLETE') $invalid.Text

    $no = Invoke-RunnerProbe -Name 'no' -MinFreeGB ([int]::MaxValue) -Answer 'N'
    Check 'no aborts direct runner after low-space confirmation' ($no.ExitCode -ne 0 -and $no.Text -notmatch 'PIPELINE COMPLETE') $no.Text
    Check 'direct no path displays the low-space prompt' ($no.Text -match 'Only [0-9]+ GB free on' -and $no.Text -match '(?i)Continue anyway\? \[y/N\]') $no.Text

    $empty = Invoke-RunnerProbe -Name 'empty' -MinFreeGB ([int]::MaxValue) -Answer ''
    Check 'empty direct answer fails closed' ($empty.ExitCode -ne 0 -and $empty.Text -notmatch 'PIPELINE COMPLETE') $empty.Text

    $normal = Invoke-RunnerProbe -Name 'normal' -MinFreeGB 0 -Answer $null
    Check 'direct runner with sufficient space does not prompt' ($normal.ExitCode -eq 0 -and $normal.Text -match 'PIPELINE COMPLETE' -and $normal.Text -notmatch '(?i)Continue anyway') $normal.Text
} finally {
    Remove-Item -LiteralPath $probeRoot -Recurse -Force -ErrorAction SilentlyContinue
}

if ($failures.Count -gt 0) {
    Write-Host ("$($failures.Count) direct-runner low-space test(s) failed")
    exit 1
}
Write-Host 'ALL DIRECT RUNNER LOW-SPACE PROMPT TESTS PASSED'
exit 0

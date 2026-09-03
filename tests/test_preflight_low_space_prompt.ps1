# test_preflight_low_space_prompt.ps1 - low-disk confirmation regression test.
# Exercises the real preflight process through stdin; no vendor actions run.
# PowerShell 5.1 compatible. Pure ASCII, no BOM.
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$preflightPath = Join-Path $repoRoot 'preflight.ps1'
$psHost = $null
if ($PSVersionTable.PSEdition -eq 'Desktop') {
    $psHost = Join-Path $PSHOME 'powershell.exe'
} else {
    $psHost = (Get-Command pwsh -ErrorAction Stop).Source
}

$probeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('scc-preflight-prompt-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $probeRoot -Force
$toolStub = Join-Path $probeRoot 'toolpack-stub.ps1'
@'
param([switch]$Verify, [switch]$Quiet)
exit 0
'@ | Set-Content -LiteralPath $toolStub -Encoding ASCII

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

function Invoke-PreflightProbe {
    param(
        [string]$Name,
        [int]$MinFreeGB,
        [string]$Answer
    )
    $runRoot = Join-Path $probeRoot $Name
    $arguments = @(
        '-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass',
        '-File', $preflightPath,
        '-np', '-Force',
        '-MinFreeGB', [string]$MinFreeGB,
        '-WorkingRoot', $runRoot,
        '-ToolPackPath', $toolStub
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
    # An intentionally impossible threshold forces the actual disk check to
    # enter the operator-confirmation branch on both Windows and Linux CI.
    $yes = Invoke-PreflightProbe -Name 'yes' -MinFreeGB ([int]::MaxValue) -Answer 'Y'
    Check 'yes continues after low-space confirmation' ($yes.ExitCode -eq 0 -and $yes.Text -match 'PREFLIGHT COMPLETE') $yes.Text
    Check 'prompt reports measured free space' ($yes.Text -match 'Only [0-9]+([.,][0-9]+)? GB free on') $yes.Text
    Check 'prompt asks whether to continue' ($yes.Text -match '(?i)Continue anyway\? \[y/N\]') $yes.Text

    $yesLong = Invoke-PreflightProbe -Name 'yes-long' -MinFreeGB ([int]::MaxValue) -Answer 'Yes'
    Check 'Yes alias continues after low-space confirmation' ($yesLong.ExitCode -eq 0 -and $yesLong.Text -match 'PREFLIGHT COMPLETE') $yesLong.Text

    $invalid = Invoke-PreflightProbe -Name 'invalid' -MinFreeGB ([int]::MaxValue) -Answer 'maybe'
    Check 'invalid answer fails closed' ($invalid.ExitCode -ne 0 -and $invalid.Text -match 'PREFLIGHT FAILED') $invalid.Text

    $no = Invoke-PreflightProbe -Name 'no' -MinFreeGB ([int]::MaxValue) -Answer 'N'
    Check 'no aborts after low-space confirmation' ($no.ExitCode -ne 0 -and $no.Text -match 'PREFLIGHT FAILED') $no.Text
    Check 'no path still displays the low-space prompt' ($no.Text -match 'Only [0-9]+([.,][0-9]+)? GB free on' -and $no.Text -match '(?i)Continue anyway\? \[y/N\]') $no.Text

    $empty = Invoke-PreflightProbe -Name 'empty' -MinFreeGB ([int]::MaxValue) -Answer ''
    Check 'empty answer fails closed' ($empty.ExitCode -ne 0 -and $empty.Text -match 'PREFLIGHT FAILED') $empty.Text

    $normal = Invoke-PreflightProbe -Name 'normal' -MinFreeGB 0 -Answer $null
    Check 'sufficient space does not prompt' ($normal.ExitCode -eq 0 -and $normal.Text -match 'PREFLIGHT COMPLETE' -and $normal.Text -notmatch '(?i)continue') $normal.Text
} finally {
    Remove-Item -LiteralPath $probeRoot -Recurse -Force -ErrorAction SilentlyContinue
}

if ($failures.Count -gt 0) {
    Write-Host ("$($failures.Count) low-space prompt test(s) failed")
    exit 1
}
Write-Host 'ALL PREFLIGHT LOW-SPACE PROMPT TESTS PASSED'
exit 0

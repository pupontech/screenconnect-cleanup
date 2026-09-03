# test_review_wrapper_low_space_prompt.ps1 - wrapper low-disk confirmation test.
# Exercises Invoke-ReviewAndRemove.ps1 with synthetic findings and WhatIfOnly.
# No vendor executable or removal engine is launched. PowerShell 5.1 compatible.
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$reviewPath = Join-Path $repoRoot 'Invoke-ReviewAndRemove.ps1'
$psHost = $null
if ($PSVersionTable.PSEdition -eq 'Desktop') {
    $psHost = Join-Path $PSHOME 'powershell.exe'
} else {
    $psHost = (Get-Command pwsh -ErrorAction Stop).Source
}

$probeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('scc-review-prompt-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $probeRoot -Force
$findingsPath = Join-Path $probeRoot 'findings.json'
$findings = [ordered]@{
    RunId = 'synthetic-review-run'
    ComputerName = 'synthetic-host'
    ScreenConnect = [ordered]@{
        Instances = @(
            [ordered]@{
                Identifier = 'synthetic-instance'
                InstallDir = 'C:\Program Files\ScreenConnect'
                ServiceName = 'ScreenConnect'
                RelayHost = 'relay.example.test'
                SessionType = 'Cloud'
                DisplayVersion = '1.0'
                Publisher = 'ConnectWise'
            }
        )
    }
}
$findings | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $findingsPath -Encoding ASCII

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

function Invoke-ReviewProbe {
    param(
        [string]$Name,
        [int]$MinFreeGB,
        [string]$AnswerLines
    )
    $workDir = Join-Path $probeRoot $Name
    $arguments = @(
        '-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass',
        '-File', $reviewPath,
        '-FindingsJson', $findingsPath,
        '-WorkDir', $workDir,
        '-MinFreeGB', [string]$MinFreeGB,
        '-WhatIfOnly'
    )
    try {
        $inputLines = $AnswerLines -split "`n"
        $output = $inputLines | & $psHost @arguments 2>&1
        return [pscustomobject]@{
            ExitCode = $LASTEXITCODE
            Text = ($output -join "`n")
        }
    } finally {
        Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

try {
    $yes = Invoke-ReviewProbe -Name 'yes' -MinFreeGB ([int]::MaxValue) -AnswerLines "Y`nY`nY"
    Check 'wrapper Y continues after low-space confirmation' ($yes.ExitCode -eq 0 -and $yes.Text -match '(?i)Continue anyway\? \[y/N\]' -and $yes.Text -match '-WhatIfOnly') $yes.Text
    Check 'wrapper low-space prompt reports measured free space' ($yes.Text -match 'Only [0-9]+ GB free on') $yes.Text

    $yesLong = Invoke-ReviewProbe -Name 'yes-long' -MinFreeGB ([int]::MaxValue) -AnswerLines "Y`nY`nYes"
    Check 'wrapper Yes alias continues after low-space confirmation' ($yesLong.ExitCode -eq 0 -and $yesLong.Text -match '(?i)Continue anyway\? \[y/N\]') $yesLong.Text

    $no = Invoke-ReviewProbe -Name 'no' -MinFreeGB ([int]::MaxValue) -AnswerLines "Y`nY`nN"
    Check 'wrapper N aborts after low-space confirmation' ($no.ExitCode -ne 0 -and $no.Text -match '(?i)Continue anyway\? \[y/N\]') $no.Text

    $invalid = Invoke-ReviewProbe -Name 'invalid' -MinFreeGB ([int]::MaxValue) -AnswerLines "Y`nY`nmaybe"
    Check 'wrapper invalid answer fails closed' ($invalid.ExitCode -ne 0 -and $invalid.Text -match '(?i)Continue anyway\? \[y/N\]') $invalid.Text
} finally {
    Remove-Item -LiteralPath $probeRoot -Recurse -Force -ErrorAction SilentlyContinue
}

if ($failures.Count -gt 0) {
    Write-Host ("$($failures.Count) review-wrapper low-space test(s) failed")
    exit 1
}
Write-Host 'ALL REVIEW-WRAPPER LOW-SPACE PROMPT TESTS PASSED'
exit 0

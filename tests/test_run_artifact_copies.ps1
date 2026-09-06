# test_run_artifact_copies.ps1 - run-folder transcript copy + Desktop report
# copy regression test (owner directive 2026-09-06).
#
# Exercises the REAL detect-remote-access.ps1 through its -SelfTest path with
# a fake USERPROFILE, so the console transcript is created on a controlled
# "Desktop" and the finally-block copy (-TranscriptCopyDir) is observable
# without touching a live machine or any real user profile. Verifies:
#   1. the transcript's Desktop original is preserved,
#   2. a copy lands in the -TranscriptCopyDir folder as detect-remote-access.log
#      with identical content (no silent empty/partial copy),
#   3. a failed copy is reported loudly (never silently swallowed) while the
#      run itself still reports success (the transcript still exists),
#   4. the run reports the successful copy path on stdout.
# The START-HERE.bat / sc-cleanup.ps1 wiring for both copies is asserted by
# tests/ci/Test-PipelineLauncherContracts.ps1 (C11/C12).
# PowerShell 5.1 compatible. Pure ASCII, no BOM.
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$detectPath = Join-Path $repoRoot 'detect-remote-access.ps1'
$psHost = $null
if ($PSVersionTable.PSEdition -eq 'Desktop') {
    $psHost = Join-Path $PSHOME 'powershell.exe'
} else {
    $psHost = (Get-Command pwsh -ErrorAction Stop).Source
}

$probeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('rit-scc-artifact-copies-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $probeRoot -Force
$profileDir = Join-Path $probeRoot 'userprofile'
$desktopDir = Join-Path $profileDir 'Desktop'
$null = New-Item -ItemType Directory -Path $desktopDir -Force

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

function Invoke-DetectProbe {
    param([string]$TranscriptCopyDir)
    $arguments = @(
        '-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass',
        '-File', $detectPath,
        '-SelfTest', '-NoPause'
    )
    if ($TranscriptCopyDir) { $arguments += @('-TranscriptCopyDir', $TranscriptCopyDir) }
    $savedUserProfile = $env:USERPROFILE
    try {
        $env:USERPROFILE = $profileDir
        $output = & $psHost @arguments 2>&1
        $rc = $LASTEXITCODE
        return [pscustomobject]@{
            ExitCode = $rc
            Text = ($output -join "`n")
        }
    } finally {
        $env:USERPROFILE = $savedUserProfile
    }
}

function Get-DesktopTranscript {
    $item = Get-ChildItem -LiteralPath $desktopDir -Filter 'detect-remote-access_*.log' -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
    return $item
}

try {
    # --- Success path: copy lands in the run folder, original preserved ----
    $runRoot = Join-Path $probeRoot 'runroot'
    $null = New-Item -ItemType Directory -Path $runRoot -Force
    $ok = Invoke-DetectProbe -TranscriptCopyDir $runRoot
    Check 'self-test run exits 0' ($ok.ExitCode -eq 0) ("exit=" + $ok.ExitCode)
    Check 'run reports the transcript copy' ($ok.Text -match 'Transcript copy:') $ok.Text
    Check 'run names the run-folder copy path' ($ok.Text -match [regex]::Escape((Join-Path $runRoot 'detect-remote-access.log'))) $ok.Text

    $sourceLog = Get-DesktopTranscript
    Check 'transcript original stays on the Desktop' ($null -ne $sourceLog) 'no Desktop detect-remote-access_*.log was produced'
    $copyLog = Join-Path $runRoot 'detect-remote-access.log'
    Check 'run-folder copy exists' (Test-Path -LiteralPath $copyLog) $copyLog
    if ($sourceLog -and (Test-Path -LiteralPath $copyLog)) {
        $sourceText = Get-Content -LiteralPath $sourceLog.FullName -Raw
        $copyText = Get-Content -LiteralPath $copyLog -Raw
        Check 'run-folder copy content matches the original' ($copyText -eq $sourceText) "source=$($sourceLog.FullName) copy=$copyLog"
        Check 'copy is not empty' ($copyText.Length -gt 0) 'transcript copy is empty'
    }

    # --- Failure path: copy failure is loud but the run still succeeds ------
    $blocker = Join-Path $probeRoot 'blocker-file'
    Set-Content -LiteralPath $blocker -Value 'not a directory' -Encoding ASCII
    $fail = Invoke-DetectProbe -TranscriptCopyDir $blocker
    Check 'failed copy keeps self-test exit 0' ($fail.ExitCode -eq 0) ("exit=" + $fail.ExitCode)
    Check 'failed copy is reported loudly' ($fail.Text -match 'Could not copy the transcript log') $fail.Text
} finally {
    Remove-Item -LiteralPath $probeRoot -Recurse -Force -ErrorAction SilentlyContinue
}

if ($failures.Count -gt 0) {
    Write-Host ("$($failures.Count) run-artifact-copies test(s) failed")
    exit 1
}
Write-Host 'ALL RUN-ARTIFACT-COPY TESTS PASSED'
exit 0

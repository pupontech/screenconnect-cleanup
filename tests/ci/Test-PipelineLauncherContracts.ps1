# =====================================================================
# Test-PipelineLauncherContracts.ps1 -- CI contract gate for the
# pipeline launcher lane (task: truthful outcomes + robust batch
# self-elevation).
#
# Contracts under test (non-destructive; source-level checks only,
# never any vendor executable):
#   C1. sc-cleanup.ps1 must NOT finish with "All stages executed
#       successfully." plus exit 0 when remove-screenconnect.ps1
#       returned a nonzero exit code. It must report an incomplete
#       pipeline and propagate a nonzero exit code, while still
#       producing post-removal evidence (manifest/diff/report).
#   C2. sc-cleanup.ps1 must fail closed BEFORE a destructive Stage 4
#       execution when the Stage 0 restore point failed, unless the
#       operator explicitly passed -np (-NoRestorePoint). Read-only /
#       dry-run paths stay unaffected.
#   C3. Every self-elevating .bat launcher must build its elevated
#       relaunch from an environment variable (apostrophe-safe), NOT
#       from a single-quoted literal like '%~f0', and must surface a
#       useful error when elevation cannot be launched/cancelled
#       instead of exiting silently.
#   C4. Touched .bat files are pure ASCII, no BOM, CRLF line endings.
#   C5. The last step opens the report folder (Explorer) and the report
#       itself (default browser) - in START-HERE.bat Step 10 and in
#       sc-cleanup.ps1 Stage 9 (owner directive 2026-08-27).
#   C6. collect-snapshot.ps1 collects sections in concurrent GROUPS
#       (-Sections mode, Invoke-SectionGroups) and shows a live progress
#       ticker that is not gated by -Quiet (owner directive 2026-08-28).
#
# Exit codes: 0 = all contracts hold, 1 = violations found.
# PowerShell 5.1 compatible. Pure ASCII, no BOM.
# =====================================================================
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$failures = @()

function Add-Failure {
    param([string]$Contract, [string]$Message)
    $script:failures += ("[{0}] {1}" -f $Contract, $Message)
}

function Read-AsciiText {
    param([string]$Path)
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    return [System.Text.Encoding]::ASCII.GetString($bytes)
}

# --- C1: truthful pipeline outcome -----------------------------------------
$cleanupPath = Join-Path $repoRoot 'sc-cleanup.ps1'
$cleanup = Read-AsciiText $cleanupPath

if ($cleanup -match '(?m)All stages executed successfully\.') {
    # The success line may exist, but only acceptable if the script can
    # still report failure and return nonzero afterwards. Require both:
    # a failure summary marker AND an explicit nonzero exit path that is
    # reachable after the success line is evaluated.
    if ($cleanup -notmatch 'PIPELINE COMPLETED WITH ERRORS') {
        Add-Failure 'C1' ("sc-cleanup.ps1 never reports 'PIPELINE COMPLETED WITH ERRORS' - a nonzero remove-screenconnect exit still ends as a claimed success.")
    }
    if ($cleanup -notmatch '(?ms)PIPELINE COMPLETED WITH ERRORS.*?exit 1') {
        Add-Failure 'C1' "sc-cleanup.ps1 does not return a nonzero exit code after reporting pipeline errors."
    }
    # The final exit decision must consult the recorded removal exit code.
    if ($cleanup -notmatch 'RemovalExitCode') {
        Add-Failure 'C1' "sc-cleanup.ps1 does not carry the remove-screenconnect exit code (RemovalExitCode) out of Stage 4."
    }
    # The ExitCode read must be StrictMode-safe: a WhatIf/skipped Stage 4
    # payload has no ExitCode, and direct property access throws
    # PropertyNotFoundStrict on Windows PowerShell 5.1.
    if ($cleanup -notmatch 'Contains\(''ExitCode''\)') {
        Add-Failure 'C1' "sc-cleanup.ps1 reads the Stage 4 ExitCode without a StrictMode-safe Contains guard (WhatIf runs would throw PropertyNotFoundStrict and exit nonzero)."
    }
} else {
    Add-Failure 'C1' "sc-cleanup.ps1 lost its completion banner; verify outcome reporting was not broken."
}

# --- C2: restore point fail-closed gate before destructive Stage 4 --------
# Stage 0 must record restore-point failure...
if ($cleanup -notmatch 'RestorePointFailed') {
    Add-Failure 'C2' "sc-cleanup.ps1 does not record restore-point failure state (RestorePointFailed)."
}
# ...and Stage 4 must refuse destructive execution when it failed and -np
# was not explicitly passed.
$stage4Gate = [regex]::Match($cleanup, '(?ms)-StageId 4 .*?(?=-StageId 5 )')
if (-not $stage4Gate.Success) {
    Add-Failure 'C2' "Could not locate the Stage 4 block in sc-cleanup.ps1."
} else {
    if ($stage4Gate.Value -notmatch 'RestorePointFailed') {
        Add-Failure 'C2' "Stage 4 does not check RestorePointFailed before executing - restore-point failure cannot fail the run closed."
    }
    if ($stage4Gate.Value -notmatch '\$np') {
        Add-Failure 'C2' "Stage 4 fail-closed gate does not honor explicit -np (-NoRestorePoint)."
    }
    # Operator correction: Invoke-Stage rethrows, so the gate must NOT throw -
    # it records a blocked result (nonzero code) and returns normally so
    # Stages 5-8 still produce evidence.
    if ($stage4Gate.Value -notmatch 'RestorePointBlocked') {
        Add-Failure 'C2' "Stage 4 does not record a RestorePointBlocked result - a failed restore point cannot fail the run closed without aborting the evidence chain."
    }
}

# --- C5: truthful preflight admin log ---------------------------------------
if ($cleanup -match '(?m)Write-StageLog "Admin check: PASSED"') {
    Add-Failure 'C5' "Stage 0 logs 'Admin check: PASSED' unconditionally - must reflect the actual admin state (Admin check: PASSED/FAILED)."
}

# --- C3: apostrophe-safe, failure-aware batch self-elevation ---------------
$launchers = @('START-HERE.bat', 'RUN-REMOVAL-TEST.bat', 'Run-DetectRemoteAccess.bat')
foreach ($name in $launchers) {
    $path = Join-Path $repoRoot $name
    if (-not (Test-Path $path)) {
        Add-Failure 'C3' ("{0} missing from repo root." -f $name)
        continue
    }
    $bat = Read-AsciiText $path

    if ($bat -match "-FilePath '%~f0'") {
        Add-Failure 'C3' ("{0}: elevated relaunch uses single-quoted '%~f0' literal - breaks on paths containing apostrophes." -f $name)
    }
    if ($bat -notmatch '\$env:SCC_SELF') {
        Add-Failure 'C3' ("{0}: elevated relaunch does not pass the script path through the SCC_SELF environment variable (apostrophe-safe)." -f $name)
    }
    if ($bat -notmatch 'set "?SCC_SELF=?=%~f0"?') {
        Add-Failure 'C3' ("{0}: SCC_SELF is never populated from %%~f0." -f $name)
    }
    # Elevation failure must be visible, not swallowed by >nul 2>&1 + bare exit.
    $elevBlock = [regex]::Match($bat, '(?ms)fltmc\.exe.*?\r?\n\)\r?\n')
    if (-not $elevBlock.Success) {
        Add-Failure 'C3' ("{0}: could not locate the fltmc self-elevation block." -f $name)
    } else {
        if ($elevBlock.Value -match '>nul 2>&1\s*\r?\n\s*exit /b\s*$') {
            Add-Failure 'C3' ("{0}: elevation attempt is silenced with >nul 2>&1 and a silent 'exit /b' - a cancelled/blocked UAC prompt leaves no error." -f $name)
        }
        if ($elevBlock.Value -notmatch 'errorlevel') {
            Add-Failure 'C3' ("{0}: elevation block does not check errorlevel after the relaunch attempt." -f $name)
        }
        if ($elevBlock.Value -notmatch 'pause') {
            Add-Failure 'C3' ("{0}: elevation failure path does not pause, so the window closes before the technician can read it." -f $name)
        }
    }
}

# Run-DetectRemoteAccess.bat forwards arguments; they must also travel via
# the environment rather than a single-quoted '%*' literal.
$rdr = Read-AsciiText (Join-Path $repoRoot 'Run-DetectRemoteAccess.bat')
if ($rdr -match "'%*'") {
    Add-Failure 'C3' "Run-DetectRemoteAccess.bat: forwarded arguments use a single-quoted '%*' literal - unsafe with apostrophes in arguments."
}
if ($rdr -match '-ArgumentList' -and $rdr -notmatch '\$env:SCC_ARGS') {
    Add-Failure 'C3' "Run-DetectRemoteAccess.bat: forwarded arguments do not travel via the SCC_ARGS environment variable."
}

# --- C4: touched .bat files are pure ASCII, no BOM, CRLF -------------------
foreach ($name in $launchers) {
    $path = Join-Path $repoRoot $name
    if (-not (Test-Path $path)) { continue }
    $bytes = [System.IO.File]::ReadAllBytes($path)
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        Add-Failure 'C4' ("{0}: file starts with a UTF-8 BOM." -f $name)
    }
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        if ($bytes[$i] -gt 127) {
            Add-Failure 'C4' ("{0}: non-ASCII byte 0x{1:X2} at offset {2}." -f $name, $bytes[$i], $i)
            break
        }
    }
    $text = [System.Text.Encoding]::ASCII.GetString($bytes)
    $lfCount = ([regex]::Matches($text, "(?<!`r)`n")).Count
    if ($lfCount -gt 0) {
        Add-Failure 'C4' ("{0}: {1} lone LF line ending(s) found - .bat files must use CRLF." -f $name, $lfCount)
    }
}

# --- C5: report auto-open at the end of a run --------------------------------
# Owner directive 2026-08-27: the last step opens the report folder (Explorer)
# and the report itself (default browser). Both the guided runner (START-HERE
# Step 9) and the orchestrator (sc-cleanup.ps1 Stage 9) must do it.
$startHereBat = Read-AsciiText (Join-Path $repoRoot 'START-HERE.bat')
if ($startHereBat -notmatch '(?i)explorer /select,[^\r\n]*report\.html') {
    Add-Failure 'C5' "START-HERE.bat Step 9 does not open the current-run report folder (explorer /select)."
}
if ($startHereBat -notmatch '(?i)start "" [^\r\n]*report\.html') {
    Add-Failure 'C5' "START-HERE.bat Step 9 does not open the current-run report itself (start report.html)."
}
if ($cleanup -notmatch 'explorer\.exe') {
    Add-Failure 'C5' "sc-cleanup.ps1 Stage 9 does not open the report folder via explorer.exe."
}
if ($cleanup -notmatch 'Start-Process -FilePath \$reportHtml') {
    Add-Failure 'C5' "sc-cleanup.ps1 Stage 9 does not open the report itself (Start-Process reportHtml)."
}

# --- C6: snapshot group concurrency + live progress --------------------------
# Owner directive 2026-08-28: speed up the before/after snapshots further and
# show progress in the cmd window. collect-snapshot.ps1 must collect sections
# in concurrent groups (-Sections mode) and tick a visible progress line that
# is NOT gated by -Quiet (the guided runner passes -Quiet).
$snap = Read-AsciiText (Join-Path $repoRoot 'collect-snapshot.ps1')
if ($snap -notmatch '\[string\]\$Sections') {
    Add-Failure 'C6' "collect-snapshot.ps1 missing the -Sections group-collection parameter."
}
if ($snap -notmatch 'Sections = \$map') {
    Add-Failure 'C6' "collect-snapshot.ps1 does not emit the {Sections} group envelope."
}
if ($snap -notmatch 'Invoke-SectionGroups') {
    Add-Failure 'C6' "collect-snapshot.ps1 missing the concurrent group runner (Invoke-SectionGroups)."
}
if ($snap -notmatch 'Write-Tick') {
    Add-Failure 'C6' "collect-snapshot.ps1 missing the live progress ticker (Write-Tick)."
}
if ($snap -notmatch '\[snapshot " \+ \$Label') {
    Add-Failure 'C6' "collect-snapshot.ps1 progress ticker does not label before/after."
}

# --- C7: debug logger (v1.7.26) ----------------------------------------------
# -Debug must start a console transcript to <WorkDir>\logs\debug.log so field
# debugging is one file; an unhandled error must be named with its source
# location and exit truthfully (never a silent death).
$cleanupDbg = Read-AsciiText (Join-Path $repoRoot 'sc-cleanup.ps1')
if ($cleanupDbg -notmatch '\[switch\]\$Debug') {
    Add-Failure 'C7' "sc-cleanup.ps1 missing the -Debug switch."
}
if ($cleanupDbg -notmatch 'Start-Transcript -Path \$DebugLogPath') {
    Add-Failure 'C7' "sc-cleanup.ps1 -Debug does not start the console transcript (Start-Transcript DebugLogPath)."
}
if ($cleanupDbg -notmatch 'trap \{') {
    Add-Failure 'C7' "sc-cleanup.ps1 missing the unhandled-error trap that names the failure with source location."
}
if ($cleanupDbg -notmatch 'UNHANDLED ERROR') {
    Add-Failure 'C7' "sc-cleanup.ps1 unhandled-error trap does not log the UNHANDLED ERROR marker."
}
$preflightDbg = Read-AsciiText (Join-Path $repoRoot 'preflight.ps1')
if ($preflightDbg -notmatch '\[CmdletBinding\(\)\]') {
    Add-Failure 'C7' "preflight.ps1 must use CmdletBinding so the built-in -Debug common parameter is available."
}
if ($preflightDbg -match '(?m)^\s*\[switch\]\$Debug\s*,?\s*$') {
    Add-Failure 'C7' "preflight.ps1 redeclares the built-in -Debug common parameter, causing ParameterNameAlreadyExistsForCommand."
}
if ($preflightDbg -notmatch 'Start-Transcript -Path \$debugLogPath') {
    Add-Failure 'C7' "preflight.ps1 -Debug does not start the console transcript (Start-Transcript debugLogPath)."
}

# --- C8: preflight invocation must bind and reach its self-test -------------
# CmdletBinding automatically supplies the common -Debug switch. A duplicate
# explicit declaration fails during parameter metadata construction, before any
# UAC or self-test logic runs. Exercise the actual child invocation so this
# contract catches that runtime-only failure rather than just checking text.
$preflightPath = Join-Path $repoRoot 'preflight.ps1'
$psHost = $null
if ($PSVersionTable.PSEdition -eq 'Desktop') {
    $psHost = Join-Path $PSHOME 'powershell.exe'
} else {
    $psHost = (Get-Command pwsh -ErrorAction Stop).Source
}
$preflightOutput = & $psHost -NoProfile -File $preflightPath -SelfTest 2>&1
$preflightRc = $LASTEXITCODE
if ($preflightRc -ne 0 -or ($preflightOutput -notmatch 'SELFTEST OK')) {
    Add-Failure 'C8' ("preflight.ps1 -SelfTest did not execute successfully (exit {0}). Output: {1}" -f $preflightRc, ($preflightOutput -join ' | '))
}

# --- C9: preflight without -Debug must not read an unbound variable ---------
# The common -Debug parameter is present in PSBoundParameters only when passed;
# StrictMode must therefore not evaluate a bare $Debug variable on a normal run.
$debugProbeRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('rit-scc-preflight-debug-' + [guid]::NewGuid().ToString('N'))
try {
    $null = New-Item -ItemType Directory -Path $debugProbeRoot -Force
    $toolStub = Join-Path $debugProbeRoot 'toolpack-stub.ps1'
    @'
param([switch]$Verify, [switch]$Quiet)
exit 0
'@ | Set-Content -Path $toolStub -Encoding ASCII
    $probeRunRoot = Join-Path $debugProbeRoot 'run'
    $probeOutput = & $psHost -NoProfile -File $preflightPath -np -Force -MinFreeGB 0 -WorkingRoot $probeRunRoot -ToolPackPath $toolStub 2>&1
    $probeRc = $LASTEXITCODE
    if ($probeRc -ne 0 -and ($probeOutput -match '\$Debug.*has not been set')) {
        Add-Failure 'C9' ("preflight.ps1 normal run reads unbound `$Debug under StrictMode (exit {0})." -f $probeRc)
    } elseif ($probeRc -ne 0) {
        Add-Failure 'C9' ("preflight.ps1 safe no- Debug probe failed for another reason (exit {0}). Output: {1}" -f $probeRc, ($probeOutput -join ' | '))
    }
} catch {
    Add-Failure 'C9' ("preflight.ps1 safe no- Debug probe could not run: {0}" -f $_.Exception.Message)
} finally {
    Remove-Item -LiteralPath $debugProbeRoot -Recurse -Force -ErrorAction SilentlyContinue
}

if ($failures.Count -gt 0) {
    Write-Host ""
    Write-Host ("FAIL: {0} contract violation(s):" -f $failures.Count) -ForegroundColor Red
    foreach ($f in $failures) { Write-Host ("  " + $f) -ForegroundColor Red }
    exit 1
}

Write-Host "PASS: all pipeline-launcher contracts hold."
exit 0

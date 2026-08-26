@echo off
rem ============================================================================
rem  START-HERE.bat - one-by-one guided runner for the ScreenConnect Cleanup Tool
rem  Walks the technician through each step in order, prompting before each one.
rem  Steps 1-4 and 8-9 are read-only. Step 5 REMOVES ScreenConnect (asks first,
rem  and requires a typed confirmation). Step 7 is an opt-in destructive tool.
rem  Self-elevates. Pure ASCII, no BOM.
rem ============================================================================

setlocal EnableDelayedExpansion
title ScreenConnect Cleanup Tool

rem ---- Self-elevate: relaunch as admin automatically if not already --------
rem The script path travels via the SCC_SELF environment variable so that
rem apostrophes (and other quotes) in the path cannot break the PowerShell
rem command line. A failed/cancelled UAC prompt must be visible, never silent.
set "SCC_SELF=%~f0"
fltmc.exe >nul 2>&1
if %errorlevel% neq 0 (
    echo  Requesting administrator privileges...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath $env:SCC_SELF -Verb RunAs"
    if errorlevel 1 (
        echo.
        echo  [ERROR] Elevation could not be launched or was cancelled.
        echo          Re-run this script from an elevated command prompt.
        pause
        exit /b 1
    )
    exit /b
)
set "SCC_SELF="

cd /d "%~dp0"

echo.
echo  ============================================================
echo   SCREENCONNECT CLEANUP TOOL - guided run
echo   You will be prompted before each step. Ctrl+C to abort.
echo.
echo   1 toolpack     2 preflight    3 before-snapshot
echo   4 detection    5 REMOVE       6 antivirus scans
echo   7 tikun        8 after-snapshot+diff            9 report
echo  ============================================================
echo.

rem ---- Step 1: tool pack -----------------------------------------------------
echo  STEP 1 of 9: Build/verify tool pack (Sysinternals + KVRT/ESET/Malwarebytes)
set /p GO="    Run now? [Y/n] "
if /i not "%GO%"=="n" (
    if exist "%~dp0tools\Get-ToolPack.ps1" (
        powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\Get-ToolPack.ps1"
        powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\Get-ToolPack.ps1" -Verify
    ) else (
        echo     [WARN] tools\Get-ToolPack.ps1 missing - skipping pack.
    )
    if exist "%~dp0tools\Get-AVTools.ps1" (
        powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\Get-AVTools.ps1" -ToolDir "%~dp0tools\AV"
    ) else (
        echo     [WARN] tools\Get-AVTools.ps1 missing - skipping AV scanner staging.
    )
)
set GO=

rem ---- Step 2: preflight -----------------------------------------------------
echo.
echo  STEP 2 of 9: Preflight checks (admin, UAC, disk, working dir; restore point)
set /p GO="    Run now? [Y/n] "
if /i not "%GO%"=="n" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0preflight.ps1"
)
set GO=

rem ---- Step 3: BEFORE snapshot -----------------------------------------------
echo.
echo  STEP 3 of 9: BEFORE snapshot (baseline; step 8 diffs against this)
set /p GO="    Run now? [Y/n] "
if /i not "%GO%"=="n" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0collect-snapshot.ps1" -Label before -OutFile "%~dp0snapshot_before.json" -Quiet
    if exist "%~dp0snapshot_before.json" (
        echo     [i] Baseline saved.
    ) else (
        echo     [WARN] Baseline was NOT written - step 8 will skip the diff.
    )
)
set GO=

rem ---- Step 4: detection -----------------------------------------------------
echo.
echo  STEP 4 of 9: Remote-access detection (read-only)
set /p GO="    Full scan of all known targets? [y/N] "
if /i "%GO%"=="y" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0detect-remote-access.ps1" -All -NoPause
) else (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0detect-remote-access.ps1" -NoPause
)
set GO=
set "FINDINGS_JSON="
rem dir /b prints only the bare filename, so walk the timestamped folders
rem newest-first instead and keep the FULL path to the file.
for /f "delims=" %%D in ('dir /b /ad /o-d "%USERPROFILE%\Desktop\RemoteAccessScan\*_*" 2^>nul') do (
    if not defined FINDINGS_JSON if exist "%USERPROFILE%\Desktop\RemoteAccessScan\%%D\findings.json" (
        set "FINDINGS_JSON=%USERPROFILE%\Desktop\RemoteAccessScan\%%D\findings.json"
    )
)
if not defined FINDINGS_JSON (
    echo     [i] No findings.json found - steps 5 and 9 need it.
) else (
    echo     [i] Latest findings: !FINDINGS_JSON!
)

rem ---- Step 5: REVIEW + REMOVE ------------------------------------------------
echo.
echo  STEP 5 of 9: Review detected ScreenConnect and REMOVE the approved ones
echo    This is the step that removes ScreenConnect. KEEP is the default - type y
echo    for each instance you actually want to remove. Files are quarantined,
echo    never deleted, and every action is recorded in removal-manifest.json.
set /p GO="    Run removal review now? [Y/n] "
if /i not "%GO%"=="n" (
    if exist "%~dp0Invoke-ReviewAndRemove.ps1" (
        if defined FINDINGS_JSON (
            powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Invoke-ReviewAndRemove.ps1" -FindingsJson "!FINDINGS_JSON!"
        ) else (
            powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Invoke-ReviewAndRemove.ps1"
        )
    ) else (
        echo     [WARN] Invoke-ReviewAndRemove.ps1 missing - cannot remove.
    )
)
set GO=

rem ---- Step 6: antivirus scans - each one is its own step ---------------------
echo.
echo  STEP 6 of 9: Antivirus scans. Each scanner is asked for separately and
echo    runs to completion before the next one starts.

echo.
echo    -- 6a: Microsoft Defender (built in) --
set /p GO="    Run Defender scan? [Y/n] "
if /i not "%GO%"=="n" (
    set /p DRY="       Dry-run only (just print the command line)? [y/N] "
    if /i "!DRY!"=="y" (
        powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scanners\Invoke-DefenderScan.ps1" -WhatIf
    ) else (
        echo        Running Defender scan - this can take a while.
        powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scanners\Invoke-DefenderScan.ps1"
    )
    set DRY=
)
set GO=

echo.
echo    -- 6b: Kaspersky Virus Removal Tool (KVRT), interactive GUI --
set /p GO="    Launch KVRT? [Y/n] "
if /i not "%GO%"=="n" (
    if exist "%~dp0tools\AV\KVRT.exe" (
        echo        Launching KVRT. Accept the EULA, run the scan, and review
        echo        anything it finds in the KVRT window.
        start "" "%~dp0tools\AV\KVRT.exe"
        echo.
        echo        This script is WAITING for you. Do not press anything here
        echo        until the KVRT scan has finished.
        pause
    ) else (
        echo        [WARN] tools\AV\KVRT.exe not staged - run step 1 first.
    )
)
set GO=

echo.
echo    -- 6c: ESET Online Scanner (interactive GUI) --
set /p GO="    Launch ESET Online Scanner? [y/N] "
if /i "%GO%"=="y" (
    if exist "%~dp0tools\AV\esetonlinescanner.exe" (
        echo        Launching ESET Online Scanner. Run the scan in its window.
        start "" "%~dp0tools\AV\esetonlinescanner.exe"
        echo.
        echo        This script is WAITING for you. Do not press anything here
        echo        until the ESET scan has finished.
        pause
    ) else (
        echo        [WARN] tools\AV\esetonlinescanner.exe not staged - run step 1 first.
    )
)
set GO=

echo.
echo    -- 6d: Malwarebytes (interactive GUI) --
set /p GO="    Launch Malwarebytes installer/scanner? [y/N] "
if /i "%GO%"=="y" (
    if exist "%~dp0tools\AV\MBSetup.exe" (
        echo        Launching Malwarebytes. Install if prompted, then run a scan.
        echo        NOTE: MBSetup.exe is an installer - it exits long before
        echo        the scan finishes, which is why this waits for you
        echo        rather than for the process.
        start "" "%~dp0tools\AV\MBSetup.exe"
        echo.
        echo        This script is WAITING for you. Do not press anything here
        echo        until the Malwarebytes scan has finished.
        pause
    ) else (
        echo        [WARN] tools\AV\MBSetup.exe not staged - run step 1 first.
    )
)
set GO=

rem ---- Step 7: Tikun (OPT-IN - destructive, deletes without quarantine) --------
echo.
echo  STEP 7 of 9: Tikun ^(the general fix - tools\GeneralFix\^)
echo    Note: Tikun kills processes and DELETES files, folders and registry
echo    Run-keys system-wide, including removable drives, without quarantine.
echo    It also installs a scheduled task that reruns it at boot and on USB
echo    insertion. This is the ONLY step here that deletes instead of
echo    quarantines - type y to run it, Enter or n skips it.
set /p GO="    Run Tikun now? [y/N] "
if /i "%GO%"=="y" (
    set "GFIX_SCRIPT="
    for %%S in ("%~dp0tools\GeneralFix\*.bat") do if not defined GFIX_SCRIPT set "GFIX_SCRIPT=%%~fS"
    if defined GFIX_SCRIPT (
        call "!GFIX_SCRIPT!"
    ) else (
        echo     [WARN] No .bat found under tools\GeneralFix\ - skipping Tikun.
    )
    set GFIX_SCRIPT=
)
set GO=

rem ---- Step 8: AFTER snapshot + diff ------------------------------------------
echo.
echo  STEP 8 of 9: After-snapshot and diff vs the before-snapshot
set /p GO="    Run now? [Y/n] "
if /i not "%GO%"=="n" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0collect-snapshot.ps1" -Label after -OutFile "%~dp0snapshot_after.json" -Quiet
    rem Only diff when the baseline from step 3 actually exists - otherwise
    rem diff-snapshots.ps1 dumps a raw PowerShell error at the technician.
    if not exist "%~dp0snapshot_before.json" (
        echo     [WARN] No snapshot_before.json - step 3 was skipped, so there is
        echo         nothing to diff against. Skipping the diff.
    ) else (
        if not exist "%~dp0snapshot_after.json" (
            echo     [WARN] After-snapshot was not written - skipping the diff.
        ) else (
            powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0diff-snapshots.ps1" -BeforeFile "%~dp0snapshot_before.json" -AfterFile "%~dp0snapshot_after.json" -OutFile "%~dp0snapshot_diff.json"
            rem exit 1 from diff = RESURRECTION detected, a finding not a failure
            if errorlevel 2 (
                echo     [WARN] Diff failed to run.
            ) else if errorlevel 1 (
                echo     [WARN] RESURRECTION DETECTED - removed items came back. See snapshot_diff.json
            ) else (
                echo     [i] Diff clean - nothing resurrected.
            )
        )
    )
)
set GO=

rem ---- Step 9: report ----------------------------------------------------------
echo.
echo  STEP 9 of 9: Generate the investigation report
if not defined FINDINGS_JSON (
    echo     [WARN] No findings.json available. Detection ^(step 4^) must run first,
    echo         or enter the full path to an existing findings.json.
    set /p FINDINGS_JSON="    Path to findings.json (blank = skip report): "
)
if defined FINDINGS_JSON (
    if exist "!FINDINGS_JSON!" (
        powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0New-InvestigationReport.ps1" -FindingsJson "!FINDINGS_JSON!" -OutputPath "%~dp0report.html"
        if exist "%~dp0report.html" (
            echo     [i] Report written to .\report.html
        ) else (
            echo     [WARN] Report was not produced.
        )
    ) else (
        echo     [WARN] File not found: !FINDINGS_JSON! - skipping report.
    )
)
set GO=
set FINDINGS_JSON=

echo.
echo  ============================================================
echo   Done. Removal output (plan.json, removal-manifest.json,
echo   quarantine\) is under C:\RIT-SCC\.
echo   If ScreenConnect was found: check RELAY HOST in the report,
echo   and send back raw\ + PARSE PROBLEMS so we can validate the
echo   key map ^(see DEPLOY.md section 4^).
echo  ============================================================
pause

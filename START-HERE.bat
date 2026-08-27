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
echo   7 tikun        8 uninstall-AV 9 after-snapshot+diff   10 report
echo  ============================================================
echo.

rem ---- Step 1: tool pack -----------------------------------------------------
echo  STEP 1 of 10: Build/verify tool pack (Sysinternals + KVRT/ESET; Malwarebytes via winget)
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
echo  STEP 2 of 10: Preflight checks (admin, UAC, disk, working dir; restore point)
set /p GO="    Run now? [Y/n] "
if /i not "%GO%"=="n" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0preflight.ps1"
)
set GO=

rem ---- Step 3: BEFORE snapshot -----------------------------------------------
echo.
echo  STEP 3 of 10: BEFORE snapshot (baseline; step 8 diffs against this)
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
echo  STEP 4 of 10: Remote-access detection (read-only, automatic)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0detect-remote-access.ps1" -All -NoPause
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

rem ---- Step 5: REMOVE (automatic) ----------------------------------------------
echo.
echo  STEP 5 of 10: Remove detected ScreenConnect (automatic - no prompts)
echo    Every detected ScreenConnect instance is removed; files are quarantined,
echo    never deleted; every action is logged to removal-manifest.json +
echo    removal-report.txt. Owner directive 2026-08-27: run + remove + log only.
if exist "%~dp0Invoke-ReviewAndRemove.ps1" (
    if defined FINDINGS_JSON (
        powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Invoke-ReviewAndRemove.ps1" -FindingsJson "!FINDINGS_JSON!" -Yes
    ) else (
        powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Invoke-ReviewAndRemove.ps1" -Yes
    )
) else (
    echo     [WARN] Invoke-ReviewAndRemove.ps1 missing - cannot remove.
)
set GO=

rem ---- Step 6: antivirus scans - each one is its own step ---------------------
echo.
echo  STEP 6 of 10: Antivirus scans (KVRT, ESET Online Scanner; Malwarebytes install + launch via winget)
echo    Each scanner is a visible attended GUI. Drive the UI, then return here.

echo.
echo    -- 6a: KVRT (interactive GUI) --
set /p GO="    Launch KVRT? [y/N] "
if /i "%GO%"=="y" (
    if exist "%~dp0tools\AV\KVRT.exe" (
        powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Invoke-GUIScanner.ps1" -Scanner KVRT
        if errorlevel 1 echo        [WARN] KVRT launch failed with errorlevel !errorlevel! - see the message above
    ) else (
        echo        [WARN] tools\AV\KVRT.exe not staged - run step 1 first.
    )
)
set GO=

echo.
echo    -- 6b: ESET Online Scanner (interactive GUI) --
set /p GO="    Launch ESET Online Scanner? [y/N] "
if /i "%GO%"=="y" (
    if exist "%~dp0tools\AV\esetonlinescanner.exe" (
        powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Invoke-GUIScanner.ps1" -Scanner ESET
        if errorlevel 1 echo        [WARN] ESET launch failed with errorlevel !errorlevel! - see the message above
    ) else (
        echo        [WARN] tools\AV\esetonlinescanner.exe not staged - run step 1 first.
    )
)
set GO=

echo.
echo    -- 6c: Malwarebytes (install via winget) --
set /p GO="    Install Malwarebytes via winget now? [y/N] "
if /i not "%GO%"=="y" goto :skip_6c
where winget >nul 2>&1
if errorlevel 1 (
    echo        [WARN] winget not found on this machine - install the App
    echo        Installer first, or stage MBSetup.exe manually under tools\AV\.
    goto :skip_6c
)
echo        Installing Malwarebytes via winget - id Malwarebytes.Malwarebytes
winget install -e --id Malwarebytes.Malwarebytes
if errorlevel 1 echo        [WARN] winget install exited with errorlevel %errorlevel%
if errorlevel 1 goto :skip_6c
echo        Launching Malwarebytes UI...
set "MBAMEXE="
if exist "%ProgramFiles%\Malwarebytes\Anti-Malware\mbam.exe" set "MBAMEXE=%ProgramFiles%\Malwarebytes\Anti-Malware\mbam.exe"
if defined MBAMEXE goto :mbam_found
if exist "%ProgramFiles(x86)%\Malwarebytes\Anti-Malware\mbam.exe" set "MBAMEXE=%ProgramFiles(x86)%\Malwarebytes\Anti-Malware\mbam.exe"
if defined MBAMEXE goto :mbam_found
echo        [WARN] mbam.exe not found at standard paths - launch Malwarebytes from the Start Menu.
goto :skip_6c
:mbam_found
start "" "%MBAMEXE%"
echo        Malwarebytes launched - drive a scan in the UI, then close it.
:skip_6c
set GO=

rem ---- Step 7: Tikun (OPT-IN - destructive, deletes without quarantine) --------
echo.
echo  STEP 7 of 10: Tikun ^(the general fix - tools\GeneralFix\^)
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

rem ---- Step 8: Uninstall installed AV (attended) -------------------------------
echo.
echo  STEP 8 of 10: Uninstall installed third-party antivirus (attended)
echo    Malwarebytes is uninstalled via winget (uninstall -e --id
echo    Malwarebytes.Malwarebytes). Every other detected AV product opens its
echo    uninstaller for YOU to drive. Never silent-uninstalls vendor
echo    uninstallers. Windows Defender is excluded (it is the OS, not
echo    installed AV). Skips if none is detected. Type y to run it.
set /p GO="    Run installed-AV uninstall now? [y/N] "
if /i "%GO%"=="y" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Invoke-AVUninstaller.ps1" -LogDir "%~dp0logs"
) else (
    echo     Skipped. (To skip this in sc-cleanup.ps1 use -avu.)
)
set GO=

rem ---- Step 9: AFTER snapshot + diff ------------------------------------------
echo.
echo  STEP 9 of 10: After-snapshot and diff vs the before-snapshot
set /p GO="    Run now? [Y/n] "
if /i not "%GO%"=="n" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0collect-snapshot.ps1" -Label after -OutFile "%~dp0snapshot_after.json" -Quiet
    if errorlevel 1 echo     [WARN] After-snapshot exited with errorlevel !errorlevel!
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

rem ---- Step 10: report ---------------------------------------------------------
echo.
echo  STEP 10 of 10: Generate the investigation report
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

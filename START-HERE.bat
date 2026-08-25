@echo off
rem ============================================================================
rem  START-HERE.bat - one-by-one guided runner for the ScreenConnect Cleanup Tool
rem  Walks the technician through each step in order. Read-only until Step 5,
rem  and nothing destructive exists in this build anyway.
rem  Pure ASCII, no BOM. Run from an elevated command prompt.
rem ============================================================================

setlocal EnableDelayedExpansion
title ScreenConnect Cleanup Tool
cd /d "%~dp0"

echo.
echo  ============================================================
echo   SCREENCONNECT CLEANUP TOOL - guided run
echo   You will be prompted before each step. Ctrl+C to abort.
echo   7 steps: 1 toolpack 2 preflight 3 before-snapshot 4 detection
echo            5 scanners 6 after-snapshot+diff 7 report
echo  ============================================================
echo.

net session >nul 2>&1
if errorlevel 1 (
    echo  [!] NOT running as administrator. Some steps will be incomplete.
    echo      Right-click this file and choose "Run as administrator".
    echo.
)

rem ---- Step 1: tool pack -----------------------------------------------------
echo  STEP 1 of 6: Build/verify Sysinternals tool pack (downloads ~20 MB once)
set /p GO="    Run now? [Y/n] "
if /i not "%GO%"=="n" (
    if exist "tools\Get-ToolPack.ps1" (
        powershell -NoProfile -ExecutionPolicy Bypass -File "tools\Get-ToolPack.ps1"
        powershell -NoProfile -ExecutionPolicy Bypass -File "tools\Get-ToolPack.ps1" -Verify
    ) else (
        echo     [!] tools\Get-ToolPack.ps1 missing - skipping pack.
    )
)
set GO=

rem ---- Step 2: preflight -----------------------------------------------------
echo.
echo  STEP 2 of 6: Preflight checks (admin, disk, working dir; restore point prompt)
set /p GO="    Run now? [Y/n] "
if /i not "%GO%"=="n" (
    powershell -NoProfile -ExecutionPolicy Bypass -File ".\preflight.ps1"
)
set GO=

rem ---- Step 3: BEFORE snapshot (must precede detection + after-snapshot) ------
echo.
echo  STEP 3 of 6: BEFORE snapshot (baseline; the after-snapshot diffs against this)
set /p GO="    Run now? [Y/n] "
if /i not "%GO%"=="n" (
    powershell -NoProfile -ExecutionPolicy Bypass -File ".\collect-snapshot.ps1" -Label before -OutFile ".\snapshot_before.json" -Quiet
)
set GO=

rem ---- Step 4: detection -----------------------------------------------------
echo.
echo  STEP 4 of 6: Remote-access detection (read-only)
set /p GO="    Full scan of all known targets? [y/N] "
if /i "%GO%"=="y" (
    powershell -NoProfile -ExecutionPolicy Bypass -File ".\detect-remote-access.ps1" -All -NoPause
) else (
    powershell -NoProfile -ExecutionPolicy Bypass -File ".\detect-remote-access.ps1" -NoPause
)
set GO=
set "FINDINGS_JSON="
for /f "delims=" %%F in ('dir /b /o-d "%USERPROFILE%\Desktop\RemoteAccessScan\*_*\findings.json" 2^>nul') do (
    if not defined FINDINGS_JSON set "FINDINGS_JSON=%USERPROFILE%\Desktop\RemoteAccessScan\%%~dpF"
    goto :found_findings
)
:found_findings
if not defined FINDINGS_JSON (
    echo     [i] No findings.json found - report step will be skipped unless you point it at one.
) else (
    echo     [i] Latest findings: !FINDINGS_JSON!
)


rem ---- Step 5: scanners -------------------------------------------------------
echo.
echo  STEP 5 of 6: Antivirus scanner pass (Defender quick scan; KVRT/ESET optional)
set /p GO="    Run Defender scan now? [Y/n] "
if /i not "%GO%"=="n" (
    powershell -NoProfile -ExecutionPolicy Bypass -File ".\scanners\Invoke-DefenderScan.ps1" -WhatIf
    echo     ^(^- remove -WhatIf above to make it real^)
)
set GO=

rem ---- Step 6: AFTER snapshot + diff ------------------------------------------
echo.
echo  STEP 6 of 6: After-snapshot and diff vs the before-snapshot
set /p GO="    Run now? [Y/n] "
if /i not "%GO%"=="n" (
    powershell -NoProfile -ExecutionPolicy Bypass -File ".\collect-snapshot.ps1" -Label after -OutFile ".\snapshot_after.json" -Quiet
    powershell -NoProfile -ExecutionPolicy Bypass -File ".\diff-snapshots.ps1" -BeforeFile ".\snapshot_before.json" -AfterFile ".\snapshot_after.json" -OutFile ".\snapshot_diff.json"
)
set GO=

rem ---- Step 7: report ----------------------------------------------------------
echo.
echo  STEP 7 of 7: Generate the investigation report
if not defined FINDINGS_JSON (
    echo     [!] No findings.json available. Detection ^(step 4^) must run first,
    echo         or enter the full path to an existing findings.json.
    set /p FINDINGS_JSON="    Path to findings.json (blank = skip report): "
)
if defined FINDINGS_JSON (
    if exist "!FINDINGS_JSON!" (
        powershell -NoProfile -ExecutionPolicy Bypass -File ".\New-InvestigationReport.ps1" -FindingsJson "!FINDINGS_JSON!" -OutputPath ".\report.html"
        echo     [i] Report written to .\report.html
    ) else (
        echo     [!] File not found: !FINDINGS_JSON! - skipping report.
    )
)
set GO=
set FINDINGS_JSON=

echo.
echo  ============================================================
echo   Done. Results are under C:\RIT-SCC\ ^(or your OutRoot^).
echo   If ScreenConnect was found: check RELAY HOST in the report,
echo   and send back raw\ + PARSE PROBLEMS so we can validate the
echo   key map ^(see DEPLOY.md section 4^).
echo  ============================================================
pause

@echo off
rem ============================================================================
rem  START-HERE.bat - one-by-one guided runner for the ScreenConnect Cleanup Tool
rem  Walks the technician through each step in order, prompting before each one
rem  that needs a decision. Steps 1-4 and 8-9 are read-only (steps 3, 4, 8 and 9
rem  run automatically). Step 5 requires typed review and confirmation before
rem  ScreenConnect removal. Self-elevates.
rem  Pure ASCII, no BOM.
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

rem ---- Bind every artifact to a fresh run root -------------------------------
for /f "delims=" %%R in ('powershell -NoProfile -Command "$p=Join-Path 'C:\RIT-SCC' ($env:COMPUTERNAME + '-' + [guid]::NewGuid().ToString('N')); New-Item -ItemType Directory -Path $p -Force ^| Out-Null; $p"') do set "SCC_RUN_ROOT=%%R"
if not defined SCC_RUN_ROOT goto :run_setup_failed

echo     Run: !SCC_RUN_ROOT!
set "PIPE_RC=0"

echo.
echo  ============================================================
echo   SCREENCONNECT CLEANUP - guided run
echo   Prompts mark decisions; Ctrl+C aborts.
echo.
echo   1 toolpack  2 preflight  3 snapshot  4 detect  5 remove
echo   6 scanners  7 AV uninstall  8 diff  9 report
echo  ============================================================
echo.

rem ---- Step 1: tool pack -----------------------------------------------------
echo  STEP 1/9: Tool pack + scanner staging
set /p GO="    Run now? [Y/n] "
if /i not "%GO%"=="n" (
    if exist "%~dp0tools\Get-ToolPack.ps1" (
        powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\Get-ToolPack.ps1" -Quiet
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

rem ---- Step 2: preflight (ALWAYS runs - owner directive 2026-08-28) ---------
echo.
echo  STEP 2/9: Preflight
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0preflight.ps1" -WorkingRoot "!SCC_RUN_ROOT!"
if errorlevel 1 goto :preflight_failed
set GO=

rem ---- Step 3: BEFORE snapshot -----------------------------------------------
echo.
echo  STEP 3/9: Before snapshot
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0collect-snapshot.ps1" -Label before -OutFile "!SCC_RUN_ROOT!\snapshot_before.json" -Quiet
if errorlevel 1 goto :before_snapshot_failed
if exist "!SCC_RUN_ROOT!\snapshot_before.json" (
    echo     [i] Baseline saved.
) else (
    goto :before_snapshot_failed
)
set GO=

rem ---- Step 4: detection -----------------------------------------------------
echo.
echo  STEP 4/9: Remote-access detection
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0detect-remote-access.ps1" -All -NoPause -NoZip -NoReportUpload -OutRoot "!SCC_RUN_ROOT!\detect"
if errorlevel 1 goto :detection_failed
set GO=
set "FINDINGS_JSON="
rem Only search the directory created for THIS run; historical findings are never
rem eligible to authorize removal.
for /f "delims=" %%D in ('dir /b /ad /o-d "!SCC_RUN_ROOT!\detect\*_*" 2^>nul') do (
    if not defined FINDINGS_JSON if exist "!SCC_RUN_ROOT!\detect\%%D\findings.json" (
        set "FINDINGS_JSON=!SCC_RUN_ROOT!\detect\%%D\findings.json"
    )
)
if not defined FINDINGS_JSON (
    echo     [i] No findings.json found - steps 5 and 8 need it.
) else (
    echo     [i] Latest findings: !FINDINGS_JSON!
)

rem ---- Step 5: REMOVE (typed confirmation) ----------------------------------
echo.
echo  STEP 5/9: Review/remove ScreenConnect
echo    Review each instance. Files are quarantined, never deleted.
echo    Type y only after confirming the instance and removal.
if exist "%~dp0Invoke-ReviewAndRemove.ps1" (
    if defined FINDINGS_JSON (
        powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Invoke-ReviewAndRemove.ps1" -FindingsJson "!FINDINGS_JSON!" -WorkDir "!SCC_RUN_ROOT!"
        set "REMOVE_RC=!errorlevel!"
        if not "!REMOVE_RC!"=="0" (
            echo     [WARN] Removal reported exit !REMOVE_RC! - continuing to collect after-evidence and report.
            set "PIPE_RC=!REMOVE_RC!"
        )
    ) else (
        echo     [i] No current-run findings - removal is skipped.
    )
) else (
    echo     [WARN] Invoke-ReviewAndRemove.ps1 missing - cannot remove.
    goto :removal_failed
)
set GO=

rem ---- Step 6: antivirus scans - each one is its own step ---------------------
echo.
echo  STEP 6/9: Antivirus scans (attended)
echo    Each scanner opens visibly. Complete it, then return here.

echo.
echo    -- 6a: KVRT --
set /p GO="    Launch KVRT? [Y/n] "
if /i not "%GO%"=="n" (
    if exist "%~dp0tools\AV\KVRT.exe" (
        powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Invoke-GUIScanner.ps1" -Scanner KVRT
        if errorlevel 1 echo        [WARN] KVRT launch failed with errorlevel !errorlevel! - see the message above
    ) else (
        echo        [WARN] tools\AV\KVRT.exe not staged - run step 1 first.
    )
)
set GO=

echo.
echo    -- 6b: ESET Online Scanner --
set /p GO="    Launch ESET Online Scanner? [Y/n] "
if /i not "%GO%"=="n" (
    if exist "%~dp0tools\AV\esetonlinescanner.exe" (
        powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Invoke-GUIScanner.ps1" -Scanner ESET
        if errorlevel 1 echo        [WARN] ESET launch failed with errorlevel !errorlevel! - see the message above
    ) else (
        echo        [WARN] tools\AV\esetonlinescanner.exe not staged - run step 1 first.
    )
)
set GO=

echo.
echo    -- 6c: Malwarebytes --
set /p GO="    Install Malwarebytes via winget now? [Y/n] "
if /i "%GO%"=="n" goto :skip_6c
where winget >nul 2>&1
if errorlevel 1 (
    echo        [WARN] winget not found on this machine - install the App
    echo        Installer first, then retry Malwarebytes.
    if not exist "!SCC_RUN_ROOT!\logs" mkdir "!SCC_RUN_ROOT!\logs"
    powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Invoke-GUIScanner.ps1" -DiagnosticsOnly -InstallerExitCode -1 -ResultPath "!SCC_RUN_ROOT!\logs\scanner-Malwarebytes-result.json"
    if errorlevel 1 echo        [WARN] Malwarebytes diagnostic wrapper exited with errorlevel !errorlevel!
    goto :skip_6c
)
echo        Installing Malwarebytes via winget - id Malwarebytes.Malwarebytes
set "MB_WINGET_RC="
winget install -e --id Malwarebytes.Malwarebytes --accept-package-agreements --accept-source-agreements
if errorlevel 1 set "MB_WINGET_RC=!errorlevel!"
if defined MB_WINGET_RC goto :mbam_install_failed
echo        Launching Malwarebytes UI...
set "MBAMEXE="
if exist "%ProgramFiles%\Malwarebytes\Anti-Malware\mbam.exe" set "MBAMEXE=%ProgramFiles%\Malwarebytes\Anti-Malware\mbam.exe"
if defined MBAMEXE goto :mbam_found
if exist "%ProgramFiles(x86)%\Malwarebytes\Anti-Malware\mbam.exe" set "MBAMEXE=%ProgramFiles(x86)%\Malwarebytes\Anti-Malware\mbam.exe"
if defined MBAMEXE goto :mbam_found
echo        [WARN] mbam.exe not found at standard paths - launch Malwarebytes from the Start Menu.
goto :skip_6c
:mbam_install_failed
echo        [WARN] Malwarebytes winget install failed with errorlevel !MB_WINGET_RC!.
if not exist "!SCC_RUN_ROOT!\logs" mkdir "!SCC_RUN_ROOT!\logs"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Invoke-GUIScanner.ps1" -DiagnosticsOnly -InstallerExitCode !MB_WINGET_RC! -ResultPath "!SCC_RUN_ROOT!\logs\scanner-Malwarebytes-result.json"
if errorlevel 1 echo        [WARN] Malwarebytes diagnostic wrapper exited with errorlevel !errorlevel!
goto :skip_6c
:mbam_found
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Invoke-GUIScanner.ps1" -ToolPath "%MBAMEXE%"
if errorlevel 1 echo        [WARN] Malwarebytes GUI wrapper exited with errorlevel !errorlevel!
echo        Malwarebytes session ended - continuing.
:skip_6c
set GO=

rem ---- Step 7: Uninstall installed AV (attended) -------------------------------
echo.
echo  STEP 7/9: Uninstall third-party AV (attended)
echo    Malwarebytes uses winget; other AV uninstallers open for you.
echo    Never silent-uninstalls - uninstallers open for you to drive.
echo    Defender is excluded. Enter skips.
set /p GO="    Run installed-AV uninstall now? [y/N] "
if /i "%GO%"=="y" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Invoke-AVUninstaller.ps1" -LogDir "!SCC_RUN_ROOT!\logs"
) else (
    echo     Skipped.
)
set GO=

rem ---- Step 8: AFTER snapshot + diff ------------------------------------------
echo.
echo  STEP 8/9: After snapshot + diff
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0collect-snapshot.ps1" -Label after -OutFile "!SCC_RUN_ROOT!\snapshot_after.json" -Quiet
if errorlevel 1 echo     [WARN] After-snapshot exited with errorlevel %errorlevel%
rem Only diff when the baseline from this run actually exists.
if not exist "!SCC_RUN_ROOT!\snapshot_before.json" (
    echo     [WARN] No snapshot_before.json - step 3 was skipped, so there is
    echo         nothing to diff against. Skipping the diff.
) else (
    if not exist "!SCC_RUN_ROOT!\snapshot_after.json" (
        echo     [WARN] After-snapshot was not written - skipping the diff.
    ) else (
        powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0diff-snapshots.ps1" -BeforeFile "!SCC_RUN_ROOT!\snapshot_before.json" -AfterFile "!SCC_RUN_ROOT!\snapshot_after.json" -OutFile "!SCC_RUN_ROOT!\snapshot_diff.json"
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
set GO=

rem ---- Step 9: report ---------------------------------------------------------
echo.
echo  STEP 9/9: Report
if not defined FINDINGS_JSON (
    echo     [WARN] No current-run findings.json available - skipping report.
) else (
    if exist "!FINDINGS_JSON!" (
    if exist "!SCC_RUN_ROOT!/removal-manifest.json" (
        powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0New-InvestigationReport.ps1" -FindingsJson "!FINDINGS_JSON!" -RemovalManifest "!SCC_RUN_ROOT!/removal-manifest.json" -OutputPath "!SCC_RUN_ROOT!/report.html"
    ) else (
        powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0New-InvestigationReport.ps1" -FindingsJson "!FINDINGS_JSON!" -OutputPath "!SCC_RUN_ROOT!/report.html"
    )
        set "REPORT_RC=!errorlevel!"
        if not "!REPORT_RC!"=="0" (
            echo     [WARN] Report generation failed with errorlevel !REPORT_RC! - see the messages above.
            if "!PIPE_RC!"=="0" set "PIPE_RC=!REPORT_RC!"
        )
        if exist "!SCC_RUN_ROOT!/report.html" (
            echo     [i] Report written to !SCC_RUN_ROOT!/report.html
            rem Owner directive 2026-08-27: open the report folder + report.
            explorer /select,"!SCC_RUN_ROOT!/report.html"
            start "" "!SCC_RUN_ROOT!/report.html"
            if exist "%~dp0Submit-ConnectWiseReport.ps1" (
                powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Submit-ConnectWiseReport.ps1" -FindingsJson "!FINDINGS_JSON!" -WorkDir "!SCC_RUN_ROOT!" -RelayUrl "https://reports.aygross.xyz/v1/uploads"
                set "UPLOAD_RC=!errorlevel!"
                if not "!UPLOAD_RC!"=="0" (
                    echo     [WARN] Report upload failed with errorlevel !UPLOAD_RC! - local evidence remains available.
                    if "!PIPE_RC!"=="0" set "PIPE_RC=!UPLOAD_RC!"
                )
            ) else (
                echo     [WARN] Submit-ConnectWiseReport.ps1 missing - local report was kept but not uploaded.
                if "!PIPE_RC!"=="0" set "PIPE_RC=1"
            )
        ) else (
            echo     [WARN] Report was not produced.
            if "!PIPE_RC!"=="0" set "PIPE_RC=1"
        )
    ) else (
        echo     [WARN] Current-run findings disappeared - skipping report.
    )
)
set GO=
set FINDINGS_JSON=

echo.
echo  ============================================================
echo   Done. Run artifacts: !SCC_RUN_ROOT!
echo   See plan.json, removal-manifest.json, quarantine\, report.html.
echo   Review the report, if produced, for relay host and parse problems.
echo  ============================================================
pause
goto :done

:run_setup_failed
echo [ERROR] Could not create a unique current-run directory. Aborting.
pause
exit /b 1

:before_snapshot_failed
echo [ERROR] Before-snapshot failed or was not written. No removal will run.
pause
exit /b 1

:preflight_failed
echo [ERROR] Preflight failed. No detection or removal will run.
pause
exit /b 1

:detection_failed
echo [ERROR] Detection failed. No removal will run and no historical findings will be used.
pause
exit /b 1

:removal_failed
echo [ERROR] Removal reported a failure. Review the current run artifacts.
pause
exit /b 1

:done
exit /b !PIPE_RC!

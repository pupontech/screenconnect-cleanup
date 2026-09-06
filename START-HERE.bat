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

rem ---- Optional MicroBin report sharing opt-in (start of run) ---------------
rem The sanitized report may additionally be posted to a MicroBin paste server
rem of the operator's choice. Default is no: a blank or n answer never uploads
rem anything anywhere. An explicit y resolves the server base URL from
rem microbin-url.txt (first nonblank trimmed line) beside this tool; when that
rem file is missing or empty the operator is asked once for an https:// base
rem URL, which is saved there for future runs. The URL file never holds
rem passwords. The default MicroBin server is passwordless, so no uploader
rem password is prompted or stored by this runner. For a server that requires
rem an uploader password the operator pre-configures it in the environment
rem before the run (a password file path that is passed through unchanged, or
rem the uploader's own password environment variable); this runner never
rem creates, echoes, or deletes an uploader password.
echo.
echo  ------------------------------------------------------------
echo   Optional: MicroBin report sharing - separate from the private
echo   relay. Default no (relay-only run). Ctrl+C aborts.
set /p GO="    Upload the sanitized report to MicroBin? [y/N] "
if /i "%GO%"=="y" goto :microbin_optin
if /i "%GO%"=="yes" goto :microbin_optin
goto :microbin_optout
:microbin_optin
set "SCC_MICROBIN_URL="
if exist "%~dp0Resolve-MicroBinRunUrl.ps1" (
    for /f "delims=" %%U in ('powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Resolve-MicroBinRunUrl.ps1" -ConfigFile "%~dp0microbin-url.txt" -SkipPrompt') do set "SCC_MICROBIN_URL=%%U"
    if not defined SCC_MICROBIN_URL (
        echo     [i] No saved MicroBin URL found - you will be asked for one now.
        powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Resolve-MicroBinRunUrl.ps1" -ConfigFile "%~dp0microbin-url.txt"
        if errorlevel 4 (
            echo     [WARN] MicroBin sharing skipped - no usable server URL was entered.
        ) else if errorlevel 1 (
            echo     [WARN] MicroBin configuration step failed - sharing skipped for this run.
        ) else (
            for /f "delims=" %%U in ('powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Resolve-MicroBinRunUrl.ps1" -ConfigFile "%~dp0microbin-url.txt" -SkipPrompt') do set "SCC_MICROBIN_URL=%%U"
        )
    )
    if defined SCC_MICROBIN_URL (
        echo     [i] MicroBin report sharing enabled for this run's report.
    ) else (
        set "SCC_MICROBIN_URL="
        echo     [i] MicroBin report sharing skipped - relay behavior unchanged.
    )
) else (
    echo     [WARN] Resolve-MicroBinRunUrl.ps1 missing - MicroBin sharing skipped.
)
rem Optional uploader password file, only for servers that require one. The
rem default MicroBin server is passwordless, so nothing is prompted and no
rem secret file is created by this runner. When the operator pre-configured a
rem password file in the environment (SCC_MICROBIN_UPLOADER_PASSWORD_FILE) it
rem is passed through unchanged to the uploader at the report step and is
rem never deleted here.
if defined SCC_MICROBIN_URL (
    if defined SCC_MICROBIN_UPLOADER_PASSWORD_FILE (
        echo     [i] Using the pre-configured MicroBin uploader password file.
    )
)
goto :microbin_done
:microbin_optout
set "SCC_MICROBIN_URL="
echo     [i] MicroBin report sharing skipped - relay behavior unchanged.
:microbin_done
set GO=
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
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0detect-remote-access.ps1" -All -NoPause -NoZip -NoReportUpload -OutRoot "!SCC_RUN_ROOT!\detect" -TranscriptCopyDir "!SCC_RUN_ROOT!"
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
    rem ---- Incident context (authorization + delivery) - one prompt per run --
    rem The technician records how the ScreenConnect activity reached the user
    rem (Delivery) and whether it was authorized, with safe defaults (Not
    rem authorized / Email invite scam) when Enter is pressed. The validated
    rem pair is written to incident-context.txt inside this run root and
    rem forwarded to the report uploader below. A failed or aborted prompt
    rem leaves the pair unset and the report honestly marks the context
    rem Not available. Values are validated by Resolve-IncidentContext.ps1
    rem (no blanks, no free-form ambiguity; Other requires a description).
    set "SCC_CTX_AUTH="
    set "SCC_CTX_DELIVERY="
    if exist "%~dp0Resolve-IncidentContext.ps1" (
        powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Resolve-IncidentContext.ps1" -OutFile "!SCC_RUN_ROOT!\incident-context.txt"
        if errorlevel 4 (
            echo     [WARN] Incident context was not completed - the report will mark it Not available.
        ) else if errorlevel 1 (
            echo     [WARN] Incident context could not be saved - the report will mark it Not available.
        ) else (
            if exist "!SCC_RUN_ROOT!\incident-context.txt" (
                for /f "usebackq delims=" %%A in ("!SCC_RUN_ROOT!\incident-context.txt") do (
                    if not defined SCC_CTX_AUTH (
                        set "SCC_CTX_AUTH=%%A"
                    ) else if not defined SCC_CTX_DELIVERY (
                        set "SCC_CTX_DELIVERY=%%A"
                    )
                )
            )
            if defined SCC_CTX_AUTH if defined SCC_CTX_DELIVERY (
                echo     [i] Incident context recorded for this run.
            )
        )
    ) else (
        echo     [WARN] Resolve-IncidentContext.ps1 missing - the report will mark context Not available.
    )
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
            rem Owner directive 2026-09-06: also leave a copy of report.html on
            rem the current user's Desktop. The run-root original is preserved;
            rem a failed copy is reported visibly (never silent) and marks the
            rem run, but never hides the local report.
            powershell -NoProfile -ExecutionPolicy Bypass -Command "$d=[Environment]::GetFolderPath('Desktop'); if(-not $d){$d=Join-Path $env:USERPROFILE 'Desktop'}; Copy-Item -LiteralPath '!SCC_RUN_ROOT!\report.html' -Destination (Join-Path $d 'report.html') -Force -ErrorAction Stop; Write-Host ('[i] Report copy on Desktop: ' + (Join-Path $d 'report.html'))"
            if errorlevel 1 (
                echo     [WARN] Could not copy report.html to the current user's Desktop - see the message above.
                if "!PIPE_RC!"=="0" set "PIPE_RC=1"
            )
            if exist "%~dp0Submit-ConnectWiseReport.ps1" (
                set "MICROBIN_EXTRA="
                set "CTX_EXTRA="
                if defined SCC_CTX_AUTH set "CTX_EXTRA=!CTX_EXTRA! -IncidentAuthorization "!SCC_CTX_AUTH!""
                if defined SCC_CTX_DELIVERY set "CTX_EXTRA=!CTX_EXTRA! -IncidentDelivery "!SCC_CTX_DELIVERY!""
                if defined SCC_MICROBIN_URL set "MICROBIN_EXTRA=!MICROBIN_EXTRA! -MicroBinUrl "!SCC_MICROBIN_URL!""
                if defined SCC_MICROBIN_UPLOADER_PASSWORD_FILE set "MICROBIN_EXTRA=!MICROBIN_EXTRA! -MicroBinUploaderPasswordFile "!SCC_MICROBIN_UPLOADER_PASSWORD_FILE!""
                powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Submit-ConnectWiseReport.ps1" -FindingsJson "!FINDINGS_JSON!" -WorkDir "!SCC_RUN_ROOT!" -ReportHtml "!SCC_RUN_ROOT!/report.html" -RelayUrl "https://reports.aygross.xyz/v1/uploads"!MICROBIN_EXTRA!!CTX_EXTRA!
                set "UPLOAD_RC=!errorlevel!"
                set "MICROBIN_EXTRA="
                set "CTX_EXTRA="
                set SCC_CTX_AUTH=
                set SCC_CTX_DELIVERY=
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

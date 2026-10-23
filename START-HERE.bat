@echo off
rem ============================================================================
rem  START-HERE.bat - guided runner for the ScreenConnect Cleanup Tool
rem  Steps 1-4 and 8-9 run automatically (tool download, preflight, snapshots,
rem  detection, diff, report share). Step 5 asks ONE typed confirmation before
rem  ScreenConnect removal. Steps 6-7 launch attended scanner/AV-uninstall work.
rem  Self-elevates.
rem  Requires explicit confirmation before starting when AC power is disconnected.
rem  Pure ASCII, no BOM.
rem ============================================================================

rem ---- Capture our own path/args BEFORE enabling delayed expansion --------
rem A folder name such as "screenconnect-cleanup-v1.8.8 (1)" (what Explorer
rem creates when you extract a ZIP a second time) breaks cmd: %~dp0 / %~f0
rem expand at PARSE time, so the ( ) inside a ( ... ) block terminate the
rem block early and the batch aborts with no message and no UAC prompt.
rem Delayed expansion (!VAR!) is substituted at RUN time, after parsing, so
rem it is safe for such paths. These are the only %~dp0/%~f0/%* expansions.
set "SCC_DP0=%~dp0"
set "SCC_F0=%~f0"
set "SCC_ARG1=%~1"
set "SCC_ARGS=%*"
setlocal EnableDelayedExpansion
rem ---- Use a dedicated cmd.exe so the keep-awake helper has a bounded lifetime ----
if not defined SCC_RUNNER_CHILD (
    set "SCC_RUNNER_CHILD=1"
    if "!SCC_ARG1!"=="" (
        start "" /b /wait cmd.exe /d /s /c ""!SCC_F0!""
    ) else (
        start "" /b /wait cmd.exe /d /s /c ""!SCC_F0!" !SCC_ARGS!"
    )
    set "SCC_RUNNER_RC=!errorlevel!"
    exit /b !SCC_RUNNER_RC!
)
title ScreenConnect Cleanup Tool

rem ---- Self-elevate: at most ONE UAC prompt, decided by the real admin token ---
rem The script path travels via the SCC_SELF environment variable so that
rem apostrophes (and other quotes) in the path cannot break the PowerShell
rem command line. A failed/cancelled UAC prompt must be visible, never silent.
rem The relaunch passes --elevation-attempted. If that flag is present and this
rem window is STILL not elevated, the runner stops instead of prompting again:
rem a probe that misreports elevation must never loop UAC at the technician.
set "SCC_SELF=!SCC_F0!"
powershell -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "if(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){exit 0}else{exit 1}"
if errorlevel 1 (
    if /i "!SCC_ARG1!"=="--elevation-attempted" (
        echo.
        echo  [ERROR] This window is still not elevated after the UAC request, so
        echo          the tool will not ask again. Right-click START-HERE.bat and
        echo          choose "Run as administrator", or open an elevated Command
        echo          Prompt in this folder and run START-HERE.bat there.
        pause
        exit /b 1
    )
    echo  Requesting administrator privileges...
    rem This is the ONLY elevation request the tool makes.
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath $env:SCC_SELF -ArgumentList '--elevation-attempted' -Verb RunAs"
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

rem ---- Confirm battery power before starting any cleanup work ----------------
rem This foreground child shares the runner console; Hidden would hide the whole run.
rem Only the separately started keep-awake helper below should use WindowStyle Hidden.
powershell.exe -NoLogo -NoProfile -STA -ExecutionPolicy Bypass -File "!SCC_DP0!tools\Confirm-OnBattery.ps1"
if errorlevel 1 goto :battery_not_confirmed

rem ---- Keep the system and display awake for this runner only ----------------
start "" powershell.exe -NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "!SCC_DP0!tools\Keep-Awake.ps1"
if errorlevel 1 echo     [WARN] Keep-awake helper could not start; this computer may sleep during the run.

cd /d "!SCC_DP0!"

rem ---- Bind every artifact to a fresh run root -------------------------------
for /f "delims=" %%R in ('powershell -NoProfile -Command "$p=Join-Path 'C:\RIT-SCC' ($env:COMPUTERNAME + '-' + [guid]::NewGuid().ToString('N')); New-Item -ItemType Directory -Path $p -Force ^| Out-Null; $p"') do set "SCC_RUN_ROOT=%%R"
if not defined SCC_RUN_ROOT goto :run_setup_failed

echo     Run: !SCC_RUN_ROOT!
set "PIPE_RC=0"
set "POWER_REPAIR_RAN=0"

echo.
echo  ============================================================
echo   SCREENCONNECT CLEANUP - guided run
echo   Steps 1-4 and 8-9 run automatically. Step 5 asks ONE typed
echo   confirmation before removal. Ctrl+C aborts.
echo.
echo   1 toolpack  2 preflight  3 snapshot  4 detect  5 remove
echo   6 scanners  7 AV uninstall  8 diff  9 report
echo  ============================================================
echo.

rem ---- Step 1: tool pack (always runs) --------------------------------------
echo  STEP 1/9: Tool pack + KVRT/ESET staging (Malwarebytes fallback at Step 6)
if exist "!SCC_DP0!tools\Get-ToolPack.ps1" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "!SCC_DP0!tools\Get-ToolPack.ps1" -Quiet
    powershell -NoProfile -ExecutionPolicy Bypass -File "!SCC_DP0!tools\Get-ToolPack.ps1" -Verify
) else (
    echo     [WARN] tools\Get-ToolPack.ps1 missing - skipping pack.
)
if exist "!SCC_DP0!tools\Get-AVTools.ps1" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "!SCC_DP0!tools\Get-AVTools.ps1" -ToolDir "!SCC_DP0!tools\AV"
) else (
    echo     [WARN] tools\Get-AVTools.ps1 missing - skipping AV scanner staging.
)

rem ---- Step 2: preflight (ALWAYS runs - owner directive 2026-08-28) ---------
echo.
echo  STEP 2/9: Preflight
powershell -NoProfile -ExecutionPolicy Bypass -File "!SCC_DP0!preflight.ps1" -WorkingRoot "!SCC_RUN_ROOT!"
if errorlevel 1 goto :preflight_failed

rem ---- Step 3: BEFORE snapshot -----------------------------------------------
echo.
echo  STEP 3/9: Before snapshot
powershell -NoProfile -ExecutionPolicy Bypass -File "!SCC_DP0!collect-snapshot.ps1" -Label before -OutFile "!SCC_RUN_ROOT!\snapshot_before.json" -Quiet
if errorlevel 1 goto :before_snapshot_failed
if exist "!SCC_RUN_ROOT!\snapshot_before.json" (
    echo     [i] Baseline saved.
) else (
    goto :before_snapshot_failed
)

rem ---- Step 4: detection -----------------------------------------------------
echo.
echo  STEP 4/9: Remote-access detection
powershell -NoProfile -ExecutionPolicy Bypass -File "!SCC_DP0!detect-remote-access.ps1" -All -NoPause -NoZip -NoReportShare -OutRoot "!SCC_RUN_ROOT!\detect" -TranscriptCopyDir "!SCC_RUN_ROOT!"
if errorlevel 1 goto :detection_failed
set "FINDINGS_JSON="
rem Only search the directory created for THIS run; historical findings are never
rem eligible to authorize removal.
for /f "delims=" %%D in ('dir /b /ad /o-d "!SCC_RUN_ROOT!\detect\*_*" 2^>nul') do (
    if not defined FINDINGS_JSON if exist "!SCC_RUN_ROOT!\detect\%%D\findings.json" (
        set "FINDINGS_JSON=!SCC_RUN_ROOT!\detect\%%D\findings.json"
    )
)
if not defined FINDINGS_JSON (
    echo     [i] No findings.json found - steps 5 and 9 need it.
) else (
    echo     [i] Latest findings: !FINDINGS_JSON!
)

rem ---- Step 5: REMOVE (single typed confirmation) -----------------------------
echo.
echo  STEP 5/9: Review/remove ScreenConnect
echo    One typed confirmation removes ALL detected ScreenConnect instances.
echo    Files are quarantined, never deleted.
if exist "!SCC_DP0!Invoke-ReviewAndRemove.ps1" (
    if defined FINDINGS_JSON (
        powershell -NoProfile -ExecutionPolicy Bypass -File "!SCC_DP0!Invoke-ReviewAndRemove.ps1" -FindingsJson "!FINDINGS_JSON!" -WorkDir "!SCC_RUN_ROOT!"
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

rem ---- Step 6: antivirus scans - each one is its own step ---------------------
echo.
echo  STEP 6/9: Antivirus scans (attended)
echo    Each scanner opens visibly. Complete it, then return here.

echo.
echo    -- 6a: KVRT --
set /p GO="    Launch KVRT? [Y/n] "
if /i not "%GO%"=="n" (
    if exist "!SCC_DP0!tools\AV\KVRT.exe" (
        powershell -NoProfile -ExecutionPolicy Bypass -File "!SCC_DP0!Invoke-GUIScanner.ps1" -Scanner KVRT
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
    if exist "!SCC_DP0!tools\AV\esetonlinescanner.exe" (
        powershell -NoProfile -ExecutionPolicy Bypass -File "!SCC_DP0!Invoke-GUIScanner.ps1" -Scanner ESET
        if errorlevel 1 echo        [WARN] ESET launch failed with errorlevel !errorlevel! - see the message above
    ) else (
        echo        [WARN] tools\AV\esetonlinescanner.exe not staged - run step 1 first.
    )
)
set GO=

rem ---- Step 6c: Malwarebytes (winget, then official offline fallback) -----
echo.
echo    -- 6c: Malwarebytes --
set /p GO="    Install and launch Malwarebytes now? [Y/n] "
if /i "%GO%"=="n" goto :skip_6c
if not exist "!SCC_RUN_ROOT!\logs" mkdir "!SCC_RUN_ROOT!\logs"
powershell -NoProfile -ExecutionPolicy Bypass -File "!SCC_DP0!Invoke-GUIScanner.ps1" -Scanner Malwarebytes -ResultPath "!SCC_RUN_ROOT!\logs\scanner-Malwarebytes-result.json"
if errorlevel 1 echo        [WARN] Malwarebytes wrapper exited with errorlevel !errorlevel! - see the result JSON and message above
echo        Malwarebytes session ended - continuing.
:skip_6c
set GO=

rem ---- Step 6d: mandatory persistence scan/review after AV scanners -----------
echo.
echo  STEP 6d/9: Persistence inventory and review
powershell -NoProfile -ExecutionPolicy Bypass -File "!SCC_DP0!Invoke-PersistenceScan.ps1" -WorkDir "!SCC_RUN_ROOT!" -PreflightRoot "!SCC_RUN_ROOT!"
set "PERSIST_RC=!errorlevel!"
if not "!PERSIST_RC!"=="0" (
    echo     [WARN] Persistence scan/review incomplete - exit !PERSIST_RC!; evidence will still be reported.
    if "!PIPE_RC!"=="0" set "PIPE_RC=!PERSIST_RC!"
)

rem ---- Step 6e: open the review windows for the technician ----------------------
echo.
echo  STEP 6e/9: Open review windows (no changes made)
echo    Opens the evidence + startup folders, Services and Task Scheduler so you
echo    can inspect what the persistence scan flagged. Nothing is changed here.
set /p OPENREVIEW="    Open the review windows now? [Y/n] "
if /i "%OPENREVIEW%"=="n" goto :skip_6e
powershell -NoProfile -ExecutionPolicy Bypass -File "!SCC_DP0!Show-PersistenceReview.ps1" -WorkDir "!SCC_RUN_ROOT!"
if errorlevel 1 echo     [WARN] Some review windows could not be opened - see the messages above.
:skip_6e
set OPENREVIEW=

rem ---- Step 7: Uninstall installed AV (attended) -------------------------------
echo.
echo  STEP 7/9: Uninstall third-party AV (attended)
echo    Malwarebytes uses winget; other AV uninstallers open for you.
echo    Never silent-uninstalls - uninstallers open for you to drive.
echo    Defender is excluded. Enter skips.
set /p GO="    Run installed-AV uninstall now? [y/N] "
if /i "%GO%"=="y" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "!SCC_DP0!Invoke-AVUninstaller.ps1" -LogDir "!SCC_RUN_ROOT!\logs"
) else (
    echo     Skipped.
)
set GO=

rem ---- Step 8: AFTER snapshot + diff ------------------------------------------
echo.
echo  STEP 8/9: Optional power-options repair + after snapshot/diff
echo    The repair is opt-in. Managed devices may need administrator approval.
set "GO="
set /p GO="    Repair missing power options now? [y/N] "
if /i not "!GO!"=="y" goto :skip_power_repair
set "RESET_GPO="
set /p RESET_GPO="    Back up, then reset local Group Policy folders? [y/N] "
set "RESET_GPO_ARGS="
if /i "!RESET_GPO!"=="y" set "RESET_GPO_ARGS=-ResetLocalGpo"
powershell -NoProfile -ExecutionPolicy Bypass -File "!SCC_DP0!Repair-PowerOptions.ps1" -Apply -Confirm:$false -WorkDir "!SCC_RUN_ROOT!" -ResultPath "!SCC_RUN_ROOT!\power-options-repair.json" !RESET_GPO_ARGS!
set "POWER_REPAIR_RC=!errorlevel!"
set "POWER_REPAIR_RAN=0"
if exist "!SCC_RUN_ROOT!\power-options-repair.json" set "POWER_REPAIR_RAN=1"
if not "!POWER_REPAIR_RC!"=="0" (
    echo     [WARN] Power-options repair exited !POWER_REPAIR_RC! - review power-options-repair.json.
    if "!PIPE_RC!"=="0" set "PIPE_RC=!POWER_REPAIR_RC!"
)
:skip_power_repair
set GO=
set RESET_GPO=
set RESET_GPO_ARGS=
powershell -NoProfile -ExecutionPolicy Bypass -File "!SCC_DP0!collect-snapshot.ps1" -Label after -OutFile "!SCC_RUN_ROOT!\snapshot_after.json" -Quiet
if errorlevel 1 echo     [WARN] After-snapshot exited with errorlevel %errorlevel%
rem Only diff when the baseline from this run actually exists.
if not exist "!SCC_RUN_ROOT!\snapshot_before.json" (
    echo     [WARN] No snapshot_before.json - step 3 was skipped, so there is
    echo         nothing to diff against. Skipping the diff.
) else (
    if not exist "!SCC_RUN_ROOT!\snapshot_after.json" (
        echo     [WARN] After-snapshot was not written - skipping the diff.
    ) else (
        powershell -NoProfile -ExecutionPolicy Bypass -File "!SCC_DP0!diff-snapshots.ps1" -BeforeFile "!SCC_RUN_ROOT!\snapshot_before.json" -AfterFile "!SCC_RUN_ROOT!\snapshot_after.json" -OutFile "!SCC_RUN_ROOT!\snapshot_diff.json"
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

rem ---- Step 9: report + MicroBin share ----------------------------------------
echo.
echo  STEP 9/9: Report
if not defined FINDINGS_JSON (
    echo     [WARN] No current-run findings.json available - skipping report.
) else (
    if exist "!FINDINGS_JSON!" (
    if exist "!SCC_RUN_ROOT!/removal-manifest.json" (
        powershell -NoProfile -ExecutionPolicy Bypass -File "!SCC_DP0!New-InvestigationReport.ps1" -FindingsJson "!FINDINGS_JSON!" -RemovalManifest "!SCC_RUN_ROOT!/removal-manifest.json" -PersistenceInventory "!SCC_RUN_ROOT!\persistence\inventory.json" -PersistenceRemoval "!SCC_RUN_ROOT!\persistence\removal.json" -PersistenceResult "!SCC_RUN_ROOT!\persistence\result.json" -PowerOptionsRepair "!SCC_RUN_ROOT!/power-options-repair.json" -OutputPath "!SCC_RUN_ROOT!/report.html"
    ) else (
        powershell -NoProfile -ExecutionPolicy Bypass -File "!SCC_DP0!New-InvestigationReport.ps1" -FindingsJson "!FINDINGS_JSON!" -PersistenceInventory "!SCC_RUN_ROOT!\persistence\inventory.json" -PersistenceRemoval "!SCC_RUN_ROOT!\persistence\removal.json" -PersistenceResult "!SCC_RUN_ROOT!\persistence\result.json" -PowerOptionsRepair "!SCC_RUN_ROOT!/power-options-repair.json" -OutputPath "!SCC_RUN_ROOT!/report.html"
    )
        set "REPORT_RC=!errorlevel!"
        set "REPORT_OPENED=0"
        if not "!REPORT_RC!"=="0" (
            echo     [WARN] Report generation failed with errorlevel !REPORT_RC! - see the messages above.
            if "!PIPE_RC!"=="0" set "PIPE_RC=!REPORT_RC!"
        )
        if exist "!SCC_RUN_ROOT!/report.html" (
            echo     [i] Report written to !SCC_RUN_ROOT!/report.html
            if exist "!SCC_DP0!Submit-ConnectWiseReport.ps1" (
                rem MicroBin share is automatic (no relay): the uploader reads the
                rem server base URL from microbin-url.txt beside the tool.
                powershell -NoProfile -ExecutionPolicy Bypass -File "!SCC_DP0!Submit-ConnectWiseReport.ps1" -FindingsJson "!FINDINGS_JSON!" -WorkDir "!SCC_RUN_ROOT!" -ReportHtml "!SCC_RUN_ROOT!/report.html" -PersistenceInventory "!SCC_RUN_ROOT!\persistence\inventory.json" -PersistenceRemoval "!SCC_RUN_ROOT!\persistence\removal.json" -PersistenceResult "!SCC_RUN_ROOT!\persistence\result.json"
                set "UPLOAD_RC=!errorlevel!"
                if not "!UPLOAD_RC!"=="0" (
                    echo     [WARN] Report share failed with errorlevel !UPLOAD_RC! - local evidence remains available.
                    if "!PIPE_RC!"=="0" set "PIPE_RC=!UPLOAD_RC!"
                )
            ) else (
                echo     [WARN] Submit-ConnectWiseReport.ps1 missing - local report was kept but not shared.
                if "!PIPE_RC!"=="0" set "PIPE_RC=1"
            )
            rem Upload/annotation finishes before opening or copying the report.
            rem Owner directive 2026-08-27: open the report folder + report.
            explorer /select,"!SCC_RUN_ROOT!/report.html"
            start "" "!SCC_RUN_ROOT!/report.html"
            if not errorlevel 1 set "REPORT_OPENED=1"
            rem Owner directive 2026-09-06: also leave a copy of report.html on
            rem the current user's Desktop. The run-root original is preserved;
            rem a failed copy is reported visibly (never silent) and marks the
            rem run, but never hides the local report.
            powershell -NoProfile -ExecutionPolicy Bypass -Command "$d=[Environment]::GetFolderPath('Desktop'); if(-not $d){$d=Join-Path $env:USERPROFILE 'Desktop'}; Copy-Item -LiteralPath '!SCC_RUN_ROOT!\report.html' -Destination (Join-Path $d 'report.html') -Force -ErrorAction Stop; Write-Host ('[i] Report copy on Desktop: ' + (Join-Path $d 'report.html'))"
            if errorlevel 1 (
                echo     [WARN] Could not copy report.html to the current user's Desktop - see the message above.
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
if not "!POWER_REPAIR_RAN!"=="1" goto :skip_optional_reboot
if not "!REPORT_RC!"=="0" goto :skip_optional_reboot
if not "!REPORT_OPENED!"=="1" goto :skip_optional_reboot
set "REBOOT="
echo.
echo  The report was opened above. Restart closes apps without warning and may lose unsaved work.
echo  Command: shutdown /r /t 0 /f
set /p REBOOT="    Restart now through CMD? [y/N] "
if /i not "!REBOOT!"=="y" goto :skip_optional_reboot
set "REBOOT="
echo     Running cmd.exe /d /c "shutdown /r /t 0 /f"
cmd.exe /d /c "shutdown /r /t 0 /f"
if errorlevel 1 echo     [WARN] Restart was denied. Do not force power off except as a last resort; unsaved data may be lost.
:skip_optional_reboot
set REBOOT=
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

:battery_not_confirmed
echo.
echo [CANCELLED] Battery warning was not confirmed. No cleanup stages ran.
pause
exit /b 1

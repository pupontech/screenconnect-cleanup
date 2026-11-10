@echo off
rem ============================================================================
rem  START-HERE.bat - guided runner for the ScreenConnect Cleanup Tool
rem  Steps 1-4 and 8-9 run automatically (tool download, preflight, snapshots,
rem  detection, diff, report share). Step 5 asks ONE typed confirmation before
rem  ScreenConnect removal. Steps 6-7 launch attended scanner/AV-uninstall work.
rem  Self-elevates.
rem  Requires explicit confirmation before starting when AC power is disconnected.
rem  Pure ASCII, no BOM.
rem
rem  SPLIT (offline / online halves). With no flag this is the full pipeline,
rem  unchanged. Technicians start one of the two launchers, which pass one flag:
rem    --offline  START-HERE-OFFLINE.bat  cleanup that needs NO internet: preflight,
rem               snapshots, detection, removal, persistence review, diff, local
rem               report. No downloads, no scanners, no upload. Shown as steps 1-7.
rem               It asks whether any ScreenConnect should be KEPT (same as --select).
rem    --online   START-HERE-ONLINE.bat   everything that needs internet: stage the
rem               scanners, run KVRT/ESET/Malwarebytes, AV uninstall, share the
rem               report. Continues the run folder the offline half left behind.
rem               Shown as steps 1-4.
rem  Flags with no launcher of their own: --stage (downloads only) and --select
rem  (pick instances to keep without being asked).
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

rem ---- Phase selection (offline / online split) ------------------------------
rem No phase flag = the full pipeline exactly as before. The flags are plain
rem arguments (not environment variables) so they survive the UAC relaunch below.
set "SCC_PHASE=ALL"
set "SCC_PHASE_ARG="
set "SCC_ELEV_ATTEMPTED=0"
set "SCC_SELECT=0"
rem No 'if defined' guard: an empty list simply runs the loop zero times.
for %%A in (!SCC_ARGS!) do (
    if /i "%%~A"=="--elevation-attempted" set "SCC_ELEV_ATTEMPTED=1"
    if /i "%%~A"=="--select" set "SCC_SELECT=1"
    if /i "%%~A"=="--offline" set "SCC_PHASE=OFFLINE"
    if /i "%%~A"=="--online" set "SCC_PHASE=ONLINE"
    if /i "%%~A"=="--stage" set "SCC_PHASE=STAGE"
)
if /i "!SCC_PHASE!"=="OFFLINE" set "SCC_PHASE_ARG=--offline"
if /i "!SCC_PHASE!"=="ONLINE" set "SCC_PHASE_ARG=--online"
if /i "!SCC_PHASE!"=="STAGE" set "SCC_PHASE_ARG=--stage"
rem --select (keep chosen legitimate ScreenConnect instances) travels through the UAC relaunch too.
if "!SCC_SELECT!"=="1" set "SCC_PHASE_ARG=!SCC_PHASE_ARG! --select"
set "SCC_DO_STAGE=1"
set "SCC_DO_PRE=1"
set "SCC_DO_SCAN=1"
set "SCC_DO_PERSIST=1"
set "SCC_DO_AVU=1"
set "SCC_DO_SHARE=1"
set "SCC_SUBMIT_ARGS="
set "SCC_SCANNER_ONLY=0"
if /i "!SCC_PHASE!"=="OFFLINE" (
    set "SCC_DO_STAGE=0"
    set "SCC_DO_SCAN=0"
    set "SCC_DO_AVU=0"
    set "SCC_DO_SHARE=0"
    set "SCC_SUBMIT_ARGS=-NoUpload"
)
if /i "!SCC_PHASE!"=="ONLINE" (
    set "SCC_DO_PRE=0"
    set "SCC_DO_PERSIST=0"
)
rem Download-only phase: needs neither admin rights nor a run folder.
if /i "!SCC_PHASE!"=="STAGE" goto :stage_only

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
    if "!SCC_ELEV_ATTEMPTED!"=="1" (
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
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath $env:SCC_SELF -ArgumentList ('--elevation-attempted ' + $env:SCC_PHASE_ARG) -Verb RunAs"
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

rem ---- Bind every artifact to a run root ---------------------------------------
rem Full pipeline and the offline half: a fresh run root. The online half instead
rem continues the run the offline half finished (so findings.json and the report it
rem built are shared), or starts a scanner-only run when there is none.
if /i "!SCC_PHASE!"=="ONLINE" goto :select_run_root
call :new_run_root
if not defined SCC_RUN_ROOT goto :run_setup_failed
goto :run_root_ready

:select_run_root
set "SCC_PRIOR_RUN="
set "SCC_PRIOR_FINDINGS=NONE"
for /f "usebackq tokens=1,2 delims=|" %%R in (`powershell -NoProfile -ExecutionPolicy Bypass -File "!SCC_DP0!tools\Find-OfflineRun.ps1"`) do (
    set "SCC_PRIOR_RUN=%%R"
    set "SCC_PRIOR_FINDINGS=%%S"
)
if defined SCC_PRIOR_RUN (
    echo     Finished offline-half run found for this PC:
    echo       !SCC_PRIOR_RUN!
    set "USE_PRIOR="
    set /p USE_PRIOR="    Continue that run? [Y/n] "
    if /i not "!USE_PRIOR!"=="n" (
        set "SCC_RUN_ROOT=!SCC_PRIOR_RUN!"
        if /i not "!SCC_PRIOR_FINDINGS!"=="NONE" set "FINDINGS_JSON=!SCC_PRIOR_FINDINGS!"
    )
    set "USE_PRIOR="
)
if not defined SCC_RUN_ROOT (
    echo     [i] No offline-half run is being continued: starting a scanner-only run.
    echo         There is no report to share from it. To clean this PC first, run
    echo         START-HERE-OFFLINE.bat.
    set "SCC_SCANNER_ONLY=1"
    call :new_run_root
    if not defined SCC_RUN_ROOT goto :run_setup_failed
)

:run_root_ready
echo     Run: !SCC_RUN_ROOT!
set "PIPE_RC=0"
set "POWER_REPAIR_RAN=0"

echo.
echo  ============================================================
if /i "!SCC_PHASE!"=="OFFLINE" goto :banner_offline
if /i "!SCC_PHASE!"=="ONLINE" goto :banner_online
echo   SCREENCONNECT CLEANUP - guided run
echo   Steps 1-4 and 8-9 run automatically. Step 5 asks ONE typed
echo   confirmation before removal. Ctrl+C aborts.
echo.
echo   1 toolpack  2 preflight  3 snapshot  4 detect  5 remove
echo   6 scanners  7 AV uninstall  8 diff  9 report
goto :banner_done
:banner_offline
echo   SCREENCONNECT CLEANUP - OFFLINE (no internet needed)
echo   Runs by itself except Step 4, which asks ONE typed
echo   confirmation before removal. Ctrl+C aborts.
echo.
echo   1 preflight  2 before snapshot  3 detect  4 remove
echo   5 persistence  6 after snapshot + diff  7 report
echo.
echo   Nothing is downloaded or uploaded. Afterwards, once the PC is
echo   online, run START-HERE-ONLINE.bat for the virus scans.
goto :banner_done
:banner_online
echo   SCREENCONNECT CLEANUP - ONLINE (needs internet)
echo   Run this after START-HERE-OFFLINE.bat, once the PC is online.
echo   Ctrl+C aborts.
echo.
echo   1 download scanners  2 virus scans  3 AV uninstall  4 share report
:banner_done
echo  ============================================================
echo.

rem ---- Step 1: tool pack + scanner staging (internet) -------------------------
if "!SCC_DO_STAGE!"=="0" goto :step1_done
if /i "!SCC_PHASE!"=="ONLINE" echo  STEP 1/4: Download the tool pack and the KVRT/ESET scanners
if /i not "!SCC_PHASE!"=="ONLINE" echo  STEP 1/9: Tool pack + KVRT/ESET staging (Malwarebytes fallback at Step 6)
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
:step1_done

rem ---- Steps 2-5 belong to the offline half (and the full run) ----------------
if "!SCC_DO_PRE!"=="0" goto :after_pre

rem ---- Step 2: preflight (ALWAYS runs - owner directive 2026-08-28) ---------
echo.
if /i "!SCC_PHASE!"=="OFFLINE" echo  STEP 1/7: Preflight
if /i not "!SCC_PHASE!"=="OFFLINE" echo  STEP 2/9: Preflight
set "SCC_PRE_ARGS="
if "!SCC_DO_STAGE!"=="0" set "SCC_PRE_ARGS=-SkipToolPack"
powershell -NoProfile -ExecutionPolicy Bypass -File "!SCC_DP0!preflight.ps1" -WorkingRoot "!SCC_RUN_ROOT!" !SCC_PRE_ARGS!
if errorlevel 1 goto :preflight_failed

rem ---- Step 3: BEFORE snapshot -----------------------------------------------
echo.
if /i "!SCC_PHASE!"=="OFFLINE" echo  STEP 2/7: Before snapshot
if /i not "!SCC_PHASE!"=="OFFLINE" echo  STEP 3/9: Before snapshot
powershell -NoProfile -ExecutionPolicy Bypass -File "!SCC_DP0!collect-snapshot.ps1" -Label before -OutFile "!SCC_RUN_ROOT!\snapshot_before.json" -Quiet
if errorlevel 1 goto :before_snapshot_failed
if exist "!SCC_RUN_ROOT!\snapshot_before.json" (
    echo     [i] Baseline saved.
) else (
    goto :before_snapshot_failed
)

rem ---- Step 4: detection -----------------------------------------------------
echo.
if /i "!SCC_PHASE!"=="OFFLINE" echo  STEP 3/7: Remote-access detection
if /i not "!SCC_PHASE!"=="OFFLINE" echo  STEP 4/9: Remote-access detection
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
    echo     [i] No findings.json found - removal and the report need it.
) else (
    echo     [i] Latest findings: !FINDINGS_JSON!
)

rem ---- Step 5: REMOVE (single typed confirmation) -----------------------------
echo.
if /i "!SCC_PHASE!"=="OFFLINE" echo  STEP 4/7: Review/remove ScreenConnect
if /i not "!SCC_PHASE!"=="OFFLINE" echo  STEP 5/9: Review/remove ScreenConnect
set "SCC_REVIEW_ARGS="
rem Offline half: ask whether any instance is supposed to stay (the customer's own
rem support agent, for example). y = select mode; Enter = remove all, as before.
rem Written without "defined": a contract test reads the first FINDINGS_JSON check as the review block.
if /i "!SCC_PHASE!"=="OFFLINE" if not "!SCC_SELECT!"=="1" if not "!FINDINGS_JSON!"=="" call :ask_keep
if "!SCC_SELECT!"=="1" (
    set "SCC_REVIEW_ARGS=-SelectKeep"
    echo    SELECT MODE: you first mark the legitimate instances to KEEP, then one
    echo    typed confirmation removes the rest.
) else (
    echo    One typed confirmation removes ALL detected ScreenConnect instances.
)
echo    Files are quarantined, never deleted.
if exist "!SCC_DP0!Invoke-ReviewAndRemove.ps1" (
    if defined FINDINGS_JSON (
        powershell -NoProfile -ExecutionPolicy Bypass -File "!SCC_DP0!Invoke-ReviewAndRemove.ps1" -FindingsJson "!FINDINGS_JSON!" -WorkDir "!SCC_RUN_ROOT!" !SCC_REVIEW_ARGS!
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

:after_pre

rem ---- Step 6: antivirus scans (internet) - online half only ---------------------
if "!SCC_DO_SCAN!"=="0" goto :scanners_skipped_phase
echo.
if /i "!SCC_PHASE!"=="ONLINE" echo  STEP 2/4: Antivirus scans (attended)
if /i not "!SCC_PHASE!"=="ONLINE" echo  STEP 6/9: Antivirus scans (attended)
echo    Each scanner opens visibly. Complete it, then return here.

echo.
if /i "!SCC_PHASE!"=="ONLINE" echo    -- 2a: KVRT --
if /i not "!SCC_PHASE!"=="ONLINE" echo    -- 6a: KVRT --
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
if /i "!SCC_PHASE!"=="ONLINE" echo    -- 2b: ESET Online Scanner --
if /i not "!SCC_PHASE!"=="ONLINE" echo    -- 6b: ESET Online Scanner --
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
if /i "!SCC_PHASE!"=="ONLINE" echo    -- 2c: Malwarebytes --
if /i not "!SCC_PHASE!"=="ONLINE" echo    -- 6c: Malwarebytes --
set /p GO="    Install and launch Malwarebytes now? [Y/n] "
if /i "%GO%"=="n" goto :skip_6c
if not exist "!SCC_RUN_ROOT!\logs" mkdir "!SCC_RUN_ROOT!\logs"
powershell -NoProfile -ExecutionPolicy Bypass -File "!SCC_DP0!Invoke-GUIScanner.ps1" -Scanner Malwarebytes -ResultPath "!SCC_RUN_ROOT!\logs\scanner-Malwarebytes-result.json"
if errorlevel 1 echo        [WARN] Malwarebytes wrapper exited with errorlevel !errorlevel! - see the result JSON and message above
echo        Malwarebytes session ended - continuing.
:skip_6c
set GO=
goto :after_scanners

:scanners_skipped_phase

:after_scanners
rem ---- Step 6d: mandatory persistence scan/review after AV scanners -----------
if "!SCC_DO_PERSIST!"=="0" goto :after_persist
echo.
if /i "!SCC_PHASE!"=="OFFLINE" echo  STEP 5/7: Persistence inventory and review
if /i not "!SCC_PHASE!"=="OFFLINE" echo  STEP 6d/9: Persistence inventory and review
rem Offline half only: the final inventory write timed out at the default 60 s on the first real PC, so give it more room.
set "SCC_PERSIST_ARGS="
if /i "!SCC_PHASE!"=="OFFLINE" set "SCC_PERSIST_ARGS=-InventorySectionTimeoutSeconds 240 -InventoryTotalTimeoutSeconds 600"
powershell -NoProfile -ExecutionPolicy Bypass -File "!SCC_DP0!Invoke-PersistenceScan.ps1" -WorkDir "!SCC_RUN_ROOT!" -PreflightRoot "!SCC_RUN_ROOT!" !SCC_PERSIST_ARGS!
set "PERSIST_RC=!errorlevel!"
if not "!PERSIST_RC!"=="0" (
    echo     [WARN] Persistence scan/review incomplete - exit !PERSIST_RC!; evidence will still be reported.
    if "!PIPE_RC!"=="0" set "PIPE_RC=!PERSIST_RC!"
)

rem ---- Step 6e: open the review windows for the technician ----------------------
echo.
if /i "!SCC_PHASE!"=="OFFLINE" echo  STEP 5b/7: Open review windows (no changes made)
if /i not "!SCC_PHASE!"=="OFFLINE" echo  STEP 6e/9: Open review windows (no changes made)
echo    Opens the evidence + startup folders, Services and Task Scheduler so you
echo    can inspect what the persistence scan flagged. Nothing is changed here.
set /p OPENREVIEW="    Open the review windows now? [Y/n] "
if /i "%OPENREVIEW%"=="n" goto :skip_6e
powershell -NoProfile -ExecutionPolicy Bypass -File "!SCC_DP0!Show-PersistenceReview.ps1" -WorkDir "!SCC_RUN_ROOT!"
if errorlevel 1 echo     [WARN] Some review windows could not be opened - see the messages above.
:skip_6e
set OPENREVIEW=
:after_persist

rem ---- Step 7: Uninstall installed AV (attended) - online half / full run ------
if "!SCC_DO_AVU!"=="0" goto :after_avu
echo.
if /i "!SCC_PHASE!"=="ONLINE" echo  STEP 3/4: Uninstall third-party AV (attended)
if /i not "!SCC_PHASE!"=="ONLINE" echo  STEP 7/9: Uninstall third-party AV (attended)
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
:after_avu

rem The online half ends here: nothing left but sharing the offline half's report.
if /i "!SCC_PHASE!"=="ONLINE" goto :online_share

rem ---- Step 8: AFTER snapshot + diff ------------------------------------------
echo.
if /i "!SCC_PHASE!"=="OFFLINE" echo  STEP 6/7: Optional power-options repair + after snapshot/diff
if /i not "!SCC_PHASE!"=="OFFLINE" echo  STEP 8/9: Optional power-options repair + after snapshot/diff
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
    echo     [WARN] No snapshot_before.json - the before snapshot was skipped, so there is
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
if /i "!SCC_PHASE!"=="OFFLINE" echo  STEP 7/7: Report (kept on this PC, not uploaded)
if /i not "!SCC_PHASE!"=="OFFLINE" echo  STEP 9/9: Report
set "SCC_KEPT_ARG="
if exist "!SCC_RUN_ROOT!\kept-instances.json" set "SCC_KEPT_ARG=-KeptInstances "!SCC_RUN_ROOT!\kept-instances.json""
if not defined FINDINGS_JSON (
    echo     [WARN] No current-run findings.json available - skipping report.
) else (
    if exist "!FINDINGS_JSON!" (
    if exist "!SCC_RUN_ROOT!/removal-manifest.json" (
        powershell -NoProfile -ExecutionPolicy Bypass -File "!SCC_DP0!New-InvestigationReport.ps1" -FindingsJson "!FINDINGS_JSON!" !SCC_KEPT_ARG! -RemovalManifest "!SCC_RUN_ROOT!/removal-manifest.json" -PersistenceInventory "!SCC_RUN_ROOT!\persistence\inventory.json" -PersistenceRemoval "!SCC_RUN_ROOT!\persistence\removal.json" -PersistenceResult "!SCC_RUN_ROOT!\persistence\result.json" -PowerOptionsRepair "!SCC_RUN_ROOT!/power-options-repair.json" -OutputPath "!SCC_RUN_ROOT!/report.html"
    ) else (
        powershell -NoProfile -ExecutionPolicy Bypass -File "!SCC_DP0!New-InvestigationReport.ps1" -FindingsJson "!FINDINGS_JSON!" !SCC_KEPT_ARG! -PersistenceInventory "!SCC_RUN_ROOT!\persistence\inventory.json" -PersistenceRemoval "!SCC_RUN_ROOT!\persistence\removal.json" -PersistenceResult "!SCC_RUN_ROOT!\persistence\result.json" -PowerOptionsRepair "!SCC_RUN_ROOT!/power-options-repair.json" -OutputPath "!SCC_RUN_ROOT!/report.html"
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
                powershell -NoProfile -ExecutionPolicy Bypass -File "!SCC_DP0!Submit-ConnectWiseReport.ps1" -FindingsJson "!FINDINGS_JSON!" -WorkDir "!SCC_RUN_ROOT!" -ReportHtml "!SCC_RUN_ROOT!/report.html" -PersistenceInventory "!SCC_RUN_ROOT!\persistence\inventory.json" -PersistenceRemoval "!SCC_RUN_ROOT!\persistence\removal.json" -PersistenceResult "!SCC_RUN_ROOT!\persistence\result.json" !SCC_SUBMIT_ARGS!
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
call :write_offline_marker
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
if /i "!SCC_PHASE!"=="OFFLINE" (
    echo.
    echo   OFFLINE HALF FINISHED. Nothing was downloaded or uploaded.
    echo   When this PC is online again, run START-HERE-ONLINE.bat to stage
    echo   and run the antivirus scanners and share the report.
)
pause
goto :done

rem ============================================================================
rem  Sections reached only through goto/call (never by falling through)
rem ============================================================================

:new_run_root
rem Creates the run folder for real. The original line piped New-Item to Out-Null with a
rem caret-escaped pipe, but a caret inside double quotes reaches PowerShell literally and
rem New-Item then failed (the folder only appeared later, when preflight created a nested
rem folder under it). No pipe here, so nothing needs escaping.
set "SCC_RUN_ROOT="
for /f "delims=" %%R in ('powershell -NoProfile -Command "$p=Join-Path 'C:\RIT-SCC' ($env:COMPUTERNAME + '-' + [guid]::NewGuid().ToString('N')); $null = New-Item -ItemType Directory -Path $p -Force; $p"') do set "SCC_RUN_ROOT=%%R"
exit /b 0

:ask_keep
echo    Is any ScreenConnect on this PC SUPPOSED to be there, for example the
echo    customer's own support agent? y = choose which ones to keep.
echo    Enter = remove all of them.
set "KEEPQ="
set /p KEEPQ="    Keep any ScreenConnect? [y/N] "
if /i "!KEEPQ!"=="y" set "SCC_SELECT=1"
set "KEEPQ="
exit /b 0

:write_offline_marker
if /i not "!SCC_PHASE!"=="OFFLINE" exit /b 0
powershell -NoProfile -ExecutionPolicy Bypass -File "!SCC_DP0!tools\Write-PhaseMarker.ps1" -RunRoot "!SCC_RUN_ROOT!" -Phase offline -FindingsJson "!FINDINGS_JSON!" -ExitCode !PIPE_RC!
if errorlevel 1 echo     [WARN] Could not record the offline-half marker - START-HERE-ONLINE.bat will not find this run by itself.
exit /b 0

:stage_only
echo.
echo  ============================================================
echo   STAGE TOOLS - needs internet
echo   Downloads the tool pack and the KVRT / ESET scanners into this
echo   folder. Run it on a connected PC, then copy this whole folder
echo   to the client PC for the offline half. Malwarebytes is not
echo   staged here: the online half installs it when it runs.
echo  ============================================================
echo.
cd /d "!SCC_DP0!"
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
echo.
echo  Staged in this folder:
if exist "!SCC_DP0!tools\AV\KVRT.exe" (echo     KVRT.exe .................. ready) else (echo     KVRT.exe .................. MISSING)
if exist "!SCC_DP0!tools\AV\esetonlinescanner.exe" (echo     esetonlinescanner.exe ..... ready) else (echo     esetonlinescanner.exe ..... MISSING)
if exist "!SCC_DP0!tools\manifest.json" (echo     Sysinternals tool pack .... ready) else (echo     Sysinternals tool pack .... MISSING)
echo.
echo  Staging finished. Copy this folder to the client PC, then run
echo  START-HERE-OFFLINE.bat there.
pause
exit /b 0

:online_share
echo.
echo  STEP 4/4: Share the report
set "SCC_REPORT_ARG="
if exist "!SCC_RUN_ROOT!\report.html" set "SCC_REPORT_ARG=-ReportHtml "!SCC_RUN_ROOT!\report.html""
if "!SCC_SCANNER_ONLY!"=="1" (
    echo     [i] Scanner-only run: there is no offline-half report, so nothing is shared.
    goto :online_done
)
if not defined FINDINGS_JSON (
    echo     [i] The offline-half run has no findings.json, so there is nothing to share.
    goto :online_done
)
if not exist "!SCC_DP0!Submit-ConnectWiseReport.ps1" (
    echo     [WARN] Submit-ConnectWiseReport.ps1 missing - the report was not shared.
    if "!PIPE_RC!"=="0" set "PIPE_RC=1"
    goto :online_done
)
powershell -NoProfile -ExecutionPolicy Bypass -File "!SCC_DP0!Submit-ConnectWiseReport.ps1" -FindingsJson "!FINDINGS_JSON!" -WorkDir "!SCC_RUN_ROOT!" !SCC_REPORT_ARG! -PersistenceInventory "!SCC_RUN_ROOT!\persistence\inventory.json" -PersistenceRemoval "!SCC_RUN_ROOT!\persistence\removal.json" -PersistenceResult "!SCC_RUN_ROOT!\persistence\result.json"
set "UPLOAD_RC=!errorlevel!"
if not "!UPLOAD_RC!"=="0" (
    echo     [WARN] Report share failed with errorlevel !UPLOAD_RC! - the local report and evidence remain on this PC.
    if "!PIPE_RC!"=="0" set "PIPE_RC=!UPLOAD_RC!"
) else (
    rem The share adds the paste link to report.html, so refresh the Desktop copy.
    if exist "!SCC_RUN_ROOT!\report.html" (
        powershell -NoProfile -ExecutionPolicy Bypass -Command "$d=[Environment]::GetFolderPath('Desktop'); if(-not $d){$d=Join-Path $env:USERPROFILE 'Desktop'}; Copy-Item -LiteralPath '!SCC_RUN_ROOT!\report.html' -Destination (Join-Path $d 'report.html') -Force -ErrorAction Stop; Write-Host ('[i] Report copy on Desktop refreshed: ' + (Join-Path $d 'report.html'))"
        if errorlevel 1 echo     [WARN] Could not refresh the Desktop copy of report.html - the run folder has the updated one.
    )
)
:online_done
if "!SCC_SCANNER_ONLY!"=="0" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "!SCC_DP0!tools\Write-PhaseMarker.ps1" -RunRoot "!SCC_RUN_ROOT!" -Phase online -FindingsJson "!FINDINGS_JSON!" -ExitCode !PIPE_RC!
)
set FINDINGS_JSON=
echo.
echo  ============================================================
echo   ONLINE HALF finished. Run artifacts: !SCC_RUN_ROOT!
echo   Scanner results are under logs\ in that folder.
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

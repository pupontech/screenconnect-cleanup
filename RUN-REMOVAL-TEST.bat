@echo off
rem ============================================================================
rem  RUN-REMOVAL-TEST.bat - LAB ONLY. Runs the full sc-cleanup.ps1 pipeline with
rem  removal PRE-AUTHORIZED (-ExecuteRemoval), so Stage 4 actually stops
rem  services, runs vendor uninstallers, quarantines files and cleans
rem  persistence instead of dry-running.
rem
rem  Use this on a disposable VM with a snapshot taken first. Do NOT run it on
rem  a client machine - use START-HERE.bat or sc-cleanup.ps1 (which asks for the
rem  typed confirmation) there.
rem
rem  Pure ASCII, no BOM. Run from an elevated command prompt.
rem ============================================================================

rem ---- Capture our own path/args BEFORE enabling delayed expansion --------
rem A folder name containing ( ) - e.g. the "name (1)" copy Windows creates
rem on a second extract - would otherwise end a ( ... ) block early at PARSE
rem time and abort this launcher with no message. !VAR! is substituted at run
rem time, after parsing, so it is safe for such paths.
set "SCC_DP0=%~dp0"
set "SCC_F0=%~f0"
set "SCC_ARG1=%~1"
setlocal EnableDelayedExpansion
title ScreenConnect Cleanup Tool - REMOVAL TEST

rem ---- Self-elevate: at most ONE UAC prompt, decided by the real admin token --
rem The script path travels via the SCC_SELF environment variable so that
rem apostrophes (and other quotes) in the path cannot break the PowerShell
rem command line. A failed/cancelled UAC prompt must be visible, never silent.
rem The relaunch passes --elevation-attempted; if that flag is present and this
rem window is STILL not elevated, stop instead of prompting again, so a probe
rem that misreports elevation can never loop UAC.
set "SCC_SELF=!SCC_F0!"
powershell -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "if(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){exit 0}else{exit 1}"
if errorlevel 1 (
    if /i "!SCC_ARG1!"=="--elevation-attempted" (
        echo.
        echo  [ERROR] This window is still not elevated after the UAC request, so
        echo          the tool will not ask again. Right-click RUN-REMOVAL-TEST.bat
        echo          and choose "Run as administrator".
        pause
        exit /b 1
    )
    echo  Requesting administrator privileges...
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

cd /d "!SCC_DP0!"

echo.
echo  ============================================================
echo   REMOVAL TEST RUN - THIS WILL ACTUALLY MAKE CHANGES
echo.
echo   Stage 4 will run for real: services stopped, uninstallers
echo   invoked, binaries moved to the quarantine folder, service
echo   registrations and persistence entries removed.
echo.
echo   Nothing is deleted - everything is quarantined with its
echo   original path and SHA256 recorded in removal-manifest.json.
echo.
echo   Take a VM snapshot BEFORE continuing.
echo  ============================================================
echo.

set /p GO="  Type YES to proceed: "
if /i not "%GO%"=="yes" (
    echo  Aborted - nothing was changed.
    pause
    exit /b 0
)
set GO=

set /p SKIPAV="  Skip the antivirus scanner stage (much faster)? [Y/n] "
set "AVFLAG=-sa"
if /i "%SKIPAV%"=="n" set "AVFLAG="
set SKIPAV=

powershell -NoProfile -ExecutionPolicy Bypass -File ".\sc-cleanup.ps1" -ExecuteRemoval %AVFLAG%
set "PIPE_RC=%ERRORLEVEL%"

echo.
echo  ============================================================
if "%PIPE_RC%"=="0" (
    echo   Pipeline exited 0.
) else (
    echo   [WARN] Pipeline exited %PIPE_RC% - review master.log and the report.
)
echo   Results are under the work directory the pipeline printed above:
echo     master.log             - full stage log
echo     plan.json              - what Stage 3 approved
echo     removal-manifest.json  - every action and its result
echo     quarantine\            - the files that were moved aside
echo     snapshot_diff.json     - before/after difference
echo     report.html            - the investigation report
echo  ============================================================
pause
exit /b %PIPE_RC%

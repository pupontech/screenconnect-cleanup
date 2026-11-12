@echo off
rem ============================================================================
rem  START-HERE-GUI.bat - the ScreenConnect Cleanup WINDOW (docs\14-gui-architecture.md).
rem  Same start-up as START-HERE.bat (one UAC request, battery check, keep-awake),
rem  then it opens gui\Start-CleanupGui.ps1 instead of running the steps in this
rem  console. The window runs the same scripts START-HERE.bat runs, one at a time.
rem
rem  The window toggles between the Offline half (no internet), the Online half,
rem  Detect only and Stage tools (no full run: that is Offline, then Online). It asks the same questions the
rem  batch files ask; removal needs the technician to type REMOVE. START-HERE.bat /
rem  START-HERE-OFFLINE.bat / START-HERE-ONLINE.bat are unchanged and remain the
rem  fallback.
rem
rem  This console stays open behind the window on purpose: if the window cannot
rem  load, the error is readable here. Do not add -NonInteractive anywhere: it
rem  makes Read-Host throw in the child scripts.
rem  Pure ASCII, no BOM, CRLF.
rem ============================================================================

rem ---- Capture our own path/args BEFORE enabling delayed expansion --------
rem Same reason as START-HERE.bat: a folder name such as "screenconnect-cleanup-v1.8.8 (1)"
rem breaks cmd because %~dp0 / %~f0 expand at PARSE time and the ( ) inside a ( ... )
rem block end it early. Delayed expansion (!VAR!) is substituted at RUN time.
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
title ScreenConnect Cleanup (window)

set "SCC_ELEV_ATTEMPTED=0"
for %%A in (!SCC_ARGS!) do (
    if /i "%%~A"=="--elevation-attempted" set "SCC_ELEV_ATTEMPTED=1"
)

rem ---- Self-elevate: at most ONE UAC prompt, decided by the real admin token ---
rem Identical rules to START-HERE.bat: the path travels via SCC_SELF so quotes in it
rem cannot break the command line, and --elevation-attempted stops a second prompt.
set "SCC_SELF=!SCC_F0!"
powershell -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "if(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){exit 0}else{exit 1}"
if errorlevel 1 (
    if "!SCC_ELEV_ATTEMPTED!"=="1" (
        echo.
        echo  [ERROR] This window is still not elevated after the UAC request, so
        echo          the tool will not ask again. Right-click START-HERE-GUI.bat and
        echo          choose "Run as administrator", or open an elevated Command
        echo          Prompt in this folder and run START-HERE-GUI.bat there.
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
powershell.exe -NoLogo -NoProfile -STA -ExecutionPolicy Bypass -File "!SCC_DP0!tools\Confirm-OnBattery.ps1"
if errorlevel 1 goto :battery_not_confirmed

rem ---- Keep the system and display awake for this runner only ----------------
start "" powershell.exe -NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "!SCC_DP0!tools\Keep-Awake.ps1"
if errorlevel 1 echo     [WARN] Keep-awake helper could not start; this computer may sleep during the run.

cd /d "!SCC_DP0!"

if not exist "!SCC_DP0!gui\Start-CleanupGui.ps1" (
    echo [ERROR] gui\Start-CleanupGui.ps1 is missing next to this file.
    echo         Use START-HERE.bat instead.
    pause
    exit /b 1
)

echo.
echo  ScreenConnect Cleanup - opening the window. Leave this console open.
echo.
rem -STA is required for WPF. The window runs elevated because this console is.
powershell -NoLogo -NoProfile -STA -ExecutionPolicy Bypass -File "!SCC_DP0!gui\Start-CleanupGui.ps1"
set "SCC_GUI_RC=!errorlevel!"
if not "!SCC_GUI_RC!"=="0" (
    echo.
    echo  [ERROR] The window ended with an error ^(exit !SCC_GUI_RC!^). Read the message above.
    echo          START-HERE.bat still works as before.
    pause
)
exit /b !SCC_GUI_RC!

:battery_not_confirmed
echo.
echo [CANCELLED] Battery warning was not confirmed. No cleanup stages ran.
pause
exit /b 1

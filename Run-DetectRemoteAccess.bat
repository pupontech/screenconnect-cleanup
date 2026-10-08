@echo off
REM Double-click launcher for detect-remote-access.ps1.
REM Must sit in the SAME FOLDER as detect-remote-access.ps1.
REM
REM Run this ON the machine you are investigating. READ-ONLY - it detects and
REM reports, it never stops, changes or removes anything.
REM
REM Right-click "Run as administrator" for the full picture: without admin the
REM System event log (service install history) is usually unreadable. The
REM report says so when that happens.

rem ---- Self-elevate: at most ONE UAC prompt, decided by the real admin token --
rem The script path and forwarded arguments travel via environment variables
rem (SCC_SELF / SCC_ARGS) so apostrophes cannot break the PowerShell command
rem line. A failed/cancelled UAC prompt must be visible, never silent.
rem The relaunch passes --elevation-attempted; if that flag is present and this
rem window is STILL not elevated, stop instead of prompting again, so a probe
rem that misreports elevation can never loop UAC.
set "SCC_SELF=%~f0"
set "SCC_ARGS=%*"
powershell -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "if(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){exit 0}else{exit 1}"
if errorlevel 1 (
    if /i "%~1"=="--elevation-attempted" (
        echo.
        echo [ERROR] This window is still not elevated after the UAC request, so
        echo         this script will not ask again. Right-click it and choose
        echo         "Run as administrator", or run it from an elevated prompt.
        pause
        exit /b 1
    )
    echo Requesting administrator privileges...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath $env:SCC_SELF -ArgumentList ('--elevation-attempted ' + $env:SCC_ARGS) -Verb RunAs"
    if errorlevel 1 (
        echo.
        echo [ERROR] Elevation could not be launched or was cancelled.
        echo         Right-click this script and choose "Run as administrator".
        pause
        exit /b 1
    )
    exit /b
)
set "SCC_SELF="
set "SCC_ARGS="

rem Drop the internal elevation marker before forwarding arguments onward.
set "SCC_FORWARD=%*"
if /i "%~1"=="--elevation-attempted" (
    for /f "tokens=1,*" %%A in ("%*") do set "SCC_FORWARD=%%B"
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0detect-remote-access.ps1" %SCC_FORWARD%
set "SCC_FORWARD="
if %errorlevel% neq 0 (
    echo.
    echo PowerShell exited with an error before its own pause could run.
    pause
)

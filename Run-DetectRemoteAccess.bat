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

rem ---- Self-elevate: relaunch as admin automatically if not already --------
fltmc.exe >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator privileges...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -ArgumentList '%*' -Verb RunAs" >nul 2>&1
    exit /b
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0detect-remote-access.ps1" %*
if %errorlevel% neq 0 (
    echo.
    echo PowerShell exited with an error before its own pause could run.
    pause
)

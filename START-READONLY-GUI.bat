@echo off
setlocal
if not exist "%~dp0ScreenConnectCleanup.Gui.exe" (
    echo ScreenConnectCleanup.Gui.exe is missing. Extract the complete prototype ZIP first.
    exit /b 2
)
start "" "%~dp0ScreenConnectCleanup.Gui.exe"
exit /b 0

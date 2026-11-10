@echo off
rem ============================================================================
rem  START-HERE-GUI.bat - top of the ScreenConnect Cleanup package.
rem  Double-click this to open the window. Everything else (the scripts, the
rem  console launchers, docs and tools) is in the "files" folder next to it;
rem  this file only starts files\START-HERE-GUI.bat, which asks for
rem  administrator rights once.
rem  Same hand-over pattern as START-HERE-OFFLINE.bat: %~dp0 is captured into a
rem  variable and used outside any ( ) block, so a folder name with parentheses
rem  - for example "screenconnect-cleanup (1)" - cannot break it.
rem  Pure ASCII, no BOM, CRLF.
rem ============================================================================
set "SCC_TOP_DP0=%~dp0"
if not exist "%SCC_TOP_DP0%files\START-HERE-GUI.bat" goto :missing
call "%SCC_TOP_DP0%files\START-HERE-GUI.bat" %*
exit /b %errorlevel%

:missing
echo.
echo  [ERROR] The "files" folder is missing next to this file.
echo          Extract the WHOLE zip (not just this file) and run it again.
echo.
pause
exit /b 1

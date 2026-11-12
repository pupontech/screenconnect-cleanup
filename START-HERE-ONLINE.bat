@echo off
rem ============================================================================
rem  START-HERE-ONLINE.bat - HALF 2 of 2: the steps that NEED internet.
rem  Runs: stage KVRT / ESET (and the tool pack), the attended antivirus scans
rem  (KVRT, ESET, Malwarebytes), the optional AV uninstall, then shares the
rem  sanitized report. It continues the run folder START-HERE-OFFLINE.bat left
rem  on this PC (one folder per run under C:\RIT-SCC); with none, it runs only the
rem  scanners.
rem  Pure ASCII, no BOM. Self-elevates (inside START-HERE.bat).
rem ============================================================================
set "SCC_W_DP0=%~dp0"
call "%SCC_W_DP0%START-HERE.bat" --online
exit /b %errorlevel%

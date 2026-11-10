@echo off
rem ============================================================================
rem  START-HERE-OFFLINE.bat - HALF 1 of 2: cleanup that needs NO internet.
rem  Runs: preflight, before snapshot, detection, ScreenConnect removal (typed
rem  confirmation), persistence review, after snapshot + diff, local report.
rem  Does NOT: download anything, run the antivirus scanners, uninstall AV, or
rem  upload the report. Safe to run with the network cable out / Wi-Fi off.
rem  Afterwards, when the PC is online again, run START-HERE-ONLINE.bat.
rem  Pure ASCII, no BOM. Self-elevates (inside START-HERE.bat).
rem ============================================================================
set "SCC_W_DP0=%~dp0"
call "%SCC_W_DP0%START-HERE.bat" --offline
exit /b %errorlevel%

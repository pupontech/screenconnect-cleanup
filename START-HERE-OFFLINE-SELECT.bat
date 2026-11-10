@echo off
rem ============================================================================
rem  START-HERE-OFFLINE-SELECT.bat - HALF 1 (no internet), with a choice of which
rem  ScreenConnect instances to KEEP as legitimate before the removal prompt.
rem  Same as START-HERE-OFFLINE.bat otherwise: nothing is downloaded or uploaded.
rem  Pure ASCII, no BOM. Self-elevates (inside START-HERE.bat).
rem ============================================================================
set "SCC_W_DP0=%~dp0"
call "%SCC_W_DP0%START-HERE.bat" --offline --select
exit /b %errorlevel%

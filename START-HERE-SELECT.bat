@echo off
rem ============================================================================
rem  START-HERE-SELECT.bat - the FULL run, but you choose which ScreenConnect
rem  instances to KEEP as legitimate before the removal prompt.
rem  Step 5 lists every detected instance (relay host, service, signature,
rem  install date); you type the numbers to keep, then one y/N removes the rest.
rem  Kept instances are never touched and are labelled KEPT in the report.
rem  Everything else is identical to START-HERE.bat (needs internet).
rem  Pure ASCII, no BOM. Self-elevates (inside START-HERE.bat).
rem ============================================================================
set "SCC_W_DP0=%~dp0"
call "%SCC_W_DP0%START-HERE.bat" --select
exit /b %errorlevel%

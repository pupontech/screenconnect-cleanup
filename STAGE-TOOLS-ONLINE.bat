@echo off
rem ============================================================================
rem  STAGE-TOOLS-ONLINE.bat - download-only. Run on a connected PC BEFORE a job:
rem  fetches the KVRT / ESET scanners and the tool pack into this folder, so the
rem  folder can be copied to a client PC and used with no connection. Needs no
rem  admin rights. Does not touch the PC it runs on beyond writing into tools\.
rem  Pure ASCII, no BOM.
rem ============================================================================
set "SCC_W_DP0=%~dp0"
call "%SCC_W_DP0%START-HERE.bat" --stage
exit /b %errorlevel%

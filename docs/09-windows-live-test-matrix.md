# Windows Live-Test Matrix (crash-path + destructive-safety remediation)

This document is the exact validation checklist for the 2026-08-26 remediation of
the PowerShell 5.1 crash paths and destructive-safety defects. All items below run
on a dedicated, disposable Windows lab VM under Windows PowerShell 5.1 unless noted.
NEVER run the destructive scenarios on a production machine. No ScreenConnect
software or vendor scanner executable is required for the synthetic checks; only
the final full-removal scenario involves a real (lab) installation.

## 0. Prerequisites

- Windows 10/11 or Server 2019/2022 lab VM, Windows PowerShell 5.1
  (`powershell.exe -NoProfile -Command "$PSVersionTable.PSVersion"` -> 5.1.x)
- Clean copy of the repository (deployment bundle from a released zip or git clone)
- If testing real removal: a disposable ScreenConnect installation inside the lab VM

## 1. Parse + contract suites (must pass on 5.1 BEFORE any scenario)

Run each of these from the repository root. Every one must print its OK/PASS line
and exit 0. Any parse error here is a release blocker.

    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\ci\Test-Parse.ps1
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\ci\Test-RemovalRuntimeContracts.ps1
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\ci\Test-PipelineLauncherContracts.ps1
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\ci\Test-ScannerProcessContracts.ps1
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\ci\Test-WindowsIntegration.ps1
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\ci\Test-HouseRules.ps1

Expected: "Parser check ... 0 with errors", "PASS: all pipeline-launcher contracts
hold", "Scanner-process contracts OK", removal runtime contracts OK, integration OK,
"House rules OK".

## 2. Stage 4 uninstaller execution (remove-screenconnect.ps1)

2.1 Bounded concurrent drain (synthetic, no vendor software)
    - Create a temporary console exe/script that floods BOTH stdout and stderr
      (each > 64 KiB), faster than the parent reads, then exits 0.
    - Confirm Run-BoundedProcess returns ExitCode 0 with complete StdOut/StdErr and
      does NOT hang.
2.2 Timeout termination (synthetic)
    - Create a temporary console exe that floods stderr and sleeps 10 minutes.
    - Call Run-BoundedProcess with TimeoutMs 3000. Expected: returns within ~5s,
      TimedOut=True, process killed and reaped (no orphan in Task Manager),
      StreamDrainTimedOut field present, no indefinite block.
2.3 Exit 3010 reboot-required path (synthetic manifest loop or real lab uninstaller)
    - Force the vendor uninstaller exit code to 3010.
    - Expected: manifest entry Result=Success with 3010 detail; NO manual surgery,
      NO Clean-Persistence on this pass; resume status becomes RebootPending (never
      Completed); the run schedules a post-reboot resume and exits nonzero/incomplete
      so the pipeline reports INCOMPLETE rather than success.
2.4 Failed uninstaller (exit 1603 or similar)
    - Expected: manifest Failed + manual surgery + quarantine fallback executes;
      status can never become Completed when any required action failed.
2.5 PS 5.1 parse gate
    - `powershell.exe -NoProfile -Command "[System.Management.Automation.Language.Parser]::ParseFile('...\remove-screenconnect.ps1',[ref]$null,[ref]$e); $e.Count"`
      must print 0 (no parse errors) - this specifically guards the former
      inline-if-expression regression.

## 3. Pipeline truthfulness (sc-cleanup.ps1)

3.1 Clean read-only run: `-sr` (snapshot only) must finish "All stages executed
    successfully" and exit 0.
3.2 Forced nonzero Stage 4 exit (e.g. failed restore point with confirmed removal,
    no -np): expect Stage 4 BLOCKED log, Stages 5-8 still run and produce
    manifest/diff/report evidence, console banner "PIPELINE COMPLETED WITH ERRORS",
    `echo %ERRORLEVEL%` -> 1 (not 0).
3.3 Restore-point gate: with -ExecuteRemoval and confirmed plan but restore point
    creation failing and NO -np -> destructive Stage 4 is blocked; with -np ->
    removal proceeds. Dry-run/-sr behavior unchanged.
3.4 Non-admin console run: preflight must NOT log "Admin check: PASSED" when the
    shell is not elevated.

## 4. Batch launchers (START-HERE.bat, RUN-REMOVAL-TEST.bat, Run-DetectRemoteAccess.bat)

4.1 Apostrophe path: copy the tool tree to `C:\temp\it's the cleanup\` and launch
    each .bat. Self-elevation must succeed without quoting errors.
4.2 UAC cancel: launch START-HERE.bat unelevated, click Cancel on the UAC prompt.
    Expected: visible [ERROR] elevation message, pause, and `echo %ERRORLEVEL%` -> 1
    (never a silent exit 0).
4.3 Run-DetectRemoteAccess.bat argument forwarding: pass a target argument; confirm
    it reaches detect-remote-access.ps1 after elevation (SCC_ARGS env forwarding).
4.4 Confirm fltmc privilege probe and default KEEP prompt semantics are unchanged.

## 5. Scanner adapters (Stage 5, ESET/KVRT)

5.1 WhatIf: both adapters with -WhatIf must return Skipped without spawning a
    process.
5.2 Chatty scanner (synthetic stand-in binary flooding stdout+stderr): no deadlock,
    output captured, exit-code mapping unchanged (ESET 0/50/10/100,
    KVRT report-file detection).
5.3 Hung scanner (synthetic stand-in that never exits): TimeoutMinutes respected,
    Status=Timeout with the new error string, process terminated, no orphan.
5.4 Real scanners (optional, lab only): run each adapter with a short
    TimeoutMinutes against the actual tool once installed, and confirm the
    StreamDrainTimedOut diagnostic never appears on a healthy scan.

## 6. Windows-integration strict-mode checks (Test-WindowsIntegration.ps1)

6.1 QuietUninstallString-only registration: dry-run must not crash with a
    StrictMode property error; manifest target falls back to QuietUninstallString.
6.2 Registration with NEITHER UninstallString nor QuietUninstallString: dry-run
    records a non-destructive Failed/Skipped manifest result and no ProcessInstance
    failure.

## 6b. FIELD VALIDATION (2026-08-26, machine INPIRON4SANITY2, real install)

A real removal ran on live Windows with ExecuteMode=true (manifest 2026-08-26
15:39 UTC). Evidence-backed results:

- ProductVerification Passed; ValidateUninstallKey Accepted (instance id
  763257a7941a63ef confirmed from DisplayName + install dir) -> M0 key-map
  identity path validated on a real install.
- No UninstallString present on the registration (tampered/damaged key case):
  recorded Skipped with the truthful "manual surgery will handle this instance"
  note, NOT Failed.
- Manual surgery completed: Quarantine Success (19 files hashed to
  quarantine-hashes-763257a7941a63ef.csv), DeleteService Success,
  DeleteUninstallKey Success (exported to .reg first), CleanPersistence
  Skipped (no artifacts). No reboot needed.

Defect found from this run and fixed (see commit that adds this note): the
main loop recorded a SECOND 'Uninstall' entry with Result=Failed and an EMPTY
Target on the no-uninstall-string path, so a successful surgery-run showed a
failed Uninstall. Fixed: Run-VendorUninstaller returns $null when nothing was
attempted (truthful Skipped entry already written); the main loop records the
decision as Action=UninstallFallback, Result=Planned, Target=DisplayName.
CI test updated to assert the new truth.
6.3 HKCU cleanup: after the test, the created GUID leaf is removed and the
    RIT-SCC-CI parent is removed only when empty.

## 7. Full end-to-end (optional, destructive, dedicated lab VM only)

7.1 Install ScreenConnect, confirm detection, run the cleanup pipeline with
    -ExecuteRemoval, and verify: approved plan contract honored, no cmd.exe shell
    execution of registry uninstall strings (log shows direct exe/msiexec
    invocation), quarantine-not-delete behavior, post-removal snapshot/diff/report
    produced, truthful final exit code.
7.2 Reboot case: force 3010 via /norestart msiexec semantics; after reboot the
    scheduled resume must complete persistence cleanup WITHOUT re-running the
    vendor uninstaller on a RebootPending instance.

## 8. Release gate summary

A release is blocked if ANY of the following fails on Windows PowerShell 5.1:
parse errors in any .ps1; any contract suite non-zero; a synthetic flood causing a
hang; a hung process surviving TimeoutMinutes; a failed/cancelled UAC producing
silent success; a failed Stage 4 producing exit 0 or a Completed resume marker.

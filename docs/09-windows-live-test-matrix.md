# Windows Live-Test Matrix (validation checklist, current for v1.7.37)

This document is the exact validation checklist for the ScreenConnect Cleanup
Tool. All items run on a dedicated, disposable Windows lab VM under Windows
PowerShell 5.1 unless noted. NEVER run the destructive scenarios on a
production machine. No ScreenConnect software or vendor scanner executable is
required for the synthetic checks; only the final full-removal scenario
involves a real (lab) installation.

Sections marked **[NEW v1.7.x]** cover behavior added since the 2026-08-26
remediation matrix and are the priority for the current validation pass.

## 0. Prerequisites

- Windows 10/11 lab VM, Windows PowerShell 5.1
  (`powershell.exe -NoProfile -Command "$PSVersionTable.PSVersion"` -> 5.1.x)
- Deployment bundle from the release zip (v1.7.31) or a git clone at HEAD
- If testing real removal: a disposable ScreenConnect installation in the lab VM

## 1. Parse + contract suites (must pass on 5.1 BEFORE any scenario)

Run each from the repository root. Every one must print its OK/PASS line and
exit 0. Any parse error here is a release blocker.

    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\ci\Test-Parse.ps1
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\ci\Test-RemovalRuntimeContracts.ps1
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\ci\Test-PipelineLauncherContracts.ps1
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\ci\Test-ScannerProcessContracts.ps1
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\ci\Test-WindowsIntegration.ps1
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\ci\Test-HouseRules.ps1

Expected: "Parser check ... 0 with errors", "PASS: all pipeline-launcher
contracts hold", scanner contracts OK (incl. the new agreement-flag and
no-NAS assertions), removal runtime contracts OK, integration OK,
"House rules OK".

## 2. Stage 4 uninstaller execution (remove-screenconnect.ps1)

2.1 Bounded concurrent drain (synthetic, no vendor software)
    - Create a temporary console exe/script that floods BOTH stdout and stderr
      (each > 64 KiB), faster than the parent reads, then exits 0.
    - Confirm Run-BoundedProcess returns ExitCode 0 with complete StdOut/StdErr
      and does NOT hang.
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
      if quarantine fails, service and uninstall registry metadata remain in place
      and the instance is incomplete. A vendor exit 0 requires payload/service
      postconditions; a false success must not be recorded.
2.5 PS 5.1 parse gate
    - `powershell.exe -NoProfile -Command "[System.Management.Automation.Language.Parser]::ParseFile('...\remove-screenconnect.ps1',[ref]$null,[ref]$e); $e.Count"`
      must print 0 (no parse errors).

## 3. Pipeline truthfulness (sc-cleanup.ps1)

3.1 Clean read-only run: `-sr` (snapshot only) must finish "All stages executed
    successfully" and exit 0.
3.2 Forced nonzero Stage 4 exit (e.g. failed restore point with confirmed removal,
    no -np): expect Stage 4 BLOCKED log, Stages 5-9 still run and produce
    manifest/diff/report evidence, console banner "PIPELINE COMPLETED WITH ERRORS",
    `echo %ERRORLEVEL%` -> 1 (not 0).
3.3 Restore-point gate: with -ExecuteRemoval and confirmed plan but restore point
    creation failing and NO -np -> destructive Stage 4 is blocked; with -np ->
    removal may proceed only when registry exports succeeded (a registry-export
    failure always blocks). Dry-run/-sr behavior unchanged.
3.4 Non-admin console run: preflight must NOT log "Admin check: PASSED" when the
    shell is not elevated.

**[NEW v1.7.18]**
3.5 results.json truth: after a run, `results.json` must carry non-null
    `AfterSnapshot`, `DiffPath` and `RemovalManifest` (these were read from the
    wrong stage before v1.7.18 and were always null on a normal run).

**[NEW v1.7.19]**
3.6 Launch-grace probe: launch a scanner that dies within 60s (e.g. point
    `-ToolPath` at a bogus-but-PE-valid exe). Expected: exit code 5,
    "SUSPICIOUS: ... exited Ns after launch with no surviving GUI process",
    and the report shows `ExitedEarly` - NEVER a completed scan.

**[NEW v1.7.21]**
3.7 Procmon stage (opt-in): run `sc-cleanup.ps1 -procmon -ProcmonRuntime 30 ...`.
    Expected: "Reproduce the resurrection now" guidance, a `.pml` written to
    `<WorkDir>\logs\Procmon\procmon-<stamp>.pml`, Stage 7 reports a successful
    capture; when the Stage 8 diff finds a resurrection, the log names the
    capture path and the resurrected paths to filter on. Without `-procmon`
    Stage 7 logs "SKIPPED (not requested via -procmon)".
3.8 Amcache: the snapshot's `Sections.Amcache` is present (progress ticks to
    18/18); if the artifact is absent, the section is empty with a
    `CollectionWarning`. A mount/read/unload failure is a `CollectionError` and
    sets `CollectionComplete=false`. `diff-snapshots.ps1` treats Amcache as a
    stable section. The implementation temporarily mounts the hive with
    `reg.exe load`; it reuses a pre-existing mount without unloading it, and
    checks unload status for mounts it owns. Confirm those paths on Windows
    before release.
3.8a ShimCache: the candidate records only raw blob metadata (length/hash/header)
    plus an explicit decoder limitation; it must not claim decoded cached paths.
    A future parser needs Windows 8.1/10/11 fixtures and cross-checks against a
    trusted parser before the section can emit path rows.
**[NEW v1.7.26]**
3.9 Debug logger: run `sc-cleanup.ps1 -Debug -sr ...` (and `preflight.ps1
    -Debug`). Expected: "DEBUG LOGGER ACTIVE - transcript: ..." on the
    console, `<WorkDir>\logs\debug.log` written containing EVERYTHING the
    console showed (including child-script output) plus per-stage result
    lines with timing, and the final summary prints "Debug log: <path>".
    This file is what to send back when a field issue needs debugging.

## 4. Batch launchers (START-HERE.bat, RUN-REMOVAL-TEST.bat, Run-DetectRemoteAccess.bat)

4.1 Apostrophe path: copy the tool tree to `C:\temp\it's the cleanup\` and launch
    each .bat. Self-elevation must succeed without quoting errors.
4.2 UAC cancel: launch START-HERE.bat unelevated, click Cancel on the UAC prompt.
    Expected: visible [ERROR] elevation message, pause, and `echo %ERRORLEVEL%` -> 1
    (never a silent exit 0).
4.3 Run-DetectRemoteAccess.bat argument forwarding: pass a target argument; confirm
    it reaches detect-remote-access.ps1 after elevation (SCC_ARGS env forwarding).

**[NEW v1.7.24]**
4.4 Preflight always runs: START-HERE.bat Step 2 runs preflight.ps1. If free space
    is below the minimum, it prints the measured amount and asks "Continue anyway?"
    in the same command window. Only an explicit Y/Yes continues; blank, no, or an
    invalid answer aborts. Direct `sc-cleanup.ps1` runs the same 10 GB check at
    startup; `-MinFreeGB` records any explicitly configured threshold. Step 4 runs
    detection automatically; Step 5 requires typed per-instance review plus a final
    confirmation. Detection and removal artifacts are bound to a fresh run directory,
    and a failed detection cannot fall back to older findings.
4.5 UAC-disabled prompt-and-wait: on a machine with EnableLUA=0 (or a test that
    fakes it), run sc-cleanup.ps1 and preflight.ps1. Expected: prominent red
    banner with the `reg add ... EnableLUA ... /d 1` command, then a WAIT for
    "Type Y once UAC is enabled, or F to force-continue". Only explicit Y or F
    is accepted; blank or invalid input aborts with an error. Y re-checks and
    continues (log: "UAC check: enabled (confirmed after user action)"; a
    pending-reboot machine logs the "still reads disabled" warning and
    continues on your confirmation). F force-continues and logs the finding.
    -force/-Force still bypasses the prompt entirely. Owner field confirmation
    (2026-08-30): KVRT launches and works with UAC disabled. The scanner still
    emits the "[WARN] UAC is DISABLED" banner and records `UacDisabled: true`;
    a genuine early exit remains `ExitedEarly` (exit 5).

## 5. Scanner downloads and attended GUI launches (Stage 5)

**[NEW v1.7.22/23/25/35]**
  5.1 `tools\Get-AVTools.ps1` on a lab network: downloads/stages KVRT.exe and
     esetonlinescanner.exe from the official vendor URLs only. Expected output:
     `(BITS) KVRT.exe` and `(BITS) esetonlinescanner.exe` (BITS engine, v1.7.25;
     v1.7.35 adds a visible PowerShell progress bar while the asynchronous job
     is transferring). A machine with BITS disabled falls back to
     Invoke-WebRequest with its expensive renderer suppressed. KVRT (~114 MB)
     should stage in seconds-to-a-minute on a normal link, not many minutes.
     **FIELD-CONFIRMED 2026-08-28 on VMs:** the BITS + polling path is faster
     than the old Invoke-WebRequest progress-bar download; v1.7.35 now exposes
     that polling as a real progress bar instead of a text-only carriage-return
     line.
    - NO NAS/share fallback exists (v1.7.22): there is no InternalShare
      parameter and nothing ever copies from a network share.
    - A failed download prints `FAILED to stage: <tools>` and exits 1 (v1.7.23) -
      never a silent green exit with nothing staged.
5.2 `Invoke-GUIScanner.ps1 -Scanner KVRT`: launches a visible GUI and waits.
    KVRT is a SELF-EXTRACTOR (proven on Windows VMs 2026-08-30): the parent
    KVRT.exe exits ~7-8s after launch and hands off to a random-named child
    process. The tool logs "launcher exited after Ns but child <name>.exe is
    still running - waiting on the child GUI" and keeps waiting. A child that
    dies instantly is reported as ExitedEarly (exit 5), never Completed - the
    usual cause on a real machine is the machine's own AV killing the extracted
    child or a dismissed UAC prompt for it. With UAC disabled (EnableLUA=0) the
    tool warns before launching that KVRT/ESET commonly exit immediately and
    records `UacDisabled: true` in the result JSON (v1.7.27).
5.3 `Invoke-GUIScanner.ps1 -Scanner ESET`: launches a visible GUI and waits;
    no scan/clean flags are passed.
5.4 `Invoke-GUIScanner.ps1 -Scanner Malwarebytes`: runs
    `winget install -e --id Malwarebytes.Malwarebytes --accept-package-agreements
    --accept-source-agreements` (v1.7.24 - no agreement prompts, msstore/source
    accepted by default), visible console, and waits; then launches the
    Malwarebytes GUI. If the bootstrapper exits before the scan finishes, the
    guided START-HERE runner still tells the technician to wait manually.
5.5 Missing-tool paths: each scanner exits 3 with the clear "stage it first"
    message; the top-level Stage 5 records NotInstalled and continues.

**[NEW v1.7.18]**
5.6 Report scanner status: after a Stage 5 run, report.html contains a
    "Antivirus / malware scanners" section with each scanner's Tool/Status/
    Exit code. With `-sa`, the report says "Scanners were SKIPPED for this run"
    - it never implies a clean malware verdict when nothing ran.

## 6. Windows-integration strict-mode checks (Test-WindowsIntegration.ps1)

6.1 QuietUninstallString-only registration: dry-run must not crash with a
    StrictMode property error; manifest target falls back to QuietUninstallString.
6.2 Registration with NEITHER UninstallString nor QuietUninstallString: dry-run
    records a non-destructive Failed/Skipped manifest result and no ProcessInstance
    failure.

## 6b. FIELD VALIDATION (2026-08-26, machine INPIRON4SANITY2, real install) - historical record

A prior owner-reported real removal (2026-08-26, before the v1.7.32
identity/signature and deferred-hash hardening) recorded the following evidence:

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
- KVRT attended-GUI launch confirmed in the field on v1.7.19 (2026-08-28),
  including owner confirmation that it works with UAC disabled on 2026-08-30;
  owner also reports ESET/Malwarebytes are fine. The 3010 reboot-resume lab run
  remains outstanding (docs/10).

## 6c. AV-uninstall leftover sweep (v1.7.5, owner directive 2026-08-27)

`Invoke-AVUninstaller.ps1` sweeps leftovers after every uninstall attempt and
MOVES them (never deletes) to `<LogDir>\av-uninstall-quarantine`.

6c.1 On a machine with ESET installed, run Step 7. After the vendor uninstaller
      window closes, confirm the script reports the leftover sweep with N
      item(s) moved.
6c.2 Confirm the ESET Start Menu folder and Program Files\ESET are GONE from
      their original locations and present under
      av-uninstall-quarantine\<product>-<stamp>\.
6c.3 Confirm non-ESET folders (e.g. a decoy other-vendor folder) were NOT
      touched, and av-uninstall-results.json carries LeftoversMoved + the
      quarantine path (rendered in the report's AV section).
6c.4 Re-run with -NoLeftoverSweep: the sweep is skipped (leftovers stay).

## 7. Full end-to-end (optional, destructive, dedicated lab VM only)

7.1 Install ScreenConnect, confirm detection, run the cleanup pipeline with
    -ExecuteRemoval, and verify: approved plan contract honored, no cmd.exe shell
    execution of registry uninstall strings (log shows direct exe/msiexec
    invocation), reparse-point rejection, recursive quarantine ACL verification,
    quarantine-not-delete behavior, post-removal snapshot/diff/report produced,
    truthful final exit code, and no false completion when a vendor uninstaller
    leaves a payload or service behind.
7.2 Reboot case: force 3010 via /norestart msiexec semantics; after reboot the
    scheduled resume must validate script/plan hashes, deferred source/destination
    identity, containment, and destination ACLs, then complete persistence cleanup
    WITHOUT re-running the vendor uninstaller on a RebootPending instance.

## 7b. Installer (install-latest.ps1) **[NEW v1.7.20]**

7b.1 Run the one-liner twice: `irm https://raw.githubusercontent.com/
    pupontech/screenconnect-cleanup/main/install-latest.ps1 | iex`.
    First run installs the version folder and launches START-HERE.bat. Second
    run prints "already installed and up to date", does NOT re-download, and
    launches the existing folder (no hard error).
7b.2 `-Force` re-extracts; a folder missing VERSION or START-HERE.bat is
    auto-repaired (re-installed fresh).

## 8. Release gate summary

A release is blocked if ANY of the following fails on Windows PowerShell 5.1:
parse errors in any .ps1; any contract suite non-zero; a synthetic flood causing
a hang; a hung process surviving TimeoutMinutes; a failed/cancelled UAC
producing silent success; a failed Stage 4 producing exit 0 or a Completed
resume marker; results.json showing null AfterSnapshot/DiffPath/RemovalManifest
after a normal run; a scanner that dies at launch being reported as Completed;
a failed scanner download exiting 0; the report omitting scanner status (or
implying clean when -sa was used); the UAC-disabled prompt not appearing (or
not waiting); the installer hard-erroring on a same-version re-run.

# Changelog

Semantic versions. The deploy zip is named `screenconnect-cleanup-v<VER>.zip`
and carries a `VERSION` file so each build is self-identifying.

## [1.7.33] - 2026-09-01
- Shortened the guided runner's command-prompt banners and repeated policy text
  while preserving decision prompts, destructive warnings, filter-block alerts,
  and the current-run artifact path. Added PowerShell 5.1/pwsh output contracts.
- Compacted the `sc-cleanup.ps1` pipeline console output: stage sections are one
  line (`== STAGE n: Name ==`), the redundant "Starting Stage" line is
  debug-only, stage-0/final environment and path pairs print once, per-scanner
  session chatter and the duplicate completion banner are gone. Child snapshot
  runs use `-Quiet` while collection-error warnings stay visible. Shortened
  UAC/removal/diff/procmon wording, Malwarebytes diagnostics tails, tool-pack
  and AV-staging summaries, and the early-exit alarm. `RUN-REMOVAL-TEST.bat`
  now reports the pipeline's real exit code instead of an unconditional Done.
- Fixed the Windows integration fixture to use an approved synthetic uninstall
  root and supplied the isolated uninstaller test's path-containment shim.

## [1.7.32] - 2026-08-31
Safety and correctness hardening from the read-only audit:
- Bound the guided runner to a fresh per-run artifact directory; failed detection,
  preflight, and removal now stop the destructive path instead of using stale
  findings. Automatic `-Yes` approval is rejected.
- Added plan schema/provenance checks: explicit confirmation, detector tool/run
  identity, source hash, and current-computer binding are required for execute mode.
- Registry export failures and non-elevated destructive execution now fail closed.
- Quarantine paths are canonicalized and contained; the quarantine root receives
  restrictive Windows ACLs. Deferred moves remain `RebootPending` until a later
  run verifies source disappearance and destination existence; resume uses a
  highest-privilege scheduled task.
- Removed global process-kill fallback and made persistence enumeration failures
  visible failures. Added Authenticode identity checks for execute-mode binaries.
- AV uninstall strings are parsed and launched directly without `cmd.exe /c`,
  registry-derived AV cleanup paths are constrained to product roots, Malwarebytes
  launch failures are no longer reported as completed scans, and stale tool
  manifests are revalidated.
- Forensic-history snapshot additions are informational, missing sections count as
  zero, and duplicate keys are reported instead of overwritten.
- Diff field comparison preserves nested/array values under PowerShell 5.1;
  BAM/DAM timestamps use native full registry paths; parallel snapshot groups have
  a bounded timeout; and the report receives the removal manifest plus normalized
  singleton/empty summary counts.
- The guided runner aborts when the baseline snapshot is missing and waits through
  the Malwarebytes GUI using the common validated scanner wrapper.
- Malwarebytes install failures now run read-only diagnostics against the official
  download endpoint and collect DNS, proxy, hosts-file, installed-filter, and
  block-page evidence. Techloq and common web filters are named when indicated;
  possible blocking is shown to the technician, persisted in the per-scanner JSON,
  surfaced in the HTML report, and returns distinct exit code 6. No scan is claimed
  when winget fails.
- Added focused safety regression contracts and updated version identifiers.
- Fixed child-process initialization and native `reg.exe` stderr handling under
  Windows PowerShell `Stop`; execute-mode identity checks now consume the
  detector's `MainExe` and quoted service command lines.
- Reboot resume now requires prior manifest identity proof and uses the same
  guard for its post-reboot branch; scheduled-task names and plan uninstall
  registry paths are collision-safe/root-constrained. Resume-marker write
  failures now abort the initial execute path or force an incomplete result.
- Stage 0 now runs tool-pack and AV staging helpers in isolated Windows
  PowerShell child processes so helper `exit` codes cannot terminate the main
  orchestrator; nonzero staging remains a visible nonfatal warning.
- ShimCache is conservatively recorded as raw metadata (length/hash/header)
  with an explicit decoder limitation until Windows 8.1/10/11 fixtures validate
  a format-specific parser.
- Amcache's temporary hive mount now reuses a pre-existing mount, unloads only mounts
  owned by this collector, checks unload status, and records modern field-name
  fallbacks; application inventory is not described as execution proof.
- `-np` waives only a failed restore point; registry-export failure always blocks
  destructive removal. Manual service/uninstall-key surgery is skipped when
  quarantine fails, and process matching uses literal canonical containment.
- BAM/DAM uses the registry value name as `ProgramPath`, decodes the REG_BINARY
  FILETIME into `LastExecutionUtc`, and retains raw value bytes/length.
- Collection errors now mark snapshots incomplete while intentional limitations are
  warnings; timed-out sections cannot produce a false-clean diff. Srum comparison
  ignores timestamped offline-copy paths, targeted Srum/Amcache collection is
  supported, and the diff status is rendered in the HTML report and final pipeline
  outcome.
- The guided review wrapper runs the removal engine in a child PowerShell host so
  the remover's exit code cannot terminate the wrapper before its status report.

## [1.7.31] - 2026-08-30
Fixed a preflight startup failure introduced by the debug logger:
- `preflight.ps1` uses `[CmdletBinding()]`, which already supplies PowerShell's
  common `-Debug` parameter. Its explicit duplicate `[switch]$Debug` declaration
  caused `ParameterNameAlreadyExistsForCommand` before any preflight or UAC
  logic could run.
- Removed the duplicate declaration while retaining the built-in `-Debug`
  switch and transcript logger behavior.
- Added a runtime preflight self-test contract so duplicate parameter metadata
  failures are caught in CI.
- Verified with PowerShell 7 locally; Windows PowerShell 5.1 remains covered by
  the Windows CI matrix.

## [1.7.30] - 2026-08-28
KVRT "skipped totally when UAC is disabled" (owner report) - root cause was
NOT UAC: the guided runner's scanner prompts defaulted to NO.
- START-HERE.bat Steps 6a/6b/6c (KVRT, ESET, Malwarebytes) were
  `Launch ...? [y/N]` - pressing Enter SKIPPED the scanner entirely. On a
  no-UAC machine the chain was: UAC prompt -> F (force-continue) -> Step 6a
  default-NO -> KVRT never launched. All three now default to YES
  (`[Y/n]`, run unless you type `n`), matching the run-scanners-by-default
  intent. Step 1 was already `[Y/n]`.
- Steps 8/9 (Tikun + installed-AV uninstall) remain explicit opt-in - they
  are removal actions and stay decision-gated.
- Verified: CRLF + ASCII house rules pass; bat contracts pass; diff shows
  only the prompt lines changed.

## [1.7.29] - 2026-08-28
BITS downloads now show a live progress line (owner report: "bits is not
showing a download progress bar"):
- `Get-AVTools.ps1` runs the BITS transfer ASYNCHRONOUSLY and polls
  `Get-BitsTransfer` every second, rendering an in-place progress line:
  `KVRT.exe: 47% (53.7 / 114.1 MB)` (updates only when the percent changes;
  no console spam). Completion via `Complete-BitsTransfer`; BITS Error state
  reports `ErrorDescription`; a 20-minute watchdog bounds a stalled job
  (then the existing IWR fallback takes over). The IWR fallback path is
  unchanged.
- Verified: parse/ASCII clean; contract suites green; the async poll loop
  exercised against the REAL extracted function with mocked BITS cmdlets
  (Transferring 50MB/100MB -> Transferred): progress line "50% (50 / 100 MB)"
  rendered, Complete-BitsTransfer called.

## [1.7.27] - 2026-08-28
KVRT on UAC-disabled machines (owner report: "kvrt still seems bugged on no
uac on .24"):
- **Pre-launch UAC warning.** `Invoke-GUIScanner.ps1` now checks EnableLUA
  before launching KVRT/ESET; when UAC is disabled it warns prominently that
  these scanners typically exit immediately without UAC elevation semantics,
  prints the reg add EnableLUA command, and records `UacDisabled: true` in
  the result JSON. The ExitedEarly message (exit 5) now names UAC-disabled as
  a likely cause when applicable.
- **Reparenting-race fix in the hand-off check.** The KVRT self-extractor
  parent exits ~7-8s after launch; its extracted child can already have been
  reparented by the time Win32_Process is queried, so the old
  ParentProcessId-only lookup could miss it and report a FALSE ExitedEarly
  ("bugged") on a machine where KVRT actually launched. The check now falls
  back to scanner-family name + start-time evidence (kvrt|kaspersky|kav,
  eos|eset) before declaring an early exit.
- Both UAC prompt banners (sc-cleanup.ps1, preflight.ps1) now state that KVRT
  and ESET will likely fail to launch until UAC is enabled.
- CI: scanner contracts assert the UAC warning and the reparent fallback.
- Verified: parse/ASCII clean; contract suites green; the reparenting
  fallback logic exercised against the real extracted code with a mocked
  CIM query (parent lookup empty -> family/start-time fallback finds the
  child -> waits on it instead of ExitedEarly).

## [1.7.26] - 2026-08-28
Debug logger added (owner request: "add in a logger to help with debugging"):
- **`-Debug` on `sc-cleanup.ps1` and `preflight.ps1`** starts a full console
  transcript to `<WorkDir>\logs\debug.log` - EVERYTHING the console shows is
  captured, including child-script output, so a field issue can be debugged
  from one file (send that file back instead of pasting console text).
- Debug-level detail is emitted at the natural choke points: per-stage
  entry/result with timing, child-script exit codes, and the invocation
  flags at startup (`Write-Dbg`; console + transcript always, master.log
  only with -VerboseLog).
- Unhandled errors are named: a `trap` logs `UNHANDLED ERROR: <message> |
  <source location>` (position info), closes the transcript, prints the
  debug-log path and exits 1 - no more silent deaths in the field.
- CI: pipeline-launcher contracts gain C7 (debug switch, transcript, trap
  markers present in both scripts).
- Verified: parse/ASCII clean; full suite green; -Debug functional run on
  Linux (WhatIf path) produced the transcript with stage/child debug lines
  and the final "Debug log:" line.

## [1.7.25] - 2026-08-28
Scanner downloads sped up (KVRT is ~114 MB):
- **BITS first.** `Get-AVTools.ps1` now downloads through `Start-BitsTransfer`
  (the OS transfer engine - markedly faster than Invoke-WebRequest for
  100MB+ files) whenever BITS is available on Windows, with an automatic
  fallback to Invoke-WebRequest if BITS fails (403/UA rejection, BITS
  disabled by policy, service stopped).
- **Progress bar suppressed.** `$ProgressPreference = 'SilentlyContinue'` -
  IWR's rendered progress bar is a notorious large-download slowdown in
  PS 5.1 (can halve or worse the throughput of a 100MB+ file).
- Both CDNs verified to support HTTP ranges (206) - parallel chunking is a
  documented future option if BITS is ever unavailable on a field network.
- Verified: full live download of KVRT + ESET through the new path on Linux
  (BITS absent -> IWR fallback): 122 MB total, PE-validated, staged; parse/
  ASCII clean; contract suites green.

## [1.7.24] - 2026-08-28
Owner directives: winget agreements accepted by default; preflight always
runs; UAC-disabled becomes prompt-and-wait instead of a hard abort.
- **Malwarebytes winget install/uninstall now passes
  `--accept-package-agreements --accept-source-agreements`** (accept msstore/
  source agreements by default - the install can no longer stall on an
  interactive agreement prompt). Applied everywhere winget runs:
  `Invoke-GUIScanner.ps1` (install), `Invoke-AVUninstaller.ps1` (uninstall),
  `START-HERE.bat` Step 6c. Docs + CI contract assertions updated.
- **Preflight always runs.** `START-HERE.bat` Step 2 no longer asks - it runs
  `preflight.ps1` unconditionally.
- **UAC-disabled machines are no longer hard-aborted.** Both `sc-cleanup.ps1`
  and `preflight.ps1` now, when UAC is disabled (and no -force/-Force): print
  a prominent banner with the exact `reg add ... EnableLUA /d 1` command,
  prompt the user to enable UAC, WAIT for confirmation, re-check, and continue
  the preflight/pipeline. `F` at the prompt force-continues with UAC disabled
  (equivalent to -force) and logs the finding. The re-check honors a pending
  reboot ("reported enabled but EnableLUA still reads disabled").
- Verified: parse/ASCII clean; scanner contract suite green (new agreement-flag
  assertions); UAC prompt flow exercised against the real extracted code with
  a mocked UAC state (Y path re-checks and continues, F path force-continues
  with the finding logged).

## [1.7.23] - 2026-08-28
Two staging fixes found by the Windows VM scanner-launch probe:
- **Download failures are now loud.** `Get-AVTools.ps1` used to `exit 0`
  even when a download failed (`$null = Ensure-Tool ...`) - a 403 or network
  error silently produced "nothing staged" with a green exit. It now tracks
  per-tool failures and exits 1 with "FAILED to stage: <tools>" so callers
  and CI see the truth. sc-cleanup Stage 0 already treats a nonzero exit as
  "some tools unavailable".
- **Browser-like User-Agent on downloads.** The default PowerShell client UA
  gets `403 Forbidden` from Kaspersky's CDN on some egress IPs (observed
  live on GitHub Windows runners). Downloads now send a standard Chrome UA
  header. ESET unaffected but gets the same header for consistency.
- The scanner-launch probe workflow (windows-2022/2025) found these: KVRT
  launched correctly on Windows (parent exits ~7s, hands off to a child
  process - the v1.7.19 hand-off check waits on it; child still alive at the
  1-min cap), ESET staged OK. Verified: parse/ASCII clean, contract suites
  green.

## [1.7.22] - 2026-08-28
NAS/internal-share fallback removed from scanner staging (owner directive:
"remove all logic for nas just do fresh downloads ... keep it clean"):
- `tools/Get-AVTools.ps1` no longer has the `-InternalShare` parameter or the
  copy-from-`\\10.0.0.5\Public\Tools` fallback block. Staging is exclusively
  from the official vendor URLs (Kaspersky for KVRT, ESET for the Online
  Scanner); a failed download is a loud FAILED and the next run fetches fresh.
  The fallback could copy stale/corrupt copies from the share and masked the
  real download state - that whole class of field issue is gone.
- The skip-existing logic (valid copy already staged -> skip the ~150 MB
  re-fetch; -Force to refresh) is UNCHANGED - it is the v1.7.14 anti-re-
  download-loop behavior, not NAS logic.
- CI: Test-ScannerProcessContracts now asserts the script contains no
  internal-share path and no InternalShare parameter, so the fallback cannot
  silently return.
- Verified: parse/ASCII clean; scanner contract suite passes; no NAS
  references remain in the script.

## [1.7.21] - 2026-08-28
Two remaining builds landed (roadmap items M6 + Q4b#2):
- **M6 - Procmon stage is now real.** `sc-cleanup.ps1 -procmon` runs a bounded
  live capture: resolves Procmon64.exe from the tool pack (missing -> skipped
  non-fatally), captures for `-ProcmonRuntime` seconds (default 180) with
  `/AcceptEula /Quiet /Minimized /BackingFile <pml> /Runtime <sec>`, saves the
  .pml under `<WorkDir>\logs\Procmon\`, and logs what the technician should do
  (reproduce the resurrection during the window). The Stage 8 diff, when it
  detects a resurrection and a capture exists, points the technician at the
  .pml and the resurrected paths. Boot-logging and pre-built PMF path filters
  still need a GUI-set config (docs/07 Q6) - capture is intentionally
  full-scope for the bounded window.
- **Q4b#2 - Amcache collector implemented.** `collect-snapshot.ps1` now
  collects `C:\Windows\AppCompat\Programs\Amcache.hve` (reg.exe mount under
  HKLM\Amcache, InventoryApplicationFile + InventoryApplication, then
  unmount; admin-only, loud CollectionError on failure, never aborts). Keys
  are `AF:<FileId>` / `AP:<AppId>` so the before/after diff matches them
  stably. `diff-snapshots.ps1` treats Amcache as a stable section. Snapshot
  progress now runs to 18/18. Windows content path still needs the real-box
  cross-check called out in docs/07 Q4b#4 and docs/10.
- **NEW docs/10-field-test-pack.md** - owner-run checklists for the
  remaining field items: M0 relay-key capture (with belt-and-braces manual
  dump), 3010 reboot-resume, ESET/Malwarebytes confirmation, and the
  v1.7.21-specific live checks (Procmon .pml, Amcache section in snapshots).
- Status lines updated (README, docs/02, docs/07) for both builds.
- Verified: parse/ASCII clean; snapshot e2e on Linux (Amcache section
  present, empty + CollectionError as expected on non-Windows); diff suite
  treats Amcache as a stable section; Stage 7 capture path exercised against
  the real extracted code with a fake Procmon (arg construction, quoting,
  bounded wait, .pml detection); full CI contract suites pass.

## [1.7.20] - 2026-08-28
install-latest.ps1 same-version re-run no longer throws (owner report:
"Already installed at ... - pass -Force" on a plain `irm | iex` re-run):
- The release tag names the install folder, so an existing folder means this
  exact version is already present. The installer now detects a complete
  same-version install, skips the download, prints "already installed and up
  to date", and launches the existing START-HERE.bat (or respects -NoLaunch).
- Re-extracting blindly would have DELETED any AV scanners the technician
  already staged into `tools\AV` inside that folder - avoided.
- An existing folder that is incomplete or mismatched (missing VERSION /
  START-HERE.bat) is still re-installed fresh; -Force still re-extracts.
- Verified live against the real GitHub API: fresh install, same-version
  fast path (no re-download), -Force re-extract, broken-folder repair.

## [1.7.19] - 2026-08-28
KVRT "does not launch" (owner live report on v1.7.17) - third report on this
failure mode. Root-cause check: the official KVRT URL serves a real 114 MB PE
(verified from CI, passes the v1.7.17 PE-header guard), so download/staging
were cleared. The remaining blind spot was the LAUNCH itself:
- **The launcher could not tell "GUI open, technician scanning" from "process
  died instantly".** `Invoke-GUIScanner.ps1` did `Start-Process -PassThru` +
  `WaitForExit` and reported `Completed` on ANY exit - so a KVRT that was
  killed by the client's own AV, or a self-extracting launcher that exited
  while its child GUI was still starting (or failing), read as a successful
  scan.
- **NEW - 60s launch-grace probe (direct EXE scanners only).** If the launched
  process exits within 60s, the script now checks for a surviving child
  process (self-extractor hand-off) and waits on it if found; if there is no
  child, it reports `ExitedEarly` (exit code 5, shown in the report as
  `ExitedEarly`, never as a completed scan) with guidance: client AV
  blocking, stale staged copy (re-stage with `Get-AVTools.ps1 -Force`),
  SmartScreen. The winget path is exempt (cmd exits quickly by design).
- **NEW - richer scanner result JSON:** `ScannerPath`, `FileSizeBytes`,
  `PeValid`, `EarlyExit` for every session, so the report can name what
  actually happened instead of a bare status.
- `sc-cleanup.ps1` Stage 5 maps exit 5 to the `ExitedEarly` status.
- CI: new ScannerProcessContracts assertions for the grace probe + ExitedEarly.
- Verified: parse/ASCII clean; grace-probe logic exercised on Linux against
  the real extracted code (instant-exit -> ExitedEarly, alive-past-grace ->
  normal wait, winget path untouched).

## [1.7.18] - 2026-08-28
SPEC-axis review fixes (findings from the 2026-08-28 code review, items 1-9):
- **FIX - results.json was always null on the verification fields.** Stage 9 read
  `AfterSnapshot` / `DiffPath` / `RemovalManifest` from `$stage7Result` (Procmon,
  opt-in) instead of `$stage8Result` (after-snapshot + diff), so a normal run
  wrote `null` for all three. Now reads the correct stage result.
- **FIX - `-procmon` flag was inverted.** Stage 7's skip flag was named `procmon`,
  so passing `-procmon` logged "Stage 7 (Procmon) SKIPPED via -procmon" - the
  opposite of the documented "force the Procmon stage". The stage now gates on
  the flag itself: absence skips ("not requested via -procmon"), presence
  reaches the (still stub) run path.
- **NEW - scanner status in the report (docs/06 rules 9-10).**
  `New-InvestigationReport.ps1` gains `-ScannerSummary` and `-ScannersSkipped`;
  `sc-cleanup.ps1` Stage 9 passes the results file when Stage 5 ran, or the
  skipped marker when `-sa` was used. The HTML report now renders each
  scanner's Tool/Status/ExitCode and an explicit "Scanners were SKIPPED" block,
  so a skipped or failed scanner can never read as a clean malware verdict.
  Regression test: `tests/test_report_scanner_section.ps1` (portable).
- **REMOVED - dead flags `-safemode` and `-resume`** from `sc-cleanup.ps1`.
  Safe-mode relaunch was an unimplemented stub; reboot-resume lives inside
  `remove-screenconnect.ps1` (RunOnce key invoking the remover directly), so
  the orchestrator flags did nothing and were removed. Flags docs updated.
- **Docs aligned to the real 10-stage pipeline (0-9).** README ("9-stage
  (Stages 0-8)" -> 10 stages), `docs/02` (added the Stage 6 "Uninstall installed
  AV" stage, renumbered Procmon/after+diff/report to 7/8/9, replaced the stale
  CLI scanner-adapter contract with the attended-GUI operation, dropped MSERT,
  snapshot schema block updated to SchemaVersion 2 with the retro sections),
  `docs/06` (rule 2 now documents the `-ExecuteRemoval` lab-only exception),
  `docs/07` (Q1 un-blocked from M5, M3/M6 stage numbers, Amcache formally kept
  open, incident window now consumed by Stages 1+8), `docs/01` (D1 status),
  `docs/00`, `docs/09`, `plan-schema-example.json` (added `RemovalConfirmed`),
  `START-HERE.bat` header (Step 5 is automatic, not "asks first"), and the
  `Invoke-ReviewAndRemove.ps1` header.
- **TEST FIX - `Test-WindowsIntegration.ps1`** no longer passes the removed
  `-TechName` / `-ClientName` args to `sc-cleanup.ps1` (pre-existing breakage
  after the no-prompt directive removed those params).
- `$ScriptVersion` banner in `sc-cleanup.ps1` aligned to the VERSION file.

## [1.7.17] - 2026-08-27
KVRT still "does not launch" (owner live report on v1.7.14) - root cause
nailed: the staging "usable copy" check was SIZE-ONLY, so a broken-but-big
file (e.g. a download interrupted at 30 MB, or any >1-MB non-executable) was
treated as valid, SKIPPED by the v1.7.10 skip logic forever, and then
launched to nothing. Fixed with a structural **PE-header validation** (MZ +
PE\0\0 signature at e_lfanew) at every point that touches a staged exe:
- **Get-AVTools.ps1**: Test-ToolUsable now requires a valid PE header (not
  just >= 1 MB), so a corrupt copy is NEVER skipped - it is re-fetched.
  Fresh downloads are PE-validated on the .part file BEFORE the atomic swap,
  so a corrupt exe can never be staged. -Verify flags such files CORRUPT.
- **Invoke-GUIScanner.ps1**: launch-time guard - if the resolved scanner exe
  exists but fails the PE check, it now says exactly that
  ("Scanner file is corrupt/truncated (not a valid executable): <path>")
  and exits 3, instead of Start-Process silently doing nothing.
- CI: new scanner-contract assertions for the PE check in both scripts and
  the corrupt messages.
- Verified with crafted-PE fixtures + a request-counted local server:
  3-MB zeros file (valid size, no PE) is now flagged corrupt, re-downloaded
  and swapped for a valid PE; valid-PE copies still skip with ZERO requests;
  the launch guard exits 3 with the message on a corrupt KVRT.exe and lets a
  valid PE through. Full CI suite green.

## [1.7.16] - 2026-08-27
Snapshot speed-up (round 2) + live progress bar in the cmd window (owner
directives: "can you improve the snapshot before and after logic to speed up"
and "add a progress bar inside the cmd so I can know its still going"):
- **Concurrent GROUPS instead of sequential waves.** v1.7.12 ran 4 waves one
  after another (wall-clock = SUM of the waves). v1.7.16 starts all 4 groups
  at once - CIM (scheduled tasks/services/accounts/WMI), network
  (connections/firewall/processes/installed programs), registry (autoruns/
  BAM-DAM/UserAssist/startup folders) and files (prefetch/ShimCache) - so
  wall-clock = the SLOWEST group. Same 4-process peak as one old wave, only 4
  job spawns instead of 14. Per-group sequential fallback and -NoParallel are
  unchanged.
- **Live progress ticker**: while collecting, the console shows
  `[snapshot before] 12/17 sections, 34s elapsed` on a self-overwriting line.
  It is NOT gated by -Quiet (the guided runner passes -Quiet and this is
  exactly what the technician needs to see), and it labels before/after.
- **CRITICAL FIX - flat section arrays restored.** The v1.7.12 wave merge used
  the comma-wrap idiom (", @(...)") which double/triple-nested every section
  in the output JSON: v1.7.12-15 shipped "[[[rows]]]" instead of "[rows]" (and
  "[[]]" for empty sections). The diff/report still ran, but section arrays
  were wrapped 2-3 levels deep. v1.7.16 stores rows flat (capture-then-
  collect), verified with empty and non-empty synthetic data through the
  whole receive/merge pipeline, and the diff-snapshots chain returns
  "Verdict: CLEAN".
- CI: new C6 contracts (group mode, {Sections} envelope, group runner, ticker
  with before/after label). Verified: Linux e2e rc=0 with all 17 sections
  flat, group-mode envelope smoke, -NoParallel e2e, diff chain, full suite.

## [1.7.15] - 2026-08-27
One-liner install via irm | iex (owner directive: "can you create a irm/iex
cmd line version of this tool and add to readme"):
- **`install-latest.ps1`** (repo root + shipped in the zip): resolves the
  latest GitHub release via the API, downloads the deploy zip, extracts it to
  `Desktop\ScreenConnect-Cleanup\<version>\` (versions coexist, -Force
  overwrites), sanity-checks VERSION + START-HERE.bat, then launches the
  guided runner. No admin needed to install; the runner self-elevates only
  when a step needs it. Refuses to clobber an existing version folder without
  -Force; -NoLaunch skips the launch; -Destination overrides the folder.
- **README**: new "Quick start — one-liner" section at the top:
  `irm https://raw.githubusercontent.com/pupontech/screenconnect-cleanup/main/install-latest.ps1 | iex`
  with a security note (review the script first; zip not hash-verified;
  manual download alternative).
- `make-deploy-bundle.sh` now ships install-latest.ps1 inside the zip too.
- Verified live: fresh install against the real GitHub API resolved v1.7.14,
  downloaded the real asset, extracted + lifted the inner folder, refused a
  no-Force re-install, -Force re-installed; full CI suite green (19 scripts
  parse, 44 files house-rules-clean).

## [1.7.14] - 2026-08-27
AV scanners were STILL re-downloading on the owner's machine even though the
v1.7.10 skip logic is correct in isolation. Root cause found: **the download
itself was never atomic** - `Invoke-WebRequest -OutFile` wrote straight to
`KVRT.exe`, so an interrupted download left a partial file AT THE FINAL PATH.
Every Step 1 run then saw a sub-1-MB file, treated it as corrupt, deleted it
and re-downloaded - the exact loop reported. The old code also deleted the
corrupt file BEFORE fetching, so a failed download left nothing staged.
Fixed with atomic staging in `tools/Get-AVTools.ps1`:
- **Download to `<name>.part`, verify (>= 1 MB), then `Move-Item` into
  place.** An interrupted/partial download can never leave a broken file at
  the final path again - the previous copy (or its absence) stays untouched
  until a verified replacement exists, so the skip check stays honest.
- **A failed fetch no longer deletes the old file.** The corrupt copy is kept
  until the fresh download actually succeeds (then swapped), so a flaky
  network degrades to a loud FAILED + the previous state, never to nothing.
- New diagnostics: `not staged in <dir> yet - downloading` vs `existing copy
  is corrupt/partial ... fetching a fresh copy` - Step 1 now SAYS why it is
  downloading instead of just doing it.
- CI: new scanner-contract assertions for the .part staging file, the atomic
  Move-Item swap, and a guard that the destination is never deleted before
  the download.
- Verified with a local HTTP server (request-counted): valid copies present =
  ZERO requests; missing = exactly 2 requests + clean swap, no .part left;
  truncated download = loud FAILED, nothing staged, .part cleaned; corrupt
  old file + failed fetch = old file PRESERVED; corrupt old file + good
  fetch = swapped. Full CI suite green.

## [1.7.13] - 2026-08-27
The last step now OPENS the report folder and the report itself (owner
directive: "on the last step the folder with the report should be opened and
the report itself should be opened as well"):
- **`START-HERE.bat` Step 10**: after the report is confirmed written, the
  runner opens the folder with the report file selected
  (`explorer /select,"%~dp0report.html"`) and opens the report in the default
  browser (`start "" "%~dp0report.html"`). Only when the report actually
  exists; the [WARN] paths are unchanged.
- **`sc-cleanup.ps1` Stage 9** (orchestrator path): same behavior - Explorer
  opens the work dir with report.html selected, then the report opens in the
  default browser. Both opens are non-fatal (logged as WARN if they fail;
  the report is already on disk).
- CI: new C5 contract in Test-PipelineLauncherContracts.ps1 asserts both
  auto-open lines exist in the bat Step 10 and both Start-Process calls in
  sc-cleanup.ps1 Stage 9.
- Verified: full CI suite green, bat all-CRLF (278 lines), zip byte-verified.

## [1.7.12] - 2026-08-27
Snapshot collection refactored to run in parallel WAVES (owner directive:
"can it be refactored to speed up faster"). Previously only 3 of 18 sections
(scheduled tasks, firewall rules, network connections) ran in background
jobs; the other ~11 slow sections - CIM queries, registry walks, file
parsing - ran strictly one after another, so wall-clock was the SUM of every
section. Now:
- **Wave A** (unchanged, since v1.7.6): scheduled tasks, connections, firewall.
- **Wave B** (new): services, processes, local accounts, WMI persistence.
- **Wave C** (new): registry autoruns, installed programs, BAM/DAM, UserAssist.
- **Wave D** (new): Prefetch, ShimCache, startup folders.
  Wall-clock drops from sum-of-sections to ~sum-of-waves: each wave is capped
  at 4 concurrent background jobs so a weak client never spawns a
  powershell.exe per section (~4 x 150 MB peak, not 15 x).
- Every job keeps the v1.7.6 guarantees: collect one section via -Section
  mode, one-line JSON envelope, silent sequential fallback on ANY failure
  (spawn/timeout/bad payload), and -NoParallel still forces fully serial
  collection. RecentFiles stays serial (it owns the cap flag) and is skipped
  instantly at the default 0-day window.
- The -Section single-section mode now covers all 14 job-able sections (was 3).
- Verified: 18 sections end-to-end on Linux (rc=0, graceful per-section
  errors), -Section smoke tests for the new sections, wave-overlap proof
  (4 x 3s jobs = 4.6s vs ~12s serial), full CI suite green. Real Windows
  timing still needs the owner's live test (matrix item 3.1).

## [1.7.11] - 2026-08-27
Before/after snapshots run AUTOMATICALLY in the guided runner - no more [Y/n]
toggle (owner directive: "keep them both but do it automatically withouth yes
no toggles it should just be done"):
- **`START-HERE.bat` Step 3** (BEFORE snapshot) and **Step 9** (after-snapshot
  + diff) no longer prompt; both run unconditionally. sc-cleanup.ps1 already
  ran them unconditionally - the bat was the only prompting path.
- Step 3 gains the same `[WARN] ... errorlevel N` diagnostic as steps 6a/6b so
  a failed collector is loud instead of silent; the stale "step 8 will skip
  the diff" text is corrected to step 9. The baseline-missing and
  resurrection WARN paths are unchanged.
- Verified: Steps 3/9 contain zero `set /p` prompts, both
  `collect-snapshot.ps1 -Label before/after` lines are unconditional, bat
  stays all-CRLF (275 lines), full CI suite green.

## [1.7.10] - 2026-08-27
Step 1 no longer re-downloads scanners that are already on disk (owner
directive: "check if the tools are already downloaded - if they are, dont
download them again"). Get-ToolPack.ps1 already skipped via its manifest;
**Get-AVTools.ps1** was the offender - it fetched KVRT + ESET fresh on every
single run (~150 MB of downloads each session):
- **Skip-existing staging**: a staged KVRT.exe / esetonlinescanner.exe that is
  present AND at least 1 MB (the v1.7.8 sanity threshold) is kept and skipped
  with `already present (N MB) - skipping download`. Only missing or
  corrupt/partial copies are fetched.
- **Corrupt copies self-heal**: a present-but-under-1-MB file (0-byte / partial
  / HTML error page - the v1.7.8 "KVRT does not launch" class) is removed and
  re-downloaded automatically, so a broken stage can never silently persist.
- **-Force** switch re-downloads even valid copies (fresh KVRT is desirable
  before a big job); documented in the header.
- **-Verify upgraded**: now flags under-1-MB copies as CORRUPT (red, exit 1)
  instead of claiming "present" - verification and the skip logic share the
  same 1 MB usability rule.
- CI: new scanner-contract assertions for the -Force switch, the skip message,
  the corrupt-re-download path, the 1 MB constant and the Verify CORRUPT flag.
- Verified: harness scenarios - valid copies skipped with zero downloads;
  0-byte KVRT flagged corrupt then re-downloaded while valid EOS was skipped;
  -Verify exit 1 on corrupt / 0 on valid; -Force re-downloads both. Full CI
  suite green.

## [1.7.9] - 2026-08-27
Malwarebytes now LAUNCHES after the winget install (owner directive) - it was
installed but never opened, so the technician had to find it in the Start Menu
to run the scan. Both launch paths fixed:
- **`START-HERE.bat` Step 6c**: after a successful `winget install`, the bat
  locates `mbam.exe` under `%ProgramFiles%\Malwarebytes\Anti-Malware` (with a
  `%ProgramFiles(x86)%` fallback) and `start`s the Malwarebytes UI. If the
  install fails (errorlevel != 0) it skips the launch; if mbam.exe is not found
  at either standard path it says so instead of failing silently.
- **`Invoke-GUIScanner.ps1` Malwarebytes branch** (used by `sc-cleanup.ps1`
  Stage 5): after winget exits 0, the launcher finds mbam.exe (Program Files /
  Program Files (x86), braced `${env:ProgramFiles(x86)}` form for PS 5.1) and
  starts it, then WAITS for the Malwarebytes UI to close - the same attended
  model as KVRT/ESET, so the pipeline stays paused while the technician runs
  the scan. mbam missing or launch failure degrades to a visible WARN, never a
  crash; the timeout cap still applies and never kills the GUI.
- CI: new scanner-contract assertions for both paths (mbam.exe launch markers,
  the x86 braced lookup, the bat's `:mbam_found` label + `start "" "%MBAMEXE%"`,
  and the `%ProgramFiles(x86)%` fallback line).
- Verified on Linux: fake-cmd/fake-mbam harness - install-ok+mbam-present
  launches and waits (duration includes the scan), mbam-missing degrades with
  WARN, winget-failure does NOT launch; full CI suite green.

## [1.7.8] - 2026-08-27
KVRT "no longer launches" on the latest zip (owner live report) - the KVRT launch code itself is byte-identical to the version where it worked, so the failure was environmental and silent. Fixed by making staging and launch failures LOUD:
- **`START-HERE.bat` Steps 6a/6b** now echo `[WARN] ... errorlevel N` when KVRT/ESET launch fails (previously the failure was swallowed and the step looked like a no-op). The `if exist` gate passed for a 0-byte/partial exe, and Start-Process then failed silently.
- **`tools/Get-AVTools.ps1`** now sanity-checks every download: a staged KVRT/ESET smaller than 1 MB (HTML error page, partial or interrupted download) is deleted and reported FAILED instead of leaving a broken exe that "launches" to nothing. A corrupt/0-byte KVRT.exe from an earlier failed staging is the most likely cause of the report.
- Verified: KVRT launch path regression-checked on Linux (rc=0), Get-AVTools -Verify passes with staged KVRT+EOS, reject-threshold logic checked, bat paren/CRLF scan clean, full CI suite green.

## [1.7.7] - 2026-08-27
Crash right after the Malwarebytes step (owner live report) - fixed the two crash classes in that neighborhood:
- **`Invoke-GUIScanner.ps1` Malwarebytes launch**: winget on Windows 10/11 is an App Execution Alias (0-byte WindowsApps reparse stub). `Start-Process -FilePath` on the stub is unreliable in PS 5.1 (silent `$null` process handle, or "not a valid Win32 application") and the next line called `$proc.WaitForExit(...)` on a possibly-null process - an unhandled exception that killed the launcher right after the Malwarebytes launch. winget is now launched through `cmd.exe /c winget install -e --id Malwarebytes.Malwarebytes` (the OS resolves the alias; console stays visible), and a null-process guard reports LaunchFailed cleanly instead of crashing.
- **`START-HERE.bat` Step 6c**: rewritten from a nested `if/else` paren block to goto-style flow (the proven WPD pattern) - no parens-in-echo, no nested blocks; winget exit code is now echoed so failures are visible. Step 9 echoes the after-snapshot errorlevel too.
- Verified on Linux: fake-cmd harness captures the exact `/c winget install -e --id Malwarebytes.Malwarebytes` argv and completes rc=0; KVRT path regression-checked; bat paren/CRLF scan clean; full CI suite green (new scanner-contract asserts for the alias-via-cmd launch and the null guard).

## [1.7.6] - 2026-08-27
Technician tags/dates removed + snapshot collection sped up (owner directives: "remove the technician tags and dates and what not I dont need that step"; "can you speed them up").
- **No more tech/client prompts or tags.** `preflight.ps1` no longer prompts for technician name / client (prompt function, params, master-log lines and the handoff's Technician/Client/IncidentDate fields removed). `sc-cleanup.ps1` no longer prompts for tech/client (Prompt-IfMissing removed; `-TechName`/`-ClientName` params gone; plan + summary no longer carry the tags). Plan files (`Invoke-ReviewAndRemove.ps1` and Stage 3) now carry only GeneratedUtc/ComputerName/Decision/SourceFindings/RemovalConfirmed/Instances. `-IncidentDate` remains a never-prompted internal anchor for the snapshot's recent-files window (defaults to today).
- **Snapshot speedup.** The three slowest, independent collectors (ScheduledTasks, FirewallRules, Connections) now run in background jobs in parallel by default and are merged back; any job failure falls back to the sequential in-process path (`-NoParallel` disables). Firewall rules are filtered server-side (`-Direction Inbound -Action Allow -Enabled True`) instead of enumerating every rule. RecentFiles already had its own walk budget (120s / 40k dirs / depth 6) and returns instantly when the window is 0.
- Verified on Linux: parallel-success (fake section script -> merged rows), parallel-failure -> sequential fallback, -NoParallel, and the real script end-to-end (rc=0, all 18 sections, graceful section errors). Full CI suite green.

## [1.7.5] - 2026-08-27
AV-uninstall leftover sweep - some vendor uninstallers "don't seem to work" (observed live with ESET) and leave the product's Start Menu shortcuts + install folder behind. `Invoke-AVUninstaller.ps1` now sweeps leftovers after every uninstall attempt and MOVES them (never deletes - quarantine-never-delete stays the invariant) to `<LogDir>\av-uninstall-quarantine`, logging every move.
- New `Clear-ProductLeftovers`: keyword-matched sweep of the Start Menu (all-users + current user), the install folder (registry InstallLocation, else a `*<kw>*` folder under Program Files / (x86)), and the matching temp folder (covers ESET Online Scanner's runtime dir). Targets are moved to a timestamped quarantine dir; locked items are recorded as MoveFailed, not silently skipped.
- Runs automatically after each product's uninstall (winget or vendor GUI); new `-NoLeftoverSweep` disables it. Results gain `LeftoversMoved` + `Leftovers` (source/destination/status per item) and the JSON root carries `QuarantineRoot`.
- Report: the AV-uninstall section gains a "Leftovers" column and a note pointing at the quarantine root.
- Verified on Linux with a synthetic ESET layout: Start Menu "ESET", Program Files\ESET and TEMP\"ESET Online Scanner" all moved to quarantine; a decoy other-vendor folder untouched. A PS parse bug (`$env:'ProgramFiles(x86)'`) was caught by the harness and fixed to `${env:ProgramFiles(x86)}`.

## [1.7.4] - 2026-08-27
Guided runner removes the ScreenConnect check/removal prompts - it now just runs, removes and logs (owner directive: "remove the prompts asking to check for screenconnect and just run and remove and log").
- `START-HERE.bat` **Step 4** (detection) runs automatically with no prompt: full scan (`detect-remote-access.ps1 -All -NoPause`).
- `START-HERE.bat` **Step 5** (removal) runs automatically with no prompt: `Invoke-ReviewAndRemove.ps1 -Yes` - every detected ScreenConnect instance is marked REMOVE, `-Execute` applied, everything logged to `removal-manifest.json` + `removal-report.txt`. The prominent red banner still prints before removal; quarantine-never-delete and ScreenConnect-only targeting are unchanged.
- `Invoke-ReviewAndRemove.ps1 -Yes` is now the automatic mode used by the guided runner (was "unattended lab use"); the interactive per-instance gate and typed confirmation remain for direct runs without `-Yes` and for `sc-cleanup.ps1` Stage 3 (unchanged).
- Docs (README, safety model, START-HERE, live-test matrix) updated to record the owner-directive exception to the review gate.

## [1.7.3] - 2026-08-27
Malwarebytes is now installed and uninstalled via winget (owner directive: "change malwarebytes to installing and uninstalling via winget via winget install -e --id Malwarebytes.Malwarebytes"). No more MBSetup.exe staging or GUI-installer launch.
- `tools/Get-AVTools.ps1` stages **KVRT.exe + esetonlinescanner.exe only**; the Malwarebytes download (downloads.malwarebytes.com) and the InternalShare MBSetup fallback are removed.
- `Invoke-GUIScanner.ps1 -Scanner Malwarebytes` now runs `winget install -e --id Malwarebytes.Malwarebytes` (visible console, bounded wait, JSON result; exits 3 with a clear message when winget is missing; `-ToolPath` still overrides). KVRT/ESET keep the staged-EXE launch.
- `Invoke-AVUninstaller.ps1` uninstalls Malwarebytes via `winget uninstall -e --id Malwarebytes.Malwarebytes` (result carries `Method=winget` + `ExitCode`); if winget is absent it falls back to the vendor uninstaller GUI. All other detected AV products still open their vendor uninstaller attended.
- `START-HERE.bat` Step 6c installs Malwarebytes via winget (warns when winget is missing); Step 1/6/8 wording updated.
- CI contracts updated: stager must NOT stage/download MBSetup, scanner must map Malwarebytes to the winget package id, AV-uninstaller must run `winget uninstall -e --id`.

## [1.7.2] - 2026-08-27
Bundle the General Fix tool ("Tikun HaKlali", `tools/GeneralFix/תיקון הכללי v10.bat`) in the deploy zip so it never needs to be staged from a network share at runtime.
- The script is fully self-contained - verified: no UNC paths, no `net use`, no URLs; it only uses built-in Windows commands and its embedded VBS/WSF jobs. It was never bundled because `tools/.gitignore` whitelists only the downloader scripts; it now ships under `tools/GeneralFix/` with the original filename and byte layout (CRLF + cp1255) preserved.
- `make-deploy-bundle.sh` copies `tools/GeneralFix/` when present; `tools/.gitignore` un-ignores it. `Test-HouseRules.ps1` already excludes `tools/GeneralFix\` from the pure-ASCII code scan (intentional cp1255 third-party batch that self-sets `chcp 1255`).

## [1.7.1] - 2026-08-27
Two live-run fixes, both observed on DESTROYERLTC202 (2026-08-27).
- `remove-screenconnect.ps1` computes the manifest summary counts **before**
  writing `removal-report.txt`. The report referenced `$successCount` /
  `$failedCount` / etc. under `Set-StrictMode -Version 2.0` before they were
  assigned, throwing "The variable '$successCount' cannot be retrieved because
  it has not been set." — the manifest was written but the run exited 1 despite
  every action succeeding. Reproduced on Linux from `HEAD` with a StrictMode
  tail-harness; fixed harness now writes the report and exits 0.
- `Invoke-GUIScanner.ps1` now searches the `tools\AV\` staging sibling **first** —
  the default directory `tools/Get-AVTools.ps1` downloads KVRT.exe /
  esetonlinescanner.exe / MBSetup.exe into. The old lookup only checked `AV\`,
  the script root, `..\tools\AV`, `%USERPROFILE%\Downloads` and `%TEMP%`, so a
  freshly staged scanner reported "Scanner not found" (exit 3) even though the
  download had succeeded. Verified on Linux with a synthetic `tools\AV` layout:
  fixed resolves and launches (exit 0), `HEAD` version still exits 3.
- CI regression contracts for both fixes: `Test-RemovalRuntimeContracts.ps1`
  Test 10 (counts assigned before the report block) and
  `Test-ScannerProcessContracts.ps1` (Invoke-GUIScanner must search `tools\AV\`).

## [1.7.0] - 2026-08-27
Restore KVRT and ESET as staged scanner downloads.
- `tools/Get-AVTools.ps1` again downloads **KVRT.exe** from Kaspersky's official
  current KVRT URL and **esetonlinescanner.exe** from ESET's official Online
  Scanner URL, while keeping **MBSetup.exe** from Malwarebytes' official URL.
- `Invoke-GUIScanner.ps1` now accepts `-Scanner KVRT`, `-Scanner ESET`, and
  `-Scanner Malwarebytes`; all three are visible attended launches with no
  invented silent scan/clean flags. AdwCleaner and Defender remain removed.
- Stage 5 in `sc-cleanup.ps1` records all three attended scanner sessions and
  treats missing tools as nonfatal scanner results.
- `START-HERE.bat`, docs and CI scanner contracts updated for the restored
  KVRT/ESET/Malwarebytes line-up.

## [1.6.1] - 2026-08-27
Human-readable removal report.
- `remove-screenconnect.ps1` now also writes **`removal-report.txt`** (plain
  English) alongside `removal-manifest.json`: problems/failures called out up
  top, a summary, and a full chronological action log. The JSON is retained for
  the report stage + resurrection logic; the .txt is the human-facing file.
- `sc-cleanup.ps1` Stage 4 return carries `ReportTxtPath`; the HTML report's
  removal section points to `removal-report.txt`.

## [1.6.0] - 2026-08-27
Uninstall-installed-AV option (owner directive: "add an option to uninstall the installed av as the third to last option, open the uninstaller, add it to the report").
- New `Invoke-AVUninstaller.ps1`: discovers installed third-party AV via the
  Uninstall registry keys, opens each product's uninstaller as an attended GUI
  (waits for the technician to finish; never silent-uninstalls), and writes
  `av-uninstall-results.json`. Windows Defender / MSRT excluded (OS component).
- New Stage 6 in `sc-cleanup.ps1` (skip via `-avu`); wired into the report.
- `New-InvestigationReport.ps1` gains an "Installed antivirus / security
  products uninstalled" section (driven by `-AVUninstall`).
- `START-HERE.bat` is now 10 steps; Step 8 = uninstall installed AV (third-to-last:
  8 uninstall-AV, 9 after-snap+diff, 10 report).
- CI contract test extended to assert the AV-uninstaller is attended-only.

## [1.5.0] - 2026-08-26
Malwarebytes-only scanner line-up (owner decision: "i just want malwarebytes").
- `Get-AVTools.ps1` stages **only MBSetup.exe** (Malwarebytes MB5); KVRT, ESET,
  AdwCleaner, and Defender removed from staging.
- Stage 5 launches Malwarebytes attended via `Invoke-GUIScanner.ps1` (GUI
  launch-and-wait); the KVRT/ESET adapter scripts were deleted.
- `START-HERE.bat` Step 6 now offers Malwarebytes only.

## [1.4.0] - 2026-08-26
Final cleanup of the scanner line-up (owner decisions, 2026-08-26).
- Remove Microsoft Defender from Stage 5 (line-up was KVRT + ESET).
- Incident date auto-defaults to the computer's clock; no technician prompt.
- (Includes 1.3.0 AdwCleaner removal + 1.2.0 manifest-truth fix + 1.1.0 GUI
  scanners + 1.0.0 crash fixes.)

## [1.3.0] - 2026-08-26
- Remove AdwCleaner from AV staging. `Get-AVTools.ps1` fetches KVRT / ESET
  Online Scanner / Malwarebytes MB5 only.

## [1.2.0] - 2026-08-26
- Manifest truth fix: no misleading `Uninstall: Failed` with an empty Target
  on the manual-surgery fallback path (field-validated on INPIRON4SANITY2).

## [1.1.0] - 2026-08-26
- Add `Invoke-GUIScanner.ps1` launch-and-wait runner (ESET / Malwarebytes).
- Stage AV tools from official vendor URLs (`Get-AVTools.ps1`).

## [1.0.0] - 2026-08-26
- Crash fixes adopted from owner's upstream: P0 uninstaller pipe deadlock +
  3010 reboot-resume, P1 scanner drains, truthful pipeline exits, batch UAC
  elevation, StrictMode property crashes, WhatIf PropertyNotFoundStrict.
- Windows CI green on windows-2022 / windows-2025 (PS 5.1 + pwsh).

## [0.9.0] - 2026-08-25
- Field build: Stage 3/4 removal live, lab-only `-ExecuteRemoval` switch,
  `Invoke-ReviewAndRemove.ps1` guided runner. (Historical; pre-semver.)

## [0.8.0] - 2026-08-25
- Audit build: full safety/docs/CI audit; Stage 4 removal implemented
  (dry-run default). (Historical; pre-semver.)

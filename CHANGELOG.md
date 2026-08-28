# Changelog

Semantic versions. The deploy zip is named `screenconnect-cleanup-v<VER>.zip`
and carries a `VERSION` file so each build is self-identifying.

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

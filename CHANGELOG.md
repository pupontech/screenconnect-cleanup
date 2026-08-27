# Changelog

Semantic versions. The deploy zip is named `screenconnect-cleanup-v<VER>.zip`
and carries a `VERSION` file so each build is self-identifying.

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

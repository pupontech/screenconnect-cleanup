# Changelog

Semantic versions. The deploy zip is named `screenconnect-cleanup-v<VER>.zip`
and carries a `VERSION` file so each build is self-identifying.

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

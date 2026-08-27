# Changelog

Semantic versions. The deploy zip is named `screenconnect-cleanup-v<VER>.zip`
and carries a `VERSION` file so each build is self-identifying.

## [1.4.0] - 2026-08-26
Final cleanup of the scanner line-up (owner decisions, 2026-08-26).
- Remove Microsoft Defender from Stage 5 (line-up is now KVRT + ESET only).
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

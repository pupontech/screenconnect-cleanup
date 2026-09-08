# Changelog

All notable changes to ScreenConnect Cleaner (GUI Revision) are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.2.0] - 2026-08-27

### Fixed - GUI shell actually opens and runs

- **Dead action buttons (root cause of "GUI does nothing"):** the click
  handlers passed the workflow object as `-CancellationToken`, but the job
  runspace only ever received a fresh token copy - so `Start-SccWorkflow`
  ran against a hashtable with no `.Stages` and completed instantly as a
  no-op. The token now carries a `Workflow` payload and the new exported
  `Invoke-SccGuiWorkflow` runs the real state machine; a missing payload
  fails loudly instead of silently doing nothing.
- **`$script:ActiveJob` now assigned** (audit SCC-003): the 200ms
  `DispatcherTimer` polls the real job handle, shows live progress in a new
  `TxtStatus` line on the Dashboard, cleans the job up on completion, and
  allows subsequent runs (second click no longer throws "Only one concurrent
  Scc job is allowed").
- **Dashboard is populated on open:** computer name, OS/version, architecture,
  user, admin state, free disk and app version (from `Get-SccComputerInfo`),
  plus the previous-runs list in the Resume tab (`Find-SccRecentRuns`) with a
  working Resume button.
- **Runspace hygiene:** the job runspace now inherits the caller's
  `PSModulePath` (backends resolve inside the job), runspaces are disposed
  deterministically on reset, and `Start-SccWorkflow` no longer leaks one
  workflow object per stage step into the pipeline (the GUI job result is
  exactly one workflow).
- **Crash visibility:** a GUI startup failure is now written to
  `%TEMP%\SccCleaner-gui-error.log` and shown in a message box, so "the app
  does not open" can no longer happen silently (elevated console flash-close
  used to hide every startup error).

### Added - Review gate (audit SCC-001)

- **Findings Review window** (`Findings.xaml` wired): opens automatically
  when a Full run reaches the Review stage. Lists detected ScreenConnect /
  remote-access findings (deduplicated) with per-item **Remove** checkboxes
  (default KEEP), **Preview Actions** (dry-run plan) and **Approve Plan**
  (continues the workflow with a dry-run remediation).
- **Remediation Preview window** (`RemediationPreview.xaml` wired): shows the
  exact action lines, dry-run checkbox, and the Execute button guarded by
  safety invariant #2 - two explicit confirmations (Yes/No dialog + typed
  phrase `PERMANENTLY REMOVE`) before `Invoke-SccRemediation -Execute` is
  allowed. The stage-4 backend wrapper only passes `-Execute` when the GUI
  gate explicitly authorized it (`Workflow.Data.ExecuteRemediation`).
- **Settings / Advanced / Review Previous Report** buttons open their views.
- GUI workflows now create a real run (`New-SccRun`) so `plan.json`,
  evidence and reports land in the run directory.

### Added - GUI smoke test (Windows CI)

- `tests/ci/Test-GuiSmoke.ps1`: opens the WPF shell for real on Windows
  runners (PowerShell 5.1 and pwsh `-Sta`), auto-closes after 5 seconds and
  asserts clean exit; also verifies the entry point stays alive (window open)
  for 10 seconds. Wired into `gui-revision-ci.yml`.

### Tests

- Unit regression tests for the click-handler pattern (workflow reaches the
  runspace), missing-payload failure, and stop-signal cancellation.

---

## [0.1.0] - 2026-08-26

### Added - GUI Revision (this folder)

**New Application Structure**
- Complete rewrite as modular PowerShell 5.1 + WPF application
- Package: portable folder (primary) + optional Program Files installer
- Entry point: `Scc.Cleaner.ps1` (GUI default, `-Headless` for CI/CLI)
- Launcher: `Start-ScreenConnectCleaner.bat` (CRLF, pure ASCII)
- 9 PowerShell modules under `src/Scc.*/`:
  - `Scc.Core` - Foundation (config, paths, runs, logging, caching, computer info)
  - `Scc.Detection` - ScreenConnect instance identity + remote-access presence
  - `Scc.Evidence` - Snapshot collection (before/after, retro artifacts)
  - `Scc.Snapshots` - A/B diff + resurrection detection
  - `Scc.Tools` - NAS-first ToolManager (catalog, acquisition, validation, provenance)
  - `Scc.Scanners` - Scanner registry + adapters (CLI + attended GUI)
  - `Scc.Remedy` - Plan-gated remediation (quarantine, vendor uninstaller, restore)
  - `Scc.Report` - HTML/JSON/Technician summary reports (XSS-safe)
  - `Scc.UI` - WPF shell + stage state machine (shared by GUI + headless)
- Configuration: `config/scc-config.json`, `config/trusted-relays.json`, `config/targets.json`
- Documentation: `docs/ARCHITECTURE.md` (contract), `docs/MIGRATION.md`, `docs/TESTING.md`, `docs/USER-GUIDE.md`
- Build: `build/Build-Portable.ps1` (stages + zips + SHA256), `build/Install-Scc.ps1` (optional installer)
- CI: `.github/workflows/gui-revision-ci.yml` (linux-static + windows-dynamic matrix)

**Safety Model (12 Rules - Preserved from Legacy)**
1. Snapshot before any change (Stage 1, cannot be skipped)
2. Hard approval gate before removal (no unattended removal)
3. Quarantine, never delete (deletion = separate double-confirmed operation)
4. Restore point + registry export before first change (default on, verifies enabled)
5. Vendor uninstaller first (read from registry at runtime)
6. Never clean temp before looking at it
7. Never clear event logs
8. Server OS refuses by default (config override)
9. Scanner failure is non-fatal AND reported as failure
10. Report says what it did NOT check
11. Post-remediation verification re-collects fresh from system
12. Removal != remediation (credential-reset checklist in report)

**Key Features**
- Deep ScreenConnect detection (relay host, server key, session type, custom properties, install timestamp, confidence, trust matching)
- Broad remote-access detection (14+ products, configurable via targets.json)
- Trusted relay matching (Known/Unknown, never auto-classify malicious)
- NAS-first tool acquisition (local -> NAS -> official, signature/hash/size/version validation)
- Scanner adapters: Defender, KVRT, MSERT (CLI); AdwCleaner, ESET Online, Malwarebytes (attended GUI only per owner policy)
- Plan-gated remediation (dry-run default, ScreenConnect-only removable, ACL-locked quarantine)
- Before/after snapshots + diff (catches resurrection)
- HTML/JSON/Technician summary reports (self-contained HTML, XSS-safe)
- GUI workflow: Dashboard -> Preflight -> Snapshot A -> Detection -> Review (default KEEP) -> Remediate -> Scanners -> Snapshot B -> Compare -> Report
- Headless mode (same state machine, no WPF)
- Resume interrupted runs (reloads runstate.json)
- Portable packaging with SHA256SUMS.txt

**Testing Infrastructure**
- Pester 6.1.0 unit tests for all 9 modules (`tests/Unit/`)
- Integration test: headless smoke with synthetic SC fixture (`tests/Integration/Headless-Smoke.Tests.ps1`)
- CI contract tests (no Pester dep): HouseRules (ASCII/BOM/JSON/CRLF/binary), Parse (PS 5.1 + pwsh), SelfTests (module hooks)
- CI workflow: linux-static (pwsh) + windows-dynamic (PS 5.1 + pwsh matrix)

### Known Limitations (Honest Status)

- **SC key map ASSUMED NOT CONFIRMED** - Relay-identity extraction based on legacy analysis, not validated against live ScreenConnect install. M0 live lab validation is top priority, out of scope for agents.
- **Windows-only forensic decoders unverified** - ShimCache offsets, BAM/DAM P/Invoke, UserAssist offset, Prefetch naming, SRUM live-copy need real-box cross-check against known-good forensic tooling.
- **Scanner detection parsers heuristic** - KVRT/ESET/MSERT log parsers based on vendor docs, not sample logs. Keep copied logs; require real-box eyeball before trusting counts.
- **GUI untested on real machines** - WPF workflow, Findings UI, RemediationPreview, attended scanner launches all need manual walkthrough on Windows.
- **Amcache collector missing** - Stage 1 retrospective expansion implements Prefetch, ShimCache, BAM/DAM, UserAssist, SRUM but no Amcache collector/schema field/diff class.
- **Defender historical detections** - `Get-ThreatDetections` reads all history and reports as this run's detections; pre-existing detections may be mis-attributed.

### Not Yet Implemented
- Stage 6: Targeted Procmon boot logging (opt-in stub only)
- Stage 6 CLI equivalent for Procmon boot logging (unconfirmed if exists)

### Relationship to Legacy Scripts

This folder (`gui-revision-screenconnect-cleaner/`) is the **new application**.
The repo-root scripts (`*.ps1`, `scanners/`, `tools/`, `tests/`) are the **legacy pipeline** and remain untouched.

| Legacy | New |
|--------|-----|
| `sc-cleanup.ps1` (stage runner) | `Scc.Cleaner.ps1` + `Scc.UI` state machine |
| `preflight.ps1` | `Scc.Core` + Stage 0 |
| `detect-remote-access.ps1` | `Scc.Detection` |
| `targets.json` | `config/targets.json` + embedded defaults |
| `collect-snapshot.ps1` | `Scc.Evidence` |
| `diff-snapshots.ps1` | `Scc.Snapshots` |
| `remove-screenconnect.ps1` | `Scc.Remedy` (plan-gated, same safety) |
| `Invoke-ReviewAndRemove.ps1` | `Scc.UI` Findings.xaml + `New-SccPlan` |
| `Invoke-GUIScanner.ps1` / `scanners/Invoke-*.ps1` | `Scc.Scanners` adapters |
| `tools/Get-AVTools.ps1` / `Get-ToolPack.ps1` | `Scc.Tools` catalog + `tools/Get-AVTools.ps1` |
| `New-InvestigationReport.ps1` | `Scc.Report` |
| `START-HERE.bat` / `RUN-REMOVAL-TEST.bat` | `Start-ScreenConnectCleaner.bat` + headless |
| `.github/workflows/windows-ci.yml` | `.github/workflows/gui-revision-ci.yml` |

The legacy scripts are preserved for reference and for any environment that still depends on them. They are not deleted or modified by this revision.

---

## [Unreleased]

### Planned
- M0: Live lab validation of SC relay-key map (requires Windows VM + live ScreenConnect, out of scope for agents)
- Amcache collector for Stage 1
- Defender historical vs scan-specific detection split
- Real Windows validation of all forensic decoders
- Procmon Stage 6 implementation (if CLI equivalent confirmed)
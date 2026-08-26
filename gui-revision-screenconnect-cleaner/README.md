# ScreenConnect Cleaner

> **Completely vibe coded.** This application was built primarily through AI-assisted development ("vibe coding") with automated tests and code review as guardrails. It has NOT been validated against a live ScreenConnect installation and has NOT been run on real client machines. Treat it as a technician's power tool that requires professional judgment: review every finding, test it in your own lab before using it in production, and never trust automated removal without human review. MIT license, no warranty.

---

## What it is

ScreenConnect Cleaner is a Windows GUI technician application for investigating and cleaning machines with unauthorized ScreenConnect / ConnectWise Control installations, other remote-access software, and scam-related malware. It follows a **Detect -> Review -> Remediate -> Verify** workflow designed for professional incident response.

The application is built on Windows PowerShell 5.1 + WPF, packaged as a portable folder (primary) with an optional Program Files installer. All logic lives in PowerShell modules under `src/Scc.*/`  -  testable on Linux via `pwsh` + Pester, runnable on Windows without any build chain.

---

## Safety model (Detect -> Review -> Remediate -> Verify; 12 rules)

1. **Snapshot before any change**  -  Stage 1 runs first and cannot be skipped.
2. **Hard approval gate before removal**  -  No unattended removal; no detect-and-remove flag.
3. **Quarantine, never delete**  -  Deletion is a separate double-confirmed operation.
4. **Restore point + registry export before first change**  -  Default on, verifies restore actually enabled.
5. **Vendor uninstaller first**  -  Read from registry at runtime; manual surgery is fallback.
6. **Never clean temp before looking at it**  -  The scammer's installer in `%TEMP%` is evidence.
7. **Never clear event logs**  -  Event ID 7045 survives uninstall and is valuable.
8. **Server OS refuses by default**  -  Config override required.
9. **Scanner failure is non-fatal AND reported as failure**  -  Never silently swallowed into a "clean" verdict.
10. **Report says what it did NOT check**  -  If scanners skipped, report says "scanners skipped," never "no malware found."
11. **Post-remediation verification re-collects fresh from system**  -  Not from the actor's own record.
12. **Removal != remediation**  -  Credential-reset checklist always in report.

---

## Features

- **Deep ScreenConnect detection**  -  Extracts instance identity (relay host, server key, session type, custom properties, install timestamp) from services, processes, config files, and registry.
- **Broad remote-access presence detection**  -  AnyDesk, TeamViewer, UltraViewer, Supremo, RustDesk, Splashtop, LogMeIn/GoTo, Zoho Assist, Atera, DWAgent, MeshCentral, NetSupport, Remote Utilities, VNC family (configurable via `targets.json`).
- **Trusted relay matching**  -  Technician-maintained `trusted-relays.json` marks known infrastructure as "Known"; unknown relays are "Unknown" (never auto-classified malicious).
- **NAS-first tool acquisition**  -  Local cache -> NAS -> official vendor, with signature/hash/size/version validation and provenance recording.
- **Scanner adapters**  -  Defender (MpCmdRun), KVRT, MSERT (CLI); AdwCleaner, ESET Online, Malwarebytes (attended GUI launch per owner policy).
- **Plan-gated remediation**  -  Dry-run default; only ScreenConnect entries removable; quarantine with ACL (SYSTEM + Admins only); vendor uninstaller first.
- **Before/after snapshots + diff**  -  Catches resurrection (something reinstalled the agent).
- **HTML/JSON/Technician summary reports**  -  Self-contained HTML (XSS-safe), machine-readable JSON, <=60 line plain-text handoff.
- **GUI workflow**  -  Dashboard -> Preflight -> Snapshot A -> Detection -> Review (Findings UI, default KEEP) -> Remediate -> Scanners -> Snapshot B -> Compare -> Report.
- **Headless mode**  -  Same state machine without WPF (CI, automation).
- **Resume interrupted runs**  -  Reloads `runstate.json`, re-enters at first non-completed stage.

---

## Architecture summary

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full contract: module exports, stage state machine, configuration schema, file placement, run directory structure, and migration map.

---

## Supported Windows versions

- Windows 10 x64 (1809+)
- Windows 11 x64
- Windows PowerShell 5.1 baseline (also runs on PowerShell 7+)
- Server OS refused by default (configurable override)
- ARM64 where PowerShell 5.1 exists

---

## Quick start (portable)

1. Download `ScreenConnectCleaner-<version>-portable.zip` from releases (or run `build/Build-Portable.ps1`).
2. Unzip to any folder (including a NAS share).
3. Run `Start-ScreenConnectCleaner.bat` (right-click "Run as administrator" for full detection).
4. The GUI opens at the Dashboard. Click **Start Full Investigation** to begin.

No installation required. The portable folder is self-contained.

---

## Installation (optional installer)

Run `build/Install-Scc.ps1 -Install` (PowerShell as Administrator) to install to:
- `%ProgramFiles%\ScreenConnectCleaner\`
- Start Menu shortcuts (app + docs)
- Machine config stub at `%ProgramData%\ScreenConnectCleaner\config\scc-config.json`

Use `-WhatIf` to preview. Use `-Uninstall` to remove only what the installer placed.

---

## GUI workflow walkthrough

1. **Dashboard**  -  System info, admin status, internet/NAS connectivity, tool status, disk space, app version. Actions: Start Full Investigation, Detection Only, Scan Only, Review Previous Report, Settings, Advanced Tools.
2. **Preflight (Stage 0)**  -  Admin check, restore point, working dir, tool pack. Can be skipped (`-SkipPreflight`).
3. **Snapshot A (Stage 1)**  -  Services, scheduled tasks, autoruns, startup folders, processes, connections, installed programs, local accounts, firewall rules, WMI persistence, recent files, SC installations, system settings (RDP, hosts file). Runs before any change.
4. **Detection (Stage 2)**  -  ScreenConnect instance identity + other RAT presence. Read-only. Writes `findings.json`.
5. **Review (Stage 3)**  -  **Findings screen**: per-finding checkbox KEEP/REMOVE with full SC identity fields, trust badge (Known/Unknown), evidence links. **Default KEEP for everything.** Only ScreenConnect entries may be switched to REMOVE. Technician approves -> writes `plan.json`.
6. **Remediate (Stage 4)**  -  Consumes `plan.json`. Dry-run default (`-Execute` required for real actions). Sequence per approved item: stop service, kill processes, vendor uninstaller, validate removal, manual cleanup (service, scheduled task, Run key, firewall rule), quarantine leftovers (ACL-locked). Writes `remediation.json` + `quarantine-manifest.json`.
7. **Scanners (Stage 5)**  -  Runs enabled CLI scanners sequentially (Defender, KVRT, MSERT). Attended scanners (AdwCleaner, ESET Online, Malwarebytes) launch visible GUI and wait for close. Results in `scanner-results/`. Skippable.
8. **Snapshot B (Stage 6)**  -  Same collection as Stage 1, post-remediation.
9. **Compare (Stage 7)**  -  Diffs Snapshot A vs B: Removed / Still Present / New / Changed per section. Flags resurrections in SC installations and remote-access services.
10. **Report (Stage 8)**  -  Generates `report.html`, `report.json`, `technician-summary.txt` in the run directory.

---

## NAS setup

Configure in Settings or `config/scc-config.json`:

```json
"nas": {
  "enabled": true,
  "path": "\\\\NAS\\TechnicianTools\\Security",
  "priorityOrder": ["local", "nas", "official"],
  "timeoutSeconds": 15
}
```

- **Priority order**  -  Acquisition order for each tool. Default: local cache -> NAS -> official vendor.
- **Path**  -  UNC path to technician tools share. Supports `%ENVVAR%` expansion.
- **Timeout**  -  NAS reachability test timeout (default 15s). Failure is WARNING, proceeds to next source.
- **Layout**  -  NAS expected at `<nas.path>\<Tool>\<FileName>` (case-insensitive). Flat layout also accepted.

---

## Scanner acquisition + licensing notes

| Scanner | Type | Acquisition | Licensing |
|---------|------|-------------|-----------|
| **Defender** | CLI (`MpCmdRun`) | Built-in Windows | No licensing |
| **KVRT** | CLI (documented) | Official download | Owner-approved (D2) |
| **MSERT** | CLI (documented) | Microsoft free tool, self-expiring | Free, verify current CLI from docs |
| **AdwCleaner** | Attended GUI only | Official download | Owner policy: attended only |
| **ESET Online** | Attended GUI only | Official download | Owner policy: attended only |
| **Malwarebytes** | Attended GUI only | Official download | Owner policy: attended only |
| **Sysinternals** (autorunsc64, sigcheck64, procmon, tcpview) | CLI | `download.sysinternals.com` only, hash-verified | Microsoft free, redistribution permitted |

**Never invent silent-scan flags** for GUI-only scanners. Attended means: launch EXE visible, wait for exit, record Start/End/Duration + Result.

---

## Trusted relays

File: `config/trusted-relays.json` (template included). Format:

```json
{
  "trustedRelays": [
    { "relay": "support.example.com", "name": "Our MSP", "fingerprint": "a3f9c1...", "notes": "" }
  ]
}
```

- **Matching**  -  Case-insensitive hostname match. Optional fingerprint match (16 hex chars, lowercase) against detected `ServerKeyFingerprint`.
- **Result**  -  Finding shows **Known** (exact match) or **Unknown** (no match). Unknown is NEVER auto-classified malicious  -  technician decides.
- **Editor**  -  GUI Settings tab includes a trusted-relays editor.

---

## Quarantine

- **Location**: `%ProgramData%\ScreenConnectCleaner\Quarantine\<RunId>\q\...`
- **ACL**: SYSTEM + Administrators full control; Users removed. Never inside `%TEMP%`.
- **Manifest**: `quarantine-manifest.json` records `OriginalPath`, `QuarantinePath`, `SHA256`, `SizeBytes`, `MovedUtc`, `FindingId`, `Reason`, `ActionType`, `RestoreInstructions`.
- **Restore**: `Restore-SccQuarantineItem -Run -ItemId`  -  moves file back to original path (explicit confirmation required).
- **Permanent delete**: `Clear-SccQuarantine -Run -Approved`  -  double-confirmation required, never automatic, logged + reported.

---

## Report locations

Per-run directory: `%USERPROFILE%\Documents\ScreenConnect Cleanup\Reports\SC-<date>-<host>-<time>\`

Files:
- `report.html`  -  Self-contained, XSS-safe, all sections (Executive Summary, System Info, Incident Timeline, ScreenConnect Findings with trust column, Other Remote Access, Persistence, Network, Scanner Results, Remediation Actions, Quarantine, Before/After Comparison, Outstanding Concerns, Errors/Warnings, Tool Provenance, Credential/Incident Follow-up Checklist, Raw Evidence Index).
- `report.json`  -  Machine-readable everything.
- `technician-summary.txt`  -  <= 60 lines plain text for quick handoff.

---

## Configuration (all keys, table)

File: `config/scc-config.json` (defaults embedded in `Scc.Core`)

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `SchemaVersion` | int | 1 | Config schema version |
| `nas.enabled` | bool | true | Enable NAS as a tool source |
| `nas.path` | string | `\\NAS\TechnicianTools\Security` | UNC path to technician tools share |
| `nas.priorityOrder` | array | `["local","nas","official"]` | Acquisition order per tool |
| `nas.timeoutSeconds` | int | 15 | NAS reachability timeout |
| `paths.reportRoot` | string | `%USERPROFILE%\Documents\ScreenConnect Cleanup\Reports` | Report root directory |
| `paths.programData` | string | `%ProgramData%\ScreenConnectCleaner` | Machine-wide data |
| `paths.userData` | string | `%LocalAppData%\ScreenConnectCleaner` | User settings + tool cache |
| `scanners.enabled` | array | `["Defender","KVRT","MSERT"]` | CLI scanners to run |
| `scanners.order` | array | `["Defender","KVRT","MSERT"]` | Execution order |
| `scanners.attended` | array | `["AdwCleaner","ESETOnline","Malwarebytes"]` | GUI-only scanners |
| `scanners.defaultTimeoutMinutes` | int | 120 | Per-scanner timeout |
| `download.allowed` | bool | true | Allow official downloads |
| `download.maxAttempts` | int | 2 | Retry attempts |
| `download.timeoutSeconds` | int | 300 | Download timeout |
| `detection.incidentWindowDays` | int | 7 | Incident window for snapshots |
| `detection.defaultTargets` | array | `["screenconnect"]` | Default detection targets |
| `logging.level` | string | `INFO` | Log level (TRACE..CRITICAL) |
| `logging.retentionDays` | int | 90 | Log retention |
| `safety.serverOsRefusal` | bool | true | Refuse on Server OS |
| `safety.dryRunDefault` | bool | true | Dry-run by default |
| `safety.removableProducts` | array | `["screenconnect"]` | Products allowed for REMOVE |
| `evidence.retentionDays` | int | 30 | Evidence retention |
| `ui.confirmDestructive` | bool | true | Double-confirm destructive actions |
| `ui.language` | string | `en` | GUI language (English only currently) |

---

## Headless mode + examples

```powershell
# Full headless run (detect + scan + report; stops at Review without -PlanPath)
pwsh -NoProfile -File Scc.Cleaner.ps1 -Headless

# Detection only (read-only, no scanners, no review gate)
pwsh -NoProfile -File Scc.Cleaner.ps1 -Headless -Mode DetectOnly -SkipScanners

# Resume an interrupted run
pwsh -NoProfile -File Scc.Cleaner.ps1 -Headless -ResumeRunId SC-20260826-HOST-173000

# With pre-approved plan (for automation)
pwsh -NoProfile -File Scc.Cleaner.ps1 -Headless -PlanPath .\approved-plan.json
```

Exit codes: 0 = finished, 1 = failed/incomplete/awaiting review, 2 = missing dependency, 3 = refused (Server OS).

---

## Testing status (honest matrix)

| What | CI-Tested (Linux pwsh + Windows runners) | Needs Live Windows Testing |
|------|------------------------------------------|----------------------------|
| Parse checks (PS 5.1 + pwsh) | YES (both) |  -  |
| ASCII/BOM scan | YES |  -  |
| Pester unit tests (all modules) | YES |  -  |
| Headless smoke (DetectOnly) | YES (synthetic fixtures) |  -  |
| Config parsing (defaults/overrides/malformed) | YES |  -  |
| Snapshot diff (synthetic) | YES |  -  |
| Report XSS escaping / empty cases | YES |  -  |
| Tool acquisition paths (mock NAS/official/signature/hash fail) | YES |  -  |
| State machine transitions (headless) | YES |  -  |
| **WPF GUI on real box** | NO | **YES** |
| **Real KVRT / MSERT execution** | NO | **YES** |
| **Real ScreenConnect install/uninstall** | NO | **YES** |
| **ACL quarantine behavior** | NO | **YES** |
| **NAS access from domain-joined box** | NO | **YES** |
| **Restore point creation/verification** | NO | **YES** |
| **Attended scanner launches** | NO | **YES** |
| **Procmon boot logging (Stage 6)** | NO (stub only) | **YES** |

**Explicit statement**: Destructive removal must only be tested on a disposable lab machine, never a real client or dev machine.

---

## Known limitations

- **SC key map ASSUMED NOT CONFIRMED**  -  The relay-identity extraction (keys `h`=relay host, `e`=session type, `k`=server key, etc.) is based on legacy analysis, not validated against a live ScreenConnect install. M0 live lab validation is the top priority and out of scope for agents.
- **Windows-only forensic decoders unverified**  -  ShimCache offsets, BAM/DAM P/Invoke, UserAssist offset, Prefetch naming, SRUM live-copy all need real-box cross-check against known-good forensic tooling.
- **Scanner detection parsers heuristic**  -  KVRT/ESET/MSERT log parsers are best-effort against vendor docs, not sample logs. Keep copied logs; require real-box eyeball before trusting counts.
- **GUI untested on real machines**  -  WPF workflow, Findings UI, RemediationPreview, attended scanner launches all need manual walkthrough on Windows.
- **Amcache collector missing**  -  Stage 1 retrospective expansion implements Prefetch, ShimCache, BAM/DAM, UserAssist, SRUM but no Amcache collector/schema field/diff class.
- **Defender historical detections**  -  `Get-ThreatDetections` reads all history and reports as this run's detections; pre-existing detections may be mis-attributed.

---

## Development / build

- **Build portable**: `pwsh -NoProfile -File build/Build-Portable.ps1 [-Version <ver>] [-OutDir <dir>] [-Zip $true]`
  - Stages: `Scc.Cleaner.ps1`, `Start-ScreenConnectCleaner.bat`, `src/`, `config/`, `docs/`, `tools/`, optional top-level `README.md`/`LICENSE`/`CHANGELOG.md`
  - Output: `ScreenConnectCleaner-<Version>-portable.zip` + `.sha256` sidecar
  - SHA256SUMS.txt with relative paths (forward slashes, ASCII)
- **Tests**: `pwsh -NoProfile -Command "Invoke-Pester tests/Unit, tests/Integration -PassThru"` (Pester 6.1.0)
- **CI**: `.github/workflows/gui-revision-ci.yml`  -  linux-static (pwsh parse + unit + ASCII) + windows-dynamic (PS 5.1 + pwsh parse, unit, self-tests, headless smoke, malformed-config, build)
- **House rules**: `tests/ci/Test-HouseRules.ps1` (ASCII, BOM, JSON parse, CRLF .bat, no binaries), `tests/ci/Test-Parse.ps1` (Parser::ParseFile), `tests/ci/Test-SelfTests.ps1` (module self-test hooks)

---

## Relationship to legacy scripts

This folder (`gui-revision-screenconnect-cleaner/`) is the **new application**. The repo-root scripts (`*.ps1`, `scanners/`, `tools/`, `tests/`) are the **legacy pipeline** and remain untouched. The new app reuses logic from the legacy scripts but is a complete rewrite as modular PS 5.1 + WPF.

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
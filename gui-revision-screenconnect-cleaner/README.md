# ScreenConnect Cleaner

> **Completely vibe coded.** This application was built primarily through
> AI-assisted development ("vibe coding") with automated tests and code review
> as guardrails. It has NOT been validated against a live ScreenConnect
> installation and has NOT been run on real client machines. Treat it as a
> technician's power tool that requires professional judgment: review every
> finding, test it in your own lab before using it in production, and never
> trust automated removal without human review. MIT license, no warranty.

---

## What it is

ScreenConnect Cleaner is a Windows GUI technician application for investigating
and cleaning machines with unauthorized ScreenConnect / ConnectWise Control
installations, other remote-access software, and scam-related malware. It
follows a **Detect -> Review -> Remediate -> Verify** workflow designed for
professional incident response.

The application is built on **Windows PowerShell 5.1** with a **WPF (XAML)**
graphical shell, packaged as a portable folder (primary) with an optional
Program Files installer. All logic lives in PowerShell modules under
`src/Scc.*/` -- testable on Linux via `pwsh` + Pester, runnable on Windows
without any build chain.

> **Platform note.** The GUI is a WPF application and therefore requires a
> Windows desktop session (PowerShell 5.1 on Windows). On non-Windows hosts
> (CI, Linux, macOS) only **headless mode** is available -- the same stage
> state machine runs without WPF. The app detects a missing WPF runtime and
> tells you to use `-Headless` rather than crashing.

---

## Safety model (read this first)

**ScreenConnect Cleaner is DETECT-ONLY / read-only by default.** No system
state is changed unless a trained technician explicitly opts in to remediation.

- **Remediation is opt-in.** In the GUI it is gated behind the Review step:
  every finding defaults to **KEEP**, and you must explicitly approve a plan
  (`plan.json`) before anything is touched. In headless mode the pipeline
  *stops and waits* at the Review gate unless you supply a pre-approved plan
  via `-PlanPath`. There is **no detect-and-remove flag** and removal is
  **never automatic**.
- **Dry-run by default.** The remediation engine (`Invoke-SccRemediation`)
  only performs real actions when called with `-Execute`. Without it, it
  reports exactly what would happen.
- **Quarantine, never delete.** Removed artifacts are moved to an ACL-locked
  quarantine directory. Permanent deletion is a separate, double-confirmed
  operation (`Clear-SccQuarantine -Approved`).
- **Snapshot before any change.** A full system snapshot (Snapshot A) is
  collected first and cannot be skipped; a post-remediation Snapshot B is
  diffed against it to catch resurrection.
- **Vendor uninstaller first.** Native uninstallers are read from the registry
  at runtime; manual cleanup is the fallback.
- **Trained technician only.** This is a power tool. It must be run by a
  trained technician on a lab or otherwise-tested machine. Destructive removal
  must only be exercised on a disposable lab VM -- never on a real client or
  production machine.
- **"Unknown" is not "malicious".** ScreenConnect instances with relays that
  do not match your `trusted-relays.json` are labelled **Unknown**, never auto
  classified as malicious. The technician decides.

The full safety contract (12 invariants) is documented in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and in the GUI workflow.

---

## What this tool is NOT

- **Not antivirus.** It does not provide real-time protection, scanning
  on-access, or quarantine of active threats. It is an investigation and
  cleanup aid used after the fact.
- **Not a replacement for vendor cleanup.** Kaspersky (KVRT), ESET, and
  Malwarebytes scanners are detect-only integrations; the respective vendor
  tools are run *by the technician* (attended or CLI). ScreenConnect Cleaner
  orchestrates and records them; it does not substitute for running the real
  vendor cleanup.
- **Not for unauthorized use.** It is intended for technicians cleaning
  machines they are authorized to service (incident response, approved
  remediation). Running it against systems you do not have permission to
  modify is out of scope and inappropriate.
- **Not validated against live ScreenConnect.** The relay-identity extraction
  and several forensic decoders are based on legacy analysis, not confirmed
  against a live install. Always corroborate with known-good tooling.

---

## Features

- **Deep ScreenConnect detection** -- extracts instance identity (relay host,
  server key, session type, custom properties, install timestamp) from
  services, processes, config files, and registry.
- **Broad remote-access presence detection** -- AnyDesk, TeamViewer,
  UltraViewer, Supremo, RustDesk, Splashtop, LogMeIn/GoTo, Zoho Assist,
  Atera, DWAgent, MeshCentral, NetSupport, Remote Utilities, VNC family
  (configurable via `targets.json`).
- **Trusted relay matching** -- technician-maintained `trusted-relays.json`
  marks known infrastructure as "Known"; unknown relays are "Unknown" (never
  auto-classified malicious).
- **NAS-first tool acquisition** -- local cache -> NAS -> official vendor, with
  signature/hash/size/version validation and provenance recording.
- **Scanner adapters** -- Defender (`MpCmdRun`), KVRT, MSERT (CLI); AdwCleaner,
  ESET Online Scanner, Malwarebytes (attended GUI launch, run by the
  technician per owner policy).
- **Plan-gated remediation** -- dry-run default; only ScreenConnect entries
  removable; quarantine with ACL (SYSTEM + Admins only); vendor uninstaller
  first.
- **Before/after snapshots + diff** -- catches resurrection (something
  reinstalled the agent).
- **HTML/JSON/technician-summary reports** -- self-contained XSS-safe HTML,
  machine-readable JSON, and a <=60 line plain-text handoff.
- **GUI workflow** -- Dashboard -> Preflight -> Snapshot A -> Detection ->
  Review (Findings UI, default KEEP) -> Remediate -> Scanners -> Snapshot B ->
  Compare -> Report.
- **Headless mode** -- same state machine without WPF (CI, automation, Linux).
- **Resume interrupted runs** -- reloads `runstate.json`, re-enters at the
  first non-completed stage.

---

## Architecture summary

The app is a thin `Scc.Cleaner.ps1` orchestrator plus **9 PowerShell modules**.
The GUI (WPF) and headless mode share 100% of the stage state machine, which
lives in the non-visual part of `Scc.UI`.

| Module | Responsibility |
|--------|----------------|
| `Scc.Core` | Logging, configuration, paths, run/state management, computer info, caches, safe wrappers |
| `Scc.Detection` | ScreenConnect + remote-access detection, SC parameter parsing, trusted-relay matching |
| `Scc.Evidence` | System snapshot collection (schema v2) |
| `Scc.Snapshots` | A/B snapshot store + diff + resurrection detection |
| `Scc.Tools` | ToolManager (NAS-first acquisition, integrity, provenance) |
| `Scc.Scanners` | Scanner registry + CLI/attended adapters (Defender/KVRT/MSERT/AdwCleaner/ESET/Malwarebytes) |
| `Scc.Remedy` | Plan creation, dry-run preview, remediation, quarantine, restore |
| `Scc.Report` | `report.html` / `report.json` / `technician-summary.txt` generation |
| `Scc.UI` | WPF shell + shared stage state machine (`Start-SccApp`, `Start-SccWorkflow`) |

Key design points:

- **Evidence snapshot schema v2.** Each snapshot is
  `{SchemaVersion:2, Label, ComputerName, CollectedUtc, IsAdmin, OsCaption,
  IncidentWindowDays, SccAppVersion, CollectionErrors[], Sections{...}}`. Every
  item carries a stable `Key` (identity fields only -- never PID/timestamps),
  arrays are sorted by `Key`, and every section is wrapped so one failure does
  not abort the run.
- **Relay-trust model.** `trusted-relays.json` is technician-maintained. A
  finding is `Known` (exact case-insensitive host match, optional fingerprint
  match) or `Unknown`. `Unknown` is never a verdict -- the technician decides.
- **Scanner integrations (detect-only; vendor tools run by the technician).**
  CLI adapters run Defender/KVRT/MSERT and parse their logs (never stdout).
  AdwCleaner/ESET Online/Malwarebytes are launched attended (visible GUI, wait
  for close) and never with invented silent-scan flags.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full contract: module
exports, stage state machine, configuration schema, file placement, run
directory layout, and migration map.

---

## Supported Windows versions

- Windows 10 x64 (1809+)
- Windows 11 x64
- Windows PowerShell 5.1 baseline (also runs on PowerShell 7+)
- Server OS refused by default (configurable override)
- ARM64 where PowerShell 5.1 exists

**PowerShell version compatibility.** The tool targets Windows PowerShell 5.1
and is also validated on PowerShell 7 (`pwsh`). Note: the 9 module manifests
deliberately do **NOT** set `PowerShellVersion = '5.1'`. Setting that value
forced the modules to load in 5.1-compatibility mode on the CI runner, which
broke module-scope cmdlet/function visibility (the runner's default `pwsh` 7
behavior). The manifests keep `RequiredModules` and qualify the
`Microsoft.PowerShell.Management` cmdlets instead, so the modules load and
expose their functions correctly on both editions.

---

## Quick start (portable)

1. Download `ScreenConnectCleaner-<version>-portable.zip` from releases (or
   build it -- see below).
2. Unzip to any folder (including a NAS share).
3. Run `Start-ScreenConnectCleaner.bat` (right-click **Run as administrator**
   for full detection).
4. The GUI opens at the Dashboard. Click **Start Full Investigation** to begin.

No installation required. The portable folder is self-contained.

---

## Build, install, run

### Clone

```powershell
git clone <repo-url>
cd screenconnect-cleanup/gui-revision-screenconnect-cleaner
```

### Build the portable package

```powershell
# Output: ScreenConnectCleaner-<Version>-portable.zip + .sha256 sidecar
pwsh -NoProfile -File build/Build-Portable.ps1 [-Version <ver>] [-OutDir <dir>] [-Zip $true] [-IncludeConfigs $true]
```

`Build-Portable.ps1` stages `Scc.Cleaner.ps1`, `Start-ScreenConnectCleaner.bat`,
`src/`, `config/`, `docs/`, and optional top-level `README.md`/`LICENSE`/
`CHANGELOG.md`, computes SHA256 of every staged file into `SHA256SUMS.txt`,
then zips. Missing optional files are skipped with a warning (never fatal).

### Install (optional Program Files installer)

```powershell
# Run as Administrator
pwsh -NoProfile -File build/Install-Scc.ps1 -Install
# Preview without changes:
pwsh -NoProfile -File build/Install-Scc.ps1 -WhatIf
# Remove only what the installer placed:
pwsh -NoProfile -File build/Install-Scc.ps1 -Uninstall
```

Installs to `%ProgramFiles%\ScreenConnectCleaner\`, Start Menu shortcuts
(app + docs), and a machine config stub at
`%ProgramData%\ScreenConnectCleaner\config\scc-config.json`.

### Run the full GUI

```powershell
# Default: launches the WPF shell. On Windows, right-click the .bat and
# choose "Run as administrator".
pwsh -NoProfile -File Scc.Cleaner.ps1
```

`Scc.Cleaner.ps1` self-elevates (re-launches as administrator) on Windows when
not already elevated.

### Run DetectOnly headless (read-only)

```powershell
pwsh -NoProfile -File Scc.Cleaner.ps1 -Headless -Mode DetectOnly -SkipScanners
```

This collects Snapshot A, runs detection (writes `findings.json`), generates a
report, and exits. It never reaches the Review/Remediate gates.

### Headless examples (all opt-in for removal)

```powershell
# Full headless run (detect + scan + report). Stops at Review unless a plan is
# provided via -PlanPath.
pwsh -NoProfile -File Scc.Cleaner.ps1 -Headless

# Resume an interrupted run
pwsh -NoProfile -File Scc.Cleaner.ps1 -Headless -ResumeRunId SC-20260826-HOST-173000

# Continue past the Review gate with a pre-approved plan (automation only)
pwsh -NoProfile -File Scc.Cleaner.ps1 -Headless -PlanPath .\approved-plan.json
```

**Exit codes:** `0` = finished, `1` = failed/incomplete/awaiting review,
`2` = missing dependency, `3` = refused (Server OS).

Remediation is only executed when a plan is approved and the remediation
engine is invoked with `-Execute` (GUI: explicit Approve + double-confirm;
headless: `-PlanPath` referencing a plan produced by `New-SccPlan` or the GUI).

---

## Testing

### Pester unit + integration (Linux and Windows)

```powershell
# Pester 6.1.0
pwsh -NoProfile -Command "Invoke-Pester tests/Unit, tests/Integration -PassThru"
```

Unit tests cover every module's public API: SC parameter parser (ordering,
URL encoding, malformed, unknown, multi-instance), trusted-relay matching,
config parsing (defaults/overrides/malformed), quarantine manifest, snapshot
diff (synthetic), report XSS escaping, scanner exit-code mapping, run-state
interrupted runs, tool acquisition paths (mock NAS/official/signature/hash
failure), and the GUI/backend boundary (state-machine transitions in headless
mode).

### Windows CI

The real-Windows CI is `.github/workflows/windows-ci.yml`. It runs two jobs:

- `windows-tests` -- exercises the legacy house rules (ASCII, BOM, JSON parse)
  and safe integration paths under **both** Windows PowerShell 5.1 and
  PowerShell 7 (`pwsh`) on `windows-2022` and `windows-2025`.
- `gui-revision-tests` -- the gui-revision suite: house rules, parse check
  under pwsh, Pester unit tests, module self-tests, a headless **DetectOnly**
  smoke run (read-only, deterministic), and a portable-package build +
  hash verification.

No ScreenConnect install or destructive removal happens in CI. Destructive
removal stays on a disposable dedicated lab VM, owned and run by a human.

### House rules (CI-enforced)

- Pure ASCII source, no BOM; no emoji in `.ps1`.
- Every module: parse check (0 errors), ASCII byte check, Pester unit tests.
- Verification by running, never by inspection.

---

## Known limitations (honest)

- **SC key map ASSUMED NOT CONFIRMED** -- relay-identity extraction (keys
  `h`=relay host, `e`=session type, `k`=server key, etc.) is based on legacy
  analysis, not validated against a live ScreenConnect install.
- **Windows-only forensic decoders unverified** -- ShimCache offsets, BAM/DAM
  P/Invoke, UserAssist offset, Prefetch naming, SRUM live-copy need real-box
  cross-checks against known-good tooling.
- **Scanner detection parsers heuristic** -- KVRT/ESET/MSERT log parsers are
  best-effort against vendor docs, not sample logs. Keep copied logs; require
  a real-box eyeball before trusting counts.
- **GUI untested on real machines** -- WPF workflow, Findings UI, attended
  scanner launches all need a manual walkthrough on Windows.
- **Amcache collector missing** -- Stage 1 implements Prefetch, ShimCache,
  BAM/DAM, UserAssist, SRUM but no Amcache collector/schema field/diff class.

**Explicit statement:** Destructive removal must only be tested on a
disposable lab machine, never a real client or dev machine.

---

## Documentation

- `docs/USER-GUIDE.md` -- step-by-step for a technician (launch, DetectOnly,
  review findings, guided removal with confirmation, reading the evidence
  snapshot and HTML report).
- `docs/ARCHITECTURE.md` -- the full technical contract (module exports, stage
  state machine, configuration schema, file placement, run-directory layout,
  migration map, safety invariants).
- `docs/TESTING.md` -- test status, live-test matrix, known limitations.
- `docs/MIGRATION.md` -- legacy component -> new module map.

---

## Relationship to legacy scripts

This folder (`gui-revision-screenconnect-cleaner/`) is the **new application**.
The repo-root scripts (`*.ps1`, `scanners/`, `tools/`, `tests/`) are the
**legacy pipeline** and remain untouched. The new app reuses logic from the
legacy scripts but is a complete rewrite as modular PowerShell 5.1 + WPF. The
legacy scripts are preserved for reference and for any environment that still
depends on them.

---

## License

MIT. See [LICENSE](LICENSE). No warranty. You assume all risk.

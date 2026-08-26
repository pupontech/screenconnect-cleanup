# DEVIATIONS.md - Integration / Entry-point deviations

This file records adjustments made by the integration engineer. Other module
builders own files under src/Scc.*/; this file does not modify them.

## 2026-08-26 - Initial integration wiring

### Scc.Cleaner.ps1

- **Elevation**: Implements Start-Process -Verb RunAs self-elevation inside the
  .ps1 (Windows only). Uses an env marker SCC_ELEVATED to avoid infinite relaunch
  loops. Linux hosts bypass elevation (Test-SccCleanerIsAdmin returns true on
  non-Windows so CI does not attempt elevation).

- **PSModulePath**: Prepends src/ to PSModulePath so Import-Module Scc.Core etc.
  resolves via standard discovery (src/Scc.Core/Scc.Core.psd1). No shared file
  was modified to achieve this.

- **Config handling**: -Config <path> is forwarded to Get-SccConfig -Path before
  New-SccRun and before Start-SccApp. If the file does not exist a warning is
  printed but the run continues with defaults (mirrors Scc.Core malformed-file
  behavior).

- **Server OS refusal**: Checked via Get-SccComputerInfo + Get-SccConfig safety.
  serverOsRefusal -> exit 3. No -ForceServer flag is exposed on Scc.Cleaner
  (the underlying New-SccRun -ForceServer exists but is not surfaced; operator
  must override via config).

- **Resume**: -ResumeRunId loads an existing run directory by ReportRoot +
  Find-SccRecentRuns fallback. If the run is not found the script exits 1.

- **Plan injection**: When -PlanPath is given the file is copied to
  <RunDir>/plan.json and Workflow.PlanPath is set before Start-SccWorkflow.
  This matches Scc.UI Get-SccPlanFromRun lookup order (PlanPath then RunDir).
  Never auto-approves: without PlanPath the workflow stops at AwaitingReview
  and the script exits 1 with a clear message.

- **SkipPreflight / NoRestorePoint**: -SkipPreflight marks stage 0 Skipped
  before the workflow starts and persists via Save-SccRunState. -NoRestorePoint
  is logged; actual restore-point creation is owned by Scc.Remedy and is
  skipped via its own config.

- **Exit codes**: 0 finished, 1 failed stage / incomplete / AwaitingReview,
  2 missing dependency (manifest not found or Import-Module failure),
  3 refused (Server OS). Partial runs never report success.

- **Graceful degradation**: Missing module is detected before the pipeline
  starts (manifest existence check) and exits 2. A failed stage does not abort
  remaining stages (Scc.UI Invoke-SccStageBody already isolates failures).

### Start-ScreenConnectCleaner.bat

- Single line: powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Scc.Cleaner.ps1" %*
  Stored with CRLF line ending, pure ASCII, no BOM. Elevation is handled inside
  the .ps1 rather than in the .bat (consistent with Scc.Cleaner contract).

### tests/ci/Test-HouseRules.ps1

- Ported from legacy tests/ci/Test-HouseRules.ps1 and adapted:
  - Scans only the new tree (gui-revision-screenconnect-cleaner/) instead of
    the repo root, so legacy top-level scripts are out of scope.
  - Checks every .ps1/.psm1/.psd1/.xaml/.json/.bat/.md for pure ASCII and no BOM
    (legacy checked only .ps1/.bat for ASCII).
  - Adds .bat CRLF enforcement (every LF must be preceded by CR).
  - Adds binary check: no *.zip / *.exe committed under the new tree.
  - Still validates every .json parses.

### tests/ci/Test-Parse.ps1

- Ported from legacy tests/ci/Test-Parse.ps1:
  - Scans .ps1 and .psm1 (legacy scanned only .ps1).
  - New tree root instead of repo root.
  - No other behavior change; still uses Parser::ParseFile and runs under both
    5.1 and pwsh.

### tests/ci/Test-SelfTests.ps1

- New file (no direct legacy equivalent; spec requires invoking each module's
  self-test entry points). Discovers Invoke-SccDetectionSelfTest and similar
  hooks (Invoke-Scc*SelfTest) across all Scc.* modules, imports each module,
  calls the function if present, and fails on any non-empty failure list or
  thrown exception.

### tests/Integration/Headless-Smoke.Tests.ps1

- New file per spec. Key choices:
  - Module list is discovered from src/ at runtime (hardcoded expected list of
    9 modules: Scc.Core, Scc.Detection, Scc.Evidence, Scc.Snapshots, Scc.Tools,
    Scc.Scanners, Scc.Remedy, Scc.Report, Scc.UI). The test FAILS if any is
    missing - this is the wiring validator.
  - Uses isolated temp ReportRoot and temp LocalAppData/ProgramData so the smoke
    does not pollute real config or reports.
  - Mocks detection at the inventory level (Mock Scc.Detection
    Get-SccServiceInventory / Get-SccProcessInventory / Get-SccUninstallInventory
    plus ServiceInstallEvents/Connections/ScDirs) to produce exactly 1 synthetic
    ScreenConnect instance (identifier a1b2c3d4e5f6a7b8) that survives
    deduplication.
  - Plan with 0 REMOVE items (single KEEP item) injected via -PlanPath; covers
    the review gate without invoking destructive remediation. Asserts
    findings.json has 1 instance and quarantine dir is empty.
  - Asserts runstate.json stages, report.html/json/txt existence and parse,
    diff.json existence, and that no quarantine occurred.
  - Also verifies the AwaitingReview guard by running a second workflow without
    a plan and asserting it stops.

### No changes to src/Scc.*/

- No file under src/ was modified. Any cross-module wiring issues that required
  a fix are noted here rather than edited in place, per house rule 8.


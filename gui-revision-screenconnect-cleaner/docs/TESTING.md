# ScreenConnect Cleaner - Testing Documentation

This document describes the test inventory, how to run tests locally, the live Windows test matrix, and explicit safety statements.

---

## Test Inventory

### Unit Tests (Pester 6.1.0)

Located in `tests/Unit/`:

| Test File | Module Under Test | Description |
|---|---|---|
| `Scc.Core.Tests.ps1` | Scc.Core | Config parsing (defaults/overrides/malformed), paths, runs, caching, logging, computer info, internet/NAS tests, file facts, env resolution, safe invoke, JSON helpers |
| `Scc.Detection.Tests.ps1` | Scc.Detection | SC parameter parser (ordering, URL encoding, malformed, unknown params, multi-instance), trust matching, remote-access detection, targets.json parsing, self-test |
| `Scc.Evidence.Tests.ps1` | Scc.Evidence | Snapshot collection (schema v2, stable keys, sorted arrays, error wrapping, retro collectors), incident window filter |
| `Scc.Snapshots.Tests.ps1` | Scc.Snapshots | Synthetic diff (Removed/StillPresent/New/Changed), resurrection detection, summary counts |
| `Scc.Tools.Tests.ps1` | Scc.Tools | Tool catalog, Resolve-SccTool (local/NAS/official/none, signature/hash/size/version validation, provenance), Test-SccToolIntegrity, Get-SccToolStatus |
| `Scc.Scanners.Tests.ps1` | Scc.Scanners | Scanner list, CLI adapters (Defender/KVRT/MSERT - WhatIf, exit codes, log parsing), GUI adapters (attended launch), timeout enforcement |
| `Scc.Remedy.Tests.ps1` | Scc.Remedy | Plan generation (KEEP default, only SC removable), Test-SccPlan dry-run, Invoke-SccRemediation (-Execute), vendor uninstaller resolution, quarantine manifest, restore/clear |
| `Scc.Report.Tests.ps1` | Scc.Report | HTML generation (XSS escaping, empty cases, all sections), JSON report, technician summary (<=60 lines), ConvertTo-SccHtml |
| `Scc.UI.Tests.ps1` | Scc.UI | State machine transitions (headless), Start-SccJob (progress, cancel), WPF boundary (mocked) |

**Run all unit tests:**
```powershell
pwsh -NoProfile -Command "Invoke-Pester tests/Unit -PassThru"
```

### Integration Tests

Located in `tests/Integration/`:

| Test File | Description |
|---|---|
| `Headless-Smoke.Tests.ps1` | Full headless pipeline with synthetic SC fixture (mocked detection). Verifies: all 9 modules load, runstate.json stages, findings.json (1 instance), plan with 0 REMOVE, no quarantine, report.html/json/txt exist and parse, diff.json exists, AwaitingReview guard works without plan. |

**Run integration tests:**
```powershell
pwsh -NoProfile -Command "Invoke-Pester tests/Integration -PassThru"
```

### CI / Contract Tests (Standalone, No Pester Dependency)

Located in `tests/ci/`:

| Test File | Description |
|---|---|
| `Test-HouseRules.ps1` | Pure ASCII (0 non-ASCII bytes), no BOM, JSON parse, .bat CRLF enforcement, no binaries committed (.zip/.exe) - scans `gui-revision-screenconnect-cleaner/` only |
| `Test-Parse.ps1` | Parser::ParseFile on every .ps1 and .psm1 under new tree - runs under both Windows PowerShell 5.1 and pwsh |
| `Test-SelfTests.ps1` | Discovers and invokes `Invoke-Scc*SelfTest` hooks across all Scc.* modules, fails on any failure list or exception |

**Run CI tests:**
```powershell
# On Linux (pwsh)
pwsh -NoProfile -File tests/ci/Test-HouseRules.ps1
pwsh -NoProfile -File tests/ci/Test-Parse.ps1
pwsh -NoProfile -File tests/ci/Test-SelfTests.ps1

# On Windows (PS 5.1)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tests/ci/Test-HouseRules.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tests/ci/Test-Parse.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tests/ci/Test-SelfTests.ps1
```

---

## How to Run Tests Locally

### Linux (pwsh 7.6.5)

```bash
# Parse + ASCII checks
pwsh -NoProfile -File tests/ci/Test-HouseRules.ps1
pwsh -NoProfile -File tests/ci/Test-Parse.ps1

# Unit tests
pwsh -NoProfile -Command "Invoke-Pester tests/Unit -PassThru"

# Integration tests
pwsh -NoProfile -Command "Invoke-Pester tests/Integration -PassThru"

# Self-tests
pwsh -NoProfile -File tests/ci/Test-SelfTests.ps1

# All together (CI-like)
pwsh -NoProfile -Command "Invoke-Pester tests/Unit, tests/Integration -PassThru"
```

### Windows (Windows PowerShell 5.1 + pwsh)

```powershell
# Parse checks under BOTH engines
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tests/ci/Test-Parse.ps1
pwsh -NoProfile -File tests/ci/Test-Parse.ps1

# House rules
powershell.exe -NoProfile -ExecutionPolicy Bypass -File tests/ci/Test-HouseRules.ps1

# Unit tests (pwsh preferred for Pester 6)
pwsh -NoProfile -Command "Invoke-Pester tests/Unit -PassThru"

# Integration tests
pwsh -NoProfile -Command "Invoke-Pester tests/Integration -PassThru"

# Self-tests
pwsh -NoProfile -File tests/ci/Test-SelfTests.ps1
```

### CI Pipeline (Reference)

The CI workflow `.github/workflows/gui-revision-ci.yml` runs:

- **linux-static** (ubuntu-latest, pwsh): Test-HouseRules + Test-Parse (pwsh) + Pester unit + Pester integration
- **windows-dynamic** (matrix: windows-2022, windows-2025):
  - Test-HouseRules + Test-Parse under BOTH `powershell` (5.1) and `pwsh`
  - Pester unit (pwsh)
  - Test-SelfTests.ps1
  - Headless smoke (DetectOnly -SkipScanners)
  - Malformed-config guard
  - Build-Portable.ps1 + verification
  - Artifact upload

---

## Live Windows Test Matrix

The following items **require a real Windows machine** (disposable lab VM) and **cannot be validated on Linux**. They are the responsibility of the human owner to execute before any production use.

| Test Area | Description | Legacy Ref | Status |
|---|---|---|---|
| **WPF GUI on real box** | Launch `Start-ScreenConnectCleaner.bat` as admin; walk full workflow: Dashboard -> Preflight -> Snapshot A -> Detection -> Review (Findings UI) -> Remediate -> Scanners -> Snapshot B -> Compare -> Report. Verify all Views render, buttons work, progress updates. | docs/07 M5 | **NOT DONE** |
| **Real KVRT execution** | Run `Scc.Cleaner.ps1 -Headless -Mode Full` with KVRT enabled; verify adapter downloads/runs KVRT, parses log correctly, records detections in report. | docs/07 Q4 | **NOT DONE** |
| **Real MSERT execution** | Same with MSERT; verify self-expiring tool handling, CLI switches from current vendor docs. | docs/07 Q4 | **NOT DONE** |
| **Real ScreenConnect install/uninstall** | Install ScreenConnect from test cloud instance in VM. Run detection -> verify relay/identity extraction -> approve plan -> run remediation with `-Execute` -> verify vendor uninstaller path, quarantine behavior, post-removal diff. | docs/07 M0, M5 | **NOT DONE** |
| **ACL quarantine behavior** | Verify quarantine folder at `%ProgramData%\ScreenConnectCleaner\Quarantine\<RunId>\q\` has ACL: SYSTEM+Admins full, Users removed. Test restore and double-confirmed permanent delete. | docs/09 2.3 | **NOT DONE** |
| **NAS access from domain-joined box** | Configure `nas.path` to domain share; run tool acquisition; verify UNC path works, timeout handling, flat layout fallback, priority order respected. | docs/07 M5 | **NOT DONE** |
| **Restore point creation/verification** | Verify `Checkpoint-Computer` works, restore point actually enabled (not silently failed), registry export (`reg.exe save`) succeeds. Test `-NoRestorePoint` skip. | docs/09 3.3 | **NOT DONE** |
| **Attended scanner launches** | Run with AdwCleaner/ESETOnline/Malwarebytes enabled; verify GUI launches visible, waits for close, records Start/End/Duration/Result. | docs/07 M4 | **NOT DONE** |
| **Procmon boot logging (Stage 6)** | Verify opt-in Procmon boot logging works non-interactively (CLI equivalent of GUI Options menu). | docs/07 Q6 | **STUB ONLY** |
| **Apostrophe path handling** | Copy tool tree to `C:\temp\it's the cleanup\`; launch `.bat`; verify self-elevation succeeds without quoting errors. | docs/09 4.1 | **NOT DONE** |
| **UAC cancel behavior** | Launch unelevated, click Cancel on UAC; verify visible [ERROR], pause, exit code 1 (not silent 0). | docs/09 4.2 | **NOT DONE** |
| **Real destructive removal (full)** | **ONLY ON DISPOSABLE LAB VM.** Install ScreenConnect, run full pipeline with `-Execute`, verify: approved plan honored, no cmd.exe shell execution of uninstall strings (direct exe/msiexec), quarantine-not-delete, post-removal snapshot/diff/report, truthful exit code. | docs/09 7.1 | **NOT DONE** |
| **Reboot/resume (3010)** | Force MSI exit 3010; verify RebootPending status, scheduled resume completes persistence cleanup WITHOUT re-running vendor uninstaller. | docs/09 7.2 | **NOT DONE** |

---

## Explicit Safety Statement

**DESTRUCTIVE REMOVAL MUST ONLY BE TESTED ON A DISPOSABLE LAB MACHINE, NEVER A REAL CLIENT OR DEV MACHINE.**

The Stage 4 remediation path (`Invoke-SccRemediation -Execute`) performs real system changes:
- Stops Windows services
- Kills processes
- Runs vendor uninstallers (msiexec /x, executable uninstallers)
- Removes scheduled tasks, Run keys, firewall rules
- Moves files to ACL-locked quarantine (never deletes)
- Creates restore points and registry exports

These actions are **irreversible without the quarantine restore function** and **must be validated in an isolated, snapshotted VM** before any consideration of use on a machine that matters.

The tool is designed with safety defaults:
- Dry-run by default (`-Execute` required for real actions)
- Hard approval gate (Findings UI, default KEEP)
- Only ScreenConnect entries may be marked REMOVE
- Quarantine, never delete (separate double-confirmed Clear-SccQuarantine)
- Vendor uninstaller first, manual surgery fallback

But **no automated test suite can replace a human verifying on real hardware**. The CI tests use synthetic fixtures and mocks; they prove the logic flows, not that the Windows APIs behave as expected on a live system with real ScreenConnect installations.

---

## Known Test Gaps (as of this writing)

| Gap | Impact | Mitigation |
|---|---|---|
| Amcache collector missing | Retro artifact gap in Stage 1 | Documented in ARCHITECTURE.md, MIGRATION.md; scope open |
| Defender historical detections | Pre-existing detections may be mis-attributed as this run's | Documented in TESTING.md, ARCHITECTURE.md; split historical vs scan-specific needed |
| Windows-only forensic decoders unverified | ShimCache offsets, BAM/DAM P/Invoke, UserAssist, Prefetch, SRUM need real-box cross-check | Requires known-good forensic tooling comparison |
| Scanner detection parsers heuristic | KVRT/ESET/MSERT log parsers based on docs, not sample logs | Keep copied logs; require real-box eyeball before trusting counts |
| GUI untested on real machines | WPF workflow, Findings UI, RemediationPreview, attended launches need manual walkthrough | Owner must run on Windows |
| SC key map ASSUMED NOT CONFIRMED | Relay-identity extraction based on legacy analysis, not live validation | M0 live lab validation is top priority, out of scope for agents |

---

## Verification Gates Before Declaring Done

Every `.ps1/.psm1/.psd1/.xaml/.json/.bat/.md` file created/modified must pass:

1. **Parse check (0 errors):**
   ```powershell
   $e=$null; $t=$null
   [System.Management.Automation.Language.Parser]::ParseFile($path,[ref]$t,[ref]$e) | Out-Null
   if ($e.Count -eq 0) { 'PARSE OK' } else { $e | ForEach-Object { "$($_.Extent.StartLineNumber): $($_.Message)" } }
   ```

2. **ASCII byte check (0 non-ASCII):**
   ```bash
   python3 -c "import io;b=io.open('file','rb').read();print(sum(1 for c in b if c>127))"
   # Must print 0
   ```

3. **Pester tests GREEN** for the module's public API

4. **Module imports cleanly:**
   ```powershell
   Import-Module <path>; Get-Command -Module <name>
   ```

These gates are enforced by `tests/ci/Test-HouseRules.ps1`, `tests/ci/Test-Parse.ps1`, and the CI workflow.
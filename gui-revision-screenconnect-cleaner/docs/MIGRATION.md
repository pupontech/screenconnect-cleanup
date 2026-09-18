# ScreenConnect Cleaner - Migration Map

This document maps every legacy component to its new home in the GUI revision, describing what changed, what was added, and what was dropped. It is the expanded version of ARCHITECTURE.md section 11.

## Component Migration Table

| Legacy Component | New Component | What Changed / Added / Dropped |
|---|---|---|
| `sc-cleanup.ps1` (stage runner) | `Scc.Cleaner.ps1` + `Scc.UI` state machine | **Changed**: Stage runner -> state machine with resume. **Added**: Headless mode (-Headless), resume via -ResumeRunId, plan injection via -PlanPath, elevation handling inside .ps1, PSModulePath wiring, Server OS refusal (exit 3), exit codes (0/1/2/3). **Dropped**: -sa/-sr/-np/-offline/-WhatIf flags (replaced by -Mode/-SkipScanners/-SkipPreflight/-NoRestorePoint). |
| `preflight.ps1` | `Scc.Core` (Get-SccComputerInfo, Test-SccInternet, Test-SccNas) + Stage 0 | **Changed**: Monolithic script -> modular functions. **Added**: Cached ComputerInfo, structured JSONL logging, NAS reachability with timeout, config-driven paths, restore point handled by Scc.Remedy. **Dropped**: Desktop output folder (replaced by Documents\\ScreenConnect Cleanup\\Reports). |
| `detect-remote-access.ps1` | `Scc.Detection` | **Changed**: Single script -> module with exports. **Added**: Trusted relay matching (Known/Unknown), confidence scoring, full SC identity fields (RelayHost, InstanceId, ServerKey, ServerFingerprint, SessionType, InstallTimestampUtc, CustomProperties, Persistence, AssociatedProcesses, NetworkConnections, ParsedParameters, UnknownParameters, ParserWarnings, Confidence, TrustMatch, TrustedRelayEntry, DetectionSources), targets.json schema with embedded defaults, self-test (Invoke-SccDetectionSelfTest). **Dropped**: -OutRoot, -NoZip, -NoPause (now part of Scc.Cleaner config). |
| `targets.json` | `config/targets.json` + embedded defaults in Scc.Detection | **Changed**: External file -> config file + embedded fallback. **Added**: Schema version, explicit Enabled flag per target, structured Detection section (Services, Processes, Registry, UninstallDisplay, Files). **Dropped**: None - fully preserved. |
| `collect-snapshot.ps1` | `Scc.Evidence` | **Changed**: Script -> module with New-SccSnapshot export. **Added**: Schema v2 with stable Keys, sorted arrays, per-section error recording, runspace parallelism (max 4), retro artifacts (Prefetch, ShimCache, BAM/DAM, UserAssist, SRUM), IncidentWindowDays filter, SystemSettings (RDP, hosts file), CollectionErrors array. **Dropped**: Output to Desktop (now run directory). |
| `diff-snapshots.ps1` | `Scc.Snapshots` | **Changed**: Script -> module with Compare-SccSnapshots, Test-SccResurrection. **Added**: Structured diff object (Removed/StillPresent/New/Changed per section), Summary counts, writes diff.json to run dir, resurrection detection for SC installations and remote-access services. |
| `remove-screenconnect.ps1` | `Scc.Remedy` | **Changed**: Script -> plan-gated module. **Added**: New-SccPlan (KEEP default, only ScreenConnect removable), Test-SccPlan (dry-run), Invoke-SccRemediation (-Execute required), vendor uninstaller read at runtime (UninstallString/QuietUninstallString/msiexec), quarantine with ACL (SYSTEM+Admins), quarantine-manifest.json with RestoreInstructions, Restore-SccQuarantineItem, Clear-SccQuarantine (double-confirm). **Dropped**: Tikun destructive step (opt-in delete with scheduled task). |
| `Invoke-ReviewAndRemove.ps1` | `Scc.UI` Findings.xaml + `New-SccPlan` | **Changed**: Interactive prompt -> WPF Findings UI with per-finding KEEP/REMOVE checkboxes, full SC identity fields, trust badge, evidence links. **Added**: Default KEEP for everything, explicit approval writes plan.json, only ScreenConnect entries switchable to REMOVE. |
| `Invoke-GUIScanner.ps1` + `scanners/Invoke-*.ps1` | `Scc.Scanners` | **Changed**: Separate scripts -> unified module with registry + adapters. **Added**: Get-SccScannerList, Invoke-SccScanner (CLI adapters: Defender, KVRT, MSERT), Invoke-SccGuiScanner (attended: AdwCleaner, ESETOnline, Malwarebytes), timeout enforcement, log-file parsing (never stdout), WhatIf mode, tool provenance recording. **Dropped**: Silent-scan flags for GUI-only scanners (owner policy: attended only). |
| `tools/Get-AVTools.ps1` | `Scc.Tools` + `tools/Get-AVTools.ps1` | **Changed**: Script -> ToolManager module (Get-SccToolCatalog, Resolve-SccTool, Test-SccToolIntegrity, Get-SccToolStatus, Save-SccToolToCache) + kept script for NAS staging. **Added**: NAS-first acquisition (local -> NAS -> official), signature/hash/size/version validation, tool-cache-manifest.json, per-run tool-provenance.json, flat NAS layout fallback, NAS timeout warning not fatal. |
| `tools/Get-ToolPack.ps1` | `Scc.Tools` (Sysinternals acquisition) | **Merged**: Sysinternals tools (autorunsc64, sigcheck64, procmon, tcpview) now in Get-SccToolCatalog. **Added**: Hash verification against download.sysinternals.com, redistribution permitted. |
| `New-InvestigationReport.ps1` | `Scc.Report` | **Changed**: Script -> module with New-SccReport. **Added**: Self-contained HTML (XSS-safe), report.json (machine-readable), technician-summary.txt (<=60 lines), all sections from ARCHITECTURE sec 12, ConvertTo-SccHtml helper. **Dropped**: Zip output to Desktop (reports stay in run directory). |
| `tests/ci/*.ps1` | `tests/ci/*.ps1` (ported) | **Changed**: Scans new tree only, checks .psm1/.xaml/.json/.md too, enforces .bat CRLF, binary check, still validates JSON parse. **Added**: Test-SelfTests.ps1 (invokes module self-test hooks). |
| `START-HERE.bat` / `RUN-REMOVAL-TEST.bat` | `Start-ScreenConnectCleaner.bat` + headless | **Changed**: Two batch files -> one launcher. **Added**: Elevation inside Scc.Cleaner.ps1, headless mode for CI/automation, -Mode DetectOnly/ScanOnly/Full, -ResumeRunId, -PlanPath. **Dropped**: RUN-REMOVAL-TEST.bat (replaced by -Headless -PlanPath). |
| `.github/workflows/windows-ci.yml` | `.github/workflows/gui-revision-ci.yml` | **New file only** (root workflows dir requirement). **Added**: linux-static (pwsh parse + unit + ASCII), windows-dynamic matrix (windows-2022/2025, PS 5.1 + pwsh parse, unit, self-tests, headless smoke DetectOnly, malformed-config, build+verify). **Dropped**: Modifies nothing existing. |

---

## Functionality Not Accidentally Lost - Checklist

Each legacy capability cross-referenced with its new home:

| Legacy Capability | New Location | Verified |
|---|---|---|
| Admin check + restore point | `Scc.Core` Get-SccComputerInfo + `Scc.Remedy` (config safety) | Yes |
| Internet/NAS connectivity test | `Scc.Core` Test-SccInternet, Test-SccNas | Yes |
| Working directory creation | `Scc.Core` New-SccRun (RunDir with subdirs) | Yes |
| Tool pack staging | `Scc.Tools` Get-SccToolStatus, Resolve-SccTool | Yes |
| Service inventory | `Scc.Evidence` Snapshot.Sections.Services | Yes |
| Scheduled tasks inventory | `Scc.Evidence` Snapshot.Sections.ScheduledTasks | Yes |
| Registry autoruns | `Scc.Evidence` Snapshot.Sections.RegistryAutoruns | Yes |
| Startup folders | `Scc.Evidence` Snapshot.Sections.StartupFolders | Yes |
| Process inventory | `Scc.Evidence` Snapshot.Sections.Processes | Yes |
| Network connections | `Scc.Evidence` Snapshot.Sections.Connections | Yes |
| Installed programs | `Scc.Evidence` Snapshot.Sections.InstalledPrograms | Yes |
| Local accounts | `Scc.Evidence` Snapshot.Sections.LocalAccounts | Yes |
| Firewall rules | `Scc.Evidence` Snapshot.Sections.FirewallRules | Yes |
| WMI persistence | `Scc.Evidence` Snapshot.Sections.WmiPersistence | Yes |
| Recent files | `Scc.Evidence` Snapshot.Sections.RecentFiles | Yes |
| ScreenConnect installations | `Scc.Evidence` Snapshot.Sections.ScInstallations | Yes |
| System settings (RDP, hosts) | `Scc.Evidence` Snapshot.Sections.SystemSettings | Yes |
| Retro: Prefetch | `Scc.Evidence` (implemented) | Yes |
| Retro: ShimCache | `Scc.Evidence` (implemented) | Yes |
| Retro: BAM/DAM | `Scc.Evidence` (implemented) | Yes |
| Retro: UserAssist | `Scc.Evidence` (implemented) | Yes |
| Retro: SRUM | `Scc.Evidence` (implemented) | Yes |
| Retro: Amcache | **MISSING** - not implemented (scope open) | No |
| SC instance identity extraction | `Scc.Detection` Get-SccScreenConnect | Yes |
| Other RAT presence detection | `Scc.Detection` Get-SccRemoteAccess | Yes |
| Trusted relay matching | `Scc.Detection` Test-SccTrustedRelay | Yes |
| Technician review gate | `Scc.UI` Findings.xaml + `Scc.Remedy` New-SccPlan | Yes |
| Vendor uninstaller first | `Scc.Remedy` Invoke-SccRemediation | Yes |
| Quarantine (not delete) | `Scc.Remedy` quarantine + manifest | Yes |
| ACL-locked quarantine | `Scc.Remedy` (SYSTEM+Admins, Users removed) | Yes |
| Quarantine restore | `Scc.Remedy` Restore-SccQuarantineItem | Yes |
| Permanent delete (double-confirm) | `Scc.Remedy` Clear-SccQuarantine | Yes |
| Before/after snapshots | `Scc.Evidence` New-SccSnapshot (before/after) | Yes |
| Snapshot diff | `Scc.Snapshots` Compare-SccSnapshots | Yes |
| Resurrection detection | `Scc.Snapshots` Test-SccResurrection | Yes |
| Defender scanner | `Scc.Scanners` Defender adapter | Yes |
| KVRT scanner | `Scc.Scanners` KVRT adapter | Yes |
| MSERT scanner | `Scc.Scanners` MSERT adapter | Yes |
| ESET Online (attended) | `Scc.Scanners` Invoke-SccGuiScanner | Yes |
| AdwCleaner (attended) | `Scc.Scanners` Invoke-SccGuiScanner | Yes |
| Malwarebytes (attended) | `Scc.Scanners` Invoke-SccGuiScanner | Yes |
| Sysinternals tools | `Scc.Tools` catalog (4 tools) | Yes |
| HTML report | `Scc.Report` New-SccReport -> report.html | Yes |
| JSON report | `Scc.Report` New-SccReport -> report.json | Yes |
| Technician summary | `Scc.Report` New-SccReport -> technician-summary.txt | Yes |
| Credential-reset checklist | `Scc.Report` (in HTML) | Yes |
| Tool provenance in report | `Scc.Report` reads tool-provenance.json | Yes |
| Resume interrupted run | `Scc.Core` Get-SccRunState + `Scc.Cleaner` -ResumeRunId | Yes |
| Headless mode | `Scc.Cleaner.ps1` -Headless | Yes |
| Portable packaging | `build/Build-Portable.ps1` | Yes |
| Optional installer | `build/Install-Scc.ps1` | Yes |
| ASCII/BOM/parse checks | `tests/ci/Test-HouseRules.ps1`, `Test-Parse.ps1` | Yes |
| Self-test hooks | `tests/ci/Test-SelfTests.ps1` | Yes |
| Headless smoke test | `tests/Integration/Headless-Smoke.Tests.ps1` | Yes |

---

## Deliberate Dropped / Changed Items

| Item | Legacy | New | Reason |
|---|---|---|---|
| Output zip to Desktop | `sc-cleanup.ps1` -NoZip | Removed | Reports stay in run directory; portable folder is the deliverable |
| Tikun destructive step | `START-HERE.bat` Step 7 | Removed | Violates "quarantine, never delete"; opt-in scheduled task delete is unsafe |
| -sa (skip scanners) | `sc-cleanup.ps1` | `-SkipScanners` | Renamed for clarity |
| -sr (snapshot only) | `sc-cleanup.ps1` | `-Mode DetectOnly` | Unified mode system |
| -np (no restore point) | `sc-cleanup.ps1` | `-NoRestorePoint` | Preserved |
| -offline | `sc-cleanup.ps1` | Config `download.allowed: false` | Config-driven |
| -WhatIf on orchestrator | `sc-cleanup.ps1` | Dry-run is default; -Execute required for real | Safety by default |
| Desktop output folder | All scripts | `Documents\ScreenConnect Cleanup\Reports\` | Standard user location, not Desktop |
| Server OS auto-run | `preflight.ps1` | Refuses by default (config override) | Safety rule 8 |
| Silent scanner failure | Various | Failure = non-fatal AND reported | Safety rule 9 |
| "No malware found" verdict | Report | "Scanners skipped" / "Scanner X failed" | Safety rule 10 |
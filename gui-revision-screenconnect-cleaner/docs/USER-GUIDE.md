# ScreenConnect Cleaner - User Guide

Technician-facing documentation for launching, using, and troubleshooting the GUI application.

> **Read this first — safety model.**
> ScreenConnect Cleaner is **DETECT-ONLY / read-only by default**. No system
> state changes unless you explicitly opt in to remediation. In the GUI, every
> finding defaults to **KEEP** and you must approve a plan (`plan.json`) at the
> Review step before anything is touched. In headless mode the pipeline *stops
> and waits* at the Review gate unless you supply a pre-approved plan via
> `-PlanPath`. There is **no detect-and-remove flag** and removal is **never
> automatic**.
>
> The remediation engine (`Invoke-SccRemediation`) is **dry-run by default** and
> only performs real actions when called with `-Execute` (GUI: explicit Approve
> + double-confirm; headless: a plan injected via `-PlanPath`).
>
> This tool is **completely vibe coded** (AI-assisted, with test guardrails) and
> has **NOT** been validated against a live ScreenConnect install or run on real
> client machines. Run it only on a lab/tested machine you are authorized to
> service. **Destructive removal only on a disposable lab VM.**

> **Platform note.** The GUI is a **WPF (XAML)** application and requires a
> Windows desktop session (PowerShell 5.1 on Windows). On non-Windows hosts
> only **headless mode** (`-Headless`) is available — the same stage state
> machine runs without the WPF shell.

---

## Launching the Application

### Portable (Recommended)

1. Download `ScreenConnectCleaner-<version>-portable.zip` from releases (or run `build/Build-Portable.ps1`).
2. Unzip to any folder (including a NAS share).
3. Run `Start-ScreenConnectCleaner.bat` (right-click **Run as administrator** for full detection).
4. The GUI opens at the Dashboard.

No installation required. The portable folder is self-contained.

### Optional Installer

Run as Administrator:
```powershell
pwsh -NoProfile -File build/Install-Scc.ps1 -Install
```

Installs to:
- `%ProgramFiles%\ScreenConnectCleaner\`
- Start Menu shortcuts (app + docs)
- Machine config stub at `%ProgramData%\ScreenConnectCleaner\config\scc-config.json`

Use `-WhatIf` to preview. Use `-Uninstall` to remove only what the installer placed.

---

## Dashboard (Stage 0 - Preflight)

The Dashboard shows:
- **System Info**: Computer name, OS, architecture, current user, admin status, free space, memory, uptime, domain/workgroup, server OS detection
- **Admin Status**: Green = elevated, Red = not elevated (click to re-launch elevated)
- **Connectivity**: Internet reachable, NAS reachable (with configured path)
- **Tool Status**: Each scanner/tool shows cached version, NAS availability, verified status
- **Disk Space**: Free space on system drive
- **App Version**: Current version

**Actions:**
- **Start Full Investigation** - Runs all stages (Preflight -> Snapshot A -> Detection -> Review -> Remediate -> Scanners -> Snapshot B -> Compare -> Report)
- **Detection Only** - Read-only: Preflight -> Snapshot A -> Detection -> Report (skips Review/Remediate/Scanners)
- **Scan Only** - Runs scanners on current machine (requires previous Detection run or runs Detection first)
- **Review Previous Report** - Opens ReportView with a selected past run
- **Settings** - Opens Settings tab
- **Advanced Tools** - Opens Advanced tab

---

## Full Workflow Walkthrough

### Stage 0: Preflight
- Admin elevation check (refuses if not admin and not overridden)
- Restore point creation (configurable, default ON; verifies System Restore is actually enabled)
- Working directory creation under `Documents\ScreenConnect Cleanup\Reports\SC-<date>-<host>-<time>\`
- Tool pack staging (local cache -> NAS -> official vendor)

**Skip with:** `-SkipPreflight` (headless) or uncheck in Workflow view.

### Stage 1: Snapshot A (Before)
Collects system state BEFORE any changes:
- Services, Scheduled Tasks, Registry Autoruns, Startup Folders
- Processes, Network Connections
- Installed Programs, Local Accounts
- Firewall Rules, WMI Persistence
- Recent Files (incident window), ScreenConnect Installations
- System Settings (RDP enabled, hosts file)
- Retro artifacts: Prefetch, ShimCache, BAM/DAM, UserAssist, SRUM

**Cannot be skipped.** This is the baseline for the after-diff.

### Stage 2: Detection (Read-Only)
- **ScreenConnect**: Deep instance identity extraction from services, processes, config files, registry, firewall rules, scheduled tasks, Run keys
  - Fields: RelayHost, InstanceId, ServerKey, ServerFingerprint, SessionType, InstallPath, ServiceName, ServiceState, ExecutablePath, InstallTimestampUtc, Publisher, SignatureStatus, FileVersion, ProductVersion, CustomProperties, Persistence, AssociatedProcesses, NetworkConnections, ParsedParameters, UnknownParameters, ParserWarnings, Confidence, TrustMatch (Known/Unknown), TrustedRelayEntry, DetectionSources
- **Other Remote Access**: Presence detection for AnyDesk, TeamViewer, UltraViewer, Supremo, RustDesk, Splashtop, LogMeIn/GoTo, Zoho Assist, Atera, DWAgent, MeshCentral, NetSupport, Remote Utilities, VNC family (configurable via `targets.json`)

Writes `findings.json` to run directory. **Never modifies system state.**

### Stage 3: Review (Findings Screen)
**This is the approval gate. Nothing is removed without your explicit decision.**

- Per-finding table with checkboxes: **KEEP** (default) / **REMOVE**
- Full ScreenConnect identity fields displayed (Relay Host, Instance ID, Server Key Fingerprint, Session Type, Install Path, Install Time, Custom Properties, Trust Badge)
- Trust badge: **Known** (matches trusted-relays.json) or **Unknown** (no match). **Unknown is NEVER auto-classified malicious.**
- Evidence links: click to view raw config, service ImagePath, process command line, registry values
- **Default KEEP for everything.** Only ScreenConnect entries may be switched to REMOVE.
- Click **Approve Plan** to write `plan.json` and proceed.

### Stage 4: Remediate
Consumes `plan.json`. **Dry-run by default.**

The remediation engine (`Invoke-SccRemediation`) only performs real actions
when invoked with `-Execute`. In the GUI this happens when you approve the plan
and pass the double-confirmation prompt (the run is created with the execute
context set by your approval). In headless mode, real removal only occurs when
you supply a plan via `-PlanPath` that was produced through an explicit review
(`New-SccPlan`) — the pipeline never auto-approves.

**With real execution enabled (GUI double-confirm, or headless with an
approved plan):**
Per approved REMOVE item (ScreenConnect only):
1. Stop service (if any)
2. Kill associated processes
3. Run vendor uninstaller (reads UninstallString/QuietUninstallString or msiexec /x {ProductCode} from registry at runtime - never hardcoded)
4. Validate removal
5. Manual cleanup of leftovers: service delete, scheduled task delete, Run key removal, firewall rule removal
6. Quarantine remaining artifacts (files/dirs moved to `%ProgramData%\ScreenConnectCleaner\Quarantine\<RunId>\q\...` with ACL: SYSTEM + Administrators full control, Users removed)

Writes `remediation.json` (every action, result, error) + `quarantine-manifest.json` (OriginalPath, QuarantinePath, SHA256, SizeBytes, MovedUtc, FindingId, Reason, ActionType, RestoreInstructions).

### Stage 5: Scanners
Runs enabled CLI scanners sequentially (Defender, KVRT, MSERT):
- **Defender**: `MpCmdRun -Scan -ScanType 3 -DisableRemediation` on system drive; threat history read separately (labeled historical)
- **KVRT**: Documented CLI, log dir `%SystemDrive%\KVRT*_Data`
- **MSERT**: Documented CLI, log `%SystemRoot%\debug\msert.log`

Attended scanners (AdwCleaner, ESET Online, Malwarebytes):
- Launch visible GUI, wait for close
- Record Start/End/Duration + Result (Completed/Aborted/Timeout/LaunchFailed)

Results written to `scanner-results/`. Skippable via `-SkipScanners` or Settings.

**Scanner failure is non-fatal AND reported as failure** - never silently swallowed into a "clean" verdict.

### Stage 6: Snapshot B (After)
Same collection as Stage 1, post-remediation.

### Stage 7: Compare
Diffs Snapshot A vs B per section:
- **Removed** - items in A not in B
- **Still Present** - items in both
- **New** - items in B not in A (flags resurrections)
- **Changed** - same Key, different fields

Flags resurrections in SC installations and remote-access services specifically.

Writes `snapshots/diff.json`.

### Stage 8: Report
Generates in run directory:
- `report.html` - Self-contained, XSS-safe, all sections (see Report Locations)
- `report.json` - Machine-readable everything
- `technician-summary.txt` - <= 60 lines plain text for quick handoff

---

## NAS Setup

Configure in Settings tab or `config/scc-config.json`:

```json
"nas": {
  "enabled": true,
  "path": "\\\\NAS\\TechnicianTools\\Security",
  "priorityOrder": ["local", "nas", "official"],
  "timeoutSeconds": 15
}
```

- **Priority Order**: Acquisition order for each tool. Default: local cache -> NAS -> official vendor.
- **Path**: UNC path to technician tools share. Supports `%ENVVAR%` expansion.
- **Timeout**: NAS reachability test timeout (default 15s). Failure is WARNING, proceeds to next source.
- **Layout**: NAS expected at `<nas.path>\<Tool>\<FileName>` (case-insensitive). Flat layout also accepted.

---

## Scanner Acquisition + Licensing

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

## Trusted Relays

File: `config/trusted-relays.json` (template included). Format:

```json
{
  "trustedRelays": [
    { "relay": "support.example.com", "name": "Our MSP", "fingerprint": "a3f9c1...", "notes": "" }
  ]
}
```

- **Matching**: Case-insensitive hostname match. Optional fingerprint match (16 hex chars, lowercase) against detected `ServerKeyFingerprint`.
- **Result**: Finding shows **Known** (exact match) or **Unknown** (no match). Unknown is NEVER auto-classified malicious - technician decides.
- **Editor**: GUI Settings tab includes a trusted-relays editor.

---

## Quarantine

- **Location**: `%ProgramData%\ScreenConnectCleaner\Quarantine\<RunId>\q\...`
- **ACL**: SYSTEM + Administrators full control; Users removed. Never inside `%TEMP%`.
- **Manifest**: `quarantine-manifest.json` records `OriginalPath`, `QuarantinePath`, `SHA256`, `SizeBytes`, `MovedUtc`, `FindingId`, `Reason`, `ActionType`, `RestoreInstructions`.
- **Restore**: `Restore-SccQuarantineItem -Run <RunId> -ItemId <Id>` - moves file back to original path (explicit confirmation required).
- **Permanent delete**: `Clear-SccQuarantine -Run <RunId> -Approved` - double-confirmation required, never automatic, logged + reported.

---

## Report Locations

Per-run directory: `%USERPROFILE%\Documents\ScreenConnect Cleanup\Reports\SC-<date>-<host>-<time>\`

Files:
- `report.html` - Self-contained, XSS-safe, all sections:
  - Executive Summary
  - System Information
  - Incident Timeline
  - ScreenConnect Findings (with identity table + trust column Known/Unknown)
  - Other Remote Access Findings
  - Persistence
  - Network Findings
  - Scanner Results
  - Remediation Actions
  - Quarantine
  - Before/After Comparison (Removed/Still Present/New/Reappeared/Changed)
  - Outstanding Concerns
  - Errors / Warnings
  - Tool Provenance
  - Credential / Incident Follow-up Checklist
  - Raw Evidence Index
- `report.json` - Machine-readable everything
- `technician-summary.txt` - <= 60 lines plain text for quick handoff

---

## Configuration (All Keys)

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
| `detection.defaultTargets` | array | `["ScreenConnect"]` | Default detection targets |
| `logging.level` | string | `INFO` | Log level (TRACE..CRITICAL) |
| `logging.retentionDays` | int | 90 | Log retention |
| `safety.serverOsRefusal` | bool | true | Refuse on Server OS |
| `safety.dryRunDefault` | bool | true | Dry-run by default |
| `safety.removableProducts` | array | `["ScreenConnect"]` | Products allowed for REMOVE |
| `evidence.retentionDays` | int | 30 | Evidence retention |
| `ui.confirmDestructive` | bool | true | Double-confirm destructive actions |
| `ui.language` | string | `en` | GUI language (English only currently) |

---

## Headless Mode (CLI / CI / Automation)

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

**Exit codes:**
- 0 = finished successfully
- 1 = failed / incomplete / awaiting review (no plan provided)
- 2 = missing dependency (manifest not found or module import failure)
- 3 = refused (Server OS, config override required)

---

## Resuming an Interrupted Run

1. **GUI**: Dashboard shows "Resume Previous Run" with a dropdown of recent runs (last 7 days). Select and click Resume.
2. **Headless**: Use `-ResumeRunId SC-<date>-<host>-<time>`.
3. The tool reloads `runstate.json`, re-opens the run directory, and re-enters at the first non-Completed stage.
4. Completed stages never re-run automatically.

---

## Advanced Tools Tab

- **Quarantine Browser**: List all quarantined items across runs, restore or permanently delete (double-confirm).
- **Manual Tool Acquisition**: Force-download/verify any tool from the catalog to local cache or NAS.
- **Procmon Note**: Documents Stage 6 (opt-in Procmon boot logging) - not yet implemented.
- **Dry-Run Runner**: Run `Test-SccRemediation` against any plan.json to preview exact actions without touching the system.

---

## Troubleshooting

### "Script won't run - execution policy"
Run the `.bat` launcher (bypasses execution policy) or use:
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File Scc.Cleaner.ps1
```

### "Not elevated - detection incomplete"
Right-click `Start-ScreenConnectCleaner.bat` -> **Run as administrator**. Or click the "Re-launch Elevated" button on the Dashboard.

### "Server OS refused"
By default, Server OS (Windows Server 2016/2019/2022) is refused. Override in Settings -> Safety -> uncheck "Refuse on Server OS" or set `safety.serverOsRefusal: false` in config.

### "NAS unreachable"
Check `nas.path` in Settings. Verify UNC path is accessible from this machine. Timeout is 15s default (configurable). Failure is a warning only - tool acquisition falls back to official vendor.

### "Scanner failed / timed out"
Check `scanner-results/<scanner>.log` in the run directory. Increase `scanners.defaultTimeoutMinutes` in config. Scanner failure is reported in the report - it does not fail the run.

### "No findings but I know it's there"
- Run with `-All` to scan all targets (ignores enabled/disabled in targets.json)
- Check `targets.json` - the product may be disabled by default
- Review `logs/master.log` and `logs/detection.jsonl` for parser warnings
- The SC key map is ASSUMED NOT CONFIRMED - relay identity extraction may miss unknown parameter formats

### "Quarantine restore failed"
- Must run as Administrator
- Original path must be writable
- Use `Restore-SccQuarantineItem -Run <RunId> -ItemId <Id>` from PowerShell for detailed error

### "Report won't open"
Open `report.html` in any browser (self-contained, no external dependencies). If browser blocks local file access, serve via `python3 -m http.server` in the run directory.

---

## Safety Reminders

1. **Review every finding** - the Findings UI defaults to KEEP. Never approve a plan without verifying each entry.
2. **Test in your lab first** - this tool has NOT been validated against a live ScreenConnect installation and has NOT been run on real client machines.
3. **Quarantine, never delete** - removal moves to ACL-locked quarantine. Permanent delete requires double-confirmation.
4. **Removal != remediation** - the report ends with a credential-reset checklist. If a scammer had interactive access, credentials, browser cookies, saved passwords, mail rules, and new accounts are all at risk.
5. **Destructive removal only on disposable lab machines** - never on a real client or dev machine.
6. **MIT license, no warranty** - you assume all risk.

---

## Keyboard Shortcuts (GUI)

| Key | Action |
|-----|--------|
| F1 | Open this guide (local copy) |
| F5 | Refresh current view |
| Ctrl+S | Save settings (Settings tab) |
| Ctrl+R | Resume last run (Dashboard) |
| Escape | Cancel current operation / close dialog |

---

## Log Files

Per-run logs in `<RunDir>/logs/`:
- `master.log` - Human-readable, tailed by Logs view
- `<stage>.jsonl` - Structured JSONL per stage (for programmatic analysis)

Log level configurable: `TRACE`, `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` (default: `INFO`)

---

## Getting Help

- Check `docs/ARCHITECTURE.md` for the full technical contract
- Check `docs/TESTING.md` for test status and known limitations
- Check `docs/MIGRATION.md` for legacy-to-new mapping
- Report issues with: run directory (zipped), `logs/master.log`, `findings.json`, and description of expected vs actual behavior
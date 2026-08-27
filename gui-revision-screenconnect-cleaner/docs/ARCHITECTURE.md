# ScreenConnect Cleaner (GUI Revision) - Architecture

Target: a technician-friendly Windows GUI application for investigating and cleaning
machines with unauthorized ScreenConnect / ConnectWise Control installs, other
remote-access software, and scam-related malware. This document is the contract for
all builders. Everything in this revision lives in the folder
`gui-revision-screenconnect-cleaner/` on branch `gui-revision-screenconnect-cleaner`.
The legacy top-level scripts remain untouched.

Status: M1 architecture. Decisions below supersede older docs where they conflict.

---

## 1. Core decisions

| Decision | Choice | Why |
|---|---|---|
| D-ARCH-1 App shell | Windows PowerShell 5.1 + WPF (XAML) | Reuses the ~7K lines of mature PS logic directly; PS 5.1 is present on every target box; no build chain; a compiled EXE would trip AV on the machines under investigation (legacy decision, still valid). |
| D-ARCH-2 Backend | PowerShell modules, one file set each, PS 5.1 compatible | Testable on Linux via pwsh + Pester; single language for the whole app. |
| D-ARCH-3 UI responsiveness | Dedicated background runspace pool + WPF Dispatcher | Long ops never block the UI thread. Cancel = cooperative token + runspace stop. |
| D-ARCH-4 Packaging | Portable folder as primary; optional PS install script (Program Files + Start menu) | Portable-first fits technician/NAS use. |
| D-ARCH-5 Runtime baseline | Windows PowerShell 5.1, Windows 10/11 x64 (also arm64 where 5.1 exists); Server OS refuses unless config override | Legacy safety rule 8. |
| D-ARCH-6 Trust | trusted-relays.json: technician-maintained known-good relays. A finding is Known (exact match) or Unknown. NEVER auto-classified malicious. | New brief sec. 23. Supersedes old D4 "no allowlist": matching is config-driven and never a verdict on unknowns. |
| D-ARCH-7 Scanners | CLI adapters ONLY where vendor CLI is documented (Defender MpCmdRun, KVRT, MSERT). GUI-only scanners (ESET Online, Malwarebytes, AdwCleaner) launch ATTENDED and wait for close (owner policy 2026-08-26). | Never invent silent-scan flags. |
| D-ARCH-8 Tool acquisition | ToolManager: local cache -> NAS -> official vendor, with signature/hash/size/version validation + provenance record. Order configurable. | New brief sec. 4-7. |
| D-ARCH-9 Removal | Plan-file gated, dry-run default, ScreenConnect-only removable, quarantine-never-delete, vendor uninstaller first. | Legacy 12 safety rules + owner policy. |

---

## 2. Folder layout

```text
gui-revision-screenconnect-cleaner/
  README.md                      # app README (prominent "Completely vibe coded")
  LICENSE                        # MIT
  CHANGELOG.md
  Scc.Cleaner.ps1                # entry point: GUI default, -Headless for CI/CLI
  Start-ScreenConnectCleaner.bat # launcher (CRLF, pure ASCII)
  src/
    Scc.Core/       Scc.Core.psd1 + Scc.Core.psm1        # logging, config, paths, runs, caches, errors
    Scc.Detection/  Scc.Detection.psd1 + Scc.Detection.psm1  # SC + remote-access detection, trust matching
    Scc.Evidence/   Scc.Evidence.psd1 + Scc.Evidence.psm1     # snapshot collection
    Scc.Snapshots/  Scc.Snapshots.psd1 + Scc.Snapshots.psm1   # A/B store + diff
    Scc.Tools/      Scc.Tools.psd1 + Scc.Tools.psm1           # ToolManager (NAS-first)
    Scc.Scanners/   Scc.Scanners.psd1 + Scc.Scanners.psm1     # scanner registry + adapters
    Scc.Remedy/     Scc.Remedy.psd1 + Scc.Remedy.psm1         # plan, review, uninstall, quarantine
    Scc.Report/     Scc.Report.psd1 + Scc.Report.psm1         # report.html/json/technician-summary.txt
    Scc.UI/         Scc.UI.psm1 + Views/*.xaml + UI code-behind   # WPF shell + stage workflow
  config/
    scc-config.json         # defaults (embedded copy also lives in Scc.Core)
    trusted-relays.json     # template
    targets.json            # detection targets (toggleable)
  tests/
    Unit/                   # Pester *.Tests.ps1
    Integration/            # Pester integration
    ci/                     # house-rules, parse, contract checks (standalone, no Pester dep)
  build/
    Build-Portable.ps1      # stages portable folder + zip + SHA256
    Install-Scc.ps1         # optional Program Files install + shortcuts
  tools/
    Get-AVTools.ps1         # ported: stage AV tools from official URLs (NAS-aware via Scc.Tools)
  docs/
    ARCHITECTURE.md (this file)
    MIGRATION.md            # old component -> new module map
    TESTING.md              # test status, live-test matrix, known limitations
    USER-GUIDE.md
```

New CI workflow file (the ONLY addition outside the new folder):
`.github/workflows/gui-revision-ci.yml` (root-level workflows dir is a GitHub
requirement; the file is new, nothing existing is modified).

---

## 3. Module contracts

Common rules for ALL modules:
- PS 5.1 compatible: no `?:`, `??`, `?.`, `&&`, `||`, no `ConvertFrom-Json -AsHashtable`.
- Pure ASCII source, no BOM. No emoji in .ps1. CRLF not required for .ps1.
- Public API = functions listed below, exported via `Export-ModuleMember`. Private
  helpers stay internal (psm1 top-level functions not exported, or -Private flag).
- Every module must pass: parse check (0 errors), ASCII byte check (0 non-ASCII),
  Pester unit tests for its public API. VERIFY BY RUNNING, never by inspection.
- All destructive functions: `-DryRun` default or mandatory `-Execute` switch.
- Errors: throw on programmer errors; catch+record on environment errors
  (one failed section must not abort the run).

### 3.0 Manifest / PowerShell-version note (module-scope cmdlet fix)

The 9 module manifests deliberately do **NOT** set `PowerShellVersion = '5.1'`.
Setting that value forced the modules to load in 5.1-compatibility mode on the
CI runner (whose default shell is PowerShell 7 / `pwsh`). In that mode,
`Microsoft.PowerShell.Management` cmdlets (and module-scope functions) lost
visibility inside the modules, causing runtime failures on Windows CI.

Root-cause fix (verified on `windows-2022` + `windows-2025`, PS 5.1 and pwsh):
- Remove `PowerShellVersion = '5.1'` from every `.psd1` (keep `RequiredModules`).
- Qualify every `Microsoft.PowerShell.Management` cmdlet with its module prefix
  (e.g. `Microsoft.PowerShell.Management\Test-Path`) so resolution is
  unambiguous regardless of the loading edition.
- Keep modules PS 5.1 compatible (no `??`/`?:`/`&&`/`||`/`-AsHashtable`); rely on
  edition detection at runtime instead of a manifest-imposed version floor.

This is why the app runs on both Windows PowerShell 5.1 and PowerShell 7 while
still loading and exposing its functions correctly.

### 3.1 Scc.Core  (foundation - all others import it)

Exports:
- `Get-SccConfig [-Path <file>]` -> config hashtable/object (defaults merged with file
  overrides; malformed file -> defaults + warning record). Also loads trusted-relays.
- `Set-SccConfigValue -Name <string> -Value <obj> [-UserScope|-MachineScope]` -> writes
  the config file (user: %LocalAppData%\ScreenConnectCleaner\config\scc-config.json,
  machine: %ProgramData%\ScreenConnectCleaner\config\scc-config.json).
- `Get-SccPaths [-Run <run>]` -> computed path object:
  AppBinDir, ProgramDataDir (%ProgramData%\ScreenConnectCleaner), UserDataDir
  (%LocalAppData%\ScreenConnectCleaner), TempDir (%TEMP%\ScreenConnectCleaner\<runid>),
  ReportRoot (default %USERPROFILE%\Documents\ScreenConnect Cleanup\Reports),
  QuarantineRoot (%ProgramData%\ScreenConnectCleaner\Quarantine\<runid>),
  ToolCacheDir (%LocalAppData%\ScreenConnectCleaner\tools),
  ConfigUserDir, ConfigMachineDir, LogRoot.
- `New-SccRun [-IncidentDate <date>] [-Technician <name>] [-Client <name>]
  [-ForceServer]` -> run object: RunId = SC-yyyyMMdd-<HOST>-<hhmmss>, RunDir under
  ReportRoot, created on disk with subdirs evidence/ snapshots/ scanner-results/
  logs/ quarantine-meta/. Returns object. Refuses on Server OS unless -ForceServer
  or config override.
- `Save-SccRunState -Run -Stage <name> -Status Completed|Interrupted|Pending|Failed|Skipped
  [-Detail <string>]` -> updates runstate.json (stage map). `Get-SccRunState -RunId`
  -> state object. `Find-SccRecentRuns [-MaxAgeDays 7]` -> list for resume UI.
- `Write-SccLog -Run <run> -Level TRACE|DEBUG|INFO|WARNING|ERROR|CRITICAL
  -Stage <name> -Component <name> -Operation <name> -Message <string> [-Data <obj>]`
  -> appends structured JSONL line to logs/<stage>.jsonl and human line to
  logs/master.log. Level threshold from config. Data must be JSON-serializable.
- `Get-SccComputerInfo` -> ComputerName, OsCaption, OsVersion, Architecture,
  CurrentUser, IsAdmin, FreeSpaceGB (system drive), TotalMemoryGB, IsServer,
  Domain/Workgroup, UptimeMinutes. Cached per process.
- `Test-SccInternet [-TimeoutSeconds 10]` -> bool + detail.
- `Test-SccNas [-NasPath <string>]` -> {Reachable, Path, Error} (no hang > 15s).
- `Get-SccCache [-Key] / Set-SccCache -Key -Value [-TtlSeconds]` -> per-process cache
  registry (used for file metadata, hashes, signatures, service/process snapshots).
- `Get-SccFileFacts -Path` -> {Path, Exists, SizeBytes, SHA256, FileVersion,
  ProductVersion, Publisher (SignatureSubject), SignatureStatus, SignatureCert,
  LastWriteUtc, CreationUtc, Architecture} - cached; signature check never throws,
  returns SignatureStatus = Valid|Invalid|Unsigned|NotChecked|Error.
- `Resolve-SccEnv -Text` -> expands %VAR% environment placeholders in config paths.
- `Invoke-SccSafe -ScriptBlock -Stage -Component -Operation [-Throttle]` -> wraps a
  stage/section with try/catch: logs entry/exit/duration/failure, records errors in
  run state, never lets one section kill the run.
- `ConvertTo-SccJson -InputObject -Depth` -> safe JSON (MaxJsonLength, depth 10,
  single-element array fix). `ConvertFrom-SccJson -Path` -> tolerant read.

### 3.2 Scc.Detection

Exports:
- `Get-SccScreenConnect [-TargetsFile <path>] [-IncidentWindowDays <int>] [-Run <run>]`
  -> array of SC instance objects. Fields (null when not found):
  RelayHost, InstanceId, ServerKey (encoded), ServerFingerprint (derived),
  SessionType, InstallPath, ServiceName, ServiceState, ServiceImagePath,
  ExecutablePath, InstallTimestampUtc, Publisher, SignatureStatus, FileVersion,
  ProductVersion, CustomProperties (hashtable), Persistence (array of
  {Type,Location,Details}), AssociatedProcesses (array), NetworkConnections (array),
  RawLaunchParameters (string), ParamBlobSource (Service|Process|ConfigFile|None),
  ParsedParameters (hashtable), UnknownParameters (array), ParserWarnings (array),
  Confidence (High|Medium|Low), TrustMatch (Known|Unknown), TrustedRelayEntry
  (matched trusted-relays.json entry or null), DetectionSources (array of
  {Source,Key,Value}).
- `Get-SccRemoteAccess [-TargetsFile]` -> array of RAT findings: Product, DisplayName,
  DetectionType, Evidence (path/service/process/regkey + value), InstallTimestamp,
  Version, Publisher, Enabled/Stopped, Confidence. Covers: AnyDesk, TeamViewer,
  UltraViewer, Supremo, RustDesk, Splashtop, LogMeIn/GoTo, Zoho Assist, Atera,
  DWAgent, MeshCentral, NetSupport, Remote Utilities, VNC variants, plus anything in
  targets.json that is on.
- `Invoke-SccDetection -Run <run> [-Targets <array>] [-All]` -> combined findings
  object {ComputerName, DetectedUtc, ScreenConnect[], RemoteAccess[], Warnings[]}
  AND writes findings.json into the run dir. Detection is READ-ONLY - never modifies
  system state.
- `Get-SccTrustedRelays [-Config]` -> trusted-relays list.
- `Test-SccTrustedRelay -Relay <string> -Instance <obj>` -> {TrustMatch, Entry}
  (case-insensitive hostname match; optional fingerprint match).
- `Invoke-SccDetectionSelfTest` -> synthetic parameter blobs through the SC parser;
  returns failures (used by CI, no system access).

Detection techniques (must preserve at minimum, from legacy detect-remote-access.ps1):
- ScreenConnect: services (name pattern + ImagePath blob), running processes cmdline
  blob, ScreenConnect App_Config\*.config + Session groups registry, uninstall
  registry entries (DisplayName contains ScreenConnect/ConnectWise Control),
  instance dirs under Program Files (x86)\ScreenConnect Client (x86|64)\<instance>,
  Windows firewall rules, scheduled tasks, Run keys. Extract identity from the
  service ImagePath / process cmdline / config: relay host, s= session type, k=
  server key, e= access, p= port, t= thumbprint, y= proxy, c= etc. Handle URL-encoded
  values, malformed params, unknown params (record, never drop), multiple instances.
- targets.json schema (config/targets.json): { "Targets": { "<Product>": {
  "Enabled": bool, "Detection": { "Services": [...], "Processes": [...],
  "Registry": [...], "UninstallDisplay": [...], "Files": [...] } } } }.
  Embedded default copy inside the module so the module works standalone.

### 3.3 Scc.Evidence

Exports:
- `New-SccSnapshot -Run <run> -Label before|after [-IncidentWindowDays <int>]`
  -> snapshot object + writes snapshots/<label>.json. Schema v2:
  { SchemaVersion:2, Label, ComputerName, CollectedUtc, IsAdmin, OsCaption,
  IncidentWindowDays, SccAppVersion, CollectionErrors:[{Section,Error}],
  Sections: { Services, ScheduledTasks, RegistryAutoruns, StartupFolders, Processes,
  Connections, InstalledPrograms, LocalAccounts, FirewallRules, WmiPersistence,
  RecentFiles, ScInstallations, SystemSettings {RdpEnabled, HostsFileLines} } }.
  Every item carries a stable `Key` (identity fields only - never PID/timestamps).
  Arrays sorted by Key. Every section wrapped - failure recorded, collection continues.
- `Get-SccSnapshot -Run -Label` -> reads it back.
- Safe concurrency: independent sections may collect via runspaces (max 4) - see
  performance note sec. 8.

### 3.4 Scc.Snapshots

Exports:
- `Compare-SccSnapshots -Before <obj|path> -After <obj|path>` -> diff object
  { Sections: { <Section>: { Removed:[], StillPresent:[], New:[], Changed:[
    {Key, Field, Before, After}] } }, Summary: {RemovedCount, StillPresentCount,
  NewCount, ChangedCount} } and writes snapshots/diff.json when -Run given.
- `Test-SccResurrection -Diff` -> items flagged New/Changed in ScInstallations or
  services matching remote-access patterns -> important finding list.

### 3.5 Scc.Tools  (ToolManager - NAS-first)

Exports:
- `Get-SccToolCatalog` -> built-in catalog: KVRT, MSERT, AdwCleaner, ESETOnline,
  Malwarebytes, plus Sysinternals (autorunsc64, sigcheck64, procmon, tcpview).
  Per tool: Name, FileName, OfficialUrl, Publisher, MinVersion, ExpectedArchitecture,
  Licensing note, AttendedOnly (bool), Redistributable (bool).
- `Resolve-SccTool -Tool <name> -Run <run> [-ForceRefresh]` -> tool object
  { Name, ResolvedPath, Source (LocalCache|Nas|Official|None), Version, Publisher,
  SHA256, SignatureStatus, SizeBytes, AgeDays, VerifiedAtUtc, Provenance {
  CandidatesTried:[...], DownloadUrl, FinalUrl, Redirects, Warnings[] } }.
  Acquisition order per config (default: local cache -> NAS -> official).
  NAS: <nas.path>\<Tool>\<FileName> (case-insensitive, also allow flat layout).
  Failure to reach NAS is WARNING, never fatal; proceeds to next source.
  Official: HTTPS, record URL + final URL, then validate.
- `Test-SccToolIntegrity -Tool` -> re-verify cached tool (size, SHA256, signature,
  version) -> bool + report.
- `Get-SccToolStatus [-Run]` -> array for dashboard (per tool: cached?, NAS?,
  reachable?, version, verified, source).
- `Save-SccToolToCache -Path -Tool` -> copies validated tool to cache, writes
  tool-cache-manifest.json entry {Name, Version, SHA256, Size, Publisher,
  SignatureStatus, CachedUtc, Source}.
- Tool provenance for EVERY used tool goes into the run's tool-provenance.json and
  the report.

### 3.6 Scc.Scanners

Exports:
- `Get-SccScannerList [-EnabledOnly]` -> from config scanners.enabled/order.
- `Invoke-SccScanner -Name -Run <run> [-ScanPath] [-TimeoutMinutes]` -> result object
  (legacy contract preserved): ScannerName, ScannerVersion, Available, StartTimeUtc,
  EndTimeUtc, DurationSeconds, Status (Completed|Timeout|Failed|Skipped|NotInstalled|
  Unlicensed|NotVerified), ExitCode, Detections [{Path,ThreatName,Severity,Action}],
  DetectionCount, LogPath, RebootRequired, Errors[], CommandLine, ToolSource,
  ToolVersion, ToolSHA256.
  Rules: hard timeout; failure never fatal; parse the scanner's log file, never
  stdout; WhatIf mode genuinely safe.
- `Invoke-SccGuiScanner -Name -Run` -> attended: launch EXE visible, wait for exit,
  record Start/End/Duration + Result (Completed|Aborted|Timeout|LaunchFailed).
- Built-in adapters (each a private function): Defender (MpCmdRun -Scan -ScanType 3
  -DisableRemediation on system drive; threat history read separately and labeled
  historical), KVRT (documented CLI from vendor docs, log dir %SystemDrive%\KVRT*_Data),
  MSERT (documented CLI, log %SystemRoot%\debug\msert.log - verify against current
  vendor docs), AdwCleaner/ESETOnline/Malwarebytes = attended-only.

### 3.7 Scc.Remedy  (highest safety bar)

Exports:
- `New-SccPlan -Run -Findings -Decisions <hashtable: FindingId -> KEEP|REMOVE>`
  -> plan.json { PlanVersion, CreatedUtc, CreatedBy, Items: [ {FindingId, Product,
  TargetType (Service|Process|Uninstall|File|RegistryKey|ScheduledTask|FirewallRule),
  Action (KEEP|REMOVE), Detail, DisplayText} ] }. DEFAULT KEEP for everything;
  GUI writes explicit decisions; only ScreenConnect product entries may be REMOVE -
  enforced in code with per-item re-verification (legacy binding policy).
- `Test-SccPlan -Run -Plan` -> DRY RUN: returns exact action list that would run
  (commands, paths, order) without touching anything.
- `Invoke-SccRemediation -Run -Plan [-Execute]` -> without -Execute = dry run only.
  Sequence per approved item: (1) stop service (if any), (2) kill associated
  processes, (3) vendor uninstaller from registry UninstallString/QuietUninstallString
  or msiexec /x {ProductCode} /qn (never hardcoded switches - read at runtime),
  (4) validate removal, (5) manual cleanup of leftovers: service delete, scheduled
  task delete, Run key removal, firewall rule removal, (6) quarantine remaining
  artifacts (files/dirs moved to QuarantineRoot\<runid>\q\..., ACL: SYSTEM + Admins
  full, Users removed; original path + SHA256 recorded). Writes remediation.json
  (every action, result, error) + quarantine-manifest.json
  { OriginalPath, QuarantinePath, SHA256, SizeBytes, MovedUtc, FindingId, Reason,
  ActionType, RestoreInstructions }.
- `Restore-SccQuarantineItem -Run -ItemId` -> moves file back to original path
  (only after explicit confirmation).
- `Clear-SccQuarantine -Run -Approved` -> PERMANENT DELETE, double-confirmation
  required, never automatic, logged + reported.
- Every destructive action logs command + target + result to remediation.json and
  master log. On ANY safety-guard trip (non-SC product, unreadable plan, signature
  mismatch in plan) -> abort that item, record, continue or stop per config.

### 3.8 Scc.Report

Exports:
- `New-SccReport -Run` -> writes report.html, report.json, technician-summary.txt.
  Inputs: runstate.json, findings.json, plan.json, remediation.json, snapshots,
  diff.json, scanner results, tool provenance, logs. Never fabricates: every section
  states what was collected/skipped (legacy rule 10).
  HTML sections (brief sec. 12): Executive Summary; System Information; Incident
  Timeline; ScreenConnect Findings (with identity table + trust column
  Known/Unknown); Other Remote Access Findings; Persistence; Network Findings;
  Scanner Results; Remediation Actions; Quarantine; Before/After Comparison
  (Removed/Still Present/New/Reappeared/Changed); Outstanding Concerns; Errors /
  Warnings; Tool Provenance; Credential / Incident Follow-up Checklist; Raw
  Evidence Index. HTML-escape ALL values (XSS). Self-contained single file.
  report.json = machine-readable everything. technician-summary.txt = <= 60 lines
  plain text for quick handoff.
- `ConvertTo-SccHtml -Text` -> escape helper (exported for tests).

### 3.9 Scc.UI  (WPF shell)

Exports:
- `Start-SccApp [-Config] [-ResumeRunId]` -> main entry; builds WPF window, shows
  Dashboard, owns the stage workflow state machine.
- `Start-SccJob -ScriptBlock -Name [-OnProgress scriptblock] [-CancellationToken]`
  -> runs block in a background runspace; returns a plain data handle {Id, Name,
  State, Result, Error, Progress, Percent, Elapsed}. Companion functions:
  `Update-SccJob -Handle` (refresh fields), `Wait-SccJob -Handle` (block to end),
  `Stop-SccJob -Handle` (cooperative cancel). UI polls at 200ms via dispatcher
  timer. Max concurrent background jobs: 1 (stages are sequential by design).
- Views (XAML + code-behind):
  Dashboard.xaml        - system info, admin status, internet, NAS, tool status,
                          disk space, app version, resume previous run, actions:
                          Start Full Investigation / Detection Only / Scan Only /
                          Review Previous Report / Settings / Advanced Tools.
  Workflow.xaml         - stage pipeline view: Preflight -> Snapshot A -> Detection ->
                          Review -> Remediate -> Scanners -> Snapshot B -> Compare ->
                          Report. Current stage highlighted, statuses, skip options.
  Findings.xaml         - review screen: per finding checkbox KEEP/REMOVE with full
                          SC identity fields, trust badge, evidence. Default KEEP.
  RemediationPreview.xaml - advanced: exact action preview from Test-SccPlan.
  Scanners.xaml         - pick enabled scanners, order, timeout; run/attended launch;
                          live per-scanner status.
  Logs.xaml             - live log viewer (tail runstate + master log), filter by level.
  ReportView.xaml       - open generated report, show summary.
  Settings.xaml         - NAS path, paths, scanners, download behavior, logging level,
                          trusted relays editor, evidence retention.
  Advanced.xaml         - quarantine browser/restore, manual tool acquisition,
                          procmon note, dry-run runner.
- Headless mode (-Headless): same stage state machine without WPF (used by CI and
  power users). The state machine lives in Scc.UI's non-visual part so GUI and
  headless share it 100%.
- GUI strings: English. ASCII only in XAML too.

---

## 4. Stage state machine (shared by GUI + headless)

Stages: 0 Preflight, 1 SnapshotBefore, 2 Detection, 3 Review, 4 Remediate,
5 Scanners, 6 SnapshotAfter, 7 Compare, 8 Report. Each stage: {Status, StartedUtc,
EndedUtc, Detail, Skippable}. Transition rules: 1 always before 2..8; 4 requires 3
Completed (plan.json exists with >= 0 REMOVE items); 6 requires 5 Completed or
Skipped; 7 requires 6. Skipping allowed: 5 (scan skip), 4 (detect-only mode).
Resume: reload runstate.json, re-open run, re-enter at first non-Completed stage;
Completed stages never re-run automatically.

## 5. Windows file placement

- App binaries: portable folder (anywhere, including NAS share); optional install to
  %ProgramFiles%\ScreenConnectCleaner.
- Machine-wide data: %ProgramData%\ScreenConnectCleaner\ (machine config override,
  retained logs).
- User settings + tool cache: %LocalAppData%\ScreenConnectCleaner\ (config, tools).
- Temp: %TEMP%\ScreenConnectCleaner\<RunId>\ (transient; only our own files are ever
  removed, never the system temp).
- Reports: Documents\ScreenConnect Cleanup\Reports\SC-<date>-<host>-<time>\.
- Quarantine: %ProgramData%\ScreenConnectCleaner\Quarantine\<RunId>\q\ - ACL locked
  (SYSTEM + Administrators only), never inside temp, manifest inside.
- All paths overridable in config. Env-var placeholders (%VAR%) supported.

## 6. Run directory (per investigation)

```text
SC-20260826-HOST-173000/
  report.html  report.json  technician-summary.txt
  runstate.json  findings.json  plan.json  remediation.json
  tool-provenance.json
  evidence/  snapshots/(before.json after.json diff.json)
  scanner-results/  logs/(master.log *.jsonl)  quarantine-meta/
```

## 7. Configuration (config/scc-config.json - defaults embedded in Scc.Core)

```json
{
  "SchemaVersion": 1,
  "nas": { "enabled": true, "path": "\\\\NAS\\TechnicianTools\\Security",
           "priorityOrder": ["local","nas","official"], "timeoutSeconds": 15 },
  "paths": { "reportRoot": "%USERPROFILE%\\Documents\\ScreenConnect Cleanup\\Reports",
             "programData": "%ProgramData%\\ScreenConnectCleaner",
             "userData": "%LocalAppData%\\ScreenConnectCleaner" },
  "scanners": { "enabled": ["Defender","KVRT","MSERT"],
                "order": ["Defender","KVRT","MSERT"],
                "attended": ["AdwCleaner","ESETOnline","Malwarebytes"],
                "defaultTimeoutMinutes": 120 },
  "download": { "allowed": true, "maxAttempts": 2, "timeoutSeconds": 300 },
  "detection": { "incidentWindowDays": 7, "defaultTargets": ["ScreenConnect"] },
  "logging": { "level": "INFO", "retentionDays": 90 },
  "safety": { "serverOsRefusal": true, "dryRunDefault": true,
              "removableProducts": ["ScreenConnect"] },
  "evidence": { "retentionDays": 30 },
  "ui": { "confirmDestructive": true, "language": "en" }
}
```

trusted-relays.json: [ { "relay": "support.example.com", "name": "Our MSP",
"fingerprint": "optional-server-fingerprint", "notes": "" } ]

## 8. Performance rules

- Per-run caches in Scc.Core: file facts (hash+signature+version), installed programs
  list, services snapshot, processes snapshot. One collection each, reused everywhere.
- Detection reads each registry key once; never re-traverses.
- Snapshot sections may run in up to 4 parallel runspaces (independent reads only).
- Scanners run strictly sequentially (deliberate: AV conflict avoidance).
- Hashes computed once per file per run. Signature checks only on tool/SC binaries
  and executables, not on every evidence file (config-tunable).
- Log JSONL is append-only; master log tailed by UI, never fully loaded.
- Report built from structured JSON inputs only - never re-scans the system.

## 9. Safety invariants (from legacy docs/06, preserved)

1. Snapshot before any change; cannot be skipped.
2. Hard approval gate before removal; no unattended removal; no detect-and-remove flag.
3. Quarantine, never delete (deletion = separate double-confirmed operation).
4. Restore point + registry export before first change (default on, config to skip,
   verify restore actually enabled).
5. Vendor uninstaller first (read from registry at runtime), manual surgery after.
6. Never clean temp before looking at it.
7. Never clear event logs.
8. Server OS refuses by default.
9. Scanner failure is non-fatal AND reported as failure.
10. Report says what it did NOT check.
11. Post-remediation verification re-collects fresh from the system.
12. Removal != remediation: credential-reset checklist always in report.

## 10. Testing strategy

- Unit (Pester 5, runs on Linux pwsh + Windows runners): SC parameter parser
  (ordering, URL encoding, malformed, unknown, multi-instance), trust matching,
  config parsing (defaults/overrides/malformed), quarantine manifest, snapshot
  diff (synthetic), report escaping (XSS), scanner exit-code mapping, run state
  (interrupted runs), tool acquisition paths (mock sources, NAS down, invalid NAS
  binary, signature fail, hash fail, official fallback), GUI/backend boundary
  (state machine transitions in headless mode).
- Integration: full headless pipeline on Windows runners with synthetic
  ScreenConnect fixtures (fake service entries, fake registry in a throwaway hive,
  fake process entries) - no real SC install needed; destructive tests only in
  dry-run. Real destructive removal: owner live-tests on disposable lab machines
  (never our machines, never VMs we build).
- CI: .github/workflows/gui-revision-ci.yml - windows-2022 + windows-2025:
  house rules, parse under 5.1 AND pwsh, Pester unit, headless smoke run,
  synthetic fixtures, packaging (zip builds + hashes), malformed-config test.
  Linux job: pwsh parse + Pester unit + ASCII/BOM scan.
- What needs LIVE Windows testing (documented in TESTING.md, owner runs):
  WPF GUI on a real box, real KVRT/MSERT execution, real SC uninstall path,
  ACL quarantine behavior, NAS access from a domain-joined box, restore-point
  verification.

## 11. Migration map (full version in docs/MIGRATION.md)

| Legacy | New |
|---|---|
| sc-cleanup.ps1 (stages) | Scc.UI state machine + Scc.Core runs |
| preflight.ps1 | Scc.Core (Get-SccComputerInfo, Test-SccInternet/Nas) + stage 0 |
| detect-remote-access.ps1 | Scc.Detection |
| targets.json | config/targets.json + embedded defaults |
| collect-snapshot.ps1 | Scc.Evidence |
| diff-snapshots.ps1 | Scc.Snapshots |
| remove-screenconnect.ps1 | Scc.Remedy (plan-gated, same safety) |
| Invoke-ReviewAndRemove.ps1 | Scc.UI Findings.xaml + New-SccPlan |
| Invoke-GUIScanner.ps1 | Scc.Scanners Invoke-SccGuiScanner |
| scanners/Invoke-*.ps1 | Scc.Scanners adapters |
| tools/Get-AVTools.ps1 | Scc.Tools catalog + tools/Get-AVTools.ps1 |
| tools/Get-ToolPack.ps1 | Scc.Tools Sysinternals acquisition |
| New-InvestigationReport.ps1 | Scc.Report |
| tests/ci/*.ps1 | tests/ci/*.ps1 (ported) |
| START-HERE.bat / RUN-REMOVAL-TEST.bat | Start-ScreenConnectCleaner.bat + headless |
| .github/workflows/windows-ci.yml | .github/workflows/gui-revision-ci.yml |

## 12. Licensing / scanners (2026)

Defender: built-in, no licensing. KVRT: owner-approved (D2). MSERT: Microsoft free
tool, self-expiring, verify current CLI switches from docs. ESET Online Scanner /
Malwarebytes / AdwCleaner: attended GUI only (owner policy). Redistribution: owner
permits bundling (D8), but ToolManager still prefers NAS + validated downloads.
Sysinternals: download from download.sysinternals.com only, hash-verified.

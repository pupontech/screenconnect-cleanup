# AUDIT-04: Evidence, Reporting, and Tool Acquisition Inventory

Audit of the evidence-collection, before/after diff, report-generation, scanner,
and tool-acquisition components of the PowerShell codebase that will be rebuilt
into the Windows technician GUI application. Read-only audit; no existing file
was modified.

Scope map: the top-level pipeline is snapshot (Stage 1/7) -> detect
(Stage 2, covered by AUDIT-02) -> review (Stage 3) -> remove (Stage 4, covered
elsewhere) -> scan (Stage 5) -> diff/report (Stage 7/8). This audit covers the
snapshot, diff, report, scanner-adapter, and tool-staging components plus their
tests and CI.

---

## 1. Scope Inventory

| File | Lines | Purpose |
|------|-------|---------|
| collect-snapshot.ps1 | 1390 | Stage 1/7 read-only snapshot collector. Emits a stable, diffable JSON snapshot (SchemaVersion 2) of the machine's persistence and execution surface. 18 top-level section collectors plus 5 retrospective execution-artifact decoders (Prefetch, ShimCache, BAM/DAM, UserAssist, SRUM). Per-section error capture into CollectionErrors so one failure never aborts the run. |
| diff-snapshots.ps1 | 261 | Stage 7 before/after diff. Matches snapshot items by stable `Key`, classifies sections as stable/volatile/object, reports Removed/Added/Changed per section, computes a RESURRECTION/CLEAN verdict (any stable-section addition = resurrection), writes a UTF-8-no-BOM JSON diff report, exits 0/1/2. |
| New-InvestigationReport.ps1 | 824 | Stage 8 report generator. Consumes findings.json (from detect-remote-access.ps1) plus an optional removal manifest and renders a single self-contained, XSS-escaped HTML report with embedded CSS. Portable (no live-system dependency). |
| Invoke-GUIScanner.ps1 | 165 | Attended GUI-scanner launcher. Finds a scanner EXE, launches it as a visible window, blocks until the technician closes it (or a 240 min default timeout), then reports elapsed time + exit code as a JSON line. Handles ESET Online Scanner, Malwarebytes, AdwCleaner. |
| scanners/Invoke-DefenderScan.ps1 | 403 | Stage 5 scanner adapter: Microsoft Defender via MpCmdRun.exe. Detect-only custom scan (-ScanType 3 always, -DisableRemediation), hard timeout with concurrent pipe drain, threat-history mapping via Get-MpThreatDetection, Support-folder log copy. CRLF line endings. |
| scanners/Invoke-ESETScan.ps1 | 424 | Stage 5 scanner adapter: ESET command-line scanner (ecls.exe). Detect-only (no /auto, default clean-mode none), reads the log FILE (never stdout), Documented exit-code table, Unlicensed status detection, own temp log copied to LogDir. |
| scanners/Invoke-KVRTScan.ps1 | 449 | Stage 5 scanner adapter: Kaspersky Virus Removal Tool (KVRT.exe). Detect-only (-accepteula -silent, no -processlevel, no -adinsilent), explicit -d data dir created up front, report files parsed for detections, exit codes intentionally unmapped (undocumented). |
| tools/Get-AVTools.ps1 | 152 | Stage 5 AV-scanner stager. Downloads KVRT, AdwCleaner, ESET Online Scanner, and Malwarebytes MB5 from their official vendor URLs every run; reports FileVersion + size; optional internal-share fallback that never downgrades a fresh download; -Verify presence gate. |
| tools/Get-ToolPack.ps1 | 354 | Sysinternals diagnostic-tool pack downloader/verifier. Downloads Autoruns, Sigcheck, ProcessMonitor, TCPView from download.sysinternals.com; scoped per-tool extract; builds/updates manifest.json (url, downloaded, per-file size+sha256); -Verify checks files against manifest. |
| tools/manifest.json | 97 | Static checked-in manifest seed for the Sysinternals pack: 4 tools, 18 files, each with size + SHA-256, plus source URL and download timestamp. |
| tests/test_diff_synthetic.py | 60 | Synthetic end-to-end test of diff-snapshots.ps1. Injects a removed service, resurrected scheduled task, changed registry autorun, and volatile process churn into the sample snapshots, runs diff under pwsh/powershell.exe, asserts verdict + lists. |
| tests/ci/Test-HouseRules.ps1 | 76 | CI gate: pure ASCII on code files (.ps1/.bat/.cmd), no UTF-8 BOM on any text file, and JSON validity across the repo (excluding tools binaries). Exit 0 clean / 1 violations. |
| tests/ci/Test-Parse.ps1 | 44 | CI gate: parse-checks every .ps1 with the language parser, no execution. Run under both windows powershell 5.1 and pwsh in CI. |
| tests/ci/Test-PipelineLauncherContracts.ps1 | 180 | Static source-contract checks on sc-cleanup.ps1 (truthful outcome, restore-point fail-closed gate, truthful admin log) and the three .bat launchers (apostrophe-safe self-elevation via SCC_SELF, errorlevel + pause on failure, CRLF/ASCII/no-BOM). |
| tests/ci/Test-RemovalRuntimeContracts.ps1 | 192 | 9 static/AST contract tests on remove-screenconnect.ps1: Run-BoundedProcess existence, concurrent async drain, timeout result, 3010 reboot handling, manual-surgery skip, persistence cleanup gating, RebootPending resume, PS5.1-API scan, zero parse errors. |
| tests/ci/Test-ScannerProcessContracts.ps1 | 214 | Scanner *process-contract* gate. Section 1: static/AST checks on all three adapters (each defines Invoke-ProcessWithTimeout, uses 2 x ReadToEndAsync, no sync ReadToEnd, no HasExited poll). Section 2: independent synthetic probe (chatty child proves no pipe deadlock; langorous child proves bounded kill-on-timeout). |
| tests/ci/Test-WindowsIntegration.ps1 | 737 | Safe Windows integration: removal dry-run inertia + smuggled AnyDesk rejection, report XSS escape (hostile input -> 0 raw <script>), sc-cleanup -WhatIf gating, quiet-uninstall-only registry dry-runs with no StrictMode crash, and Run-VendorUninstaller pipe/timeout shape (static pins + dynamic stubs + real function body with patched 3s timeout). |
| .github/workflows/windows-ci.yml | 104 | GitHub Actions real-Windows CI. One job, matrix windows-2022 + windows-2025, timeout 25 min. Runs house-rules, dual-edition parse, detector smoke + self-test, preflight self-test, and every contract/integration suite under both 5.1 and pwsh, plus the Python synthetic diff test. |
| docs/ (00-09 incl. plan-schema-example.json) | 135+106+188+164+203+161+134+150+882+123+36 | Design and decision record. 00 handoff, 01 brief+decisions D1-D7, 02 architecture + component contracts, 03 ScreenConnect intelligence (KNOWN/ASSUMED/VERIFY), 04 detection PoC, 05 tools/scanners/Tron analysis, 06 safety model + coding conventions, 07 roadmap/open questions, 08 work log (history/test evidence; skimmed per task scope), 09 live-test matrix. plan-schema-example.json documents the removal plan schema. |
| snapshots/before.json, after.json, after.diff.json | 108/108/167 | Three local verification artifacts from a Linux/pwsh snapshot+diff run (all collectors empty, every Windows-only collector records a CollectionErrors entry and continues). after.diff.json shows a CLEAN verdict. Also serve as the constructor input for test_diff_synthetic.py. |

---

## 2. Full Functionality Inventory

### 2.1 collect-snapshot.ps1 - snapshot categories collected (18 sections)

Top-level result shape (SchemaVersion = 2): Label, ComputerName, CollectedUtc
(yyyy-MM-dd HH:mm:ss), IsAdmin (bool), OSCaption, IncidentWindowDays,
CollectionErrors[] ({Section, Error}), Sections{}.

Invocation flags: -OutFile, -Label (default 'before'), -IncidentWindowDays
(default 0), -Quiet. ErrorActionPreference = 'Stop'. No admin required; each
section individually wrapped. Output written UTF-8 without BOM; ConvertTo-Json
at -Depth 6 (deliberate; Depth 12 recursed into .NET internals and ballooned to
multi-GB on 5.1).

Per-section collectors and their stable Key scheme (the critical diff identity):

1. Services (Get-ServicesSection): Win32_Service. Key = Name. Fields: Name,
   DisplayName, PathName, State, StartMode, StartName.
2. ScheduledTasks (Get-ScheduledTasksSection): Get-ScheduledTask. Key =
   TaskPath + "|" + TaskName. Fields: TaskName, TaskPath, State, Author,
   Actions[] {Execute, Arguments}.
3. RegistryAutoruns (Get-RegistryAutorunsSection): Run/RunOnce across HKLM 64
   and 32 (WOW6432Node) and HKCU view combos (6 key specs), plus Winlogon
   Shell/Userinit on HKLM and HKCU. Key = Hive + "|" + KeyPath + "|" + ValueName.
   Fields: Hive, View, KeyPath, ValueName, Value, Kind ('RunKey'/'Winlogon').
4. StartupFolders (Get-StartupFoldersSection): AllUsers and CurrentUser startup
   folders. Key = Scope + "|" + FileName. Fields: Scope, FileName, FullPath,
   LastWriteUtc, LengthBytes.
5. Processes (Get-ProcessesSection): Win32_Process + per-process owner via
   Invoke-CimMethod GetOwner. Key = ExecutablePath + "|" + PID (point-in-time,
   not identity-diffed). Fields: ProcessId, ParentProcessId, Name,
   ExecutablePath, CommandLine, CreationDate, Owner.
6. Connections (Get-ConnectionsSection): Get-NetTCPConnection. Key =
   LocalAddr:LocalPort | RemoteAddr:RemotePort | State | OwningProcess
   (point-in-time). Fields incl. OwningProcessName, IsListening.
7. InstalledPrograms (Get-InstalledProgramsSection): all three Uninstall roots
   (HKLM64, HKLM32/WOW6432Node, HKCU). Key = root hint + "|" + subkey name.
   Fields: DisplayName, DisplayVersion, Publisher, InstallDate,
   InstallLocation, UninstallString. Skips keys with blank DisplayName.
8. LocalAccounts (Get-LocalAccountsSection): Win32_UserAccount LocalAccount=True
   plus Administrators-group membership via Win32_GroupUser (net localgroup
   fallback). Key = SID. Fields: Name, FullName, Disabled, Lockout,
   PasswordRequired, IsLocalAdmin.
9. FirewallRules (Get-FirewallRulesSection): enabled inbound ALLOW rules joined
   to application/port filters in one batched fetch of all filters keyed on
   InstanceID (avoids a per-rule CIM round-trip that took ~3 min). Key = Name.
   Fields: DisplayName, Profile, Program, Ports (Protocol:LocalPort).
10. WmiPersistence (Get-WmiPersistenceSection): __EventFilter,
    __EventConsumer (detail pulled from CommandLineTemplate/ScriptText/
    Destination), and __FilterToConsumerBinding under root\subscription. Key =
    Namespace|class|Name; bindings keyed Namespace|Binding|Filter->Consumer.
11. RecentFiles (Get-RecentFilesSection): incident-window sweep across TEMP,
    Windows\Temp, APPDATA, LOCALAPPDATA, Downloads, PUBLIC, ProgramData. Only
    when IncidentWindowDays > 0. Bounded walk: CapCount 500, MaxDirs 40000,
    TimeBudgetSeconds 120, maxDepth 6, ReparsePoint skip, skipDirNames list
    (node_modules/.git/winsxs/caches/etc). Extensions .exe .dll .msi .ps1 .bat
    .cmd .vbs .js .scr .lnk. Emits Items[] plus CapHit/DirsVisited/WalkSeconds/
    BudgetExhausted; records a CollectionErrors entry when the budget is hit.
12. Prefetch (Get-PrefetchSection): C:\Windows\Prefetch\*.pf inventory; exec
    name parsed from "<NAME>-<HASH>.pf" regex. Absent dir is NOT an error (SSD/
    Server builds). Key = .pf file name. Rows carry InIncidentWindow.
13. ShimCache (Convert-ShimFileTime + Get-ShimCacheSection): raw REG_BINARY
    AppCompatCache decoded in-script for Windows 8.1/10 entry types 0x30 and
    0x10 behind a 48-byte '10ts' header. Unrecognized signature -> explicit
    CollectionError + empty (never wrong paths). maxEntries 4096 guard. Key =
    lower-cased cached path. Rows carry InIncidentWindow.
14. BamDam (SCC.RegKeyTimes P/Invoke + Get-BamDamSection): bam/dam
    State\UserSettings\<SID> values; per-key last-write read via a small
    advapi32 RegQueryInfoKey P/Invoke (degrades to blank timestamp when Add-Type
    is unavailable). Key = service|SID|value-name. Rows carry InIncidentWindow.
15. UserAssist (Convert-Rot13 + Get-UserAssistSection): ROT13-decoded value
    names + RunCount from DWORD at payload offset 4; two known count GUIDs
    labelled, unknown GUIDs still collected. Key = GUID|decoded name.
16. Srum (Get-FileSha256Safe + Get-SrumSection): single object, NOT an
    identity-diffed array. SRUDB.dat presence, SHA-256 (diffable), file
    inventory, best-effort READ-ONLY offline copy beside the snapshot, and an
    explicit Limitations[] list. The ESE DB is not parsed (held exclusively
    open by Windows); copy reads share-read so it never disturbs the live DB.
17. SystemSettings (object section): RdpEnabled (fDenyTSConnections == 0) and
    HostsFileLines (flattened to plain strings to avoid the PSProvider
    note-property JSON blowup that once made the file 115 MB).

PS 5.1 traps handled inline (worth reusing): @($typedList) throws
"Argument types do not match" -> Get-CollectionErrorsArray uses .CopyTo;
Sort-ByKey returns empty array via ", @()"; .ToArray() used instead of @($list)
on empty generic lists; ConvertTo-Json depth capped at 6.

### 2.2 diff-snapshots.ps1 - every diff computation

- Section classification:
  - VolatileSections = Processes, Connections, RecentFiles (identity keys stable
    but values churn every run; only Added/Removed matter as signals).
  - StableSections = Services, ScheduledTasks, RegistryAutoruns, StartupFolders,
    InstalledPrograms, LocalAccounts, FirewallRules, WmiPersistence, Prefetch,
    ShimCache, BamDam, UserAssist.
  - ObjectSections = Srum, SystemSettings (compared wholesale by serialized
    value, with field-level comparison when both sides are PSCustomObjects).
- Read-Snapshot: existence + valid-JSON; throws exit 2 on either.
- Get-ItemKey: normalizes item to its Key string; missing/blank Key ->
  synthesized '<missing-key>' marker so the item still appears (never dropped).
- Get-ChangedFields: field-level diff of same-Key items; reports added
  properties as "+name", removed as "-name".
- Get-SectionDiff: builds before/after maps keyed on Key; Removed = in before
  not after; Added = in after not before; Changed = same Key with differing
  fields. Output sorted (zero ordering noise).
- Compare-ObjectSection: serializes each object side to JSON (compress, depth
  12, '<unserializable>' fallback), field-level compare when both are objects.
- Verdict: $resurrectionCount = sum of Added across stable sections; Verdict =
  'RESURRECTION' if any, else 'CLEAN'. Volatile churn never affects verdict.
- Report (SchemaVersion 1): DiffUtc, BeforeFile/AfterFile (leaf names),
  BeforeLabel/AfterLabel/BeforeCollectedUtc/AfterCollectedUtc, SameComputerName,
  ResurrectionsAdded, Verdict, Sections[].
- Exit codes: 0 = CLEAN, 1 = RESURRECTION (or any Added/Removed/unexpected
  change), 2 = usage/input error.
- Console summary per section (counts + REMOVED/ADDED/CHANGED lines); warns
  when ComputerName differs between snapshots (cross-machine diff meaningless).
- Output default alongside AfterFile as <after-stem>.diff.json; UTF-8 no BOM.

### 2.3 New-InvestigationReport.ps1 - every report section and format

Input: findings.json (mandatory), OutputPath (optional; defaults to
report.html beside findings.json), RemovalManifest (optional JSON), PassThru.

Escaping/formatting helpers (the migration safety net for XSS safety):
- Encode-Html: escapes & < > " ' to &amp; &lt; &gt; &quot; &#39;. Applied to
  EVERY value sourced from machine JSON before writing into markup.
- Get-Prop / Get-Items: normalize ConvertFrom-Json 5.1 quirks (empty array -> {},
  single element -> bare scalar). Get-Items handles string/scalar/array/IEnumerable.
- Fmt / FmtBool / FmtList / Get-KvPairs: escaped scalar/bool/list/dictionary
  rendering with null/blank placeholders.
- Row: one <tr><th/><td/> for definition tables; hides blank rows unless AlwaysShow.
- SessionBadgeInfo / SignatureBadgeClass: map SessionType (Access=high,
  Support=low, Meeting=medium, unknown) and signature status to styled badges.

Report sections (assembled into a single self-contained HTML doc with embedded
CSS, print stylesheet, UTF-8 no BOM written directly to disk, no shell exit):
1. Header: computer, OS, scan time (UTC), run-as user, elevated badge,
   scan tool + version; "re-run to confirm" note.
2. Summary: four stat cards (SC instances found, other RA artifacts across N
   products, parse problems, historical installs) with danger/warn/ok styling,
   plus an event-log-unavailable warning line.
3. ScreenConnect instances: one card per instance. Relay host box
   (present/missing styling with "authorized vs attacker" guidance), key facts
   (session type, install-dir created UTC, file signature badge), install
   details table, service table, file table (SHA-256, signer, timestamps),
   custom properties, unknown/unmapped launch params, running processes table,
   network connections table, related 7045 service-install events, config-file
   list. Instance title falls back identifier -> key -> '(unidentified instance)'.
4. Other remote-access agents: per-product hit cards (Kind/Name/Detail/Path/
   State/StartMode table); "None found" when clean.
5. Removal manifest + credential-reset checklist: table of removed/
   quarantined items (Instance/Action/Target/Result/Details) plus the
   credential-reset reminder (reset SC credentials, revoke sessions/tokens,
   rotate API keys, verify MFA + authorized relay hosts).
6. Historical 7045 service-install events (installations no longer present).
7. Parse problems: loud danger-styled cards with issue text, service image
   path, config files seen, param blob, keys seen.
8. Environment: scan tool/version, PS version, targets source + scanned list,
   event-log status, raw evidence files saved.
- Explicitly does not call exit (a .ps1 invoked with & never sets $LASTEXITCODE),
  so CI checks file-write + no-throw rather than exit code.
Output: currently HTML only; the rebuild requirement adds report.json +
  technician-summary.txt alongside report.html (see gap in section 7).

### 2.4 scanners - adapter capabilities (per adapter)

Common contract (docs/02): params -ScanPath, -TimeoutMinutes=120, -LogDir,
-ToolPath, -WhatIf. Single 14-field return object: ScannerName, ScannerVersion,
Available, StartTimeUtc, EndTimeUtc, DurationSeconds, Status, ExitCode,
Detections[], DetectionCount, LogPath, RebootRequired, Errors[], CommandLine.
Status set: Completed, Timeout, Failed, Skipped, NotInstalled, Unlicensed,
NotVerified. Detection shape: {Path, ThreatName, Severity, Action}.
Rules: hard timeout per scanner; failure non-fatal + reported as failure (never
silent "clean"); read the scanner's log file not stdout; -WhatIf genuinely runs
nothing.

Shared helper Invoke-ProcessWithTimeout (copied verbatim into all 3 adapters):
- ProcessStartInfo with RedirectStandardOutput/Error = true.
- BOTH streams drained concurrently via ReadToEndAsync() immediately at start
  (a full redirect pipe otherwise blocks the child's own write, HasExited never
  flips, and the timeout becomes ineffective - the exact bug history).
- Bounded WaitForExit(TimeoutSeconds*1000) honors the timeout.
- On timeout: Kill() + bounded WaitForExit(2000) reap.
- Post-termination bounded Task.WaitAll(streamTasks, 5000); reads results only
  for completed tasks; StreamDrainTimedOut diagnostic when drains are incomplete.
- Returns {TimedOut, StreamDrainTimedOut, ExitCode, StdOut, StdErr}.

Microsoft Defender (Invoke-DefenderScan.ps1):
- Tool discovery Find-MpCmdRun: newest version under
  ProgramData\Microsoft\Windows Defender\Platform\<ver> (sorted desc), then
  Program Files\Windows Defender. Explicit -ToolPath wins.
- Version Get-DefenderVersion: AMServiceVersion from Get-MpComputerStatus.
- Command line: ALWAYS a custom scan -Scan -ScanType 3 with -DisableRemediation
  (detect-only). Default target = system drive root ($env:SystemDrive, C:
  fallback); -ScanPath = targeted custom scan of that path. NEVER uses
  -ScanType 1 quick scan (documented: -DisableRemediation is custom-scan-only,
  so a quick scan would allow silent remediation, violating the safety model).
- Exit codes mapped per Microsoft doc: 0 (clean/remediated) and 2 (threats not
  remediated / errors) -> Completed; anything else -> Failed with error note.
- Detections Get-ThreatDetections: Get-MpThreatDetection history mapped to
  {Path from Resources, ThreatName = ThreatID, Severity via Get-MpThreatCatalog,
  Action from ActionSuccess}; reads ALL history (see bug section 6).
- Exit code 2 with zero detection records -> explicit error note.
- Copy-ScanLogs: copies up to 10 recent Support-folder files newer than
  max(duration/60, 5) min into LogDir. RebootRequired always false.
- -WhatIf: resolves tool, builds command line, Status=Skipped, runs nothing.

ESET (Invoke-ESETScan.ps1):
- Tool discovery Find-ECLS: Program Files\ESET\ESET Security\ecls.exe, then a
  bounded recurse for ecls.exe under Program Files\ESET.
- Version Get-ESETVersion: file ProductVersion/FileVersion resource (does not
  spawn /version).
- Command line: /subdir /no-log-console /log-file=<temp ecls_scan_*.log>; adds
  /base-dir=<exe dir>\Modules when present; targets = -ScanPath or all fixed
  drive roots (via Get-PSDrive FileSystem, Free != null) else C:\. Detect-only:
  NO /auto and NO /clean-mode override (default clean-mode = 'none').
- Output parsed from the LOG FILE (contract rule), never stdout.
- Exit-code table mapped per ESET doc: 0 Completed; 50 Completed + 'threat
  found (detect-only, nothing cleaned)'; 10 Completed + 'some files not shown';
  100 Failed; >100 Completed + 'files NOT scanned and can be infected'; any
  other <=100 -> Failed (code 1 unexpected because cleaning is never enabled).
- Unlicensed detection: on Failed, if the ecls log mentions license/activation
  -> Status=Unlicensed with error note.
- Log copy: temp ecls log copied into LogDir; LogPath = final path; missing log
  on a real exit code -> error note.
- -WhatIf: Status=Skipped, nothing runs.

Kaspersky KVRT (Invoke-KVRTScan.ps1):
- Tool discovery Find-KVRT: tools\AV next to repo, SystemDrive root, Public
  Downloads, TEMP; name-match ^(kvrt|KVRT) on *.exe (heuristic; explicit
  -ToolPath strongly preferred per docs).
- Version Get-KVRTVersion: file ProductVersion/FileVersion resource (KVRT has
  no documented --version).
- Command line: -accepteula -silent -dontencrypt -details -d <temp
  KVRT_Data_<timestamp> dir. Data dir created up front (KVRT does not reliably
  create it; a missing dir silently produced no report / 0 detections). Optional
  -custom "<ScanPath>. Deliberately uses -custom NOT -customonly:
  -customonly is REJECTED by KVRT 20.x (measured 2026-08-25 against 20.0.14.0:
  exit -2, no report) while -custom alone runs. Never passes -processlevel
  (detect-only) and never -adinsilent (would disinfect + reboot).
- Exit codes NOT mapped: undocumented in the KVRT help article, so status comes
  from completion within the timeout; nonzero codes surfaced in Errors; the
  authoritative outcome is the parsed report file.
- Detections Get-DetectionsFromReports: parses .txt/.log/.htm/.html under the
  -d data dir (top 5 newest), heuristic line match on threat vocabulary,
  extracts a path; best-effort, bounded at 200 records.
- Copy-ScanLogs: copies up to 20 recent files from the -d data dir AND any
  %SystemDrive%\KVRT*_Data wildcard dir into LogDir.
- Zero report files after a completed run -> explicit error note.
- -WhatIf: Status=Skipped, nothing runs.

### 2.5 Invoke-GUIScanner.ps1 - attended GUI-scanner runner

- Params: -Scanner (ValidateSet ESET|Malwarebytes|AdwCleaner), -ToolPath
  (explicit path wins), -TimeoutMinutes (default 240).
- knownTools map: ESET -> esetonlinescanner.exe, Malwarebytes -> MBSetup.exe,
  AdwCleaner -> adwcleaner.exe.
- Search order (no -ToolPath): script-root\AV\<name>, script-root\<name>,
  ..\tools\AV\<name>, C:\AdwCleaner\adwcleaner.exe (only AdwCleaner),
  <home>\Downloads\<name>, TEMP\<name>. Not found -> exit 3 with a clear message
  pointing at Get-AVTools.ps1 (this script never downloads).
- Launches VISIBLE via Start-Process -PassThru (no CreateNoWindow, no redirects
  - it is a GUI app).
- Blocks with WaitForExit(TimeoutMinutes*60*1000). On timeout the process is
  LEFT RUNNING (a mid-scan kill could abort a cleanup mid-write); status Timeout,
  exit 4.
- Writes a compact JSON line to stdout: Tool, Status (Completed/Timeout/
  LaunchFailed), StartTimeUtc, EndTimeUtc, DurationSeconds, ProcessExitCode.
- Exit codes: 0 technician closed it; 2 launch failed; 3 not found; 4 timeout.
- Set-StrictMode -Version 2.0. No scan/clean switches ever passed; never parses
  scanner output; never fabricates a result.

### 2.6 tools/Get-AVTools.ps1 - AV stager

- Params: -ToolDir (default <script>\AV), -InternalShare (default literal
  '\\10.0.0.5\Public\Tools'), -Verify, -Quiet. Enforces TLS 1.2.
- Verify mode: presence check for KVRT.exe, adwcleaner.exe,
  esetonlinescanner.exe, MBSetup.exe in ToolDir; exit 1 if any missing.
- Get-DownloadFile: Invoke-WebRequest -UseBasicParsing -OutFile; reports each
  download's FileVersion resource + size (a version-tracking trick: shows
  exactly what got staged without spawning the binary).
- Four tools, EVERY run downloads FRESH from official vendor URLs
  (verified live 2026-08-26, endpoints and content type noted in comments):
  - KVRT.exe: https://devbuilds.s.kaspersky-labs.com/kvrt/latest/full/KVRT.exe
  - adwcleaner.exe: https://downloads.malwarebytes.com/file/adwcleaner/
    (302-redirects to adwcleaner.malwarebytes.com)
  - esetonlinescanner.exe:
    https://download.eset.com/com/eset/tools/online_scanner/latest/esetonlinescanner.exe
  - MBSetup.exe: https://downloads.malwarebytes.com/file/mb-windows/
    (302-redirects to data-cdn.mbamupdates.com/web/mb5-setup-consumer/MBSetup.exe)
- KVRT has a documented silent CLI and is drivable by Invoke-KVRTScan.ps1. ESET
  Online Scanner, Malwarebytes, AdwCleaner are staged for ATTENDED use only
  (no silent flags invented - owner decision 2026-08-26).
- InternalShare fallback: only for ESET Online Scanner and MBSetup.exe; only
  used when the official download is absent (a stale share copy NEVER downgrades
  a fresh official build). Never overwrites a just-downloaded file.
- Exit 0 on success.

### 2.7 tools/Get-ToolPack.ps1 + tools/manifest.json - Sysinternals pack

- Params: -ToolDir (default script dir), -Force, -Verify, -Quiet. TLS 1.2.
- Four tools: Autoruns (Autoruns.zip), Sigcheck (Sigcheck.zip),
  ProcessMonitor (ProcessMonitor.zip), TCPView (TCPView.zip) from
  https://download.sysinternals.com/files/<Zip>.zip.
- Get-FileSha256: SHA256 hex uppercase (dash-stripped).
- Manifest schema (tools/manifest.json, checked in as a seed and rewritten by
  the downloader):
  { "<ToolName>": { "url": string, "downloaded": ISO8601 UTC,
      "files": { "<exeName>": { "size": int, "sha256": UPPER-hex } } } }
- Verify mode: for each tool entry, for each manifest file under
  ToolDir\<ToolName>\<file>: MISSING if absent; MISMATCH on sha256 mismatch,
  then MISMATCH on size mismatch; else OK. Missing-from-manifest tool flagged.
  Refuses when manifest.json missing/empty (uses
  @(manifest.PSObject.Properties).Count, a 5.1-safe count). Prints a summary
  Format-Table, exit 0/1.
- Download mode: skips a tool when already in the manifest unless -Force.
  Downloads the zip (ProgressPreference SilentlyContinue), extracts to a
  staging folder <ToolName>.incoming, then swaps into place only after a full
  successful extraction (an interrupted run no longer leaves a half-populated
  folder with no manifest entry). Scopes each tool's exe hashing to its own
  subfolder (fixes the historical cross-tool manifest accumulation bug). Removes
  the zip, records size+sha256 per exe, updates the manifest, and reports OK/
  SKIPPED/FAILED per tool. Exit 1 if any error.
- tools/.gitignore: '*' except .gitignore, manifest.json, Get-ToolPack.ps1,
  Get-AVTools.ps1 (binaries stay out of git; manifest stays in).

### 2.8 Test suite - what each test covers

- test_diff_synthetic.py: end-to-end correctness of the diff verdict and lists.
  Removed service -> Services.Removed; resurrected scheduled task ->
  ScheduledTasks.Added + Verdict RESURRECTION + ResurrectionsAdded=1; changed
  registry autorun value -> RegistryAutoruns.Changed Fields ['Value']; volatile
  process add/remove -> Processes.Kind 'volatile' and NOT counted as
  resurrection. Runs diff-snapshots.ps1 subprocess under pwsh (or
  powershell.exe on Windows) with SCC_TEST_TMP for output dir.
- Test-HouseRules.ps1: pure ASCII on code files, no BOM on any scanned file,
  all JSON parses. Excludes git dir and all tools\<Tool> binary folders.
- Test-Parse.ps1: every .ps1 parses with zero errors, run under both editions.
- Test-PipelineLauncherContracts.ps1: sc-cleanup.ps1 truthfulness (must carry
  RemovalExitCode, report 'PIPELINE COMPLETED WITH ERRORS' + exit 1 after
  nonzero Stage 4, StrictMode-safe Contains('ExitCode') guard), restore-point
  fail-closed gate (RestorePointFailed/RestorePointBlocked/$np), truthful
  non-unconditional 'Admin check: PASSED', and batch self-elevation contract
  (SCC_SELF env var not '%~f0', fltmc probe + errorlevel + pause, no silent
  >nul 2>&1 exit, SCC_ARGS forwarding, CRLF/ASCII/no-BOM).
- Test-RemovalRuntimeContracts.ps1: 9 static tests on remove-screenconnect.ps1 -
  Run-BoundedProcess present; concurrent ReadToEndAsync drain before bounded
  WaitForExit; Kill + bounded reap; Task[] / WaitAll; no sync ReadToEnd / no
  HasExited; TimedOut+ExitCode result fields; 'timed out after 300s and was
  killed' manifest string; exit 3010 -> RebootRequired=true + Success=true;
  manual-surgery skip on uninstall success; persistence cleanup gated on
  -not $rebootRequired; RebootPending + Set-RunOnceResume resume marker; no
  Windows-only .NET APIs; zero parse errors.
- Test-ScannerProcessContracts.ps1: per-adapter source/AST contract
  (Invoke-ProcessWithTimeout defined, >=2 ReadToEndAsync, no sync ReadToEnd,
  no HasExited member), plus an independent synthetic probe proving the
  drain+timeout pattern: a chatty child (>100KB to both pipes) exits 0 without
  deadlock; a langorous child is killed on a 3s timeout, reported TimedOut with
  no exit code, reaped promptly.
- Test-WindowsIntegration.ps1: (1) removal dry-run is inert and product
  verification rejects a smuggled AnyDesk entry (PRODUCT_VERIFICATION_FAILED,
  no destructive Success, nothing quarantined); (2) XSS escape - hostile
  findings.json produces 0 raw <script>, no live onerror= handler, bracket-
  escaped payload present; (3) sc-cleanup.ps1 -WhatIf -force -np -offline exits
  0 and runs nothing; (4) quiet-uninstall-only and stringless registry
  registrations dry-run cleanly with NO StrictMode crash (regression d71d40a),
  correct Skipped/Failed manifest branches, no destructive DryRun; (5)
  Run-VendorUninstaller shape: 5a static pins on the real function, 5b dynamic
  stderr-flood stub (no deadlock, full drain, exit code propagated), 5c real
  function body with only the timeout literal patched (3000ms) against compiled
  ok + hang stub exes (Success + Failure/timed-out-killed manifest entries).

### 2.9 CI (windows-ci.yml) - every job, step, target

Single job windows-tests; matrix os = [windows-2022, windows-2025];
fail-fast false; timeout-minutes 25. Triggers: push to main, pull_request,
workflow_dispatch. Steps in order:
1. Checkout (actions/checkout@v4)
2. House rules (pwsh): ./tests/ci/Test-HouseRules.ps1
3. Parse all scripts - Windows PowerShell 5.1 (shell powershell)
4. Parse all scripts - PowerShell 7 (shell pwsh)
5. Smoke detect-remote-access -ListTargets (5.1)
6. Smoke detect-remote-access -ListTargets (pwsh)
7. SelfTest detect-remote-access parser (5.1, -NoPause)
8. SelfTest preflight (pwsh)
9. Safe Windows integration - 5.1
10. Safe Windows integration - pwsh
11. Stage 4 removal runtime contracts - 5.1
12. Stage 4 removal runtime contracts - pwsh
13. Pipeline + launcher contracts - 5.1
14. Pipeline + launcher contracts - pwsh
15. Scanner process contracts - 5.1
16. Scanner process contracts - pwsh
17. Synthetic Stage 7 diff test (pwsh, env SCC_TEST_TMP=${{ runner.temp }}):
    python ./tests/test_diff_synthetic.py
18. Upload diff output on failure (actions/upload-artifact@v4, synth before/
    after/diff jsons from runner.temp, if-no-files-found: ignore).

---

## 3. Per-Component Verdict

| Component | Verdict | Justification |
|-----------|---------|---------------|
| collect-snapshot.ps1 | REFACTOR | Collector logic, Key scheme, and per-section error isolation are sound and must be preserved, but the sections belong behind a modelled Evidence/Snapshots module, not a 1390-line script. Split per-section collectors into functions/module files; keep schema, Key scheme, CollectionErrors model, and IncidentWindowDays concept exactly. |
| diff-snapshots.ps1 | REFACTOR | Diff algorithm and stable/volatile/object classification and resurrection verdict are correct and worth keeping verbatim; port into the Snapshots module as a pure function (input JSON -> verdict/diff), with the console summary replaced by a module-level result consumed by the GUI. |
| New-InvestigationReport.ps1 | REFACTOR | HTML structure, XSS escaping (Encode-Html), Get-Prop/Get-Items 5.1-normalization, and section rendering are proven and must be ported. But it is findings.json-specific. Generalize the escaping/formatting helpers into the Reporting module and add the required report.json + technician-summary.txt outputs (missing today). |
| Invoke-GUIScanner.ps1 | MERGE | Behavior (launch visible, block, timeout leaves process running, JSON result) is correct and must be preserved, but it is a thin attending helper - merge into the Scanners module as the "attended GUI run" path alongside the CLI adapters, driven through centralized scanner management. |
| scanners/Invoke-DefenderScan.ps1 | REFACTOR | Adapter logic is good and the detect-only custom-scan safety fix is critical to keep. Refactor to drop the duplicated New-ResultObject/Invoke-ProcessWithTimeout/Write-AdapterLog into shared module code (centralized scanner management), and fix the historical-detection mis-attribution (see 6). Keep exit-code map 0/2 and -ScanType 3 -DisableRemediation invariant. |
| scanners/Invoke-ESETScan.ps1 | REFACTOR | Same as Defender; unify duplication, keep the parse-the-log contract, exit-code table, and Unlicensed detection. |
| scanners/Invoke-KVRTScan.ps1 | REFACTOR | Same as above; keep the -data-dir-created-up-front fix, -custom-not-customonly decision, and report-file-based outcome (exit codes correctly not fabricated). |
| Invoke-ProcessWithTimeout | RETAIN | The concurrent-drain + bounded-wait + kill/reap pattern is battle-tested (removal and scanner regressions both drove it) and is the single most important piece of process-runner logic to carry over, deduplicated into one shared Process/Logging module used by both scanners and the uninstaller runner. |
| tools/Get-AVTools.ps1 | REWRITE | Current behavior (fresh official downloads, FileVersion reporting trick, no-downgrade share fallback) is the right seed, but the rebuild's requirement is NAS-first acquisition (local cache -> NAS -> official vendor) with signature/hash/size/version validation and provenance recording. The current script has only a single hardcoded share and a presence-only -Verify with no hashing. Evidently: keep all four official URLs; add multi-tier source order, manifest-based validation, and provenance. |
| tools/Get-ToolPack.ps1 | REWRITE | Download+manifest+verify mechanics are proven and the manifest schema is the basis of ToolManagement, but the requirement adds NAS-first ordering, provenance, and signature/size/version validation. Fold into the same ToolManagement acquisition path as Get-AVTools (one acquisition engine, two tool sets). Keep the staging-directory-swap extract and per-tool scoped manifests. |
| tools/manifest.json | RETAIN | The schema (tool -> url + downloaded + per-file size/sha256) is exactly the record ToolManagement needs for validation; retain as the format and as a seed, extend with provenance fields (source tier, verified-at, signer) and AV tool entries. |
| tests/ (all) | RETAIN | The contract-test approach (source/AST pins + independent synthetic probes + dual-edition parse + XSS/hostile-input tests) is the strongest asset of the old suite. All of it maps directly onto the new test suite and must not be thrown away; extend, don't replace. |
| windows-ci.yml | RETAIN | Dual-edition matrix, timeout, on-failure artifact upload, and per-suite steps carry over. Only the invocation targets change to the new module layout. |
| docs/ (evidence/reporting/tools sections) | RETAIN | 01 decisions, 02 contracts (adapter return shape, snapshot Key scheme, scanner Status values), 05 tool/scanner licensing + official URLs, 06 safety rules are binding requirements that carry directly. 08 is historical. |
| snapshots/*.json | RETAIN | before/after/after.diff are the constructor inputs for test_diff_synthetic.py and the reference shape of the snapshot/diff schemas; keep as fixtures in the new test suite. |

---

## 4. Notable Logic Worth Preserving Exactly

1. Snapshot JSON schema and the Key scheme. Each section's stable-identity Key
   (documented in the collect-snapshot.ps1 header and enforced by the diff) is
   the linchpin: services by Name; tasks by TaskPath|TaskName; autoruns by
   Hive|KeyPath|ValueName; startup files by Scope|FileName; installed programs
   by root-hint|subkey; accounts by SID; firewall by rule Name; WMI by
   namespace|class|name (bindings by namespace|Binding|Filter->Consumer);
   Prefetch by .pf name; ShimCache by lower-cased path; BamDam by
   service|SID|name; UserAssist by GUID|decoded name; Processes/Connections by
   volatile point-in-time Key (not diffed as identity); Srum/SystemSettings as
   object sections. Arrays must be sorted by Key before emit.
2. The diff algorithm: stable vs volatile vs object classification;
   resurrection = Added in any stable section; Changed reported as field-name
   lists with +/- for added/removed properties; sorted output; SameComputerName
   warning; exit codes 0/1/2. The migration safety net for "did removal work / did
   something come back."
3. Report HTML structure and escaping: Encode-Html's five-token escape applied
   to every machine-sourced value; Get-Prop/Get-Items undo ConvertFrom-Json
   5.1 unwrapping; Row/Fmt/FmtBool/FmtList/Get-KvPairs; the badge/session-type/
   signature classification; the credential-reset checklist section (safety
   rule 12); the relay-host present/missing decision box. The XSS test pins the
   escaping contract and must be ported unchanged.
4. Scanner exit-code handling: Defender 0/2 -> Completed (else Failed);
   ESET 0/50/10 Completed, 100 Failed, >100 "not scanned - can be infected"
   Completed-with-error, else Failed, plus Unlicensed; KVRT codes deliberately
   NOT mapped (undocumented) - outcome from report files, nonzero surfaced in
   Errors. Absence of fabrication here is a safety property.
5. AV tool official URLs and the version-detection trick: the four official
   vendor URLs (KVRT devbuilds disk, Malwarebytes file/ endpoints, ESET online
   scanner download path) and the fresh-every-run policy; reporting the
   downloaded FileVersion + size via Get-Item VersionInfo, and the no-downgrade
   share fallback so a stale internal copy never overwrites a fresh official
   build. These URLs are the hard-won, live-verified acquisition ground truth.
6. The Invoke-ProcessWithTimeout concurrent-drain pattern (section 2.4) and the
   Invoke-GUIScanner "timeout leaves the process running" choice.
7. Manifest schema (tool -> url + downloaded + files{size,sha256}) and the
   staging-directory atomic-swap extract + per-tool scoped hashing in
   Get-ToolPack.
8. CI test approach: run each contract suite under BOTH PowerShell editions on
   real Windows; source/AST contract pins for things that cannot run safely;
   independent synthetic probes (chatty/langorous child) that prove the pattern
   without touching vendor binaries; hostile-input tests for the report; on-
   failure artifact upload of the diff payload.

---

## 5. Duplicated Code, Dead Code, Obsolete Artifacts, Temporary/Junk, Hardcoded Paths

Duplicated code (prime REFACTOR targets):
- Invoke-ProcessWithTimeout copied byte-for-byte into all three scanner
  adapters (Defender 217-274, ESET 203-260, KVRT 252-309). Should be one shared
  Process/Logging helper (the same shape appears as Run-BoundedProcess in
  remove-screenconnect.ps1, a fourth copy).
- New-ResultObject and Write-AdapterLog are identical in all three adapters
  (differing only in the ScannerName literal).
- Get-TempRoot (TEMP->TMP->cwd fallback) duplicated in ESET, KVRT, and
  Invoke-GUIScanner.
- Copy-ScanLogs exists three times with slightly different source logic
  (Defender fixed Support dir; KVRT wildcard KVRT*_Data + data dir; ESET single
  file copy).
- Get-FileSha256 (Get-ToolPack) vs Get-FileSha256Safe (collect-snapshot),
  both lowercase-hex vs uppercase-hex variants of the same helper.
- The snapshot Key documentation exists in both code comments and docs/02 and
  risks drifting (noted; keep one canonical source).

Dead or obsolete:
- tools/manifest.json: checked in as a static seed at a fixed timestamp
  (2026-08-23) whose hashes are stale the moment Get-ToolPack re-downloads; it
  is both input and output. In the rebuild it should be a machine-managed
  artifact, not a fixture pretending to be current. (The schema itself is
  authoritative - keep it, but treat the checked-in values as seed/sample only.)
- tools/.gitignore still references the old repo-relative tools structure; the
  rebuild re-rooted into gui-revision-screenconnect-cleaner.
- detect-remote-access.ps1's finding that New-InvestigationReport's sample
  findings.json had to be hand-built because the detector crashed on Linux
  (work-log) - resolved on Windows; no action.
- docs/00-START-HERE.md state table is self-declared out of date/superseded
  (kept for history). docs/08 is a log, not a spec to port.
- Root .gitignore mentions tools/_download/ which no current tool writes.

Temporary / test junk:
- snapshots/before.json, after.json, after.diff.json are local verification
  artifacts, but they double as the input fixtures for test_diff_synthetic.py -
  keep them as fixtures, move them under tests (or keep and document).

Hardcoded paths / values (all need to move to Configuration):
- Get-AVTools.ps1 InternalShare default: hardcoded '\\10.0.0.5\Public\Tools'
  (also in the usage examples) - a site-specific literal baked into the tool.
- Scanner discovery paths: Defender ProgramData/Program Files locations; ESET
  Program Files\ESET\ESET Security\ecls.exe; KVRT SystemDrive-root / Public
  Downloads / TEMP drop points; Invoke-GUIScanner C:\AdwCleaner, Downloads,
  TEMP search order. These are reasonable heuristics but belong in
  Configuration with explicit overrides.
- Default working/output paths: snapshot_<host>_<stamp>.json beside the script;
  report.html beside findings.json; diff <after-stem>.diff.json beside after.
- Hardcoded 240-min GUI timeout and 120-min scanner timeout defaults (should be
  Configuration).
- Hardcoded report CSS palette and page text in New-InvestigationReport.ps1.

---

## 6. Bugs and Limitations Spotted (with references)

1. Defender historical-detection mis-attribution (docs/07 Q4b finding 3, still
   OPEN). Get-ThreatDetections (Invoke-DefenderScan.ps1 lines 165-196) reads
   ALL of Get-MpThreatDetection history and reports it as this run's
   Detections; a pre-existing detection can be attributed to the current scan.
   It also copies Support logs without parsing a scanner log, partly
   contradicting the read-the-log-not-stdout rule (docs/02). Fix in rebuild:
   snapshot threat history before/after the scan and attribute only new
   detections, or split historical vs scan-specific in the result shape.
2. Amcache collector absent (docs/07 Q4b finding 2, OPEN). The Stage 1
   retrospective expansion implements Prefetch/ShimCache/BAM-DAM/UserAssist/
   SRUM but no Amcache - a listed artifact set. Either implement or formally
   drop from scope.
3. Windows-only forensic decoders unverified (Q4b finding 4, OPEN). ShimCache
   offsets/signature, BAM/DAM P/Invoke, UserAssist RunCount offset 4, Prefetch
   "<NAME>-<HASH>.pf" regex, and SRUM live-copy (FileShare ReadWrite vs ESE
   sharing mode) are written from published references / assumptions and must be
   cross-checked against known-good tooling on a real Windows host before
   their output is trusted. Every decoder fails safe (records errors), so the
   risk is wrong-but-not-crashing rows, not instability.
4. KVRT/ESET detection parsers are doc-based heuristics, untested against real
   reports/logs (Q4b finding 5, OPEN). Get-DetectionsFromLog and
   Get-DetectionsFromReports produce empty or over-broad detections by design;
   counts must be eyeballed against copied logs before trust. ESET exit code 1
   (documented "cleaned", impossible here since cleaning is disabled) is treated
   as unexpected and flagged - correct but worth a comment in the new code.
5. Get-ToolPack -Verify is completeness-blind: it only checks files named in
   the manifest and silently ignores extra/stale files in a tool folder; a
   tool entry absent from the manifest is flagged but a superseded manifest
   itself is never refreshed. Verification cannot guarantee the pack is current.
6. Invoke-GUIScanner uses Set-StrictMode 2.0 and a ValidateSet - a GUI scanner
   outside the set (e.g. a future one) is unreachable via -Scanner without an
   edit; only -ToolPath bypasses. Minor; a Configuration-driven registry of
   GUI tools would fix it.
7. diff-snapshots.ps1 warns but does not fail when ComputerName differs between
   snapshots; a cross-machine (or renamed-host) diff can produce a meaningless
   RESURRECTION. Consider a hard gate in the rebuild.
8. collect-snapshot.ps1 default OutFile is the script directory, which may be
   read-only on a deployed bundle; the Srum offline copy also writes beside the
   snapshot and can raise OfflineCopyError. Path handling should honour a
   nominal/evidence output root from Configuration.
9. The report renders RelayPort as ":$(Fmt $relayPort)" without validating it
   is numeric; a malformed port produces odd but escaped (safe) markup.
10. The snapshot/diff schemas are coupled through undocumented assumptions:
    diff treats missing sections in a v1 snapshot as empty (noted in
    collect-snapshot header) but a consumer diffing v2 against v1 files relies
    on that rule; document it as a forward-compat contract in the rebuild.
11. Get-AVTools presence-only -Verify does no hashing; an attacker who has
    write access to the AV staging dir can plant a scanner and -Verify reports
    it present. The rebuild's signature/hash/size validation directly addresses
    this.

---

## 7. Mapping Suggestion: Old Components -> Target Architecture

Target modules (from the rebuild context): Evidence, Snapshots, Reporting,
Scanners, ToolManagement, Configuration, Logging.

| Old component | New module / home |
|---------------|-------------------|
| collect-snapshot.ps1 section collectors | Evidence module - one function/class per collector; snapshot wire format carried by the Snapshots module schema. IncidentWindowDays -> Configuration; CollectionErrors -> Logging/Evidence. |
| collect-snapshot.ps1 Key scheme + CollectionErrors + Sort-ByKey | Snapshots module (schema contract), shared with Evidence and Logging. |
| diff-snapshots.ps1 (classification, verdict, exit-code semantics) | Snapshots module - pure diff/resurrection function returning a structured verdict for the GUI. |
| New-InvestigationReport.ps1 Encode-Html/Get-Prop/Get-Items/Fmt/Row helpers + section renderers | Reporting module - generalized escaping + rendering primitives. |
| New-InvestigationReport.ps1 sections (SC instances, other agents, removal+credential checklist, parse problems, environment) | Reporting module - report.html builder. |
| (missing today) report.json + technician-summary.txt | Reporting module - NEW outputs required by the rebuild; derive from the same model the HTML builder uses. |
| scanners/Invoke-DefenderScan.ps1 | Scanners module - DefenderAdapter (keep -ScanType 3 -DisableRemediation invariant, fix detection attribution). |
| scanners/Invoke-ESETScan.ps1 | Scanners module - EsetAdapter (keep log-file contract + exit map + Unlicensed). |
| scanners/Invoke-KVRTScan.ps1 | Scanners module - KvrtAdapter (keep -d pre-create, -custom not -customonly, report-file outcome). |
| Invoke-GUIScanner.ps1 | Scanners module - attended/gui run path (centralized scanner management). |
| Invoke-ProcessWithTimeout (3 copies) | Logging/Process shared helper (single copy, reused by Scanners and uninstaller runner). |
| New-ResultObject / Write-AdapterLog / Get-TempRoot / Copy-ScanLogs (duplicates) | Scanners module shared base + Logging helper. |
| tools/Get-AVTools.ps1 | ToolManagement - acquisition engine (keep 4 official URLs + no-downgrade rule). |
| tools/Get-ToolPack.ps1 | ToolManagement - same acquisition engine, Sysinternals pack set. |
| tools/manifest.json schema + seed | ToolManagement/Configuration - manifest record format (extend with provenance + signature + AV entries); seed values treated as sample. |
| Invoke-GUIScanner knownTools map, scanner discovery paths, InternalShare, default timeouts | Configuration module (no hardcoded paths/IPs). |
| tests/test_diff_synthetic.py | Test suite - Snapshots.diff contract tests (keep exact assertions). |
| tests/ci/Test-HouseRules.ps1, Test-Parse.ps1 | Test suite - repo-level gates against the new tree. |
| tests/ci/Test-ScannerProcessContracts.ps1 | Test suite - Scanners process-contract tests (source/AST pins + synthetic probe) updated to shared helper path. |
| tests/ci/Test-WindowsIntegration.ps1 XSS section | Test suite - Reporting XSS regression (port the hostile-input checks verbatim). |
| tests/ci/Test-RemovalRuntimeContracts.ps1, Test-PipelineLauncherContracts.ps1 | Test suite - contract gates for the removal/runner modules (adjust to new module layout). |
| windows-ci.yml steps | New CI - same dual-edition matrix; invoke the new suite entry points; keep on-failure artifact upload. |
| docs/02 adapter contract + snapshot schema, docs/05 tool/scanner URLs + licensing, docs/06 safety rules | Configuration/Logging/Scanners/Reporting module specs - binding requirements, port as design constants. |
| snapshots/before.json, after.json, after.diff.json | Test suite fixtures - reference snapshots + expected CLEAN diff for the Snapshots module. |

Mapping summary: the evidence/reporting/tools layer is predominantly
REFACTOR + MERGE rather than REWRITE. The logic that must not be lost is (a) the
snapshot Key/diff/resurrection contract, (b) the XSS-safe report escaping, (c)
the three scanner adapters' documented-switch discipline and detect-only safety
invariants, (d) the live-verified official vendor URLs, and (e) the
contract/probe/XSS testing approach. The genuinely new work is the NAS-first
multi-tier acquisition with validation + provenance (REWRITE of the two stagers
into ToolManagement) and the added report.json + technician-summary.txt outputs
in Reporting.

DONE - AUDIT-04 evidence/reporting/tools inventory complete.
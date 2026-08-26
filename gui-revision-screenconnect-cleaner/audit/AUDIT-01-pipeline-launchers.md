# AUDIT-01: Pipeline Orchestrator and Launchers

Date: 2026-08-26
Scope: sc-cleanup.ps1, preflight.ps1, START-HERE.bat, Run-DetectRemoteAccess.bat, RUN-REMOVAL-TEST.bat, make-deploy-bundle.sh, DEPLOY.md, test_plan.json
Mode: READ-ONLY audit for GUI-revision migration (gui-revision-screenconnect-cleaner/)
Reference architecture: gui-revision-screenconnect-cleaner/docs/ARCHITECTURE.md

---

## 1. Scope Inventory

| File | Lines | Purpose |
|------|-------|---------|
| sc-cleanup.ps1 | 1019 | Staged pipeline orchestrator that runs Stages 0-8 in order (Preflight -> Snapshot Before -> Detect -> Review Gate -> Contain+Remove -> Scanners -> Snapshot After+Diff -> Report) with safety gates and skip flags. |
| preflight.ps1 | 476 | Standalone Stage-0 preflight implementation (admin/UAC/Server/disk/working-dir/restore-point/hive-export/tool-pack checks) that is duplicated and superseded by Stage 0 inside sc-cleanup.ps1 but still used by START-HERE.bat. |
| START-HERE.bat | 287 | Guided 9-step interactive batch runner that walks a technician through toolpack -> preflight -> before-snapshot -> detection -> review+remove -> AV scans -> Tikun -> after-snapshot+diff -> report, prompting before each step. |
| Run-DetectRemoteAccess.bat | 39 | Minimal double-click launcher for detect-remote-access.ps1 that self-elevates via fltmc+powershell Start-Process -Verb RunAs and forwards all args (%*). |
| RUN-REMOVAL-TEST.bat | 83 | Lab-only destructive pipeline launcher that self-elevates, requires typed YES, then runs sc-cleanup.ps1 -ExecuteRemoval [-sa] for VM testing. |
| make-deploy-bundle.sh | 59 | Bash packager that builds a clean deploy zip (scripts+docs+scanners, no binaries) to parent dir screenconnect-cleanup-deploy.zip and warns when tools/Get-ToolPack.ps1 or Get-AVTools.ps1 are missing. |
| DEPLOY.md | 133 | Technician deploy guide: what to copy/not copy, first-run steps, common flags table, outstanding live-validation checklist, and house rules for editors. |
| test_plan.json | 27 | Machine-readable example of plan.json schema (GeneratedUtc/TechName/ClientName/IncidentDate/Decision/SourceFindings/ScreenConnectInstances[1]) for testing removal without running detection. |

Total lines across audited files: 2123 (sum of wc -l). All counts verified via wc -l on 2026-08-26.

---

## 2. FULL FUNCTIONALITY INVENTORY (migration safety net)

This section is exhaustive. Anything not listed here and not ported is a regression.

### 2.1 sc-cleanup.ps1 - Parameters (param block sc-cleanup.ps1:23-45)

Skip/configuration switches:

* `-sa` [switch] skip antivirus scanners (Stage 5) - sc-cleanup.ps1:25
* `-sr` [switch] skip removal / detect+report only (Stage 4) - sc-cleanup.ps1:26
* `-np` [switch] no restore point (skips SystemRestore+hive work) - sc-cleanup.ps1:27
* `-offline` [switch] use pre-staged tool pack, do not download (affects Get-ToolPack and Get-AVTools handling) - sc-cleanup.ps1:28
* `-procmon` [switch] force Procmon stage (otherwise Stage 6 is skipped) - sc-cleanup.ps1:29
* `-force` [switch] override Server-OS refusal and allow UAC-disabled continuation - sc-cleanup.ps1:30
* `-safemode` [switch] requests safe-mode relaunch (currently stub, warns not-implemented) - sc-cleanup.ps1:31
* `-resume` [switch] internal flag used by reboot RunOnce resume path; suppresses TechName/ClientName prompts - sc-cleanup.ps1:32
* `-ExecuteRemoval` [switch] TEST MODE: pre-authorizes Stage 4, auto-marks every detected ScreenConnect instance REMOVE, waives typed confirmation (honors -sr) - sc-cleanup.ps1:33, sc-cleanup.ps1:16-20

Configuration strings:

* `-IncidentDate` [string] yyyy-MM-dd anchor for incident-window weighting - sc-cleanup.ps1:36
* `-OutRoot` [string] working-dir root, default C:\RIT-SCC - sc-cleanup.ps1:37, sc-cleanup.ps1:331
* `-ToolDir` [string] tool pack dir, default <script dir>\tools - sc-cleanup.ps1:38, sc-cleanup.ps1:358-360
* `-TechName` [string] technician name (prompted if missing and not -resume) - sc-cleanup.ps1:39
* `-ClientName` [string] client/ticket identifier (prompted if missing and not -resume) - sc-cleanup.ps1:40

Debug switches:

* `-WhatIf` [switch] show what would run, execute nothing (checked inside Invoke-Stage) - sc-cleanup.ps1:43
* `-VerboseLog` [switch] verbose stage logging (passed to child scanners/remover, gates Debug-level log lines) - sc-cleanup.ps1:44

Constants/metadata (sc-cleanup.ps1:53-65):

* `$ScriptVersion = '1.0.0'`
* `$ScriptName = 'sc-cleanup.ps1'`
* `$PipelineStages` array of 9 hashtables Id 0..8 with Name and SkipFlag mapping

### 2.2 sc-cleanup.ps1 - Pipeline Stages (9 stages, IDs 0-8)

| Stage Id | Name | SkipFlag | Skippable? | Gate / Behavior |
|----------|------|----------|------------|----------------|
| 0 | Preflight | (none) | never | Admin/OS/disk/WorkDir/master.log/tech+client/incident prompt/restore-point+hive-export/tool-pack verify (Get-ToolPack.ps1) + AV staging (Get-AVTools.ps1). Never skippable. |
| 1 | Snapshot (Before) | (none) | never | Calls collect-snapshot.ps1 -Label before -IncidentWindowDays <days> -OutFile snapshot_before.json via Invoke-ChildScript. Never skippable. |
| 2 | Detect | (none) | never | Calls detect-remote-access.ps1 -OutRoot <WorkDir>\detect -NoPause -NoZip, resolves newest findings.json recursively under detect dir. |
| 3 | Review Gate | (none) | never | Reads findings.json, uses Get-JsonItems/Get-PropertyValue, iterates ScreenConnect Instances, prompts per-instance Remove [y/N] (default N=KEEP), aggregates removeInstances ArrayList, second gate: typed confirmation "Proceed with removal? [y/N]" waived under -ExecuteRemoval. Produces plan.json (ordered hashtable, Depth 12). |
| 4 | Contain + Remove | sr | yes (-sr) | Calls remove-screenconnect.ps1 -PlanJson <plan.json> -WorkDir <WorkDir> [+ -Execute if confirmed] [+ -VerboseLog]. Fail-closed if RestorePointFailed and confirmed and not -np -> returns blocked result ExitCode 2 without throwing. Partial removal (exit 1) is recorded and pipeline continues to Stages 5-8. Produces removal-manifest.json. |
| 5 | Scanners | sa | yes (-sa) | Loops 3 adapters from scanners dir: Invoke-DefenderScan.ps1, Invoke-KVRTScan.ps1, Invoke-ESETScan.ps1 each invoked inline (& $adapterScript -LogDir <WorkDir>\logs\<SubDir> -TimeoutMinutes 120 -Verbose:$VerboseLog), never throws, reports Status=NotInstalled when absent. Writes scanner_results.json. Logs note about MSERT missing and GUI-only scanners via Invoke-GUIScanner.ps1. |
| 6 | Procmon | procmon (opt-in) | opt-in only | Stub only. Logs that procmon is not implemented, returns Skipped. Intended: filtered Procmon capture for bounded window, .pml to logs/Procmon/. Currently dead. |
| 7 | Snapshot (After)+Diff | (none) | never | Re-runs collect-snapshot.ps1 -Label after, then diff-snapshots.ps1 -Before <before> -After <after> -OutFile snapshot_diff.json (exit 0 clean, 1 resurrection, 2 failure; 1 treated as finding not error). Falls back to in-line basic diff if script missing. Correlates manifest.Entries targets/instanceIds against stable-section Added items via wildcard like. Reports Resurrected bool. |
| 8 | Report | (none) | never | Calls New-InvestigationReport.ps1 -FindingsJson -OutputPath report.html [+ -RemovalManifest], then builds results.json (machine-readable summary with SCInstanceCount/OtherHitTotal/paths). Safe null handling for skipped stages. |

Execution wrapper: `Invoke-Stage` (sc-cleanup.ps1:247-295) handles skip-flag lookup via Get-Variable, WhatIf short-circuit, try/catch with throw, duration timing (TotalSeconds rounded to 2dp), per-stage section headers and MasterLog writes, returns @{Skipped,Result,Duration,Error}.

### 2.3 sc-cleanup.ps1 - Helper Functions

* `Write-StageLog` (sc-cleanup.ps1:70-82) timestamped console + master.log (gated: Debug lines suppressed unless -VerboseLog), prefix map Info=> "==>", Warn=> "!! ", Error=> "!!!", Debug=> "..."
* `Write-Section` (sc-cleanup.ps1:84-97) 70-char dash bar, cyan title, mirrors to master.log
* `Test-IsAdmin` (sc-cleanup.ps1:99-107) WindowsIdentity/WindowsPrincipal IsInRole(Administrator)
* `Test-UacEnabled` (sc-cleanup.ps1:109-118) reads HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System!EnableLUA (absent => true, 0 => disabled)
* `Test-IsServerOS` (sc-cleanup.ps1:120-128) Get-CimInstance Win32_OperatingSystem Caption -match (?i)Server
* `Get-AvailableDiskSpace` (sc-cleanup.ps1:130-138) DriveInfo.AvailableFreeSpace /1GB floor, -1 on failure
* `Resolve-WorkingDir` (sc-cleanup.ps1:140-145) Join Root + "$HostName-yyyyMMdd_HHmmss" (UTC timestamp, sc-cleanup.ps1:142)
* `Prompt-IfMissing` (sc-cleanup.ps1:147-156) Read-Host if var empty, throw if still whitespace
* `Get-JsonItems` (sc-cleanup.ps1:158-167) null=>empty array, array=>copy, IEnumerable(!string)=>copy, scalar=>single array; uses unary comma to avoid Count bug under StrictMode 2.0
* `Get-PropertyValue` (sc-cleanup.ps1:169-175) null-safe PSObject property lookup
* `Invoke-ChildScript` (sc-cleanup.ps1:181-245) spawns child process via ProcessStartInfo, prefers pwsh then powershell.exe, args quoted if contains [\s"&|<>], UseShellExecute false, redirects stdout/stderr, reads stderr async via ReadToEndAsync to avoid deadlock, splits on \n, logs each line via Write-StageLog, returns process exit code
* `Invoke-Stage` (sc-cleanup.ps1:247-295) see above
* Anonymous StageBlocks for Stages 0-8 (sc-cleanup.ps1:402-949)

### 2.4 sc-cleanup.ps1 - Initialization and Global Flow (sc-cleanup.ps1:300-420)

* `$ScriptRoot` via Split-Path $MyInvocation.MyCommand.Path
* Hostname fallback chain: COMPUTERNAME -> HOSTNAME -> Dns.GetHostName -> 'unknown' (sc-cleanup.ps1:305-307)
* PSVersion, OSCaption via Get-CimInstance Win32_OperatingSystem (sc-cleanup.ps1:309-315)
* Banner with cyan header, pipeline stage count, Host/OS/PS/Admin/Server line, red -ExecuteRemoval warning (sc-cleanup.ps1:317-328)
* OutRoot default C:\RIT-SCC, created with New-Item -Force (sc-cleanup.ps1:330-335)
* Disk-space warning if freeGb < 5 (sc-cleanup.ps1:338-341)
* Working dir: Resolve-WorkingDir under OutRoot, created, assigned to $WorkDir (sc-cleanup.ps1:343-346)
* Master log: $WorkDir\master.log with header lines (version/Started/Host/OS/PS/Admin/Server/Flags/IncidentDate) (sc-cleanup.ps1:348-355)
* ToolDir default <ScriptRoot>\tools (sc-cleanup.ps1:357-360)
* Prompt for TechName/ClientName unless -resume (sc-cleanup.ps1:362-366)
* IncidentDate default (Get-Date).ToString('yyyy-MM-dd') if not provided (sc-cleanup.ps1:369-371)
* Preflight gates before Stage 0: isAdmin warning (not throw on non-Windows), isServer throw unless -force, UAC check throw unless -force (sc-cleanup.ps1:376-392), safemode stub warning (sc-cleanup.ps1:394-397)
* Pipeline complete section (sc-cleanup.ps1:954-1019): safe ExitCode extraction from Stage 4 payload (IDictionary.Contains vs PSObject.Properties under StrictMode), pipelineIncomplete bool, console summary (WorkDir/MasterLog/report.html/results.json), master.log final outcome line, exit 1 if incomplete else 0

### 2.5 sc-cleanup.ps1 - Stage-Critical Behaviors

* System Restore + registry hive export inside Stage 0 (sc-cleanup.ps1:424-462): Checkpoint-Computer MODIFY_SETTINGS, $script:RestorePointFailed flag, failure is warned not fatal until Stage 4 fail-closed check; hives: HKLM\SOFTWARE, HKLM\SYSTEM, HKCU\SOFTWARE via reg.exe export ("HKLM\SOFTWARE" not "HKLM:\SOFTWARE") to $WorkDir\registry_hives\<name>.reg
* Tool pack verification (sc-cleanup.ps1:464-488): tools\Get-ToolPack.ps1 -ToolDir $ToolDir -Quiet or -Verify -Quiet when -offline; checks $LASTEXITCODE not exception; logs PASSED/FAILED vs master.log
* AV staging (sc-cleanup.ps1:490-507): tools\Get-AVTools.ps1 -ToolDir <ToolDir>\AV -Quiet when exists and not -offline; logs warnings on failure; skipped when -offline with explicit message
* IncidentWindowDays calculation for both snapshots (sc-cleanup.ps1:529-534, sc-cleanup.ps1:797-801): Parse IncidentDate -> Round((Get-Date - incident).TotalDays), Max 0, cast to int, passed as string to collect-snapshot.ps1
* findings.json discovery (sc-cleanup.ps1:565-570): Get-ChildItem -Recurse -Filter findings.json under detect dir, sorted LastWriteTime descending, newest selected; throw if none
* Review Gate owner policy (sc-cleanup.ps1:604, sc-cleanup.ps1:654-664): only ScreenConnectInstances serialized as removal surface; Decision logic: KEEP_ALL vs ALL_REMOVE vs PARTIAL_REMOVE derived from removeInstances vs instances count; plan.json ordered keys: GeneratedUtc,TechName,ClientName,IncidentDate,Decision,SourceFindings,RemovalConfirmed,ScreenConnectInstances (Depth 12)
* Stage 4 fail-closed gate (sc-cleanup.ps1:692-696): if confirmed and not -sr and RestorePointFailed and not -np -> log BLOCKED Error, master.log entry, return Skipped=false ManifestPath=null Executed=false ExitCode=2 RestorePointBlocked=true, does NOT throw so Stages 5-8 still run
* Scanner adapter contract (sc-cleanup.ps1:733-737): adapters never throw, report Status=NotInstalled when absent, Status/DurationSeconds via result object
* Procmon stub (sc-cleanup.ps1:769-784): three explanatory log lines, returns Skipped=true Note='Not implemented in v1'
* Diff-snapshot resurrection logic (sc-cleanup.ps1:850-874): loads removal-manifest.json if exists, correlates stable-section Added entries against manifest Entry.Target/InstanceId via -like '*target*', collects resurrectionMatches, logs warn on match
* Report stage fallback (sc-cleanup.ps1:912-919): safe null reads for beforeSnap/afterSnap/diffPath/removalManifest/scannerSummary/planJson when stages skipped

### 2.6 preflight.ps1 - Parameters (preflight.ps1:21-49)

* `-np` [switch] alias for skip restore+hive (canonical flag from sc-cleanup -np) (preflight.ps1:24)
* `-SkipRestore` [switch] alias for -np (preflight.ps1:27)
* `-Force` [switch] override Server-OS refusal (preflight.ps1:30)
* `-MinFreeGB` [int] default 10 (vs sc-cleanup threshold 5 warning) (preflight.ps1:33)
* `-WorkingRoot` [string] default C:\RIT-SCC (preflight.ps1:36)
* `-ToolPackPath` [string] path to Get-ToolPack.ps1, default tools\Get-ToolPack.ps1 next to script (preflight.ps1:39)
* `-TechName` [string] default '' (interactive prompt otherwise) (preflight.ps1:43)
* `-ClientName` [string] default '' (preflight.ps1:44)
* `-IncidentDate` [string] default '' (blank = today via prompt) (preflight.ps1:45)
* `-SelfTest` [switch] internal selftest exercising pure logic, mutates nothing, works on Linux CI (preflight.ps1:48)

Note: preflight.ps1 is [CmdletBinding()], sc-cleanup.ps1 is not.

### 2.7 preflight.ps1 - Functions

* `Write-Stage` / `Write-StageWarn` / `Write-StageFail` (preflight.ps1:60-75) cyan/yellow/red Host prints, Fail sets $script:PreflightOk=false
* `Test-IsAdmin` (preflight.ps1:76-89) env:OS check, WindowsPrincipal path
* `Test-UacEnabled` (preflight.ps1:91-98) same as sc-cleanup
* `Get-HostNameSafe` (preflight.ps1:100-105) COMPUTERNAME->HOSTNAME->Dns.GetHostName->unknown
* `Get-OsCaptionSafe` (preflight.ps1:107-128) PS>=3 CIM else WMI fallback, else Non-Windows(platform os)
* `Test-IsServerOs` (preflight.ps1:130-133) -match (?i)windows\s+server (tighter than sc-cleanup)
* `Get-FreeSpaceGB` (preflight.ps1:135-144) DriveInfo rounded to 1 decimal, -1 sentinel
* `Invoke-RestorePoint` (preflight.ps1:146-203) probes SystemRestore CIM class + RPSessionInterval reg value, refuses if both null (fail loudly, not silent skip), creates restore point via Checkpoint-Computer MODIFY_SETTINGS
* `Export-RegistryHives` (preflight.ps1:205-247) reg.exe save HKLM\SOFTWARE, HKLM\SYSTEM, HKCU (hives as .hiv files), excludes HKLM\SAM and HKLM\SECURITY intentionally (MITRE T1003.002, AV false-positive rationale documented), pipes reg output to Out-Null to avoid truthy array bug
* `Test-ToolPack` (preflight.ps1:249-271) & $ScriptPath -Verify -Quiet, checks $LASTEXITCODE
* `Invoke-PromptTechInfo` (preflight.ps1:273-289) fills script:TechAnswer/ClientAnswer/IncidentAnswer, incident blank->today
* SelfTest block (preflight.ps1:294-329): hostname non-empty, caption non-empty, server detection (Server 2019 true, Win10 false), Test-IsAdmin returns bool, Get-FreeSpaceGB returns numeric; exit 1 on any failure else 0

### 2.8 preflight.ps1 - Main Sequence (preflight.ps1:331-476)

Stage numbering: single stage labeled === STAGE 0: PREFLIGHT === (preflight.ps1:338-339), then numbered steps 1..7 internally: 1 admin, 1b UAC, 2 OS role, 3 disk space, abort-on-fail, 4 WorkingDirectory+master.log, 5 tech/client/incident, 6 restore+hive (skippable), 7 tool pack verify. Master log uses ascii encoding (preflight.ps1:411). Work dir pattern same as sc-cleanup: <WorkingRoot>\<HOST>-<stamp> where stamp=yyyyMMdd-HHmmss (preflight.ps1:334-335, 400). Creates subdirs logs/quarantine/snapshots/registry (preflight.ps1:407-409). Final handoff: stdout one-line compressed JSON @{Stage=0,Status=Complete,WorkingDirectory,MasterLog,Technician,Client,IncidentDate,RestorePointSkipped} (preflight.ps1:468-471), exit 0 complete or 1 fail.

### 2.9 START-HERE.bat - Behavior (START-HERE.bat:1-287, 287 lines)

* Self-elevate (START-HERE.bat:14-31): stores %~f0 in SCC_SELF env var, tests fltmc.exe, if not admin then powershell Start-Process -FilePath $env:SCC_SELF -Verb RunAs (forwards no args, just self path), checks errorlevel 1 on launch failure, pauses and exits 1, else exit /b after successful re-launch; clears SCC_SELF after.
* cd /d "%~dp0" to script dir (START-HERE.bat:33)
* Header banner lines 35-44 listing 9 steps: 1 toolpack 2 preflight 3 before-snapshot 4 detection 5 REMOVE 6 antivirus scans 7 tikun 8 after-snapshot+diff 9 report; note steps 1-4 and 8-9 read-only, 5 removes with confirmation, 7 opt-in destructive (START-HERE.bat:38-43)
* Step 1 tool pack (START-HERE.bat:46-62): prompt Run now? [Y/n] (default Y unless "n"), if Get-ToolPack.ps1 exists then run twice (once normal, once -Verify), if Get-AVTools.ps1 exists then run with -ToolDir "%~dp0tools\AV", else warns per missing script. set GO= cleanup per step.
* Step 2 preflight (START-HERE.bat:64-71): prompt [Y/n], runs preflight.ps1 bare (no args).
* Step 3 before-snapshot (START-HERE.bat:73-85): prompt [Y/n], calls collect-snapshot.ps1 -Label before -OutFile "%~dp0snapshot_before.json" -Quiet, checks existence for [i]/[WARN].
* Step 4 detection (START-HERE.bat:87-109): prompt Full scan of all known targets? [y/N] (default N= ScreenConnect-only); if y adds -All, always -NoPause; resolves newest findings.json under %USERPROFILE%\Desktop\RemoteAccessScan\<timestampedFolder>\findings.json via for /f dir /b /ad /o-d loop storing FULL path in FINDINGS_JSON with delayed expansion !var!.
* Step 5 review+remove (START-HERE.bat:111-129): banner notes KEEP default and quarantine-never-delete; prompt Run removal review now? [Y/n]; if Invoke-ReviewAndRemove.ps1 exists and FINDINGS_JSON defined then launch with -FindingsJson, else bare; else warns missing script.
* Step 6 antivirus scans 4 sub-steps (START-HERE.bat:131-204):
  - 6a Defender: prompt [Y/n], inner Dry-run? [y/N] -> -WhatIf else real scan (Invoke-DefenderScan.ps1)
  - 6b KVRT interactive GUI: prompt [Y/n], checks tools\AV\KVRT.exe, start "" "KVRT.exe", then pause waiting for user to finish scan
  - 6c ESET Online Scanner: prompt [y/N] (default N), checks esetonlinescanner.exe, start + pause
  - 6d Malwarebytes: prompt [y/N], checks MBSetup.exe, notes installer exits before scan, start + pause
* Step 7 Tikun / GeneralFix (START-HERE.bat:206-225): banner warns kills/deletes without quarantine, installs scheduled task at boot/USB; opt-in [y/N] default N; if y scans tools\GeneralFix\*.bat first match into GFIX_SCRIPT and call "!GFIX_SCRIPT!", else warns.
* Step 8 after-snapshot+diff (START-HERE.bat:227-254): prompt [Y/n], runs collect-snapshot.ps1 -Label after -OutFile snapshot_after.json -Quiet, guards diff on existence of before/after files, calls diff-snapshots.ps1 -BeforeFile -AfterFile -OutFile snapshot_diff.json, handles exit codes: 2=>WARN Diff failed, 1=>WARN RESURRECTION, 0=>clean.
* Step 9 report (START-HERE.bat:256-277): if FINDINGS_JSON not defined warns and prompts for path (blank=skip), if defined and exists calls New-InvestigationReport.ps1 -FindingsJson -OutputPath "%~dp0report.html", checks report existence.
* Footer (START-HERE.bat:279-287): summary paths under C:\RIT-SCC\, relay-host check instruction, DEPLOY.md section 4 reference, final pause.

### 2.10 Run-DetectRemoteAccess.bat (Run-DetectRemoteAccess.bat:1-39)

* Self-elevate same pattern as START-HERE but forwards args via SCC_ARGS=%* (Run-DetectRemoteAccess.bat:16-32): stores self+SCC_ARGS env, fltmc test, powershell Start-Process -FilePath $env:SCC_SELF -ArgumentList $env:SCC_ARGS -Verb RunAs, errorlevel check + pause/exit 1, else exit /b, clears env vars after.
* Executes powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0detect-remote-access.ps1" %* (Run-DetectRemoteAccess.bat:34)
* If errorlevel neq 0 then echo Powershell exited with error before pause, pause (Run-DetectRemoteAccess.bat:35-39)

### 2.11 RUN-REMOVAL-TEST.bat (RUN-REMOVAL-TEST.bat:1-83)

* Lab-only banner: THIS WILL ACTUALLY MAKE CHANGES, quarantined never deleted, SHA256 recorded, snapshot warning (RUN-REMOVAL-TEST.bat:22-53)
* Self-elevate same as others (RUN-REMOVAL-TEST.bat:19-36)
* cd /d "%~dp0" (RUN-REMOVAL-TEST.bat:38)
* Typed YES gate: set /p GO="Type YES to proceed: " must be exactly "yes" case-insensitive else Aborted, pause, exit 0 (RUN-REMOVAL-TEST.bat:55-60)
* AV skip choice: set /p SKIPAV="Skip the antivirus scanner stage? [Y/n]" default Y sets AVFLAG=-sa else empty (RUN-REMOVAL-TEST.bat:63-66)
* Launch: powershell -NoProfile -ExecutionPolicy Bypass -File ".\sc-cleanup.ps1" -ExecuteRemoval %AVFLAG% (RUN-REMOVAL-TEST.bat:71)
* Footer lists outputs under C:\RIT-SCC\: master.log, plan.json, removal-manifest.json, quarantine\, snapshot_diff.json, report.html (RUN-REMOVAL-TEST.bat:73-82)

### 2.12 make-deploy-bundle.sh (make-deploy-bundle.sh:1-59)

* bash with set -euo pipefail (make-deploy-bundle.sh:11)
* SRC="$(cd "$(dirname "$0")" && pwd)", OUT="$(dirname "$SRC")/screenconnect-cleanup-deploy.zip", STAGE="$(mktemp -d)", trap rm -rf, D="$STAGE/screenconnect-cleanup" (make-deploy-bundle.sh:12-16)
* mkdir -p "$D/scanners" "$D/tools" (make-deploy-bundle.sh:17)
* Core file copy loop (fails loudly if missing, make-deploy-bundle.sh:19-25): sc-cleanup.ps1, preflight.ps1, collect-snapshot.ps1, diff-snapshots.ps1, detect-remote-access.ps1, remove-screenconnect.ps1, Invoke-ReviewAndRemove.ps1, Invoke-GUIScanner.ps1, Run-DetectRemoteAccess.bat, START-HERE.bat, targets.json, New-InvestigationReport.ps1, DEPLOY.md -> $D/ ; README.md if exists; scanners/*.ps1 -> $D/scanners/; docs/ if exists -> $D/docs
* Optional tool-pack scripts (make-deploy-bundle.sh:30-38): Get-ToolPack.ps1, Get-AVTools.ps1 copied only if present, else accumulate missing_tools and warn to stderr.
* Zip build via python3 zipfile.ZIP_DEFLATED walking $STAGE, removing old OUT if exists, print wrote $OUT (make-deploy-bundle.sh:45-56)
* Contents listing via python3 zipfile.ZipFile($OUT).infolist() printing filename and file_size (make-deploy-bundle.sh:58-59)

Note: docs reference stale comment (make-deploy-bundle.sh:5-10) says Get-ToolPack/Get-AVTools were never committed; DEPLOY.md note (2026-08-25/26) says they are now present - the script correctly handles both cases.

### 2.13 DEPLOY.md (DEPLOY.md:1-133)

* Section 1 What to copy (DEPLOY.md:9-53): lists required scripts/docs (sc-cleanup.ps1, preflight.ps1, collect-snapshot.ps1, diff-snapshots.ps1, detect-remote-access.ps1, Run-DetectRemoteAccess.bat, targets.json, New-InvestigationReport.ps1, scanners/*.ps1, tools/Get-ToolPack.ps1, tools/Get-AVTools.ps1, docs/, DEPLOY.md) and NOT to copy (tools/ProcessMonitor etc ~24MB, *.output artifacts), mentions make-deploy-bundle.sh layout, note about Get-ToolPack manifest/hash-verify via download.sysinternals.com and Get-AVTools endpoints (KVRT, AdwCleaner, MB5, ESET Online Scanner, verified 2026-08-26, internal share \\10.0.0.5\Public\Tools as fallback), GUI-only scanner launch lines for ESET/Malwarebytes/AdwCleaner via Invoke-GUIScanner.ps1 -Scanner, 4-hour safety cap.
* Section 2 First run on Windows (DEPLOY.md:67-96): reqs Win 10/11 or Server 2016+, PS 5.1, admin, internet; steps 1-7 copy zip, Unblock, extract to C:\RIT-SCC\tool, Build pack Get-ToolPack.ps1 + Verify, Dry-run -WhatIf, Real read-only run with -sr -sa -TechName -ClientName -IncidentDate, output under C:\RIT-SCC\<HOST>_<timestamp>\ (findings.json, HTML report, raw\ evidence, before/after diff); standalone detection via bat or ps1 with -Target/-All/-SelfTest.
* Section 3 Common flags table (DEPLOY.md:98-109): -sr, -sa, -np, -offline, -procmon, -IncidentDate, -WhatIf (omits -force/-safemode/-ExecuteRemoval/-VerboseLog/-OutRoot/-ToolDir - see Bugs section).
* Section 4 Before you trust it - outstanding live validation (DEPLOY.md:110-127): M0 key-map validation via real ScreenConnect install vs raw\ + PARSE PROBLEMS, snapshot diff volatility check, scanner adapter smoke, Get-ToolPack download check; note removal not trusted until M0; House rules: PS 5.1 compat, ASCII no BOM, verify by running.
* Section 5 is actually section 5 house rules (DEPLOY.md:128-133): PS 5.1 compat, ASCII, verify via execution, cite vendor docs.

### 2.14 test_plan.json (test_plan.json:1-28)

* Top-level keys: GeneratedUtc (2026-08-23 15:38:00), TechName, ClientName, IncidentDate, Decision (ALL_REMOVE), SourceFindings (C:\RIT-SCC\TESTHOST_...\detect\findings.json), ScreenConnectInstances[] (test_plan.json:1-27)
* Single entry in ScreenConnectInstances with InstanceId a1b2c3d4e5f6 (test_plan.json:11), Identifier same, ServiceName/DisplayName "ScreenConnect Client (a1b2c3d4e5f6)", ServiceState Running, ServiceStartMode Auto, ServiceAccount LocalSystem, ServiceImagePath C:\Program Files (x86)\ScreenConnect Client (a1b2c3d4e5f6)\ScreenConnect.ClientService.exe, InstallDir matching, UninstallRegistryKey HKLM:\SOFTWARE\WOW6432Node\..., UninstallDisplayName, UninstallString MsiExec.exe /X{...}, QuietUninstallString + /qn, DisplayVersion 23.5.1, Publisher ConnectWise, InstallDate 20230115
* Purpose: synthetic valid plan.json that remove-screenconnect.ps1 can consume with -PlanJson, bypassing detection/requires no live ScreenConnect install; used for dry-run/test of Stage 4 in isolation

---

## 3. Per-Component Verdict Table

| Component | Verdict | Justification |
|-----------|---------|---------------|
| sc-cleanup.ps1 (orchestrator overall) | REFACTOR | Control flow and safety gates are correct; must be decomposed into Scc.Core run + state machine + Invoke-Stage framework rather than monolith. |
| sc-cleanup.ps1 Stage 0 Preflight (hive export+restore point) | MERGE | Logic mostly correct but overlaps preflight.ps1; merge into Core preflight with canonical hive list and restore-point check. |
| sc-cleanup.ps1 Stage 1 Snapshot Before | RETAIN | Correct: child-process isolated, IncidentWindowDays wiring and OutFile handling are sound. Port as Scc.Evidence thin wrapper. |
| sc-cleanup.ps1 Stage 2 Detect | RETAIN | Correct: OutRoot isolation, recursive findings.json discovery, NoPause/NoZip flags. Port as Detection entry point. |
| sc-cleanup.ps1 Stage 3 Review Gate | REWRITE | Console Read-Host per-instance + typed confirmation is the safety core but must become WPF Findings view with KEEP-default binding; current inline loop not reusable in GUI. |
| sc-cleanup.ps1 Stage 4 Contain+Remove | REFACTOR | Fail-closed RestorePointFailed gate and Execute/ dry-run distinction are essential; execution must move into Scc.Remedy with explicit -Execute switch and plan re-verification. |
| sc-cleanup.ps1 Stage 5 Scanners | REFACTOR | Adapter contract and timeout/NotInstalled handling are solid; must be migrated to Scc.Scanners registry, run sequentially, with correct log dirs under run dir. |
| sc-cleanup.ps1 Stage 6 Procmon | REMOVE | Stub with no implementation; no portable logic to keep. Replace later with optional Evidence capture if needed. |
| sc-cleanup.ps1 Stage 7 Snapshot After+Diff | RETAIN | Diff exit-code handling (0 clean, 1 resurrection, 2 failure) and manifest-correlated resurrection check are valuable and must be preserved. |
| sc-cleanup.ps1 Stage 8 Report | RETAIN | Child-process report generation + results.json synthesis with null-safe skipped-stage access is correct; port as Scc.Report wrapper. |
| sc-cleanup.ps1 helpers Get-JsonItems / Get-PropertyValue | RETAIN | Correct StrictMode-safe JSON access with comma-protected empty array; needed for plan.json + findings.json handling in Remedy. |
| sc-cleanup.ps1 helper Invoke-ChildScript | RETAIN | Scope-bleed isolation and async stderr drain deadlock fix are essential for any child-script hosting in Core. |
| sc-cleanup.ps1 helpers Test-IsAdmin/Test-UacEnabled/Test-IsServerOS/Resolve-WorkingDir/Prompt-IfMissing | MERGE | Merge into Scc.Core Get-SccComputerInfo / Get-SccPaths / credential prompting utilities. |
| preflight.ps1 (standalone file) | MERGE | Functionally duplicates Stage 0; merge surviving improvements (MinFreeGB param, SystemRestore enable probe, ascii master.log, JSON handoff) into Core then remove file. |
| START-HERE.bat | REPLACE | 9-step guided CLI is superseded by WPF Workflow view; preserve step order/prompt semantics as Workflow state machine, replace with Start-ScreenConnectCleaner.bat + headless. |
| Run-DetectRemoteAccess.bat | REPLACE | Simple elevation+forward; replace with Start-ScreenConnectCleaner.bat CLI/headless entry and in-app Detection-Only action. |
| RUN-REMOVAL-TEST.bat | REPLACE | Lab-only typed YES + -ExecuteRemoval launcher; replace with headless -Execute flag plus explicit GUI confirmation, keep lab behavior as test mode in Remedy. |
| make-deploy-bundle.sh | REFACTOR | Zip + stage logic is sound; port to Build-Portable.ps1 with correct catalog and provenance hashing, keep bash version only as dev helper. |
| DEPLOY.md | REWRITE | Copy/what-not-to-copy, verification steps and flag docs are essential but must become USER-GUIDE.md + TESTING.md aligned to new paths (ProgramData/LocalAppData/Reports). |
| test_plan.json | RETAIN | Synthetic plan fixture is valuable for unit/integration tests; move to tests/fixtures/plan.json and expand with edge cases (empty, partial, bad signature). |

---

## 4. Notable Logic Worth Preserving Exactly

### 4.1 Control Flow Order

* Strict 0->1->2->3->4->5->6->7->8 order enforced in sc-cleanup.ps1 linear execution; no stage reordering, no parallel stages. Scc.UI state machine must enforce same order (ARCHITECTURE sec 4: 1 always before 2..8; 4 requires 3 Completed; 7 requires 6; skippable only 4 and 5).
* Snapshot Before (Stage 1) is labeled never skippable (sc-cleanup.ps1:57) - must remain so in new architecture (ARCHITECTURE safety invariant 1). Same for Snapshot After (Stage 7) and Report (Stage 8).
* Detection (Stage 2) before Review Gate (Stage 3) before Remediation (Stage 4) - preserves Detect -> Review -> Remediate -> Verify philosophy.

### 4.2 Safety Gates

* Server OS refusal: Test-IsServerOS checks caption -match (?i)Server (sc-cleanup.ps1:120-128) and throws unless -force (sc-cleanup.ps1:381-383); preflight.ps1 uses tighter (?i)windows\s+server (preflight.ps1:130-133). GUI Core New-SccRun must preserve -ForceServer/config override check (ARCHITECTURE sec 3.1, sec 5).
* UAC check: Test-UacEnabled reads HKLM\...\EnableLUA (sc-cleanup.ps1:109-118, preflight.ps1:91-98), throw/mandatory -force, warning when forced. Must survive as tool provenance/report finding.
* Admin truth in logs: Stage 0 writes Admin check PASSED vs FAILED (not elevated) honestly (sc-cleanup.ps1:405-407); preflight sets PreflightOk false on Windows without admin (preflight.ps1:344-351).
* Review Gate KEEP default (sc-cleanup.ps1:609-620, START-HERE.bat step 5): empty/whitespace answer -> 'N' -> KEEP; only explicit 'Y'/'y' maps to REMOVE; [y/N] prompt reflects default. GUI must keep KEEP default per-item and per-plan.
* Typed confirmation for destructive path (sc-cleanup.ps1:628-646): second prompt "Proceed with removal? [y/N]" after listing count, waived only under -ExecuteRemoval, still honors -sr. Also lab guard: RUN-REMOVAL-TEST.bat requires typed YES (83:55) before -ExecuteRemoval pipeline.
* Owner policy binding: only ScreenConnectInstances serialized as removal surface (sc-cleanup.ps1:654, sc-cleanup.ps1:663); other targets detect-only. Remedy must enforce per-item re-verification that only ScreenConnect may be REMOVE.
* No automatic deletes: "Files are quarantined, never deleted" (sc-cleanup.ps1:636, START-HERE.bat:115-116, RUN-REMOVAL-TEST.bat:48); Tikun is the only step that deletes (START-HERE.bat:208-209) and is opt-in default N.
* Fail-closed on restore point (sc-cleanup.ps1:692-696): if RemovalConfirmed and RestorePointFailed and not -np, Stage 4 returns blocked result ExitCode 2, does not throw, so Stages 7-8 still produce evidence/report and pipeline exits 1.

### 4.3 Dry-Run Behavior

* `-WhatIf` handled inside Invoke-Stage (sc-cleanup.ps1:274-276): returns @{WhatIf=$true} without calling $StageBlock; individual adapters also respect WhatIf (START-HERE.bat 6a Defender -WhatIf; sc-cleanup.ps1 Stage 4 dry-run when not confirmed).
* Stage 4 dry-run default: without RemovalConfirmed and without -sr, Stage 4 still calls remove-screenconnect.ps1 WITHOUT -Execute (sc-cleanup.ps1:698-701, sc-cleanup.ps1:680-711); this matches ARCHITECTURE D-ARCH-9 and safety.philosophy dryRunDefault true.
* `Test-SccPlan` equivalent: sc-cleanup.ps1 Stage 3 testability not yet - GUI needs Test-SccPlan -Run -Plan preview before Execute.
* Wait semantics: WhatIf-aware scanner adapters parse log never stdout; scan failure never fatal.

### 4.4 Skip Flags and Timeouts

* `-sr` (skip removal): Stage 4 Invoke-Stage SkipFlag=sr (sc-cleanup.ps1:60, 673), early return Skipped=true, also suppresses -Execute forwarding and triggers Stage 3 log "-sr set: removal decisions recorded but removal disabled" (sc-cleanup.ps1:647-648).
* `-sa` (skip scanners): Stage 5 SkipFlag=sa (sc-cleanup.ps1:61, 717), logs SKIPPED via -sa; RUN-REMOVAL-TEST.bat prompts default Y to set AVFLAG=-sa (83:63-66).
* `-procmon` opt-in: Stage 6 SkipFlag=procmon, but inverted logic: Invoke-Stage skips when flag true?? Actually PipelineStages entry SkipFlag=procmon combined with Invoke-Stage generic skip via Get-Variable means -procmon ISSKIP? But StageBlock itself checks if (-not $procmon) return Skipped (sc-cleanup.ps1:770-773). Preserve opt-in intent, but migrate to explicit Scanner/Tools opt-in rather than inverted skip flag.
* `-np` / `-SkipRestore`: suppresses restore point + hive export (sc-cleanup.ps1:426-441, preflight.ps1:423-427), logs SKIPPED, sets RestorePointSkipped=true in handoff.
* `-offline`: suppresses Get-ToolPack download and Get-AVTools staging, forces -Verify path (sc-cleanup.ps1:472-504, preflight.ps1 ToolPack -Verify).
* `-force` / `-Force`: overrides Server-OS refusal and UAC-disabled refusal (sc-cleanup.ps1:381-392, preflight.ps1:358-375).
* Timeouts: Stage 5 scanner adapters called with -TimeoutMinutes 120 (sc-cleanup.ps1:750); GUI-only scanners have 4-hour cap (DEPLOY.md:63); NAS timeout 15s (scc-config.json nas.timeoutSeconds); download timeout 300s (scc-config.json download.timeoutSeconds).

### 4.5 Output Paths Used

* Default OutRoot C:\RIT-SCC (sc-cleanup.ps1:331), WorkingRoot same in preflight (preflight.ps1:36); Working dir pattern C:\RIT-SCC\<HOST>-<timestamp> with timestamp yyyyMMdd_HHmmss UTC in sc-cleanup (sc-cleanup.ps1:142) and local time in preflight (preflight.ps1:335). GUI must map to ARCHITECTURE sec 5: AppBinDir, ProgramDataDir (%ProgramData%\ScreenConnectCleaner), UserDataDir (%LocalAppData%\ScreenConnectCleaner), TempDir (%TEMP%\ScreenConnectCleaner\<runid>), ReportRoot (%USERPROFILE%\Documents\ScreenConnect Cleanup\Reports), QuarantineRoot (%ProgramData%\ScreenConnectCleaner\Quarantine\<runid>), ToolCacheDir (%LocalAppData%\ScreenConnectCleaner\tools) and run dir SC-yyyyMMdd-<HOST>-<hhmmss> (ARCHITECTURE sec 3.1, sec 6).
* Files inside run dir (sc-cleanup.ps1 outputs):
  - master.log (sc-cleanup.ps1:349)
  - registry_hives\*.reg (sc-cleanup.ps1:444-452) vs registry\*.hiv in preflight (preflight.ps1:225-232) - see Bugs for mismatch
  - snapshot_before.json (sc-cleanup.ps1:529), snapshot_after.json (sc-cleanup.ps1:795), snapshot_diff.json (sc-cleanup.ps1:812)
  - detect\<timestamped>\findings.json discovered recursively (sc-cleanup.ps1:554-570) plus legacy START-HERE locations %USERPROFILE%\Desktop\RemoteAccessScan\... (START-HERE.bat:100-109) and %~dp0\snapshot_*.json flat copies (START-HERE.bat:78-83, 232-252)
  - plan.json (sc-cleanup.ps1:581), removal-manifest.json (sc-cleanup.ps1:710), scanner_results.json (sc-cleanup.ps1:759), logs\<SubDir>\ per-scanner logs under logs\ (sc-cleanup.ps1:725-748), report.html and results.json (sc-cleanup.ps1:899-945), tool-provenance.json (implied by Scc.Tools contract, not yet in legacy pipeline)
* Deploy bundle output: parent dir screenconnect-cleanup-deploy.zip (make-deploy-bundle.sh:13), staged path $STAGE/screenconnect-cleanup/ (make-deploy-bundle.sh:16)

---

## 5. Duplicated Code, Dead Code, Obsolete Artifacts, Temp/Test Junk, Leftover Debugging

### 5.1 Duplicated Code

* preflight.ps1 vs sc-cleanup.ps1 Stage 0: Test-IsAdmin, Test-UacEnabled, Test-IsServerOS, Get-FreeSpaceGB/Get-AvailableDiskSpace, Resolve-WorkingDir/Get-HostNameSafe, master log creation, restore point + hive export, tool-pack verification, tech/client prompts are implemented in both files with slightly different signatures, thresholds, hive lists, and directory layouts (sc-cleanup.ps1:70-167 vs preflight.ps1:60-289; sc-cleanup.ps1:402-518 vs preflight.ps1:331-461). This is the largest duplication; fix via single Scc.Core implementation.
* Hive export logic duplicated but diverged: sc-cleanup.ps1 uses reg.exe export to .reg for HKLM\SOFTWARE, HKLM\SYSTEM, HKCU\SOFTWARE (sc-cleanup.ps1:448-452); preflight.ps1 uses reg.exe save to .hiv for HKLM\SOFTWARE, HKLM\SYSTEM, HKCU (preflight.ps1:225-229). See bug 6.1 for format/path divergence.
* Tool pack vs AV pack staging logic repeated across START-HERE.bat Step 1 (START-HERE.bat:46-61) and sc-cleanup.ps1 Stage 0 (sc-cleanup.ps1:464-507): same two powershell invocations with slightly different arg sets.
* START-HERE.bat self-elevate boilerplate appears three times (START-HERE.bat:14-31, Run-DetectRemoteAccess.bat:16-32, RUN-REMOVAL-TEST.bat:19-36) with SCC_SELF vs SCC_SELF+SCC_ARGS variation - consolidate into single batch helper or PowerShell launcher.
* Console logging helpers Write-StageLog/Write-Stage/Write-Section/Write-StageWarn/Write-StageFail share prefix/timestamp concepts but are not reused across scripts (sc-cleanup.ps1:70-97, preflight.ps1:60-75, detect-remote-access.ps1 Write-Log/Write-Section).

### 5.2 Dead Code

* `safemode` parameter (sc-cleanup.ps1:31) and its handler (sc-cleanup.ps1:394-397): warns not implemented, TODO bcdedit /set {current} safeboot network comment, never acts. The `-resume` param (sc-cleanup.ps1:32) is documented as RunOnce internal but no RunOnce registration code exists.
* Stage 6 Procmon (sc-cleanup.ps1:769-784): entirely stub, only logs "NOT IMPLEMENTED" and returns Skipped. No procmon binary handling, no filter, no capture.
* preflight.ps1 placeholder StringDictionary creation (preflight.ps1:109-112): allocates a StringDictionary then discards it, comment says placeholder / WMI-free approach below; dead code.
* make-deploy-bundle.sh README/docs fallback guards (make-deploy-bundle.sh:26,28) for missing README.md/docs/ are correct but docs/ is always expected per DEPLOY.md.

### 5.3 Obsolete / Diverged Artifacts

* preflight.ps1 standalone relevance: sc-cleanup.ps1 now owns preflight as Stage 0 and is the only orchestrator invoked by RUN-REMOVAL-TEST.bat headless path; preflight.ps1 survives only because START-HERE.bat Step 2 calls it (START-HERE.bat:69). Once GUI replaces START-HERE, preflight.ps1 has no call site.
* Flat file locations in START-HERE.bat (%~dp0snapshot_before.json, %~dp0snapshot_after.json, %~dp0snapshot_diff.json, %~dp0report.html) (START-HERE.bat:78-83, 232-252, 266) vs run-dir locations under C:\RIT-SCC\<run>\* (sc-cleanup.ps1). Running both launchers on same box yields two different output trees.
* DEPLOY.md Step 6 example still says "-sr skips removal (Stage 4 is a stub anyway)" (DEPLOY.md:85) - stale comment from before Stage 4 became real (now Stage 4 calls remove-screenconnect.ps1).
* test_plan.json SourceFindings path C:\RIT-SCC\TESTHOST_...\detect\findings.json (test_plan.json:7) is synthetic and not a real run dir, fine for fixture but must not be assumed reachable.

### 5.4 Temp/Test Junk

* test_plan.json itself is test junk by audit definition (it lives at repo root as a synthetic fixture, not under tests/). It is valuable and worth preserving, but move to tests/fixtures/ or config/test-data/.
* START-HERE.bat flat copies of snapshot_before/after/diff/report in %~dp0 are temp artifacts that pollute the tool dir when run from portable folder; GUI report root should be the only durable location.
* No leftover debugging prints remain (no Write-Debug dumps, no commented Set-PSDebug). MasterLog verbose gating is production-intentional.

---

## 6. Bugs and Limitations Spotted

### 6.1 Bugs

| File:Line | Issue |
|-----------|-------|
| sc-cleanup.ps1:434 | `$regOutput = & reg.exe export $hive $exportPath /y 2>&1` captures stdout but not the Out-Null fix documented in preflight.ps1:232-237. If reg.exe prints success text, $regOutput contains it, but the success path is correctly gated on $LASTEXITCODE, so not a truthiness bug here. Preflight has the bug fixed; sc-cleanup does not need Out-Null because it does not use return-value truthiness for hive export. |
| sc-cleanup.ps1:452-462 vs preflight.ps1:225-232 | Hive export divergence: sc-cleanup exports HKLM\SOFTWARE / HKLM\SYSTEM / HKCU\SOFTWARE to .reg via reg export; preflight saves HKLM\SOFTWARE / HKLM\SYSTEM / HKCU to .hiv via reg save. The sets differ (HKCU vs HKCU\SOFTWARE) and formats differ (.reg vs .hiv). One of them is wrong per the SAM/SECURITY exclusion rationale documented in preflight.ps1:208-219. Migrate must pick one canonical list (AUDIT-02 also notes SAM/SECURITY exclusion) and single format. |
| sc-cleanup.ps1:60-63 PipelineStages SkipFlag vs Invoke-Stage | Stage 6 entry has SkipFlag='procmon' (sc-cleanup.ps1:63) and Invoke-Stage skips when the flag variable is true (sc-cleanup.ps1:255-263). Since procmon default is unset (false), Stage 6 is NOT skipped by the wrapper; the StageBlock itself does `if (-not $procmon) return Skipped` (sc-cleanup.ps1:770). The wrapper skip is inverted: passing -procmon causes the wrapper to SKIP the stage before it can run, opposite of intent. In practice Stage 6 is dead (stub) so harm is none, but the declared SkipFlag is incorrect. |
| sc-cleanup.ps1:78-81 | `if ($MasterLogPath -and (Test-Path $MasterLogPath) -and ($VerboseLog -or $Level -ne 'Debug'))` checks global $VerboseLog variable inside helper; if helper is extracted to a module, $VerboseLog must be passed or become a param, otherwise Debug gating is silently lost. |
| sc-cleanup.ps1:132-138 vs preflight.ps1:135-144 | DriveInfo construction differs: sc-cleanup uses `[System.IO.DriveInfo]::new($Path)` (PS5.1 ok) but preflight uses `New-Object System.IO.DriveInfo($DriveRoot)` with slash fix for non-Windows. On Windows, passing C:\RIT-SCC (a subdirectory) to DriveInfo returns drive letter correctly, but only because DriveInfo parses root; the threshold comparison (freeGb < 5 vs MinFreeGB 10) is inconsistent - sc-cleanup WARNs at <5, preflight FAILs at <10. Same machine could pass orchestrator preflight but fail standalone preflight. |
| sc-cleanup.ps1:342-346 | `New-Item -ItemType Directory -Path $WorkDir -Force` is not try/catched, while preflight wraps it (preflight.ps1:401-405). A permission/parent missing error throws unhandled before master.log exists, losing diagnostics. |
| sc-cleanup.ps1:553-569 | `$detectOutRoot = Join-Path $WorkDir 'detect'` then `Get-ChildItem -Recurse findings.json` is correct but START-HERE.bat detection writes to %USERPROFILE%\Desktop\RemoteAccessScan\* (START-HERE.bat:100-109) and New-InvestigationReport in START-HERE is pointed at that path, not $WorkDir\detect. Artifacts from guided runs are invisible to Stage 8 which reads from $stage2Result.FindingsJson. |
| sc-cleanup.ps1:584-591 | Comment warns not to wrap `Get-JsonItems` in outer `@()` because comma-protected empty array would become 1-element phantom array. Correct preservation of fix, but the same pattern is used correctly elsewhere (sc-cleanup.ps1:857-869) - migrate must keep this pattern and document as safety invariant. |
| preflight.ps1:146-183 Invoke-RestorePoint | Probe logic checks `$srStatus` (SystemRestore CIM) and `$regValue` (RPSessionInterval) for enablement, but $srEnabled is set true unconditionally on line 182 after the null check, making the probe advisory not enforcing except when both are null (line 175). On machines with SystemRestore disabled but registry key present, probe passes incorrectly. |
| preflight.ps1:230-247 | `& reg.exe save ... 2>$null | Out-Null` suppresses both stdout and stderr, but the comment says success text pollutes return value; the fix is correct. However errors via stderr are also suppressed to $null, so only $LASTEXITCODE survives; the warning message lacks the reg.exe error detail. |
| preflight.ps1:448-455 | Fallback to forward-slash tool path `$alt` for non-Windows dev boxes (preflight.ps1:452-454) is only checked on ToolPackPath, not on Get-AVTools staging (which is absent in preflight entirely - preflight never stages AV tools, while sc-cleanup does). AV staging gap between launchers. |
| START-HERE.bat:48-60 | Step 1 runs Get-ToolPack.ps1 twice (normal + -Verify) sequentially with no errorlevel branching; second run could fail after first succeeded, but script continues regardless. No summary errorlevel check. |
| START-HERE.bat:98-104 | `for /f "delims=" %%D in ('dir /b /ad /o-d ...')` newest-first enumeration breaks on paths with leading spaces or special chars due to bat quoting; robust version would use dir /b /ad /o-d with usebackq. |
| START-HERE.bat:214-224 | Tikun/GeneralFix step 7 pattern `for %%S in ("%~dp0tools\GeneralFix\*.bat") do if not defined GFIX_SCRIPT set "GFIX_SCRIPT=%%~fS"` picks arbitrary first bat by filesystem order, not deterministic; no listing or selection if multiple .bat files exist. |
| RUN-REMOVAL-TEST.bat:71 | Runs `.\sc-cleanup.ps1` via relative path after cd /d "%~dp0" - correct, but sc-cleanup.ps1 default ToolDir is <ScriptRoot>\tools which then equals RUN-REMOVAL-TEST's dir; if portable folder is launched from a UNC share, %~dp0 is UNC path, free space check via DriveInfo fails (returns -1) but is warned not fatal. |
| make-deploy-bundle.sh:19-25 | Core copy loop `for f in ...; do cp "$SRC/$f" "$D/"` uses `set -e`, so missing file aborts zip with cryptic cp error, not a clear "missing required file X" message. The optional loop for tools has explicit warning, but core loop does not. |
| DEPLOY.md:98-109 | Flag table omits -force, -safemode, -ExecuteRemoval, -VerboseLog, -OutRoot, -ToolDir, -TechName, -ClientName, -resume. Technician reading only DEPLOY.md will not discover -force needed on Server OS. |

### 6.2 Limitations

* No resume implementation despite -resume flag (sc-cleanup.ps1:32, 363-366): flag only suppresses prompts, no runstate.json, no RunOnce, no re-entry at failed stage. ARCHITECTURE sec 4 resume via runstate.json is still greenfield.
* No cooperative cancellation: stages run synchronously in foreground; Invoke-ChildScript WaitForExit has no timeout param, so a hung scanner/collector blocks pipeline indefinitely (only scanner adapters have 120m timeout internally, not the orchestrator).
* Logging is flat text + jsonl append; no structured level filtering exposed to UI (ARCHITECTURE requires Write-SccLog -Level threshold from config).
* Snapshot IncidentWindowDays is computed from IncidentDate to now as total days rounded (sc-cleanup.ps1:530-533), but collect-snapshot.ps1 semantics for 0 vs 7 vs 30 days are not documented; passing 0 when IncidentDate=today yields unfiltered recent-files section, may be noisy.
* Quarantine: RUN-REMOVAL-TEST.bat preview promises quarantine never delete, but quarantine path in legacy is C:\RIT-SCC\<run>\quarantine\ vs GUI QuarantineRoot %ProgramData%\...\<runid>\q\ (ARCHITECTURE sec 5) - migration must preserve never-delete and move manifest but change root.
* ToolManager not present: legacy Get-ToolPack / Get-AVTools are external scripts with no provenance, hash, signature or NAS-first logic; sc-cleanup validates exit code only, not hash/signature/version or provenance record (ARCHITECTURE sec 3.5 requires provenance for every tool).
* Report inputs limited: sc-cleanup Stage 8 reads only findingsJson + optional removalManifest, not scanner_results.json, diff, snapshots, tool provenance, runstate; GUI report must aggregate all (ARCHITECTURE sec 3.8).
* START-HERE.bat scan steps 6b-6d launch GUI scanners via `start ""` then `pause` (START-HERE.bat:158-203) - no process tracking, no timeout, no log path, no return code. Technician may pause forever or abort scan without record.

---

## 7. Mapping Suggestion: Old Component -> New Module

Target architecture modules per ARCHITECTURE.md: Core, Detection, Evidence, Snapshots, Remediation, Scanners, Reporting, ToolManagement, Configuration, Logging, UI.

| Old Component | New Module | Notes |
|---------------|------------|-------|
| sc-cleanup.ps1 param block + constants + $PipelineStages + init (hostname/banner/OutRoot/WorkDir/master.log/ToolDir/tech+client/incident/preflight gates) | Core (Scc.Core) | New-SccRun, Get-SccPaths, Get-SccComputerInfo, Get-SccConfig, Set-SccConfigValue, Resolve-SccEnv; map OutRoot/ToolDir/WorkingRoot to ARCHITECTURE sec 5 paths (ReportRoot/ToolCacheDir/ProgramDataDir/UserDataDir/TempDir); unified -ForceServer/config safety.serverOsRefusal handling. |
| sc-cleanup.ps1 Write-StageLog + Write-Section | Logging (Core/Logging) | Write-SccLog with Level TRACE..CRITICAL, JSONL + master.log, -Stage -Component -Operation fields, threshold from config.logging.level. Keep timestamp and prefix semantics. |
| sc-cleanup.ps1 Get-JsonItems / Get-PropertyValue | Core (Scc.Core utilities) | ConvertTo-SccJson / ConvertFrom-SccJson / safe access helpers; retain unary comma empty-array fix and ordered-hashtable handling, cover plan.json + findings.json. |
| sc-cleanup.ps1 Invoke-ChildScript + Invoke-Stage | Core (Scc.Core) | Invoke-SccSafe + background runspace pool (Scc.UI Start-SccJob); keep pwsh->powershell.exe fallback, quoting for [\s"&|<>], async stderr drain deadlock fix, per-stage entry/exit/duration/failure logging and runstate update. |
| sc-cleanup.ps1 Stage 0 (Preflight block including RestorePointFailed flag, hive export, tool-pack verify, AV staging) | Core + ToolManagement + Evidence | Preflight checks -> Core; reg export -> Evidence.New-SccSnapshot or Core quirk (registry backup) but use preflight.ps1 hive list (HKLM\SOFTWARE+SYSTEM+HKCU .hiv) as canonical; tool-pack verify -> ToolManagement Resolve-SccTool / Test-SccToolIntegrity; AV staging -> ToolManagement Get-SccToolCatalog acquisition for AV tools. Preserve RestorePointFailed -> fail-closed gate. |
| sc-cleanup.ps1 Stage 1 Snapshot (Before) | Evidence (Scc.Evidence) | New-SccSnapshot -Run -Label before -IncidentWindowDays; keep -Quiet forwarding, ExitCode handling, path under runDir/snapshots/before.json. |
| sc-cleanup.ps1 Stage 2 Detect | Detection (Scc.Detection) | Invoke-SccDetection -Run; map -OutRoot isolation to RunDir/evidence, keep NoPause/NoZip equivalent (no transcript/zip), keep recursive findings.json discovery adapted to runDir. |
| sc-cleanup.ps1 Stage 3 Review Gate (per-instance prompt, KEEP default, typed confirmation, plan.json) | Remediation + UI + Configuration | New-SccPlan -Run -Findings -Decisions in Scc.Remedy (KEEP default enforced, only ScreenConnect removable, per-item re-verification), Decisions provided by UI Findings view (checkbox KEEP/REMOVE), plan.json schema stays (GeneratedUtc/TechName/ClientName/IncidentDate/Decision/SourceFindings/RemovalConfirmed/ScreenConnectInstances); add FindingId->Action map. |
| sc-cleanup.ps1 Stage 4 Contain+Remove | Remediation (Scc.Remedy) | Invoke-SccRemediation -Run -Plan [-Execute]; keep dry-run default, -Execute gate, vendor uninstaller first, quarantine never delete, remediation.json + quarantine-manifest.json, preserve RestorePointFailed fail-closed (ExitCode 2) without aborting later stages, propagate incomplete pipeline exit 1. |
| sc-cleanup.ps1 Stage 5 Scanners (Defender/KVRT/ESET adapters, logs, scanner_results.json) | Scanners (Scc.Scanners) | Invoke-SccScanner + Get-SccScannerList registry config; keep sequential execution, -TimeoutMinutes 120 (from scc-config.json scanners.defaultTimeoutMinutes), -LogDir under runDir/scanner-results/, LogDir per-scanner subdirs, NotInstalled/Timeout/Failed/Skipped contract, pass VerboseLog as logging level. |
| sc-cleanup.ps1 Stage 6 Procmon | Evidence or ToolManagement (remove) | Remove stub; if procmon is needed later, implement as optional Evidence collector via ToolManagement procmon acquisition and bounded capture, not as dedicated stage. |
| sc-cleanup.ps1 Stage 7 Snapshot After+Diff + resurrection correlate | Snapshots (Scc.Snapshots) + Evidence | Compare-SccSnapshots + Test-SccResurrection; keep diff exit-code contract (0 clean, 1 resurrection, 2 failure) and manifest-correlated stable Added check; move inline fallback diff into Compare-SccSnapshots when diff script absent; write diff.json under snapshots/diff.json. |
| sc-cleanup.ps1 Stage 8 Report (New-InvestigationReport + results.json) | Reporting (Scc.Report) | New-SccReport; keep report.html + results.json + add technician-summary.txt + report.json; expand inputs to findings.json+plan.json+remediation.json+snapshots+diff+scanner results+tool provenance+runstate; preserve HTML-escaping (ConvertTo-SccHtml). |
| sc-cleanup.ps1 pipeline-complete exit propagation | Core + UI | Save-SccRunState stage map update per stage; final outcome SUCCESS vs INCOMPLETE (Stage 4 exit) -> Scc.UI headless exit code 1 vs 0 and Dashboard status. |
| preflight.ps1 standalone | Core | Merge improvements into New-SccRun preflight: MinFreeGB param, ascii master.log, SystemRestore enable probe, HKCU .hiv format rationale, SelfTest as Pester unit, JSON one-line handoff becomes Get-SccRunState. No standalone file after merge. |
| START-HERE.bat steps 1-9 (self-elevate, 9 prompts, toolpack/before/detect/review/KVRT/ESET/MB/Tikun/after+diff/report, FINDINGS_JSON discovery, Tikun GeneralFix call) | UI (Scc.UI) + Core + ToolManagement + Scanners + Remediation + Evidence + Snapshots + Reporting | Self-elevate -> Start-ScreenConnectCleaner.bat (CRLF, pure ASCII, SCC_SELF env elevated runas pattern retained); step order becomes Workflow view state machine (Preflight->SnapshotBefore->Detection->Review->Remediate->Scanners->SnapshotAfter->Compare->Report); per-scanner prompts become Scanners view; Tikun step renamed to attended GeneralFix note with explicit destructive warning, never auto; FINDINGS_JSON discovery becomes Detection findings.json under runDir; flat %~dp0 snapshot/report copies become runDir/Reports copies only. |
| Run-DetectRemoteAccess.bat | UI + Detection | Replace with Detection-Only workflow action (Scc.UI Dashboard: Detection Only) and headless Scc.Cleaner.ps1 -Headless -DetectionOnly; keep elevation via Start-ScreenConnectCleaner.bat and args forwarding pattern. |
| RUN-REMOVAL-TEST.bat (YES gate, -ExecuteRemoval, -sa toggle, footer paths) | UI + Remediation + Configuration | Replace with headless/test-mode: Start-ScreenConnectCleaner.bat -Headless -ExecuteRemoval equivalent gated by explicit -Force lab confirmation; map typed YES -> double-confirmation in UI (confirmDestructive), AVFLAG -> scanners.enabled config skip; preserve quarantine/manifest/diff/report footer paths via Get-SccPaths. |
| make-deploy-bundle.sh (core copy loop, optional tools warning, zip build, listing) | Configuration + ToolManagement | Port to build/Build-Portable.ps1 (primary) with manifest/hash validation and provenance; keep make-deploy-bundle.sh as Linux dev helper but update core list to include Start-ScreenConnectCleaner.bat, Scc.Core etc and fix core missing-file error message; output stays ../screenconnect-cleanup-deploy.zip with same structure. |
| DEPLOY.md (copy list, first-run steps, flags, validation checklist, house rules) | Configuration + Reporting + Logging | Split into docs/USER-GUIDE.md (deploy + first-run), docs/TESTING.md (live validation matrix from DEPLOY sec 4), README house rules (verifying by running, ASCII, PS 5.1 compat); expand flags table to include all params (-force/-safemode/-ExecuteRemoval/-VerboseLog/-OutRoot/-ToolDir/-resume) with new-path equivalents; update not-copy list from sysinternals NAS-first catalog. |
| test_plan.json | Remediation + Tests | Move to tests/fixtures/plan.json or src/Scc.Remedy/tests/fixtures; keep synthetic InstanceId/InstallDir/UninstallString/QuietUninstallString shape as valid plan; expand with fixtures for KEEP_ALL, PARTIAL_REMOVE, unknown product, missing UninstallString; used by Pester unit for New-SccPlan/Test-SccPlan and integration headless dry-run. |
| targets.json (not audited here but referenced) + trusted-relays.json | Configuration (Scc.Core) | Already migrated to gui-revision-screenconnect-cleaner/config/targets.json + trusted-relays.json with embedded defaults; sc-cleanup Stage 2 -Target filtering maps to detection.defaultTargets in scc-config.json. |
| collect-snapshot.ps1 / diff-snapshots.ps1 / detect-remote-access.ps1 / remove-screenconnect.ps1 / New-InvestigationReport.ps1 / scanners/*.ps1 / Invoke-ReviewAndRemove.ps1 / Invoke-GUIScanner.ps1 (referenced but not in this audit) | Evidence / Snapshots / Detection / Remediation / Reporting / Scanners / UI | Out-of-scope here except via call sites; invocation contracts preserved above (ArgLists with -Label/-OutFile/-IncidentWindowDays etc) must be honored by new modules or replaced with direct function calls. |

---

## 8. Migration Risks and Checklist

* Verify -force semantics are identical on Server and UAC-disabled paths between sc-cleanup and New-SccRun before removing preflight.ps1.
* Confirm registry hive export canonical set: choose either HKCU\SOFTWARE .reg (sc-cleanup) or HKCU .hiv (preflight) - do not carry both.
* Fix Procmon SkipFlag inversion before porting; model opt-in scanners as explicit config, not skip-flag.
* Ensure Get-JsonItems comma-protected array pattern is copied verbatim into Scc.Core and covered by Pester, else empty plan findings become phantom 1-element arrays.
* Test Invoke-ChildScript on Windows PowerShell 5.1 with real collect-snapshot and detect-remote-access; confirm pwsh vs powershell.exe fallback and arg quoting for paths with spaces/apostrophes.
* Decide output path migration: if flat START-HERE outputs are kept for back-compat, add a migration/shim that still writes them but marks deprecated; otherwise document breaking change in MIGRATION.md.
* DriveInfo free-space threshold: align sc-cleanup 5GB warn vs preflight 10GB fail vs GUI config.evidence/retention policy.

---

DONE

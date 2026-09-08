# AUDIT-03: Removal Engine and Review Runner Inventory

Audit date: 2026-08-26.
Scope: remove-screenconnect.ps1, Invoke-ReviewAndRemove.ps1, AUDIT-REMOVE.md.
Purpose: migration safety net for the GUI rebuild. Every capability, safety
mechanism, and bug is recorded here. Nothing in this audit modifies any file.

---

## 1. Scope Inventory

| File | Lines | Purpose |
|------|-------|---------|
| remove-screenconnect.ps1 | 1709 | Remediation engine. Consumes an approved plan.json, performs ScreenConnect-only containment + removal: stop service, kill processes, run vendor uninstaller, quarantine files, delete service registration, clean persistence (scheduled tasks, Run keys, WMI subscriptions), export+delete orphaned uninstall registry keys. Writes removal-manifest.json and supports reboot-resume via resume-marker.json + RunOnce. Single source of all destructive removal logic. |
| Invoke-ReviewAndRemove.ps1 | 213 | Guided review runner (entry point for START-HERE.bat flow). Loads findings.json, presents each ScreenConnect instance to the technician for per-item KEEP/REMOVE decision, writes plan.json, then delegates to remove-screenconnect.ps1 -Execute. Provides the review gate between detection and remediation without re-running the full 9-stage pipeline. |
| AUDIT-REMOVE.md | 289 | Previous safety audit of remove-screenconnect.ps1. Documents five binding checks, four FIX passescritically FIX 1 (per-entry product verification), FIX 2 (reboot-resume), FIX 3 (per-instance try/catch), FIX 4 (Checkpoint-Computer only in Execute mode). Records all caveats and synthetic test results. |

---

## 2. Full Functionality Inventory

### 2.1 Parameters and Switches

**remove-screenconnect.ps1:**

| Parameter | Type | Default | Purpose |
|-----------|------|---------|---------|
| -PlanFile (alias: -PlanJson) | string, Mandatory | (none) | Path to the approved plan.json from Stage 3 or Invoke-ReviewAndRemove |
| -WorkDir | string | C:\RIT-SCC | Working directory root for quarantine, manifest, master.log, resume-marker |
| -Execute | switch | false | Actually perform removal. Without this, dry-run only. Requires elevated shell. |
| -Resume | switch | false | Resume after reboot. Reads resume-marker.json, skips Completed instances, finishes RebootPending persistence cleanup. Internal, set by RunOnce key. |
| -NoRestorePoint | switch | false | Skip creating a System Restore point (for testing). Restore point creation is now Execute-only (FIX 4). |
| -VerboseLog | switch | false | Verbose logging (declared but not actively used in current code paths). |

**Invoke-ReviewAndRemove.ps1:**

| Parameter | Type | Default | Purpose |
|-----------|------|---------|---------|
| -FindingsJson | string | (auto: newest under ScanRoot) | Path to findings.json to review |
| -WorkDir | string | C:\RIT-SCC\<host>-<stamp> | Where plan.json, quarantine, manifest go |
| -ScanRoot | string | $env:USERPROFILE\Desktop\RemoteAccessScan | Where to look for findings.json when -FindingsJson not given |
| -Yes | switch | false | Unattended: mark every instance REMOVE, skip typed confirmation. LAB USE ONLY. |
| -WhatIfOnly | switch | false | Review and write plan.json, but never call the removal engine |

### 2.2 Exit Codes and Status Paths

**remove-screenconnect.ps1:**

| Exit Code | Meaning |
|-----------|---------|
| 0 | Success (all instances processed, no failures) |
| 1 | One or more actions failed or instances had errors |
| 2 | Admin check failed: -Execute requires elevated shell |

**Invoke-ReviewAndRemove.ps1:**

| Exit Code | Meaning |
|-----------|---------|
| 0 | Ok (including "nothing to do", no findings, or -WhatIfOnly stop) |
| 1 | Removal reported failure, or remove-screenconnect.ps1 not found, or findings.json not found |

**Manifest Result values (remove-screenconnect.ps1 manifest entries):**

| Result | Meaning |
|--------|---------|
| Success | Action completed successfully |
| Failed | Action encountered an error |
| DryRun | Action was logged but not executed (default mode) |
| Skipped | Action not needed (service absent, already stopped, etc.) |
| Deferred | File move scheduled for reboot via MoveFileEx |
| Passed | Product verification succeeded |
| PRODUCT_VERIFICATION_FAILED | Entry was not ScreenConnect; skipped, never uninstalled |
| RebootPending | Instance uninstall succeeded (3010) but needs reboot |
| Accepted | UninstallRegistryKey validated and accepted |
| Rejected | UninstallRegistryKey failed validation |

**Resume statuses (resume-marker.json):**

| Status | Meaning |
|--------|---------|
| Pending | Not yet processed |
| Completed | Successfully finished |
| Failed | Had errors, will be re-attempted on -Resume |
| RebootPending | Uninstaller returned 3010; post-reboot persistence cleanup needed |
| PRODUCT_VERIFICATION_FAILED | Entry failed ScreenConnect identity check |

### 2.3 Remediation Capabilities

#### Service Removal

- **Stop-ServiceSafe** (lines 742-777): Gets service by name via Get-Service. If service not present, records Skipped (not a failure). If running, calls Stop-Service -Force and WaitForStatus('Stopped', 30s). Dry-run logs "[DRY-RUN] Would stop service".
- **Delete-ServiceRegistration** (lines 870-907): Uses sc.exe delete <ServiceName> with stderr redirected to $null (avoids NativeCommandError under $ErrorActionPreference='Stop'). Checks $LASTEXITCODE for 0 = success. Dry-run logs intent.

#### Process Kill

- **Kill-ProcessesForInstance** (lines 779-868): Three-tier process discovery:
  1. Win32_Process where ExecutablePath is under the instance's InstallDir
  2. Win32_Service where Name matches and ProcessId is captured
  3. Win32_Process where Name is like 'ScreenConnect*' or ExecutablePath contains '\ScreenConnect Client\'
  
  **Self-protection** (lines 817-834): Walks the parent chain from $PID up to 12 ancestors. Any PID in that chain is refused (logged as Skipped, never killed). This prevents the tool from killing its own host process.
  
  **Note** (line 844): Loop variable is $procId, not $pid (which is read-only automatic variable). Previous bug: using $pid as loop variable shadowed $PID and no ScreenConnect process was ever killed.

#### Vendor Uninstaller Execution

- **Get-UninstallEntriesForInstance** (lines 706-737): Scans three registry roots (HKLM native, HKLM WOW6432Node, HKCU) for DisplayName matching *ScreenConnect* or *ConnectWise Control*. When InstanceIdentifier is given, further matches against DisplayName or InstallLocation.
- **Get-VerifiedUninstallEntry** (lines 496-575): Validates a plan-supplied UninstallRegistryKey by:
  1. Converting HKEY_ path to Registry:: provider path
  2. Reading the key with Get-ItemProperty
  3. Checking DisplayName contains "ScreenConnect" or "ConnectWise Control"
  4. Cross-checking: at least one value on the key references the verified install directory
  5. Fallback cross-check: DisplayName carries the instance identifier, which also names the install dir (for MSI entries where InstallLocation is empty)
  6. Unreadable/mismatched keys are rejected with a manifest entry

- **Run-VendorUninstaller** (lines 912-1078): 
  - Reads QuietUninstallString first, then UninstallString from registry
  - Detects MSI via ProductCode regex: `/x {GUID}` or `msiexec /x {GUID}`
  - **MSI path**: runs msiexec.exe directly with `/x <ProductCode> /qn /norestart` (flags we control, not registry text)
  - **Non-MSI path**: extracted bare executable must be (a) leaf name matches allowlist (`^(?i)(ScreenConnect|App_)` or `^(?i)unins[0-9]*\.exe$`), AND (b) resides under the verified install directory, AND (c) file exists on disk. Only then is it executed directly with no arguments.
  - **Security**: Never feeds verbatim registry UninstallString to cmd.exe /c. Attacker-influenced strings are never shell-interpreted. Fail-closed: unvalidated strings trigger manual surgery fallback.
  - Uses Run-BoundedProcess (lines 194-270) for concurrent stdout/stderr drain (ReadToEndAsync), 300s timeout, process kill on timeout, zombie reap.
  - Exit code 0 = success, 3010 = success + reboot required (returns hashtable with RebootRequired=$true), anything else = failure.

#### Quarantine (Move-ToQuarantine)

- **Move-ToQuarantine** (lines 1083-1212):
  - Source not found = Skipped (not a failure)
  - **Directory hashing** (lines 1099-1130): When source is a directory, hashes every file inside via Get-ChildItem -File -Recurse -Force -Attributes !ReparsePoint, writes results to quarantine-hashes-<InstanceId>.csv. Records Path, Length, SHA256 per file. Detects and skips reparse points (junctions/symlinks) with manifest entries noting the skip.
  - **File hashing**: Single file = SHA256 via Get-FileHash
  - **Collision safety** (lines 1141-1153): If quarantine destination already exists (resume or shared leaf name), derives unique name from SHA256 hash of full source path (first 8 hex chars).
  - **Move strategy** (lines 1164-1211): Attempts Move-Item -Force first (only honest test for in-use files). On failure, schedules MoveFileEx with MOVEFILE_DELAY_UNTIL_REBOOT. Calls Set-RunOnceResume to register post-reboot continuation.
  - Quarantine path structure: <WorkDir>\quarantine\<InstanceId>\<destName>

#### Scheduled Task Removal

- **Clean-Persistence** (lines 1244-1362), scheduled task section (lines 1250-1286):
  - Enumerates all scheduled tasks via Get-ScheduledTask
  - For each task, iterates Actions and reads Execute and Arguments properties defensively (StrictMode-safe via Get-EntryPropertySafe; COM handler actions without Execute do not throw)
  - Matches if Execute path or Arguments contain the InstallDir
  - Deletes via Unregister-ScheduledTask -Confirm:$false

#### Firewall Rule Removal

- **Not present in remove-screenconnect.ps1.** The AUDIT-REMOVE.md and the original safety audit note that firewall rule detection is not used. The architecture spec (ARCHITECTURE.md section 3.7) lists firewall rule removal as part of Scc.Remedy's manual cleanup, but it was never implemented in the legacy engine.

#### Registry Run Key Cleanup

- **Clean-Persistence**, Run key section (lines 1288-1325):
  - Scans 6 registry locations: HKLM and HKCU Run + RunOnce, plus WOW6432Node Run + RunOnce
  - Reads all values via Get-ItemProperty, skips PS-provider metadata properties
  - Matches if value data contains the InstallDir
  - Deletes via Remove-ItemProperty -Force

#### WMI Subscription Cleanup

- **Clean-Persistence**, WMI section (lines 1327-1355):
  - Enumerates __FilterToConsumerBinding in root\subscription
  - For each binding, reads __EventFilter by Name and CommandLineEventConsumer by Name
  - Matches if consumer CommandLineTemplate contains InstallDir
  - Deletes binding, then filter, then consumer via Remove-CimInstance
  - **Known limitation** (noted in AUDIT-REMOVE.md): WMI filter lookup uses Name='$($b.Filter)' which is a reference string, not a bare name - subscriptions will effectively never match (fails safe, feature silently dead)

#### Orphaned Uninstall Registry Key Removal

- **Manual surgery section** (lines 1527-1574):
  - Only runs when vendor uninstaller failed or was absent AND manual surgery quarantined the install dir
  - Exports the key first via `reg.exe export "<regPath>" "<backup>" /y`
  - Verifies export file landed on disk before proceeding
  - Deletes via `reg.exe delete "<regPath>" /f`
  - If export fails, key is left in place (fail-safe)

### 2.4 Safety Mechanisms

#### Dry-Run Default

- Every mutating operation is gated by `if ($Execute)` blocks
- Dry-run logs "[DRY-RUN] Would ..." for each action and records DryRun result in manifest
- Without -Execute, script never stops services, kills processes, runs uninstallers, moves files, deletes registry entries, or modifies scheduled tasks

#### Plan File Gate

- -PlanFile is Mandatory; script cannot start without it
- Plan must have Decision field set to ALL_REMOVE or PARTIAL_REMOVE
- No detection stage in this script; everything comes from the plan
- No detect-and-remove-in-one-step flag exists

#### Per-Item KEEP/REMOVE (Invoke-ReviewAndRemove.ps1)

- Lines 104-133: Each ScreenConnect instance is presented individually
- Technician types 'y' to mark REMOVE, anything else (including Enter) keeps
- Default is KEEP (N); explicit 'y' required to mark removal
- Two-stage confirmation: per-item decision, then final "Proceed with removal? [y/N]"

#### Scope Filtering: ScreenConnect-Only Removal Policy

- Owner policy binding (header comment): ScreenConnect instances ONLY may be removed
- Plan filtering (lines 298-304): Primary path reads $plan.ScreenConnectInstances; fallback filters by TargetId/Type = 'screenconnect'
- **FIX 1 - Per-entry product verification** (lines 316-494):
  - Test-ScreenConnectInstance function re-verifies EVERY entry before any action
  - Gate A: some candidate path must live under a ScreenConnect directory segment
  - Gate B: binary name must match ServiceScreenConnect.exe or targets.json patterns
  - Gate C: ServiceName (when supplied) must match ScreenConnect service patterns
  - Any failed gate = PRODUCT_VERIFICATION_FAILED, entry skipped, never uninstalled
  - Identity is name-based only, not signature-verified (logged warning)

#### Quarantine-Never-Delete

- No Remove-Item on files/dirs anywhere in the script
- No del/rd/rmdir
- No .NET File.Delete
- All artifacts moved to quarantine directory under WorkDir
- SHA256 and original path recorded per quarantined item
- Directory contents hashed to CSV sidecar (quarantine-hashes-<InstanceId>.csv)

#### Manifest Recording

- Add-ManifestEntry (lines 119-138): Every action records TimestampUtc, InstanceId, Action, Target, Result, Details, ExitCode
- Manifest written to removal-manifest.json at script end
- Fields: Script, Version, GeneratedUtc, ComputerName, PlanFile, WorkDir, QuarantineDir, ExecuteMode, ResumeMode, Entries[]

#### Logging

- Write-Log (lines 95-107): Timestamped, leveled (Info/Warn/Error/Debug), color-coded console output
- All log lines accumulated in $script:LogLines ArrayList
- Write-Section for visual section separators
- Master log written to master.log in WorkDir

#### Admin Gate

- Lines 80-87: -Execute requires elevated shell (Test-IsAdmin checks WindowsPrincipal)
- Non-elevated -Execute fails with exit 2 and diagnostic message
- Prevents partial mutations (service stop denied, reg delete denied) with misleading success exit codes

#### Self-Protection (Process Kill)

- Lines 817-834: Walks parent PID chain from $PID up to 12 ancestors
- Any PID in that chain is refused and logged
- Prevents killing the tool's own host process

#### Uninstaller Security (No Shell)

- Lines 988-1031: Non-MSI uninstallers are executed directly (ProcessStartInfo), never via cmd.exe /c
- Executable must be allowlisted (ScreenConnect/App_/unins*.exe) AND under verified install dir
- Unvalidated strings trigger manual surgery fallback, never shell execution

#### Reboot-Resume

- **FIX 2** (lines 596-691): resume-marker.json tracks per-instance status
- Write-ResumeMarker, Initialize-ResumeMarker, Update-ResumeStatus functions
- Writes only in Execute mode; dry-run never touches the file
- On -Resume: reads marker, collects Completed IDs (skipped) and RebootPending IDs (finish persistence cleanup only)
- Set-RunOnceResume (lines 1214-1239): Writes HKLM RunOnce key to re-invoke script with -Execute -Resume after reboot
- RunOnce command uses absolute resolved paths for PlanFile and WorkDir

#### Per-Instance Error Isolation

- **FIX 3** (lines 1381-1648): Each instance wrapped in try/catch
- Instance ID resolved defensively before try block
- Failure logs error, records ProcessInstance/Failed in manifest, marks resume status Failed, continues to next instance

#### System Restore Point

- **FIX 4** (line 1369 context): Checkpoint-Computer only called when -Execute AND -not -NoRestorePoint AND -not -Resume
- Pre-FIX: was called even in dry-run mode, violating inert dry-run principle
- Note: restore point creation was removed from this script entirely in later revision; preflight.ps1/sc-cleanup.ps1 Stage 0 handles it

#### Uninstall Key Export Before Delete

- Lines 1540-1574: Registry key exported via reg.exe export before deletion
- If export fails, deletion is NOT performed (fail-safe)
- Backup file stored as uninstall-key-<InstanceId>.reg in WorkDir

### 2.5 Helper Functions

| Function | Lines | Purpose |
|----------|-------|---------|
| Test-IsAdmin | 68-74 | Check WindowsPrincipal for Administrator role |
| Write-Log | 95-107 | Timestamped leveled log to console + ArrayList |
| Write-Section | 109-117 | Console section header with separator |
| Add-ManifestEntry | 119-138 | Record action to manifest ArrayList |
| Get-Sha256File | 143-149 | SHA256 hash of file contents |
| Get-Sha256Hex | 151-160 | SHA256 hash of text string |
| Expand-Env | 162-166 | Expand %VAR% environment variables |
| Get-QuarantineDir | 168-175 | Create and return quarantine subdirectory |
| Force-Array | 178-185 | PS 5.1 single-element array unwrapping protection |
| Run-BoundedProcess | 194-270 | Concurrent stdout/stderr drain with timeout, zombie reap |
| Get-ScreenConnectIdentity | 327-360 | Identity pattern set from targets.json or hardcoded defaults |
| Get-EntryPropertySafe | 362-371 | StrictMode-safe property read on plan entries |
| Get-PlanInstanceId | 373-380 | Extract instance ID from plan entry (InstanceId/Identifier/Key) |
| Get-PathBinaryLeaf | 382-415 | Extract binary filename from quoted/unquoted paths |
| Test-ScreenConnectInstance | 417-494 | Re-verify plan entry is genuinely ScreenConnect |
| Get-VerifiedUninstallEntry | 496-575 | Validate plan-supplied UninstallRegistryKey |
| Get-UninstallEntriesForInstance | 706-737 | Scan registry for ScreenConnect uninstall entries |
| Stop-ServiceSafe | 742-777 | Stop service with error handling |
| Kill-ProcessesForInstance | 779-868 | Kill processes with self-protection |
| Delete-ServiceRegistration | 870-907 | Delete service via sc.exe |
| Run-VendorUninstaller | 912-1078 | Execute vendor uninstaller (MSI or non-MSI) |
| Move-ToQuarantine | 1083-1212 | Move files to quarantine with hashing |
| Set-RunOnceResume | 1214-1239 | Write RunOnce key for post-reboot resume |
| Clean-Persistence | 1244-1362 | Remove scheduled tasks, Run keys, WMI subscriptions |
| Write-ResumeMarker | 609-628 | Persist resume state to JSON |
| Initialize-ResumeMarker | 630-654 | Seed resume statuses for all instances |
| Update-ResumeStatus | 656-667 | Update one instance status in resume marker |

### 2.6 Invoke-ReviewAndRemove.ps1 Functionality

| Function/Section | Lines | Purpose |
|------------------|-------|---------|
| Get-Prop | 51-56 | StrictMode-safe property read |
| Findings location | 59-76 | Auto-locate newest findings.json under ScanRoot or use explicit path |
| Instance extraction | 79-85 | Read ScreenConnect.Instances from findings.json |
| Review gate | 104-133 | Per-instance interactive KEEP/REMOVE prompt. Default KEEP. -Yes auto-marks REMOVE. |
| Confirmation gate | 142-160 | Final typed confirmation before removal. -Yes skips. |
| Plan writing | 163-187 | Writes plan.json with GeneratedUtc, TechName, ClientName, IncidentDate, Decision, SourceFindings, RemovalConfirmed, ScreenConnectInstances[] |
| Delegation | 195-213 | Invokes remove-screenconnect.ps1 -PlanJson $planPath -WorkDir $WorkDir -Execute, captures exit code |

### 2.7 Plan File Schema (plan.json)

```json
{
  "GeneratedUtc": "yyyy-MM-dd HH:mm:ss",
  "TechName": "$env:USERNAME",
  "ClientName": "$env:COMPUTERNAME",
  "IncidentDate": "yyyy-MM-dd",
  "Decision": "ALL_REMOVE | PARTIAL_REMOVE",
  "SourceFindings": "<path to findings.json>",
  "RemovalConfirmed": true,
  "ScreenConnectInstances": [
    {
      "Identifier": "<instance-id>",
      "ServiceName": "<service-name>",
      "InstallDir": "<install-path>",
      "ServiceImagePath": "<raw-service-image-path>",
      "MainExe": "<path-to-primary-exe>",
      "UninstallRegistryKey": "<registry-key-path>",
      "...additional fields from findings..."
    }
  ]
}
```

---

## 3. Per-Component Verdict Table

| Component | Verdict | Justification |
|-----------|---------|---------------|
| Plan file loading and validation | RETAIN | Clean schema, mandatory parameter, Decision gate. Port plan schema to Scc.Remedy. |
| Plan filtering (ScreenConnect-only) | RETAIN | Primary + fallback paths correct. Keep as-is. |
| Per-entry product verification (FIX 1) | RETAIN | Critical safety gate. Three verification gates (directory, binary, service name). Must be ported exactly to Scc.Remedy. |
| UninstallRegistryKey validation | RETAIN | Dual cross-check (install dir reference + instance ID in DisplayName) is sound. Port to Scc.Remedy. |
| Admin gate | RETAIN | Simple, correct, prevents partial mutations. Port to Scc.Remedy. |
| Logging (Write-Log, Write-Section) | REFACTOR | Functional but console-only. Replace with Scc.Core structured logging (Write-SccLog). Keep timestamp format as fallback. |
| Manifest recording (Add-ManifestEntry) | REFACTOR | Good data model but stored as ArrayList + final JSON. Replace with Scc.Remedy remediation.json + quarantine-manifest.json (dual output). Port the entry schema. |
| Force-Array | RETAIN | PS 5.1 compatibility helper. Port to Scc.Core or keep inline. |
| Run-BoundedProcess | RETAIN | Well-designed concurrent stream drain. Port to Scc.Core as a shared utility (used by scanners too). |
| Get-EntryPropertySafe | RETAIN | StrictMode-safe property accessor. Port to Scc.Core (used everywhere). |
| Get-PathBinaryLeaf | RETAIN | Platform-neutral leaf extraction. Port to Scc.Core or Scc.Remedy. |
| Get-ScreenConnectIdentity | RETAIN | Identity pattern loading from targets.json with hardcoded fallbacks. Port to Scc.Remedy. |
| Test-ScreenConnectInstance | RETAIN | Three-gate verification. Port exactly to Scc.Remedy. |
| Get-VerifiedUninstallEntry | RETAIN | Registry cross-validation logic. Port to Scc.Remedy. |
| Stop-ServiceSafe | RETAIN | Clean, handles missing services as non-failure. Port to Scc.Remedy. |
| Kill-ProcessesForInstance | RETAIN | Three-tier discovery + self-protection + ancestor walk. Port exactly to Scc.Remedy. |
| Delete-ServiceRegistration | RETAIN | sc.exe with stderr isolation. Port to Scc.Remedy. |
| Run-VendorUninstaller | RETAIN | No-shell execution, MSI/non-MSI paths, allowlist, Run-BoundedProcess integration. Port exactly to Scc.Remedy. |
| Move-ToQuarantine | RETAIN | Directory hashing, reparse point skip, collision safety, MoveFileEx fallback. Port to Scc.Remedy. |
| Set-RunOnceResume | RETAIN | Absolute path resolution, RunOnce key writing. Port to Scc.Remedy. |
| Clean-Persistence | REFACTOR | Three persistence types (tasks, Run keys, WMI). WMI section has known bug (filter lookup uses reference string, never matches). Port tasks + Run keys; fix or replace WMI section. |
| Reboot-resume (FIX 2) | RETAIN | resume-marker.json lifecycle is complete. Port to Scc.Remedy. |
| Per-instance error isolation (FIX 3) | RETAIN | try/catch with defensive ID resolution. Port to Scc.Remedy. |
| Uninstall key export-before-delete | RETAIN | Fail-safe: export verified before delete. Port to Scc.Remedy. |
| Invoke-ReviewAndRemove.ps1 (whole file) | MERGE -> Scc.UI + Scc.Remedy | Review gate becomes Findings.xaml UI. Plan writing becomes New-SccPlan. Delegation to remover becomes Invoke-SccRemediation. The console review flow is replaced by WPF. |
| Console output formatting | REPLACE | Write-Line replaced by WPF UI binding. |
| AUDIT-REMOVE.md | RETAIN | Reference document for the rebuild. Port applicable findings to architecture docs. |

---

## 4. Notable Logic Worth Preserving Exactly

### 4.1 Plan-File Schema

The plan.json structure (section 2.7) is the contract between review and remediation. It carries GeneratedUtc, TechName, ClientName, IncidentDate, Decision (ALL_REMOVE/PARTIAL_REMOVE), SourceFindings, RemovalConfirmed, and ScreenConnectInstances[]. This schema must be preserved in Scc.Remedy's New-SccPlan output. The Decision field gates whether the removal engine proceeds.

### 4.2 Review Gate Flow (Invoke-ReviewAndRemove.ps1)

The two-stage confirmation is critical:
1. Per-item: each ScreenConnect instance shown with identity fields (InstallDir, ServiceName, RelayHost, SessionType, DisplayVersion, Publisher). Technician types y to mark REMOVE. Default is KEEP (empty input = N).
2. Global: after all items reviewed, summary shown, typed "y" required to proceed with removal.

This flow must be preserved in the WPF Findings.xaml view. The -Yes switch (unattended lab mode) bypasses both gates but is logged prominently.

### 4.3 Vendor Uninstaller Discovery and Invocation

The vendor uninstaller path (Run-VendorUninstaller, lines 912-1078) follows this exact sequence:
1. Read QuietUninstallString (preferred) then UninstallString from registry
2. Detect MSI via ProductCode regex in the command string
3. MSI path: run msiexec.exe directly with curated arguments (/x ProductCode /qn /norestart)
4. Non-MSI path: extract bare executable, verify against allowlist (ScreenConnect/App_/unins*.exe), verify under verified install dir, verify file exists
5. Execute directly via ProcessStartInfo (no cmd.exe, no shell)
6. Exit code 0 = success, 3010 = success + reboot required, else failure
7. On failure: fall back to manual surgery (quarantine + service delete)

The no-shell policy (lines 988-1031) is non-negotiable. Registry UninstallString is attacker-influenced and must never be shell-interpreted.

### 4.4 Quarantine Structure and Manifest Fields

Quarantine path: <WorkDir>\quarantine\<InstanceId>\<destName>

When destination collision detected: append 8-char SHA256 prefix of full source path.

Directory contents hashed to: quarantine-hashes-<InstanceId>.csv with columns Path, Length, SHA256.

Reparse points (junctions/symlinks) explicitly skipped and recorded in manifest.

Manifest entry for quarantine: Action='Quarantine', Target=SourcePath, Result=Success/Deferred/Failed, Details includes SHA256, original path, quarantine path, description.

### 4.5 Hash Recording

- Single files: SHA256 via Get-FileHash -LiteralPath -Algorithm SHA256
- Directories: per-file CSV (Path, Length, SHA256) via Export-Csv
- Text hashing: Get-Sha256Hex for collision-safe destination naming
- Both file and text hashing are SHA-256, used for forensic record and collision avoidance

### 4.6 Re-Verification Before Acting

Test-ScreenConnectInstance (lines 417-494) is the critical safety gate:
- Gate A: directory segment match (DirSegmentPattern = *\ScreenConnect*)
- Gate B: binary name match against ServiceScreenConnect.exe or targets.json patterns
- Gate C: service name match against ScreenConnect service patterns
- All three gates must pass; any failure = reject

Get-VerifiedUninstallEntry (lines 496-575) adds a fourth verification:
- Registry key's DisplayName must contain ScreenConnect/ConnectWise Control
- At least one value must reference the verified install directory
- Fallback: DisplayName contains instance ID that also names the install dir

### 4.7 Path/Quoting Safety

- Get-PathBinaryLeaf handles: quoted paths ("C:\...\x.exe" /args), unquoted paths with trailing arguments, '/'-separated input, trailing argument tokens
- Expand-Env wraps all environment variable expansion
- LiteralPath used everywhere (avits PowerShell provider globbing)
- RunOnce command uses absolute resolved paths (Resolve-Path) to prevent working-directory-dependent failures
- Registry key path conversion from HKEY_ to Registry:: provider prefix
- Nested Join-Path calls for PS 5.1 compatibility (no third positional parameter)

### 4.8 Self-Protection in Kill-ProcessesForInstance

Parent PID chain walk (lines 817-834): walks from $PID through up to 12 ancestors using Win32_Process.ParentProcessId. Any PID in this chain is refused. This prevents the tool from killing its own process tree, which would leave the machine half-cleaned.

### 4.9 Collision-Safe Quarantine Naming

When Move-ToQuarantine detects the destination already exists (lines 1141-1153): derives a unique name by SHA256-hashing the full source path and taking the first 8 hex characters. This prevents silent overwrite during resume runs or when two installs share a leaf name.

---

## 5. Duplicated Code, Dead Code, Hardcoded Paths, Insufficiently Gated Destructive Actions

### 5.1 Duplicated Code

| Lines | Duplication | Notes |
|-------|-------------|-------|
| 162-166 (Expand-Env) | Also present in detect-remote-access.ps1 lines 186-190 | Identical implementation. Should be a shared Scc.Core utility. |
| 143-149 (Get-Sha256File) | Also present in detect-remote-access.ps1 (Get-FileFacts sub-call) | Similar but not identical. The removal script's version is standalone. |
| 151-160 (Get-Sha256Hex) | Also present in detect-remote-access.ps1 lines 175-184 | Identical implementation. Should be shared. |
| 362-371 (Get-EntryPropertySafe) | Invoke-ReviewAndRemove.ps1 lines 51-56 (Get-Prop) | Nearly identical StrictMode-safe property access. Should be one shared function. |
| Clean-Persistence WMI filter lookup | Uses Name='$($b.Filter)' but $b.Filter is a reference string | This is a bug, not intentional duplication. See section 6. |
| Reboot-persistence cleanup (lines 1435-1470) and main persistence cleanup (lines 1582-1617) | Both call Clean-Persistence with the same arguments | The reboot-pending path duplicates the service exe path extraction logic (lines 1442-1459 vs. 1598-1616). Should be extracted to a helper. |

### 5.2 Dead Code

| Lines | Dead Code | Notes |
|-------|-----------|-------|
| 55-56 | -VerboseLog parameter declared | Never checked in any code path. The Write-Log function does not have a verbose mode toggle. This parameter is unused. |
| 693-701 | System Restore point section comment block | States the restore point is NOT created here (Stage 0 handles it). The comment block exists to explain absence. No code to remove, but the comment references preflight.ps1 which may not exist in the new architecture. |
| Clean-Persistence WMI section (lines 1327-1355) | Effectively dead due to bug | Filter lookup uses Name='$($b.Filter)' which is the reference string from the binding object, not the actual filter name. Subscriptions will never match. Fails safe (silently no-ops). |

### 5.3 Hardcoded Paths and Values

| Line(s) | Hardcoded Value | Risk | Notes |
|---------|-----------------|------|-------|
| 581 | WorkDir default = 'C:\RIT-SCC' | Medium | Should be configurable. The new architecture uses %ProgramData%\ScreenConnectCleaner or config override. |
| 329-334 | ServiceNamePatterns = @('ScreenConnect*') | Low | Fallback when targets.json absent. Loaded from targets.json when available. Acceptable as safety default. |
| 331 | BinaryNamePatterns = @('ServiceScreenConnect.exe', 'ScreenConnect*.exe') | Low | Same pattern: fallback, overridden by targets.json. |
| 332 | DirSegmentPattern = '*\ScreenConnect*' | Low | Identity verification pattern. Reasonable fallback. |
| 336-337 | $targetsFile = Join-Path $PSScriptRoot 'targets.json' | Medium | Assumes targets.json is next to the script. New architecture uses config/targets.json. |
| 1217-1218 | RunOnce path and script path resolution | Low | Uses $PSScriptRoot to locate script. Reasonable for portable layout. |
| 1230 | RunOnce command template | Low | Hardcoded PowerShell invocation flags. Standard and unlikely to change. |

### 5.4 Insufficiently Gated Destructive Actions

| Line(s) | Action | Gap | Severity |
|---------|--------|-----|----------|
| 1268 | Unregister-ScheduledTask | No pre-deletion export/backup of the task definition. If deleted in error, the definition is lost. The manifest records the action but the task XML is not preserved. | Low (tasks are system-generated, not forensic evidence) |
| 1308 | Remove-ItemProperty (Run key) | No pre-deletion export. Same as above. | Low |
| 1337-1339 | Remove-CimInstance (WMI) | Three removals (binding, filter, consumer) with no export. WMI subscriptions are less commonly needed for forensics. | Low |
| 1553 | reg.exe delete (uninstall key) | Properly gated by export-first. Export verified before delete. This is well-handled. | None |
| 1577-1579 | Delete-ServiceRegistration when InstallDir absent | When install directory is not found, service is still deleted. No quarantine copy exists. This is documented in AUDIT-REMOVE.md caveat C2b. | Medium (documented, accepted) |

---

## 6. Bugs and Limitations

### 6.1 Bugs

| Line(s) | Issue | Severity | Status |
|---------|-------|----------|--------|
| 1332 | **WMI filter lookup bug**: `Get-CimInstance -Filter "Name='$($b.Filter)'"` uses the binding's Filter reference string (e.g. "__EventFilter.Name='xxx'") as the Name value, not the actual filter name. Subscriptions will never match. Feature silently dead. | Medium | Known (AUDIT-REMOVE.md notes it). Fails safe. |
| 844 | **$pid loop variable**: Previous version used $pid (shadows read-only automatic $PID). Fixed to $procId. | High | Fixed (comment at line 844 explains). |
| 274 (AUDIT-REMOVE.md line 274) | **$matches shadowing**: $matches used as local variable name in Get-UninstallEntriesForInstance. Works today because no -match precedes the assignment in that function. Line 931: $args shadowed in Clean-Persistence. | Low | Known, pre-existing, not fixed (out of scope). |
| 1183-1186 | **Add-Type Kernel32 duplicate**: Add-Type -MemberDefinition for Kernel32 MoveFileEx is called per locked file. Second invocation throws "type already exists". Multi-file reboot-deferral misreports failure. | Low | Known from AUDIT-REMOVE.md. Not fixed. Workaround: the Add-Type succeeds on first call per process; subsequent calls to the already-loaded type still work via $kernel32::MoveFileEx. |
| 1095-1212 | **Move-ToQuarantine directory hashing on empty directory**: If the source directory exists but contains no files (only subdirectories or is empty), the CSV will have zero rows. The hashNote will say "directory, 0 file(s) hashed". This is not a bug per se but could be confusing. | Very Low | Not a correctness issue. |
| 1490-1512 | **Uninstall entry not found for some instances**: When $instanceId is 'unknown', the fallback registry scan (line 1424) is skipped because the identifier guard `$instanceId -ne 'unknown'` prevents it. This is intentional but means unidentified instances always go to manual surgery. | Low | By design. |

### 6.2 Limitations

| Area | Limitation | Impact |
|------|------------|--------|
| No firewall rule detection/removal | ScreenConnect firewall rules are not detected or cleaned. | Medium. New architecture should add firewall rule cleanup to Scc.Remedy. |
| No startup folder detection | Startup folder shortcuts are not checked. | Low. ScreenConnect does not typically use startup folders. |
| No signature verification | Product verification is name-based only (directory segment, binary name, service name). A look-alike folder named "ScreenConnect..." would pass. | Medium. Documented warning logged at runtime (line 1408). New architecture could add Authenticode check. |
| No service binary signature check | Vendor uninstaller executable is not signature-checked before execution. Allowlist is name-based only. | Medium. The no-shell policy mitigates exploitation but does not prevent a renamed malicious executable. |
| WMI subscription cleanup dead | Bug means WMI persistence is never cleaned. | Medium. WMI subscriptions referencing ScreenConnect would survive removal. |
| No pre-deletion backup for tasks/Run keys/WMI | Scheduled task definitions, Run key values, and WMI subscriptions are deleted without backup export. | Low. Manifest records the action but not the deleted content. |
| No disk space check before quarantine | Large install directories could fill the quarantine partition. | Low. Technician should check available space. |
| Set-Content -Encoding UTF8 emits BOM on PS 5.1 | Manifest and resume-marker files written with Set-Content -Encoding UTF8 on PS 5.1 include a UTF-8 BOM. JSON parsers generally tolerate this but it is not pure UTF-8. | Very Low. Resume-marker.json correctly uses UTF8Encoding($false). Manifest uses Set-Content which emits BOM on 5.1. |

---

## 7. Mapping Suggestion: Old Component -> New Module

### 7.1 remove-screenconnect.ps1 -> Scc.Remedy

| Old Component | New Module | Action |
|---------------|------------|--------|
| Plan loading and validation | Scc.Remedy: New-SccPlan (schema) + internal loader | RETAIN plan schema. Load logic becomes internal to Invoke-SccRemediation. |
| Plan filtering (ScreenConnect-only) | Scc.Remedy: Invoke-SccRemediation | RETAIN. Filter by plan.ScreenConnectInstances with fallback. |
| Per-entry product verification (FIX 1) | Scc.Remedy: Test-SccPlanItem | RETAIN exactly. Three gates (directory, binary, service name). |
| UninstallRegistryKey validation | Scc.Remedy: Get-SccVerifiedUninstallEntry | RETAIN exactly. Dual cross-check. |
| Admin gate | Scc.Remedy: Invoke-SccRemediation | RETAIN. Check elevation before -Execute. |
| Stop-ServiceSafe | Scc.Remedy: Stop-SccServiceSafe | RETAIN exactly. |
| Kill-ProcessesForInstance | Scc.Remedy: Stop-SccProcesses | RETAIN exactly. Self-protection + ancestor walk. |
| Delete-ServiceRegistration | Scc.Remedy: Remove-SccServiceRegistration | RETAIN exactly. sc.exe with stderr isolation. |
| Run-VendorUninstaller | Scc.Remedy: Invoke-SccVendorUninstaller | RETAIN exactly. No-shell execution, MSI/non-MSI paths, allowlist. |
| Move-ToQuarantine | Scc.Remedy: Move-SccToQuarantine | RETAIN exactly. Directory hashing, reparse point skip, collision safety, MoveFileEx fallback. |
| Set-RunOnceResume | Scc.Remedy: Set-SccRunOnceResume | RETAIN exactly. Absolute path resolution. |
| Clean-Persistence (scheduled tasks) | Scc.Remedy: Remove-SccPersistenceTasks | RETAIN. |
| Clean-Persistence (Run keys) | Scc.Remedy: Remove-SccPersistenceRunKeys | RETAIN. |
| Clean-Persistence (WMI) | Scc.Remedy: Remove-SccPersistenceWmi | REWRITE. Fix filter lookup bug. |
| Orphaned uninstall key export+delete | Scc.Remedy: Remove-SccUninstallKey | RETAIN exactly. Export-first, verify, then delete. |
| Reboot-resume (resume-marker.json) | Scc.Remedy: SccResumeState | RETAIN lifecycle. Integrate with Scc.Core run state management. |
| Manifest recording | Scc.Remedy + Scc.Report | REFACTOR. Dual output: remediation.json (action log) + quarantine-manifest.json (quarantine metadata). Both feed into Scc.Report. |
| Logging | Scc.Core: Write-SccLog | REPLACE. Structured JSONL logging replaces ArrayList accumulator. |
| Get-EntryPropertySafe | Scc.Core | RETAIN as shared utility. |
| Get-PlanInstanceId | Scc.Remedy | RETAIN. |
| Get-PathBinaryLeaf | Scc.Core or Scc.Remedy | RETAIN. |
| Run-BoundedProcess | Scc.Core | RETAIN as shared utility (also used by scanners). |
| Force-Array | Scc.Core | RETAIN as shared utility. |
| Get-Sha256File, Get-Sha256Hex | Scc.Core: Get-SccFileFacts or Scc.Remedy helpers | RETAIN. |
| Expand-Env | Scc.Core: Resolve-SccEnv | RETAIN (already in architecture spec). |
| Get-QuarantineDir | Scc.Remedy: New-SccQuarantineDir | RETAIN. Add ACL locking per architecture spec. |

### 7.2 Invoke-ReviewAndRemove.ps1 -> Scc.UI + Scc.Remedy

| Old Component | New Module | Action |
|---------------|------------|--------|
| Findings.json location/loading | Scc.UI: Findings.xaml | REPLACE. UI reads findings from run directory. |
| Per-instance display | Scc.UI: Findings.xaml | REPLACE. WPF view shows each instance with identity fields and KEEP/REMOVE checkbox. |
| Per-instance KEEP/REMOVE prompt | Scc.UI: Findings.xaml | REPLACE. WPF checkbox replaces console Read-Host. Default KEEP preserved. |
| Global confirmation | Scc.UI: Findings.xaml | REPLACE. "Proceed with removal?" becomes WPF confirmation dialog. |
| Plan writing | Scc.Remedy: New-SccPlan | RETAIN plan schema. Plan written by Scc.Remedy module, not the UI script. |
| -Yes (unattended) | Scc.UI: headless mode | REPLACE. -Headless mode in Scc.UI handles unattended runs. |
| -WhatIfOnly | Scc.Remedy: Test-SccPlan | RETAIN concept. Becomes the dry-run preview in Scc.Remedy. |
| Delegation to remove-screenconnect.ps1 | Scc.Remedy: Invoke-SccRemediation | REPLACE. Direct module invocation instead of external script call. |
| Exit code handling | Scc.UI: stage state machine | REPLACE. Stage 4 (Remediate) status tracking via runstate.json. |

### 7.3 AUDIT-REMOVE.md -> Documentation

| Old Content | New Location | Action |
|-------------|--------------|--------|
| Check 1 (ScreenConnect-only) findings | ARCHITECTURE.md safety invariants + Scc.Remedy code | RETAIN in code (FIX 1). Reference in testing docs. |
| Check 2 (quarantine-never-delete) | ARCHITECTURE.md safety rule 3 | RETAIN. Port quarantine logic exactly. |
| Check 3 (plan + Execute gate) | ARCHITECTURE.md safety rule 2 | RETAIN. Port plan schema and dry-run default. |
| Check 4 (runtime registry read) | ARCHITECTURE.md safety rule 5 | RETAIN. Port vendor uninstaller logic exactly. |
| Check 5 (PS 5.1 compat) | tests/ci house-rules checks | RETAIN parse verification in CI. |
| FIX 1-4 details | Scc.Remedy implementation notes | RETAIN as migration reference. |
| Caveats C2a-C2d | Scc.Remedy implementation TODOs | PORT as known gaps to fix in the new architecture. |

---

## 8. Summary of Migration Safety Requirements

The following items from remove-screenconnect.ps1 are non-negotiable in the rebuild:

1. **ScreenConnect-only removal**: Every plan entry re-verified before action. Non-SC entries rejected with PRODUCT_VERIFICATION_FAILED.
2. **Dry-run default**: -Execute required for any mutation. Default logs what would happen.
3. **Plan file gate**: No detection+removal in one step. Review must produce plan.json first.
4. **Quarantine never delete**: All artifacts moved, never deleted. SHA256 + original path recorded.
5. **Vendor uninstaller first**: Run before manual surgery. Read from registry at runtime. Never invent switches.
6. **No-shell execution**: Registry UninstallString never fed to cmd.exe. Executable run directly via ProcessStartInfo.
7. **Self-protection**: Never kill the tool's own process tree.
8. **Per-instance error isolation**: One failed instance does not abort the rest.
9. **Reboot resume**: Resume-marker.json + RunOnce key for post-reboot persistence cleanup.
10. **Manifest every action**: Every stop, kill, uninstall, quarantine, delete, persistence clean recorded with timestamp, target, result, details, exit code.

DONE

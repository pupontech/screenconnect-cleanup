# Architecture

Tron's shape, our scope. A staged orchestrator that drives existing tools.

---

## The stage pipeline

```text
sc-cleanup.ps1  [flags]          <- top-level runner, NOT YET BUILT
|
+- STAGE 0  PREFLIGHT
|    admin check . OS role check (refuse on Server unless -force)
|    disk space . working dir C:\RIT-SCC\<host>-<timestamp>\
|    master log open . tech name / client / INCIDENT DATE prompt
|    System Restore point + registry hive export   [skip: -np]
|    tool pack: verify hashes (tools/Get-ToolPack.ps1)
|
+- STAGE 1  SNAPSHOT (BEFORE)          <- read-only, always runs, NEVER skippable
|    collect-snapshot.ps1 -Label before
|    services . scheduled tasks . registry autoruns . startup folders
|    processes (PPID + cmdline) . TCP connections . installed programs
|    local accounts . firewall . RDP state . hosts . WMI persistence
|    incident-window recent files
|
+- STAGE 2  REMOTE-ACCESS DETECTION    <- BUILT: detect-remote-access.ps1
|    ScreenConnect: enumerate instances, extract RELAY IDENTITY
|    Other RATs: presence-only, toggleable via targets.json
|    -> findings.json
|
+- STAGE 3  TECHNICIAN REVIEW          <- the approval gate
|    shows each finding + evidence, tech marks KEEP / REMOVE
|    NO unattended mode. Ever.
|    -> plan.json
|
+- STAGE 4  CONTAIN + REMOVE           [skip: -sr]
|    stop services . kill processes
|    uninstall via registry UninstallString / msiexec  (vendor uninstaller FIRST)
|    leftovers: service delete . dir quarantine . registry entries
|    persistence bound to removed agents: tasks, Run keys, WMI subs
|    everything moved to \quarantine\ - NOTHING deleted
|
+- STAGE 5  SCANNERS                   [skip: -sa]   <- sequential, long
|    Defender MpCmdRun  (always available, zero licensing risk - do this first)
|    AdwCleaner         (PUP/adware - closest to scam leftovers)
|    KVRT               (approved, see D2)
|    ESET               (approved, see D3)
|    MSERT              (free Microsoft second opinion)
|    each: timeout . exit code . log copied to \logs\<scanner>\
|
+- REBOOT BARRIER (if any stage flagged it)  -> RunOnce resume marker
|
+- STAGE 6  PROCMON - TARGETED ONLY    [opt-in: -procmon]
|    runs only if the Stage 7 diff shows a resurrection, or on demand
|
+- STAGE 7  SNAPSHOT (AFTER) + DIFF
|    collect-snapshot.ps1 -Label after, then diff against before
|    what went, what came back, what is new
|    ** resurrection detection lives here **
|
+- STAGE 8  REPORT
     New-InvestigationReport.ps1
     report.html (tech-facing) . results.json . master log
     + credential-reset checklist for the client
```

---

## Flags (Tron-style)

```
-sa           skip antivirus scanners (the multi-hour stage)
-sr           skip removal (detect + report only - the "just tell me" mode)
-np           no restore point
-offline      use the pre-staged tool pack, do not download
-procmon      force the Procmon stage
-incident <date>   incident window anchor
-force        override the server-OS refusal
-safemode     relaunch in safe mode with networking
-resume       internal, used by the reboot RunOnce
```

`-sr` matters more than it looks: **detect-only is the mode you can hand any technician
on day one**, before removal code is trusted.

---

## Why the pipeline is ordered this way

The single most important inversion versus Tron: Tron runs
`clean -> debloat -> disinfect`. Ours is **snapshot -> detect -> remove -> scan ->
verify**, with temp cleanup omitted entirely.

Tron's temp cleanup would delete the scammer's installer out of `%TEMP%` **before anyone
looked at it**. Tron is optimizing a slow PC; we are investigating an incident. Same
machinery, opposite priorities.

---

## Component contracts

These were specified up front so components built in parallel compose correctly.

### Scanner adapter contract (Stage 5)

Every adapter in `scanners/` takes:

```powershell
param(
    [string]$ScanPath,          # optional targeted path; omit for default scan
    [int]$TimeoutMinutes = 120,
    [string]$LogDir,            # where to copy the scanner's own log
    [string]$ToolPath,          # optional explicit path to the executable
    [switch]$WhatIf             # report availability + command line, run nothing
)
```

and returns exactly one PSCustomObject:

```
ScannerName, ScannerVersion, Available (bool), StartTimeUtc, EndTimeUtc,
DurationSeconds, Status, ExitCode, Detections (array), DetectionCount,
LogPath, RebootRequired (bool), Errors (array), CommandLine (string)
```

`Status` is one of: `Completed`, `Timeout`, `Failed`, `Skipped`, `NotInstalled`,
`Unlicensed`, `NotVerified`.

Each `Detections` element: `@{ Path=''; ThreatName=''; Severity=''; Action='' }`

Rules: **hard timeout per scanner** (a hung KVRT must not hang the run); **failure is
never fatal** — record `Failed` and continue; **read the scanner's log file, never parse
stdout**; `-WhatIf` must be genuinely safe.

### Snapshot schema (Stages 1 and 7)

```json
{
  "SchemaVersion": 1,
  "Label": "before",
  "ComputerName": "...",
  "CollectedUtc": "yyyy-MM-dd HH:mm:ss",
  "IsAdmin": true,
  "OSCaption": "...",
  "IncidentWindowDays": 0,
  "CollectionErrors": [ { "Section": "...", "Error": "..." } ],
  "Sections": {
    "Services": [ { "Key": "...", "...": "..." } ],
    "ScheduledTasks": [], "RegistryAutoruns": [], "StartupFolders": [],
    "Processes": [], "Connections": [], "InstalledPrograms": [],
    "LocalAccounts": [], "FirewallRules": [], "WmiPersistence": [],
    "RecentFiles": [],
    "SystemSettings": { "RdpEnabled": false, "HostsFileLines": [] }
  }
}
```

**The `Key` field is the critical design point.** Every item carries a `Key` that is
stable across runs and uniquely identifies it, so the diff matches before/after items by
Key alone. Key on identity (service name; hive+keypath+valuename; TaskPath+TaskName),
**never** on volatile state (PID, timestamps, current state) — those are the fields being
compared, not the identity.

Arrays must be **sorted by Key** before emitting, so a diff of two files is not full of
ordering noise.

Every section wrapped so a failure records an entry in `CollectionErrors` and collection
continues. One inaccessible section must never abort the run.

---

## What was deliberately NOT built

Rejected during design, with reasons. Do not reintroduce without a decision from the
owner.

| Rejected | Why |
|---|---|
| Three-binary Collect/Analyze/Remediate split | Over-scoped for a technician tool |
| Velociraptor / KAPE dependency | Over-scoped; adds a large dependency |
| Trust catalog / allowlist / AUTHORIZED classification | Owner decision D4: no allowlisting for now |
| Chain-of-custody / evidentiary sealing | Over-scoped |
| Compiled C# binary | PowerShell is right for a process launcher + log parser; a compiled EXE also trips AV on the machines being investigated |
| Sysmon deployment | Installing it during an investigation gives zero retroactive data |
| Debloat / optimize / repair stages | Out of scope; a real way to break a client machine while "cleaning" it |
| Temp cleanup | Destroys the evidence we came for |
| Event log clearing | Same |
| TDSSKiller | Deprecated, and reportedly abused in 2024 to disable EDR, so it may trip the client's own security stack (VERIFY) |

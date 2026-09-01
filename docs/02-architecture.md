# Architecture

Tron's shape, our scope. A staged orchestrator that drives existing tools.

---

## The stage pipeline

```text
sc-cleanup.ps1  [flags]          <- top-level runner, BUILT (wires Stages 0-9)
|
+- STAGE 0  PREFLIGHT
|    admin check . OS role check (refuse on Server unless -force)
|    disk space . working dir C:\RIT-SCC\<host>-<timestamp>\
|    master log open (no tech/client/date prompts - owner directive 2026-08-27)
|    System Restore point + registry hive export   [skip: -np]
|    tool pack: verify hashes (tools/Get-ToolPack.ps1)
|
+- STAGE 1  SNAPSHOT (BEFORE)          <- read-mostly, always runs, NEVER skippable
|    collect-snapshot.ps1 -Label before
|    services . scheduled tasks . registry autoruns . startup folders
|    processes (PPID + cmdline) . TCP connections . installed programs
|    local accounts . firewall . RDP state . hosts . WMI persistence
|    incident-window recent files
|    Amcache: temporary hive mount/unmount exception; ShimCache raw metadata only
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
+- STAGE 5  SCANNERS                   [skip: -sa]   <- attended GUIs, long
|    KVRT               (staged from Kaspersky's official URL, see docs/05)
|    ESET Online Scanner (staged from ESET's official URL, see docs/05)
|    Malwarebytes       (installed via winget, launched for the technician)
|    each: launched as a visible attended GUI via Invoke-GUIScanner.ps1;
|          session status recorded in scanner_results.json, surfaced in the
|          report (docs/06 rules 9-10)
|
+- STAGE 6  UNINSTALL INSTALLED AV     [skip: -avu]  <- attended GUIs
|    Invoke-AVUninstaller.ps1: open each detected third-party AV's own
|    uninstaller for the technician to drive; leftovers moved to quarantine,
|    never deleted (Windows Defender excluded)
|
+- STAGE 7  PROCMON - TARGETED ONLY    [opt-in: -procmon]
|    runs only if the Stage 8 diff shows a resurrection, or on demand
|    (bounded live capture since v1.7.21; boot-logging and PMF path
|    filters still need a GUI-set config - docs/07 Q6)
|
+- STAGE 8  SNAPSHOT (AFTER) + DIFF
|    collect-snapshot.ps1 -Label after, then diff against before
|    what went, what came back, what is new
|    ** resurrection detection lives here **
|
+- STAGE 9  REPORT
     New-InvestigationReport.ps1
     report.html (tech-facing) . results.json . master log
     + credential-reset checklist for the client

Reboot-resume (e.g. vendor uninstaller exit 3010) is handled inside
remove-screenconnect.ps1 via a highest-privilege Task Scheduler logon task,
not by the orchestrator. The task is removed only after post-reboot verification
succeeds.
```

---

## Flags (Tron-style)

```
-sa           skip antivirus scanners (the multi-hour stage)
-sr           skip removal (detect + report only - the "just tell me" mode)
-avu          skip uninstalling installed AV
-np           no restore point
-offline      use the pre-staged tool pack, do not download
-procmon      force the Procmon stage (currently a stub)
-IncidentDate <date>   incident window anchor (defaults to today; never prompted)
-force        override the server-OS refusal
-ExecuteRemoval  TEST MODE: pre-authorize removal (lab/VM only, no typed confirmation)
-Debug        full debug logger: console transcript + debug detail to
              <WorkDir>\logs\debug.log (send this file back when reporting a field issue)
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

### Scanner operation (Stage 5) - attended GUI, no invented flags

Stage 5 no longer uses CLI scanner adapters (owner decisions 2026-08-26/27;
see docs/05 and docs/07 Q4 - do not restore CLI adapters). It launches each
scanner as a visible attended GUI through `Invoke-GUIScanner.ps1` and the
technician drives the UI:

- KVRT and ESET Online Scanner are staged from official vendor URLs by
  `tools/Get-AVTools.ps1` (atomic `.part` staging + PE-header validation).
- Malwarebytes is installed via winget (`winget install -e --id
  Malwarebytes.Malwarebytes --accept-package-agreements
  --accept-source-agreements`) and launched for the technician.
- One session result per scanner: `Tool`, `Scanner`, `Status` and `ExitCode`,
  written to `scanner_results.json`. `Status` is one of: `Completed`,
  `LaunchFailed`, `NotInstalled`, `Timeout`, `Failed`. The report renders the
  table and an explicit "scanners skipped" block when `-sa` was used
  (docs/06 rules 9-10 - a skipped or failed scanner is shown, never hidden).
- Hard 240-minute cap per session: a hung scanner must not hang the run.
- **Never invent silent scan/clean flags** without fresh vendor documentation
  and a separate owner decision.

### Snapshot schema (Stages 1 and 8)

```json
{
  "SchemaVersion": 2,
  "Label": "before",
  "ComputerName": "...",
  "CollectedUtc": "yyyy-MM-dd HH:mm:ss",
  "IsAdmin": true,
  "OSCaption": "...",
  "IncidentWindowDays": 0,
  "CollectionComplete": true,
  "CollectionErrors": [ { "Section": "...", "Error": "..." } ],
  "CollectionWarnings": [ { "Section": "...", "Warning": "..." } ],
  "Sections": {
    "Services": [ { "Key": "...", "...": "..." } ],
    "ScheduledTasks": [], "RegistryAutoruns": [], "StartupFolders": [],
    "Processes": [], "Connections": [], "InstalledPrograms": [],
    "LocalAccounts": [], "FirewallRules": [], "WmiPersistence": [],
    "RecentFiles": [], "RecentFilesCapHit": false,
    "Prefetch": [], "ShimCache": [], "BamDam": [], "UserAssist": [],
    "Amcache": [],
    "Srum": { "DatabasePresent": false, "...": "..." },
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

Every section wrapped so a failure records an entry in `CollectionErrors`, sets
`CollectionComplete` to false, and collection continues. Intentional limitations and
absent optional artifacts are recorded in `CollectionWarnings`. A hard parallel-group
timeout does not run an unbounded fallback; it records incomplete sections so the diff
returns `INCOMPLETE` rather than treating empty placeholders as clean.

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

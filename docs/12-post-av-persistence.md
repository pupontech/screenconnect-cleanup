# v1.8.0 post-AV persistence prototype - testing guide

**TESTING ONLY.** This extends `START-HERE.bat` and `sc-cleanup.ps1`, not the
separate DetectOnly WPF GUI. Hosted Windows fixture tests do not establish live
incident-cleanup safety or owner acceptance. Use an authorized disposable test
machine before considering a client machine. Do not introduce live malware.

## What changed

The persistence investigation is scheduled immediately after the antivirus
stage, before the after-snapshot and final report. It is not an AV scan. It
looks for ways scripts/programs can restart themselves after AV cleanup:

- Scheduled tasks, flagged task XML, task registration events and hidden-task
  discrepancies (task files not enumerated or TaskCache entries missing SD).
- Machine/current-user and loaded-user registry autostart values, including
  Run/RunOnce and investigation-only Winlogon/legacy autostart values.
- Machine and user startup folders; script files and available SHA-256 hashes.
- Service/WMI subscription context, script-host processes and TCP connections.
- Defender detections/exclusions, registered AV, accounts, remote-access tools,
  recent logon/RDP context and hosts-file evidence.

The source reference was `For scc/pull-persistence.v2026-10-07.4.ps1` plus its
batch launcher. This is an adapted collector, not execution of the original
script. User-writable locations and script-host commands are **heuristics, not
proof of malware**. Absence of findings is not proof a PC is safe.

## Always-scan rule and failure behavior

- Guided Step 6d runs after the scanner choices, even when every scanner is
  declined or unavailable. There is no persistence-scan skip prompt.
- The direct runner runs the investigation after Stage 5 even with `-sa`.
- `-sr` disables persistence cleanup but still collects its evidence.
- `-ExecuteRemoval` does not waive the new selection/typed approval.
- `-WhatIf` intentionally remains a no-execution preview.
- A preflight failure/explicitly aborted run cannot reach this stage. A machine
  crash or terminating the runner also prevents later stages; "always" does not
  mean it can continue after its process ends.
- Missing access, collection failures and bounded/truncated evidence are recorded
  as unknown/incomplete, not clean. Persistence-stage failures should preserve
  later report generation and a nonzero final outcome.

## What cleanup can do

The tool displays candidate identity, command and reason. Select exact candidate
indices and then type `REMOVE` when asked. An empty or invalid answer declines
cleanup. This is independent of the earlier ScreenConnect approval.

Only these selected, revalidated target types are supported:

1. Suspicious non-Microsoft scheduled tasks: save XML, compare the current task
   definition with the scanned one, unregister the exact task, verify absence.
2. Suspicious Run/RunOnce-style values: save the exact value and type, compare
   the current value/type, remove only that named value, verify absence.
3. Suspicious startup-folder files: preserve the file through quarantine,
   recheck its hash/location and verify the move. Do not delete the referenced
   payload or recurse through startup directories.

Cleanup is refused when the target category (tasks plus task XML, Run keys, or
startup files) has incomplete/error-bearing evidence. Unrelated context gaps
such as an unloaded user hive or a bounded script-file inventory do not approve
anything and do not by themselves prevent separately approved, fully evidenced
targets from being reviewed. The overall report remains incomplete.

Cleanup is refused without current-run rollback prerequisites, on stale or
changed targets, unsafe paths, or backup failure. These are attended elevated
technician checks, **not** the independently protected non-admin GUI installer
or approval system described in the full-GUI design.

Services, WMI subscriptions, Microsoft-path tasks, hidden-task artifacts,
Winlogon settings, Defender exclusions, accounts and live processes are
**review-only**. This release does not automatically repair/delete those items,
run suspected scripts, or reboot the computer.

## Evidence and privacy

Evidence stays in `<current-run>\persistence\`:

- `inventory.json`: raw local evidence, findings and coverage status.
- `removal.json`: selected cleanup actions, backups and verified outcomes.
- `result.json`: scan/cleanup stage status used by the runner and report.
- Additional task XML, inventory artifacts and backup/quarantine files as
  produced by the modules.

Each scan requires a fresh run directory; existing persistence artifacts are
not overwritten. Redirected output paths are refused.

Protect the entire run folder. It can contain commands, usernames, IP addresses,
file paths and dangerous task definitions. Backups are evidence, not executable
instructions. Do not double-click suspected files or import task XML casually.

The existing sanitized MicroBin share adds only aggregate status/count metadata.
It does not add raw persistence evidence, file paths, command lines, user names,
IP addresses, XML or samples. The local HTML report contains detailed findings;
do not publicly upload it yourself without inspecting/redacting it.

PowerShell command histories and copies of suspected scripts are intentionally
not collected. Offline user hives are not mounted from their original
`NTUSER.DAT`; unavailable profile evidence remains a reported coverage gap.
Bounded script inventories are not exhaustive forensic disk imaging.

## Owner test checklist

Extract the entire versioned ZIP into a new folder; do not overlay an older
installation. Read `DEPLOY.md` and verify the published SHA-256 sidecar.

- [ ] Launch `START-HERE.bat`; verify the prior UAC/battery behavior is preserved.
- [ ] Decline all AV scanners; verify Step 6d still collects persistence.
- [ ] Verify inventory, removal and result JSON belong to this fresh run.
- [ ] Check `report.html` contains status, coverage gaps and candidate reasons.
- [ ] On a disposable machine, create only harmless lab persistence entries.
- [ ] Decline persistence cleanup; verify the lab entries remain unchanged.
- [ ] Select one harmless candidate and type `REMOVE`; verify only that target
      is affected, its backup exists, and the report shows the actual outcome.
- [ ] Alter a selected target after collection; verify cleanup refuses it.
- [ ] Run direct `sc-cleanup.ps1 -sr -sa -avu -NoShare`; verify persistence still
      scans but cannot remove. Do not use lab-only `-ExecuteRemoval` on clients.
- [ ] Verify incomplete/access-denied collection is visibly incomplete, not clean.
- [ ] Inspect sanitized share JSON to confirm no raw persistence identifiers leak.

Owner-only gates remain: live Windows collection coverage, attended approval
UX, actual task/registry/startup mutation, rollback usefulness and quarantine
restoration. Agents must not provision a VM or run live scanners/removers.

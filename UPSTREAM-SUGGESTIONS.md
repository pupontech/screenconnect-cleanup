# Suggestions from field use of v1.8.12-beta.1 (offline run, keep-legitimate-instances)

Thanks for the tool. We used it on real Windows 10 PCs and made a few local changes. Everything
below is something we hit or built; each item says how sure we are. We can send any of it as a PR
against the current main if you want it.

## 1. `preflight.ps1` fails when the Sysinternals tool pack is not staged (blocks offline use)

**What happened.** Running the guided runner on a PC with no internet, preflight created the
restore point and exported the hives, then stopped. `master.log` ended at
`[OK] restore point + hive export` and never reached `[OK] tool pack verified`, so
`Test-ToolPack` failed and the run exited.

**Why it matters.** As far as we can tell, none of the guided steps use the pack (only the direct
runner's opt-in Procmon stage does), yet preflight treats a missing pack as fatal.

**What we did.** New `-SkipToolPack` switch on `preflight.ps1`; `START-HERE.bat` passes it when
the tool-pack download step is skipped. The full run is unchanged (still requires the pack).
Confidence: verified by a real run past that point; the pack is not used elsewhere in the guided
path (grep, not exhaustive runtime proof).

## 2. `START-HERE.bat`: run-folder creation line fails (caret inside quotes)

The line that builds the run root pipes `New-Item ... ^| Out-Null` inside a double-quoted
PowerShell command. cmd passes a caret inside quotes through literally, so PowerShell sees
`^` as a positional parameter ("A positional parameter cannot be found that accepts argument
'^'") and `New-Item` fails. The folder only exists later because preflight creates a nested one
with `-Force`. We replaced it with `$null = New-Item ...` (no pipe, nothing to escape).
Confidence: reproduced in isolation.

## 3. Offline / online split of the guided runner

`START-HERE.bat` accepts `--offline`, `--online`, `--stage` (no flag = the full run, call-for-call
identical to 1.8.12-beta.1 in our stub test). The offline half does preflight, snapshots,
detection, removal, persistence review, diff and a local report (`-NoUpload`); the online half
stages and runs KVRT/ESET/Malwarebytes, optional AV uninstall and shares the report. The phase
travels as a command-line argument so it survives the UAC relaunch, and the halves hand over
through a small `phase-offline.json` marker. Includes a stubbed test harness (79 checks).
Caveat: persistence review moves before the scanners in the offline flow.

## 4. Opt-in "keep legitimate ScreenConnect instances"

`Invoke-ReviewAndRemove.ps1 -SelectKeep` (and `-KeepIdentifier`) lets the technician mark
instances that are supposed to be there (for example a customer's own support agent) before the
single remove prompt. Kept instances are left out of `plan.json`, so the engine never sees them.
`remove-screenconnect.ps1` already accepts `PARTIAL_REMOVE`, so no engine change was needed. The
report labels them KEPT. The default stays remove-all (your single-confirmation directive);
this is opt-in via separate launchers. Tests run the real review script (35 checks); a dry run of
the real remover processed only the non-kept instances.

## 5. Persistence inventory timed out at the final write

On one Windows 10 Pro PC (PowerShell 5.1.19041) the inventory finished every collector, then
`WriteInventory` exceeded the 60 s section limit: result `Incomplete`, removal skipped, exit 1,
and the inventory file was never written. Our guess is the single `ConvertTo-Json -Depth 12` of
the whole result is slow in 5.1, but we have not confirmed that. We raised the section/total
limits for our offline launcher (240 s / 600 s) as a workaround. A real fix may be to write the
file section by section, or to exclude the serialize step from the per-section clock.
Confidence: the timeout is observed; the cause is a hypothesis.

## 6. Smaller observations (unverified causes)

- `collect-snapshot.ps1` reported `Invalid class` for the Connections and FirewallRules sections
  and a locked Amcache hive on that same PC, so `CollectionComplete` was false and the diff verdict
  was INCOMPLETE. We did not investigate whether a fallback (netstat / netsh advfirewall, or
  copying Amcache via a VSS snapshot) would help.
- The batch file's own console output (step banners, WARN lines) is not saved anywhere; only the
  individual scripts write logs. A single transcript of the whole run would help when a step fails.
- A real run leaves a few hundred MB of hive exports and `SRUDB_*.dat` copies in the run folder
  per attempt; a note in the docs about cleaning up repeated attempts might save disk space.

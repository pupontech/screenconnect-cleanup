# Running it in two halves: offline cleanup, online scan + share

The guided runner used to go online in its very first step (it downloads the
tool pack and the scanners) and again at the end (report upload). That made it
impossible to run on a PC with no connection, or on a PC you deliberately took
off the network. It is now split by one question: **does this step need the
internet?**

| Launcher | Half | Needs internet? | What it does |
|---|---|---|---|
| `START-HERE-OFFLINE.bat` | 1 - cleanup (steps 1-7) | **No. Nothing is downloaded or uploaded.** | preflight, before snapshot, detection, ScreenConnect removal (one typed confirmation), persistence review, optional power-options repair, after snapshot + diff, local report + package |
| `START-HERE-ONLINE.bat` | 2 - scan + share (steps 1-5) | **Yes** | stages KVRT / ESET (and the tool pack), runs the attended scanners (KVRT, ESET, Malwarebytes), optional AV uninstall, shares the sanitized report |

Only these two launchers ship in the deploy zip. Each self-elevates once (UAC).
Each half numbers only its own steps: the offline screen shows 1-7, the online
screen 1-5, and neither lists the other half's steps as "skipped".
`START-HERE.bat` is the engine both call; run on its own (no flag) it is still
the original full run, unchanged, with its 1-9 numbering. It also still accepts
`--stage` (download only, no admin) and `--select` (see below), which no longer
have launchers of their own.

## Typical jobs

**A PC you want cut off from the network while you clean it** (for example a
scam victim's PC with an active remote session):

1. Unplug the cable / turn Wi-Fi off. Run `START-HERE-OFFLINE.bat`.
2. Read the report (it opens by itself and a copy lands on the Desktop).
3. Reconnect. Run `START-HERE-ONLINE.bat` for the scanners and the share.

**A PC that will never be online** (or you only want the cleanup): run only
`START-HERE-OFFLINE.bat`. The package `connectwise-report.zip` and `report.html`
stay in the run folder under `C:\RIT-SCC\`. Nothing is shared.

**Preparing a USB stick or a folder for a no-connection job:** nothing to
prepare - the offline half needs no downloads. (`START-HERE.bat --stage` from a
command prompt still downloads the scanners and tool pack into the folder.)

## How the two halves hand over

**Only locked run folders are continued.** `C:\RIT-SCC` inherits "Authenticated
Users: Modify" from `C:\`, so anything running as a normal user could create or
edit run folders there - including the intruder this tool is removing, during the
hours between the two halves. The offline half therefore creates its run folder
already locked (Administrators/SYSTEM write, Users read only, no inheritance;
`tools\RunRootSecurity.psm1`). The online half continues a run only when its folder
is still locked, is not a junction or symlink, and its `findings.json` lies on a real
path inside it. Any other folder is skipped with a visible "Not continuing ..." line.
Runs made by builds before offline.3 were never locked and cannot be continued.

**The online half checks persistence again after the scanners**, as the full run
does (a scanner can remove or reveal startup items). That second pass goes to
`after-scans\persistence` (the offline results are never overwritten); the report is
rebuilt from it as `report-after-scans.html`, and that is what gets shared. The
offline `report.html` stays as it was.

When the offline half finishes it writes `phase-offline.json` into its run
folder (`C:\RIT-SCC\<PC>-<id>`). The online half looks for the newest such
folder for this PC, shows it, and asks `Continue that run? [Y/n]`. It then
adds the scanner results to that same folder and shares **that run's** report,
so the instance details found by the cleanup (relay host and so on) are what
get shared. When it finishes it writes `phase-online.json` and refreshes the
Desktop copy of `report.html` (the share adds the paste link to it).

If there is no finished offline run (or you answer `n`), the online half does a
**scanner-only** run: it stages and runs the scanners and shares nothing,
because there is no report to share. The scanner results are under `logs\` in
that run folder.

## Differences from the full run you should know about

- **Order.** In the full run the persistence investigation comes *after* the
  scanners. In the split it comes in the offline half, *before* them, because
  the offline half cannot run scanners. If a scanner then removes or
  quarantines something, run `START-HERE-OFFLINE.bat` again: it makes a fresh
  run folder and repeats detection and the persistence review (the persistence
  scan refuses to write into a run folder that already has results, so it
  cannot simply be repeated inside the same one).
- **Package without upload.** The offline half builds `connectwise-report.zip`
  with `-NoUpload`. The online half runs the sharer again, which makes a second,
  timestamp-named zip in the same folder (the existing one is never overwritten).
- **Malwarebytes** is still installed when its step runs (winget, then the
  official installer download), so it belongs to the online half. It is not
  pre-staged by `START-HERE.bat --stage`.
- **KVRT and the ESET Online Scanner are online scanners.** They fetch fresh
  databases when they start, so they are in the online half on purpose.
- **AV uninstall** (attended, default No) is in the online half, after the
  scanners, as in the full run. Its Malwarebytes path uses winget.
- **The Sysinternals tool pack is not used by the guided steps** (only the
  direct runner's opt-in Procmon stage uses it), but `preflight.ps1` used to
  *require* it and failed without it. The offline half now runs preflight with
  `-SkipToolPack`, so a PC that never had the pack still gets through (the master
  log says `[SKIPPED] tool pack check`). The full run and the online half are
  unchanged. `START-HERE.bat --stage` still fetches the pack so `sc-cleanup.ps1
  -offline` has what it needs.

## Keeping legitimate ScreenConnect instances (select mode)

Some PCs have a ScreenConnect that is supposed to be there (the customer's own
support agent, for example). By default every detected instance is removed after
one typed `y`. When `START-HERE-OFFLINE.bat` finds ScreenConnect, Step 4 lists the
instances (numbered, with relay host:port) and asks first:

    Keep any ScreenConnect? [y/N]

Enter (or anything but `y`) keeps the default: remove all. `y` switches to select
mode. Nothing found = no question. (The full run
does not ask; `START-HERE.bat --select` turns select mode on without asking.)

In select mode every detected instance is listed with a number, its identifier, relay
host and port, service name and state, session type, signature, and install date.
The relay host is the main legit-or-not clue: a host you do not recognize is a
reason to remove it. Then:

- type the numbers to keep, for example `2` or `1,3`;
- `A` keeps all of them (nothing is removed);
- Enter alone keeps none (everything is removed, as in the normal launchers);
- anything else (a number not in the list, a letter) is rejected and asked again.

The tool then prints what will be kept and what will be removed, and the usual
single `y/N` removes only the instances that are **not** kept. Kept instances are
never put in the removal plan, so the removal engine does not see them: their
files, service and registry entries are left exactly as they are.

- **Record:** `kept-instances.json` in the run folder, and `KeptScreenConnectInstances`
  in `plan.json` (decision `PARTIAL_REMOVE`). The report shows each kept instance
  with a **KEPT** label and counts them in the section heading.
- **Scripted use:** `Invoke-ReviewAndRemove.ps1 -KeepIdentifier <id>[,<id>]` skips the
  question. An identifier that matches no detected instance stops the run with exit 2
  and removes nothing (a typo must never become "remove it").
- **Remove-all stays the default.** Only a typed `y` to the keep question changes it.

What select mode does **not** do:

- The antivirus scanners (online half) may flag a kept ScreenConnect as unwanted
  software. Decide at the scanner; this tool does not exclude it.
- The shared package/summary built from `findings.json` still lists the kept instance
  as detected (it comes from the detection results, before your choice). Only the
  local `report.html` carries the KEPT label.
- The kept choice is per run. It is not remembered; the next run asks again.
- The direct runner `sc-cleanup.ps1` has no select mode (unchanged).

## Direct runner

`sc-cleanup.ps1` already had `-offline` (use the pre-staged pack, download
nothing) and `-sa` (no scanners), and `-NoShare` (no upload). The offline half
of the guided runner is the equivalent of `-offline -sa -NoShare` for that
runner; nothing about `sc-cleanup.ps1` changed.

## What changed in the code

- `START-HERE.bat`: new `--offline`, `--online` and `--stage` arguments (the
  wrapper launchers pass them; no argument = the original full run). The
  phase flag is a command-line argument, not an environment variable, so it
  survives the UAC relaunch. Steps are skipped with `goto`, never re-ordered.
- `preflight.ps1`: new `-SkipToolPack` switch; `START-HERE.bat` passes it in the
  offline half. Found on the first real-PC test (2026-11-09): preflight stopped
  right after the registry export because the tool pack was not there.
- The offline half gives the persistence inventory longer limits (section 240 s,
  total 600 s). On the second real test the final inventory write exceeded the
  default 60 s, so the result was Incomplete and the run exited 1. The cleanup
  itself was unaffected, but an Incomplete inventory cannot be called clean.
- New: `START-HERE-OFFLINE.bat`, `START-HERE-ONLINE.bat`,
  `tools\Write-PhaseMarker.ps1`,
  `tools\Find-OfflineRun.ps1`, `tests\Test-PhaseSplit.ps1`.
- Fixed on the way: the run-folder creation line piped `New-Item` to `Out-Null`
  with a caret-escaped pipe inside double quotes; cmd passes a caret inside
  quotes through literally, so `New-Item` failed with "A positional parameter
  cannot be found that accepts argument '^'" and the folder was only created
  later as a side effect of preflight. The new `:new_run_root` routine creates
  it properly (needed by the online half's scanner-only run, which has no
  preflight).

## Testing

`tests\Test-PhaseSplit.ps1` (needs no admin, runs on any Windows PC) copies the
tool, replaces every script with a stub that only records how it was called,
drives each launcher with scripted answers, and checks which steps ran. It
also runs the original `START-HERE.bat` (`-OriginalBat <path>`) and confirms
the full run makes the same calls in the same order. Result at the time of
writing: 79 of 79 checks pass (plus 35 in Test-KeepSelection.ps1) (the stubs replace preflight, so they check the
arguments it is given, not what it does - that is how the tool-pack failure got
past them until the first real test); three deliberate breakages (scanners in the
offline half, upload in the offline half, detection repeated in the online half)
were each caught.

**Not verified here (needs a real Windows PC, owner acceptance):**

- The real UAC relaunch carrying `--offline` / `--online` (the test pretends
  the window is already elevated; the code path is checked statically).
- That the offline half really makes no network request on a PC with no
  network. Every script it runs was searched for network calls and none were
  found, but the whole half has not been run with the cable out.
- The upstream CI contract tests (`tests/ci/*`) were not in this folder, so
  they were not run. `START-HERE.bat` changed (the UAC relaunch now passes the
  phase flag, steps are guarded), so contract tests that match its exact text
  may need updating. `make-deploy-bundle.sh` was also not in this folder: add
  the new files above to it, or they will be missing from the next release zip.

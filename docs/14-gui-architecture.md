# GUI architecture

Status (2026-11-10, `1.8.12-beta.1-offline.2`, branch `offline-split`):
**phases 0 to 4 are built and tested against stubs; nothing has been accepted on a real PC.**
The start panel toggles Offline half / Online half / Detect only / Stage tools (the Full run is
not offered in the window - owner, 2026-11-10: it is only Offline followed by Online; the core
keeps the Full mode so the parity test can still prove it against `START-HERE.bat`), asks
the batch file's questions, and removal needs the typed word `REMOVE`. The removal path has been
exercised only with the real `Invoke-ReviewAndRemove.ps1` and a STUBBED remover - never a real
removal. Phase 5 (view-only history of earlier runs, bundle, docs/09 rows) is partly done
(zip verified; history is a plain list). See **section 12** for what the spikes found,
including corrections to this design. Anything still marked VERIFY below has not been run on a
real PC.

This document says what was built, in what order the rest should be built, and what must
not be built.

---

## 1. The one rule

**The GUI is a third front end, not a third engine.**

It starts the same child scripts `START-HERE.bat` starts, with the same
arguments, in the same order, each in its own `powershell.exe` process, and it
shows the artifacts those scripts already write to the run folder. It contains
no detection, snapshot, removal, scanner, persistence or report logic.

This rule comes from the two earlier attempts, both still unmerged:

| Branch | What it was | Why it stalled |
|---|---|---|
| `gui-revision-screenconnect-cleaner` | PowerShell + WPF with its own `Scc.*` module tree (about 23,000 added lines) | Re-implemented the pipeline, so it fell behind `main`'s safety work (docs/08 notes it still has the pre-fix report ordering). Ran engine code in-process in a runspace pool, the suspected source of the `CommandAlreadyExists` report (docs/11). |
| `feat/minimal-wpf-gui` | .NET 10 WPF client (about 20,000 added lines) | A compiled EXE is a rejected option (docs/02: trips AV on the machines being investigated). Running unelevated forced an elevated-helper design with a protected install, manifests and pinning, which is far more machinery than the tool it wraps. Removal was never enabled. |

Its `design.md` reached the right conclusions (one engine, thin adapter, no
runspaces, no second module tree). This design keeps those and drops the parts
that made it large.

If a GUI feature needs a line of engine logic, the change goes into the engine
script (additive, with a test), and the GUI calls it. Never the other way round.

---

## 2. Decisions

| # | Decision | Reason |
|---|---|---|
| G1 | **PowerShell 5.1 + WPF**, XAML loaded at run time with `XamlReader`. No compiled binary, no NuGet packages, no .NET install. | Runs on a client PC as found; same house rules as every other script (ASCII, no BOM, 5.1). WPF over WinForms because WinForms under `powershell.exe` is not DPI-aware and clips on scaled laptop screens. |
| G2 | **The GUI process is elevated from the start.** The launcher self-elevates once, exactly like `START-HERE.bat`. | Every guided step already runs elevated. One process, one UAC prompt, no helper, no IPC, no protected install. |
| G3 | **Every engine step is a child `powershell.exe -File` process.** Nothing from the engine is dot-sourced or imported into the GUI process. | Same isolation the batch runner has. Avoids the session-state corruption of the earlier branch. A crashing step cannot take the window down. |
| G4 | **One UI thread, one `DispatcherTimer`. No runspaces, no `Register-ObjectEvent`, no script blocks on thread-pool threads.** The timer polls the running child. | In PowerShell, a script-block event handler that fires on another thread has no runspace. Polling from the UI thread removes the whole problem class. `Invoke-PersistenceScan.ps1:90-114` already polls `ReadLineAsync` tasks this way. |
| G5 | **Prompts stay in the engine.** The GUI answers a child's `Read-Host` by writing to its redirected stdin, only after the technician answered the matching dialog. No `-Yes`-style approval switch is added. | docs/06 rule 2: no flag that removes without the confirmation. The gate stays where it is tested; the GUI is a different keyboard. |
| G6 | **The run folder is the only source of truth.** The GUI derives what to show from artifacts and exit codes. Its own session file is display-only and never authorizes anything. | Same rule as the batch runner: only findings produced in this run may reach removal. |
| G7 | **`START-HERE*.bat` stay, unchanged, and remain the fallback.** | The GUI is unproven; the batch runner is field-tested. A tech can always drop back. |
| G8 | **The GUI mirrors the guided runner (`START-HERE.bat`), not `sc-cleanup.ps1`.** Same step numbers (1-9, 6a-6e) on screen. | That is the flow technicians know and the one the tests and docs describe. |

Not decided here, owner to rule (section 11): typed word versus button for the
removal confirmation, and whether keep-selection is always visible.

---

## 3. Files

```text
START-HERE-GUI.bat            launcher: same preamble as START-HERE.bat, then starts the GUI
gui/
  Start-CleanupGui.ps1        entry: loads XAML, wires controls, owns the DispatcherTimer
  Gui.Core.psm1               NO WPF types: step catalog, command lines, state machine,
                              prompt table, artifact readers. Testable without a desktop.
  MainWindow.xaml             the one window (pure ASCII)
  steps.json                  step catalog as data (section 5)
tests/gui/
  Test-GuiCallParity.ps1      GUI core makes the same calls as START-HERE.bat (section 9)
  Test-GuiPromptContract.ps1  every prompt pattern still exists in the engine
  Test-GuiArtifactReaders.ps1 readers against fixture run folders
```

About 1,500 lines is the budget. If it heads past 3,000, something from the
engine is being rebuilt; stop and check against section 1.

`Gui.Core.psm1` must not reference `System.Windows.*`. That split is what makes
the logic testable in CI and on Linux `pwsh`, like the rest of the repo.

Also to update when the files land: `make-deploy-bundle.sh` (new files are
missing from the zip otherwise - this bit the offline split),
`tests/verify_deploy_zip.py`, the `Test-Parse.ps1` and `Test-HouseRules.ps1`
script lists, `README.md`, `DEPLOY.md`, `CHANGELOG.md`.

---

## 4. Process model

### 4.1 Launcher

`START-HERE-GUI.bat` copies the `START-HERE.bat` preamble unchanged, because
each part exists for a bug that was already paid for:

1. capture `%~dp0` / `%~f0` before delayed expansion (paths with parentheses);
2. re-run inside a dedicated `cmd.exe` (bounded lifetime for the keep-awake helper);
3. single UAC request with `--elevation-attempted` (never loop the prompt);
4. `tools\Confirm-OnBattery.ps1` (it already shows its own dialog);
5. start `tools\Keep-Awake.ps1` hidden;
6. then, instead of the steps:
   `powershell -NoLogo -NoProfile -STA -ExecutionPolicy Bypass -File "!SCC_DP0!gui\Start-CleanupGui.ps1"`

`-STA` is required for WPF. Do not pass `-NonInteractive` anywhere: it makes
`Read-Host` throw in the children.

VERIFY: `Keep-Awake.ps1` watches the runner's `cmd.exe`. Confirm it still
finds it when the foreground child is the GUI and not the step sequence.

The console window stays open behind the GUI. Leave it: if the window fails to
load, the error is readable there instead of vanishing.

### 4.2 Running one step

```text
click or auto-advance
  -> Gui.Core builds the argument list from steps.json + session answers
  -> System.Diagnostics.Process: powershell.exe -NoProfile -ExecutionPolicy Bypass -File <script> <args>
       UseShellExecute=false, CreateNoWindow=true,
       RedirectStandardOutput / RedirectStandardError / RedirectStandardInput = true
  -> DispatcherTimer tick (every 250 ms), on the UI thread:
       drain stdout and stderr      append to the log pane and to <run>\logs\gui-console.log
       check the prompt table       pending text matches -> show the dialog (4.3)
       check HasExited              yes -> read exit code, read artifacts, decide next step
```

Details that matter:

- **Read characters, not lines.** The engine prints its prompts with
  `Write-Host ... -NoNewline` and then calls `Read-Host`. A line reader never
  returns that text, so the GUI would wait forever on a prompt it cannot see.
  Keep one pending `StandardOutput.ReadAsync(char[],0,n)` task per stream; on
  each tick, while the task is completed, take the characters and start the
  next read. Complete lines go to the log; the unfinished tail is what the
  prompt table looks at.
- Pass arguments as a built string with each value quoted by one helper. Paths
  contain spaces and parentheses. Never go through `cmd.exe`.
- Set `StandardOutputEncoding` explicitly. VERIFY which code page a redirected
  `powershell.exe` 5.1 writes on a Hebrew-locale Windows.
- One child at a time. The Next button and every step button are disabled
  while a child runs.
- The GUI sets no timeouts and never kills a scanner. The engine has its own
  caps (240 minutes per scanner, persistence inventory limits). The GUI shows
  an elapsed clock and "no output for N minutes" as information only.

### 4.3 Prompts

Three kinds of question exist today, and each gets a different treatment.

**A. Questions the batch file asks (`set /p`).** The GUI owns these; they
become buttons. No engine involvement.

| Batch prompt | Default | In the GUI |
|---|---|---|
| Continue that run? (online half) | Y | start screen: "Continue run <folder>" preselected |
| Launch KVRT / ESET / Malwarebytes? | Y | Launch and Skip buttons on each scanner card |
| Open the review windows now? | Y | button on the persistence screen (once only, see 6) |
| Run installed-AV uninstall now? | N | button, not preselected |
| Repair missing power options? | N | unticked box |
| Reset local Group Policy folders? | N | unticked box, enabled only when the one above is ticked |
| Restart now through CMD? | N | button, shown only under the batch file's three conditions |

**B. Questions a script asks with `Read-Host`.** Answered over stdin. The
prompt table in `Gui.Core.psm1` maps the pending output tail to a dialog and
to the text to send.

| Script | Prompt (pattern to match) | Dialog | Sent |
|---|---|---|---|
| `preflight.ps1:163`, `Invoke-ReviewAndRemove.ps1:104` | low disk, `Continue anyway? [y/N]` | warning with the measured free space from the lines above; Continue / Stop | `y` or `n` |
| `preflight.ps1:383` | `Type Y once UAC is enabled, or F to force-continue` | the script's own red text; "UAC is now enabled" / "Force continue" / "Stop" | `Y`, `F`, or empty line (the script aborts on empty) |
| `Invoke-ReviewAndRemove.ps1:317` | `Remove all detected ScreenConnect instances? [y/N]` or `Remove the instances that are NOT kept? [y/N]` | removal confirmation (section 6, step 5) | `y` or `n` |
| `Invoke-GUIScanner.ps1:219` | `When installation is finished, type DONE` | "Malwarebytes installation finished" / "Cancel this scanner" | `DONE` or `CANCEL` |
| `Invoke-GUIScanner.ps1:254` | `When the Malwarebytes scan is finished ... type DONE` | "Scan finished and window closed" / "Cancel this scanner" | `DONE` or `CANCEL` |
| `Persistence.Removal.psm1:206` | `Enter comma-separated candidate indices` | pick list of candidates (section 6, step 6d) | the indices, or empty |
| `Persistence.Removal.psm1:216` | `Type REMOVE to confirm these exact targets` | text box; the technician types the word | exactly what was typed |

The keep-selection question (`Invoke-ReviewAndRemove.ps1:259`) is never
reached: the GUI passes `-KeepIdentifier` instead, which the script already
supports and validates (an identifier that matches nothing exits 2 and removes
nothing).

Rules for kind B:

1. The GUI writes an affirmative answer **only** as the direct result of a
   click in a dialog that named the thing being approved. Never from a
   remembered setting, never pre-typed, never on a timer.
2. Closing a dialog with the window X sends the script's own default (the
   refusing answer). It never sends yes.
3. For `Type REMOVE`, the GUI forwards the technician's own keystrokes. It does
   not offer a button that types the word.
4. **Unknown prompt fallback.** If the child is alive, has printed nothing for
   5 seconds, and the unfinished tail matches no pattern, show a generic box:
   "The tool is waiting for an answer:", the tail text, a text field, Send. An
   engine prompt that was added or reworded then degrades to a plain dialog
   instead of hanging the window.
5. `Test-GuiPromptContract.ps1` greps the engine for every pattern in the
   table and fails when one is gone, so a reworded prompt breaks CI, not a
   site visit.

**C. Dialogs a script shows itself** (`Confirm-OnBattery.ps1`). Leave alone.

VERIFY (spike S1): a redirected-stdin `powershell.exe -File` child returns the
written line from `Read-Host` on Windows PowerShell 5.1. The repo's tests
already drive the scripts with piped answers, so this is expected to hold.

---

## 5. Step catalog

`steps.json` is the single list of steps. `Gui.Core` turns an entry plus the
session answers into one command line. It is data so the parity test
(section 9) can walk it. One entry:

```json
{
  "Id": "5",
  "Title": "Review / remove ScreenConnect",
  "Script": "Invoke-ReviewAndRemove.ps1",
  "Args": ["-FindingsJson", "{FindingsJson}", "-WorkDir", "{RunRoot}", "{KeepArgs}"],
  "Phases": ["ALL", "OFFLINE"],
  "RunWhen": "FindingsJsonExists",
  "OnNonZero": "WarnAndContinue",
  "Destructive": true
}
```

Phases and what they skip are exactly the batch file's `SCC_DO_*` switches:

| Mode | Launcher equivalent | Runs |
|---|---|---|
| Full | `START-HERE.bat` | 1, 2, 3, 4, 5, 6a-c, 6d, 6e, 7, 8, 9 |
| Offline half | `START-HERE-OFFLINE.bat` | 2 (`-SkipToolPack`), 3, 4, 5, 6d (longer limits), 6e, 8, 9 (`-NoUpload`), then `phase-offline.json` |
| Online half | `START-HERE-ONLINE.bat` | 1, 6a-c, 7, share, then `phase-online.json`; continues the run found by `tools\Find-OfflineRun.ps1` or does a scanner-only run |
| Stage tools | `STAGE-TOOLS-ONLINE.bat` | downloads only; needs no elevation and no run folder |

What happens after each step is also copied from the batch file, not redesigned:

| Step | Non-zero exit means |
|---|---|
| 2 preflight | stop. No detection, no removal. |
| 3 before snapshot (or file missing) | stop. No removal. |
| 4 detection | stop. Never fall back to older findings. |
| 5 removal | warn, remember the code, **continue** to after-evidence and report |
| 6a-c scanners | warn, continue |
| 6d persistence | warn "incomplete", continue |
| 7 AV uninstall, 8 power repair | warn, continue |
| 8 diff | 0 clean, 1 **resurrection found** (a finding, not a failure), 2 or more diff failed |
| 9 report / share | warn; the local report stays |

The run's final status is the first non-zero code, as `PIPE_RC` is today.

The run folder is created the way `:new_run_root` does it
(`C:\RIT-SCC\<PC>-<guid>`), and `FindingsJson` is searched only under this
run's `detect\` folder.

---

## 6. Window

One window, about 1100 x 700, resizable, usable at 1366 x 768. English only.

```text
+----------------------------------------------------------------------------+
| ScreenConnect Cleanup  v<VERSION>     PC: <name>     Mode: Offline half    |
| Run: C:\RIT-SCC\<PC>-<id>   [Open folder]                                  |
+----------------+-----------------------------------------------------------+
| 1 Tools     ok |                                                           |
| 2 Preflight ok |   <the panel for the selected step>                       |
| 3 Snapshot  ok |                                                           |
| 4 Detect    ok |                                                           |
| 5 Remove    >> |                                                           |
| 6 Scanners  -- |                                                           |
| 6d Persist.    |                                                           |
| 7 AV remove    |                                                           |
| 8 Diff         |                                                           |
| 9 Report       |                                                           |
+----------------+-----------------------------------------------------------+
| Console output (live)                                     [Copy] [Open log]|
+----------------------------------------------------------------------------+
```

Step states: waiting, running, done, done with warning, failed, skipped,
skipped in this mode. Each has a word, not only a colour. A skipped step says
why ("needs internet - run the online half").

The stepper moves forward only. Finished steps can be clicked to look at their
output; they cannot be run again, with two exceptions: a scanner whose launch
failed, and the report share. This is a hard limit of the engine, not a UI
choice: `Invoke-PersistenceScan.ps1` and `Show-PersistenceReview.ps1` refuse a
run folder that already holds their results. "Start a new run" is the answer
to "do it again".

Panels:

- **Start.** Four mode buttons with one sentence each. Online half shows the
  run it would continue. Nothing runs until a mode is chosen.
- **1-4 (automatic).** A line of status per step, then auto-advance. On
  failure: the stop message from the table in section 5 and an Open log button.
- **5 Review / remove.** One card per ScreenConnect instance from
  `findings.json`, with the same fields the select launcher prints: identifier,
  **relay host and port (largest text - it is the decision key)**, session
  type, service name and state, signature, install date (UTC), install
  directory. Each card has Remove (default) / Keep. Other remote-access
  products are a plain list labelled "reported only - this tool never removes
  these". Below: "Remove N, keep M" and one Continue button. The script then
  runs, prints its own summary into the console pane, and its confirmation
  prompt opens the confirmation dialog, which lists the same instances again
  and says "Files are quarantined, never deleted". Zero instances: "nothing to
  remove", advance.
  **No verdicts.** The GUI must not colour, rank or label a relay host as
  safe, known or suspicious. Decision D4 (no allowlist, the technician decides)
  applies to the screen as much as to the engine.
- **6 Scanners.** Three cards: KVRT, ESET, Malwarebytes. Each shows staged or
  not staged, Launch / Skip, then running with elapsed time, then the status
  the engine recorded. A skipped or failed scanner stays visible as skipped or
  failed (docs/06 rules 9 and 10).
- **6d Persistence.** Runs automatically. Shows the inventory status
  (Complete / Incomplete) and the findings from `persistence\inventory.json`
  as a table. Heading text: "Heuristic matches, not malware verdicts". The
  script's two prompts drive the selection list and the typed REMOVE box. When
  rollback prerequisites are missing the engine does not offer removal; the
  GUI shows that as the reason, it does not work around it. One button:
  "Open review windows" (6e).
- **7 AV uninstall.** Explanatory text from the batch file and one button,
  not preselected.
- **8 Repair + diff.** The two unticked boxes, then Continue. Result banner:
  Clean / RESURRECTION DETECTED / INCOMPLETE / diff failed.
- **9 Report.** Share result and the paste URL (or "not shared" with the
  reason), Open report, Open run folder, Desktop-copy result, final status.
  The restart button appears only when a repair ran, the report was written
  and it opened - the batch file's conditions.

Artifacts each panel reads (all under the run root; read-only, tolerate
missing or half-written files by showing "not available yet"):

| Panel | Files |
|---|---|
| 5 | `detect\<host>_<stamp>\findings.json`, `plan.json`, `kept-instances.json`, `removal-manifest.json`, `removal-report.txt` |
| 6 | `logs\scanner-*-result.json` |
| 6d | `persistence\inventory.json`, `removal.json`, `result.json`, `collection-progress.log` |
| 7, 8 | `logs\av-uninstall-results.json`, `power-options-repair.json`, `snapshot_diff.json` |
| 9 | `report.html`, `connectwise-report.zip`, `phase-offline.json`, `phase-online.json` |

VERIFY the exact scanner result file names for KVRT and ESET in the guided
path before writing that reader; only the Malwarebytes one is passed
explicitly by the batch file.

Readers follow the PS 5.1 traps in docs/06: `@($x).Count`, and
`ConvertFrom-Json` gives objects, not hashtables.

---

## 7. Closing, cancelling, crashing

- **Close while idle:** closes.
- **Close during a read-only step** (1-4, 6d inventory, 8 snapshot/diff, 9):
  ask, then end the child process tree.
- **Close during step 5, the persistence removal, AV uninstall or power
  repair:** refuse while the child runs. "Removal is in progress. Closing now
  can leave the PC half cleaned. Wait for this step to finish." There is no
  Cancel button on these steps.
- **Close while a scanner is open:** ask; leaving does not close the scanner.
- **The GUI dies:** the child keeps its own files. On next start, the Start
  screen lists the newest run folders for this PC as "view only". It never
  resumes a step and never replays removal. (The 3010 reboot-resume task in
  `remove-screenconnect.ps1` is the engine's business and is untouched.)
- Unhandled error in the GUI: a `DispatcherUnhandledException` handler writes
  it to `<run>\logs\gui-error.log`, shows it, and leaves a running child alone.

`<run>\gui-session.json` records mode, step states and exit codes for the
view-only list. It is display data. Nothing reads it to decide whether a step
may run.

---

## 8. What must not be built

- A second copy of any engine logic, or any import of engine modules into the
  GUI process.
- Runspaces, jobs, or background threads running PowerShell.
- A compiled EXE, an installer, auto-update, a settings database.
- A flag or setting that confirms removal without the technician acting in
  that run. No "remember my choice", no unattended mode.
- Relay-host reputation, allowlists, or any trusted / suspicious label (D4).
- Timeouts that kill engine steps, or silent scanner flags.
- A way to pick an older `findings.json` for removal.
- Changes to `START-HERE*.bat` behaviour.

---

## 9. Tests

1. **Call parity (the acceptance test).** `tests\Test-PhaseSplit.ps1` already
   replaces every script with a stub that records `script|arguments` and
   compares launchers. Reuse that harness: drive `Gui.Core` headless (no
   window) with the same answers and require the same trace as
   `START-HERE.bat` for Full, Offline, Online (with and without a prior run),
   Stage, and both select variants. This is what keeps the GUI from drifting.
2. **Prompt contract** (4.3 rule 5).
3. **Prompt handling:** a stub child that prints a no-newline prompt and
   echoes what it read; cover each table row, window-X = default, and the
   unknown-prompt fallback.
4. **Artifact readers** against fixture run folders: complete, empty,
   truncated JSON, one instance (the single-element array trap), zero.
5. **House rules:** add `gui\*.ps1`, `gui\*.psm1`, the XAML and the new
   launcher to the parse, ASCII, no-BOM and CRLF checks.
6. **Window smoke on Windows CI:** load the XAML, find every named control,
   close. No clicks through real steps.

Not testable by an agent, owner on a real PC (add to docs/09): the UAC
relaunch, a real removal through the dialog, each scanner launched from the
GUI, a 125% and 150% scaled laptop screen, and a run with UAC disabled.

---

## 10. Build order

Each phase ships only when the one before is accepted. Read-only before
destructive, as with the engine.

**Done 2026-11-10: phases 0 to 4 against stubs** (spike answers in 12.2). The owner asked for the
offline / online toggle, so phases 3 and 4 were built without waiting for phase 2's real-PC
acceptance; every real-PC check in 12.4 is therefore still open and covers all of them.
Phase 5: zip verified, history list only.

| Phase | Builds | Done when |
|---|---|---|
| 0 Spikes | throwaway scripts for S1-S6 below | each has a yes/no answer written into this file |
| 1 Core | `Gui.Core.psm1`, `steps.json`, tests 1, 2, 4 | call parity passes with no window at all |
| 2 Detect-only window | launcher, window, steps 2-4, panel 5 as a viewer (no Continue button), report | a tech can run detection and read the cards on a real PC |
| 3 Offline half | step 5 with confirmation, 6d, 6e, 8, 9 local | owner removes a lab ScreenConnect through the GUI |
| 4 Online half and Full | step 1, scanners, AV uninstall, share, Stage mode | owner runs the full flow once on a lab PC |
| 5 Finish | view-only history, bundle, docs, docs/09 rows | release zip verified by `verify_deploy_zip.py` |

Spikes (phase 0):

- **S1** stdin answer reaches `Read-Host` in a redirected 5.1 child.
- **S2** character-level polling shows a `-NoNewline` prompt within one tick.
- **S3** a WPF window opens from an elevated `powershell.exe -STA` on stock
  Windows 10 and 11, including with UAC disabled.
- **S4** `-KeepIdentifier` with two identifiers through `powershell -File`.
  docs/06 warns that `-File` does not split arrays; if `a,b` arrives as one
  string the script exits 2. The fix, if needed, is a defensive split inside
  `Invoke-ReviewAndRemove.ps1`, with a test.
- **S5** with `CreateNoWindow=true` on the parent, the scanner windows, the
  winget install and the AV uninstallers still appear and can be driven.
- **S6** the keep-awake helper's lifetime under the GUI launcher (4.1).

---

## 11. Owner decisions needed before phase 3

The four proposals below were put to the owner on 2026-11-10 and the build went ahead on
them ("Implement"); they are **adopted as proposed, and the owner can overrule any of them
before phase 3 is built.** None of them affects phases 0 to 2.

1. **Removal confirmation: typed word or button?** The console asks for `y`.
   Adopted: the dialog needs the word `REMOVE` typed (as persistence cleanup
   already does), and the GUI then sends `y`. A plain button is easier to
   click by accident than `y` is to type.
2. **Keep / Remove on every card?** Adopted: yes, default Remove, so the two
   SELECT launchers become one screen and remove-all stays the default. The
   alternative is a "Select mode" tick box on the Start screen that mirrors
   the launchers exactly. (The core already supports it: it passes
   `-KeepIdentifier`, see 12.3. Cards whose identifier is missing, repeated or contains a
   comma are reported `KeepSelectable = $false` and must be Remove-only in the window.)
3. **Does the GUI replace `START-HERE.bat` as the documented entry point, or
   sit beside it?** Adopted: beside it until phase 4 is accepted in the field.
   `START-HERE-GUI.bat` ships next to the other launchers.
4. **Fate of the two old GUI branches.** Adopted: leave them unmerged, close
   their PRs with a pointer to this document once phase 2 is accepted.

---

## 12. What was built, and what the spikes found (2026-11-10)

### 12.1 Built

| Path | What it is |
|---|---|
| `START-HERE-GUI.bat` | Launcher. Same preamble as `START-HERE.bat`, pinned line for line by `tests\gui\Test-GuiLauncher.ps1`; then `powershell -STA -File gui\Start-CleanupGui.ps1`. |
| `gui\steps.json` | The step catalog as data (20 steps, 5 modes: Full, Offline, Online, Stage, Detect; the window offers all but Full). |
| `gui\Gui.Core.psm1` | No WPF types. Token expansion, the state machine, the child-process pump, prompt table, artifact readers. |
| `gui\MainWindow.xaml`, `gui\Start-CleanupGui.ps1` | The window: stepper, start panel, run panel with finding cards, live console, one `DispatcherTimer`. |
| `tests\gui\*` | Call parity, prompt contract, prompt handling (real child processes), artifact readers, launcher, live window. |

Also changed: `Invoke-ReviewAndRemove.ps1` (12.3), `make-deploy-bundle.sh`,
`tests\verify_deploy_zip.py`, `tests\ci\Test-HouseRules.ps1` (`.xaml`), `windows-ci.yml`.

### 12.2 Spike results

| Spike | Answer | Evidence |
|---|---|---|
| S1 stdin answer reaches `Read-Host` | **Yes**, on OEM code pages. **No** on UTF-8 (65001) until the GUI switches the console - see 12.3. | `Test-GuiPromptHandling.ps1`, run on 862 and on 65001. End to end against the real `Invoke-ReviewAndRemove.ps1`: `y`, `n`, `-KeepIdentifier a,b`. |
| S2 a `-NoNewline` prompt is visible within one tick | **Yes** for prompts written with `Write-Host -NoNewline`; **no** for prompts passed as `Read-Host '<text>'` - see 12.3. | same |
| S3 a WPF window opens from `powershell -STA` | **Yes** on this PC (Windows 11, non-elevated, interactive session). **Not yet proven**: elevated, Windows 10, UAC disabled, 125% / 150% scaling. | `Test-GuiWindow.ps1` drives the real window against stubs. |
| S4 `-KeepIdentifier` with two values via `-File` | **No, as written.** `-File` passes `a,b` as ONE string and drops a space-separated second value. Fixed in the engine - 12.3. | `Test-KeepSelection.ps1` (5 new cases), `Test-GuiPromptHandling.ps1`. |
| S5 `CreateNoWindow` hides scanner windows / winget / uninstallers | **Not run.** Needs a real PC with the scanners staged. Phase 4. | - |
| S6 keep-awake lifetime under the GUI launcher | **By construction yes**: Keep-Awake watches its parent `cmd.exe`, which stays alive as the GUI's foreground parent. **Not yet observed on a real PC.** | `Test-GuiLauncher.ps1` (call order only) |
| VERIFY: KVRT / ESET result file names | **There are none** in the guided path. `START-HERE.bat` passes `-ResultPath` for Malwarebytes only. The GUI shows the exit code for KVRT and ESET. | `Get-GuiScannerResult` |

### 12.3 Corrections to the design above

1. **UTF-8 console (65001) corrupts redirected stdin.** A redirected Windows PowerShell 5.1
   child that inherits a 65001 console returns U+FEFF + `y` from `Read-Host`, whatever
   the parent writes (raw bytes included). The engine's `y/N` loop in
   `Invoke-ReviewAndRemove.ps1` (`Trim().Substring(0,1)`) would then never accept it and
   would loop forever. OEM pages (437, 862) are clean. Windows 11's "Use Unicode UTF-8 for
   worldwide language support" makes 65001 a real field case. The GUI calls
   `Set-GuiConsoleEncoding` (switch the shared console to 437 for its lifetime) and
   restores it on exit, and writes answers as raw bytes (`Send-GuiAnswer`).
2. **Four prompts in the table (4.3, kind B) were invisible to a GUI**, because
   under redirected stdin `Read-Host '<text>'` never writes `<text>`:
   `Invoke-GUIScanner.ps1` (Malwarebytes DONE, twice) and `Persistence.Removal.psm1`
   (candidate indices, `Type REMOVE`). The other three (low disk, UAC, removal confirmation)
   already used `Write-Host '<text>' -NoNewline` + `Read-Host`. **Fixed 2026-11-10:** each of
   the four now also prints its text, guarded by `[Console]::IsInputRedirected`, and still
   passes the same text to `Read-Host` - so interactive output is unchanged and the mocks in
   `test_persistence_removal.ps1` / `test_malwarebytes_fallback.ps1`, which pick their answer
   from the prompt text, keep working (a first attempt with a bare `Read-Host` broke them).
   `Test-GuiPromptContract.ps1` asserts the guarded echo and that no row of the prompt table
   is invisible.
3. **`-KeepIdentifier a,b` did not work through `powershell -File`** although
   `OFFLINE-ONLINE-SPLIT.md` documents it. `Invoke-ReviewAndRemove.ps1` now splits a
   value that matches no identifier as a whole on commas (a whole-string match still
   wins, so an identifier containing a comma keeps working; each part must still match
   or the run exits 2 and removes nothing). The GUI passes one comma-joined string.
4. **The generic "waiting for an answer" box** (4.3 rule 4) fires only on an
   **unfinished** line that has been quiet for 5 s, not on any quiet child: a long scan that
   keeps ending its lines must not look like a question. Dismissing it is remembered for
   that text.

### 12.5 Merged with 1.8.12-offline-alpha.1 (`origin/offline-split` 88f2dbd, 9270629)

The batch file changed underneath the GUI; the catalog and core follow it call for call:

1. **Locked offline run folder.** `START-HERE.bat --offline` now creates its run folder with
   `tools\RunRootSecurity.psm1` (`New-SccProtectedRunRoot`: administrators/SYSTEM write, users read,
   no inheritance), and `Find-OfflineRun.ps1` continues only folders that are still locked. The
   GUI's Offline mode (`RunRoot: new-locked`) runs the very same command line in a child process
   (`New-GuiLockedRunRoot`) and fails closed: no locked folder, no run. Without this, the GUI's
   Online half would have refused to continue the GUI's own Offline runs.
2. **The Online half checks persistence again after the scans** (steps 6d and 6e, into
   `<run>\after-scans`, with the 240 s / 600 s limits), rebuilds the report as
   `report-after-scans.html` when that check produced a result (new step 9r; like the batch file,
   only the file's existence counts), and shares that report and those persistence results; the
   Desktop copy is refreshed from the shared report. The offline `report.html` is never changed.
3. **`-AskKeep`.** The offline review is now started with `-AskKeep`, so the script itself asks
   "Keep any?" when instances were found. The window does NOT pass it: it asks with its own
   Keep / Remove cards before the step and passes `-KeepIdentifier` (or nothing = remove all).
   This is the one declared difference from the batch file's calls; `Test-GuiCallParity.ps1`
   drops `-AskKeep`, `-SelectKeep` and `-KeepIdentifier` before comparing and asserts the
   batch passes `-AskKeep` while the window never does.

### 12.6 Code-review fixes (2026-11-10)

A two-axis review (standards, spec) of the merged tree found the following; all fixed unless noted.

1. **Test hooks could drive an unattended removal** (docs/06 rule 2, section 8 above). The canned
   dialog answers (`SCC_GUI_TEST`, `SCC_GUI_TEST_ANSWERS`) and `-RenderPng` / `-HoldSeconds` are now
   honoured ONLY in a window that is not elevated. Nothing the engine does to a PC succeeds without
   administrator rights (preflight refuses; the remover, services and Program Files need admin), and
   `START-HERE-GUI.bat` always runs the window elevated, so in a real run the hook does not exist.
   Asserted statically by `Test-GuiWindow.ps1`.
2. **Closing during a scan killed the scanner** (section 7). Closing during 6a-6c now asks, then ends
   only the step's own `powershell.exe` (`Stop-GuiChild -KeepDescendants`); the scanner window stays.
3. **Step 5 could be closed before its confirmation** (section 7). Every step marked `Destructive` in
   `steps.json` (5, 7, 8a) locks the window for its whole run; persistence cleanup locks once
   `REMOVE` is typed.
4. **The unknown-prompt box could leave a script waiting forever** (4.3 rule 2). Its window X now
   sends an empty line (the scripts' own default); "This is not a question" quiets it for 60 s, after
   which it comes back if the tool is still waiting on the same text.
5. **Results panels** (section 6): the finished run shows the persistence status with the findings
   table under "Heuristic matches, not malware verdicts" (offline `persistence\`, online
   `after-scans\persistence\`), the diff outcome (Clean / RESURRECTION DETECTED / INCOMPLETE /
   diff failed) and the share result with the paste link the share printed.
6. **Re-run** (section 6): a scanner step or the report share that ends non-zero offers "Run it
   again" (`"Retry": true` in `steps.json`).
7. **Skipped steps say why** (section 6): the stepper lists every step; those outside the chosen
   mode are greyed with the reason ("needs internet - run the Online half", "done by the Offline
   half", ...).
8. Standards clean-ups: one process-capture helper (`Invoke-GuiCapture`: exit code checked, killed on
   timeout) replaces two copies; the run finder is called with no arguments, exactly as the batch
   file calls it; the prompt table is a list of exact `Needles` (no hand-escaped regex copies, no
   always-true `Visible` column); `Exists` replaces the duplicate `File` condition; the window modes
   and their labels live only in `steps.json`; the STA relaunch forwards every bound parameter;
   a failed `gui-session.json` write is reported once instead of swallowed.

Deliberately not changed, with the reason:

- **Detect only** has no launcher of its own. Kept: it is a strict prefix of the offline half's
  calls plus its report and changes nothing, so it does not break rule 1's intent; it is recorded in
  `steps.json` (`ModesNote`). The owner can ask for it to be removed.
- **Scanner choice is one dialog**, not three cards: it shows each scanner's staged state and a tick
  box; running state, elapsed time and the recorded status appear in the step list and status line.
- **The four guarded prompt echoes repeat their text** next to `Read-Host '<text>'`. The repo's
  usual pattern is a bare `Read-Host`, but the engine tests for those two scripts mock `Read-Host` by
  its prompt text, and a bare `Read-Host` broke them (12.3).
- `VERSION` is not bumped (the owner's build decision); `START-HERE-GUI.bat` sits at the repo root
  like the other launchers rather than beside `gui\Start-CleanupGui.ps1`.

### 12.7 Restyle, and the REMOVE gate (2026-11-10)

- **Design tokens.** `gui\MainWindow.xaml` holds the only colour definitions: `Brush.*` semantic tokens
  (Background, Surface, Foreground, Muted, Border, Primary, Success/Warning/Danger/Info Fg/Bg/Border,
  Console...) for the light theme and the same keys in `Theme.Dark`, plus radius and spacing tokens and
  the component styles (`Card`, `Button.Primary|Secondary|Danger|Ghost`, `ModeCard`, scrollbars). XAML
  uses them through `DynamicResource`; the script through `Get-Brush '<Tone>'`, never a literal colour
  (`Test-GuiWindow.ps1` fails on a hex colour in the script). Dark replaces every token at start-up when
  Windows is set to dark apps, or with `-Theme Dark`. Dialogs are separate windows, so each gets a copy
  of the tokens and styles.
- **Bug found while restyling: the REMOVE gate was not in force in 1.8.12-gui-alpha.1.** Button specs
  are hashtables and `NeedsWord` was read through `PSObject.Properties`, which does not list hashtable
  keys, so the Remove button was enabled before the word was typed. The test hook (canned answers)
  never builds a real dialog, which is why no test saw it. Fixed (`Test-ButtonNeedsWord`), and
  `-SelfTest` now builds both REMOVE confirmations for real (not shown) and checks the gate against
  wrong spellings, extra spaces and a cleared box, in both themes.

### 12.4 Not testable by an agent - the owner, on a real PC (add to `docs/09`)

**Everything below is still open.** The window, the removal path and the online half have been
exercised only against stubs; the one real script in those tests is `Invoke-ReviewAndRemove.ps1`,
whose remover is stubbed.

1. **Detect only**: `START-HERE-GUI.bat` on an elevated real PC - one UAC request; the window
   appears; steps 2 to 4 and the report run; the cards show the same relay hosts the console
   runner prints; the console stays open behind; closing during a step stops only that step.
2. **Offline half on a lab PC with a real ScreenConnect**: mark one instance Keep, leave one on
   Remove; the confirmation lists REMOVE / KEEP per instance and the button stays disabled until
   `REMOVE` is typed exactly; the remover quarantines only the Remove one; the report labels the
   kept one; a second run of persistence review shows the typed-`REMOVE` dialog with the
   candidate list. Closing the window during removal must be refused.
3. **Online half**: continues the offline run; each scanner opens and can be driven (spike S5:
   the child runs with `CreateNoWindow`, so check KVRT, ESET, winget and the AV uninstallers
   really appear); the two Malwarebytes dialogs appear in the right order; the share link works.
4. **Environment**: a PC set to "UTF-8 for worldwide language support"; a 125% and a 150%
   scaled laptop; UAC disabled (the `UacDisabled` dialog); Windows 10 as well as 11.
5. **Restart offer** after a power repair; keep-awake keeps the PC awake while only the window
   is in the foreground (spike S6).
6. Watch that no browser or Explorer window opens other than the report (owner directive
   2026-08-27).
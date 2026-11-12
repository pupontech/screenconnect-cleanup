# ScreenConnect Cleanup

A Windows technician tool for PCs where someone got remote access they should not have, usually
after a tech-support scam. It finds every ScreenConnect instance, shows **which relay server each one
calls home to** (the only reliable way to tell the scammer's copy from the customer's own IT), removes
the ones you choose, checks what else was left behind to start up with Windows, runs the AV scanners,
and writes a report.

> **Beta.** The window (`START-HERE-GUI.bat`) is the main way to run it since `v1.8.12-gui-beta.1`.
> It runs the same scripts as the console launchers, which remain available. A full removal through
> the window has not yet been run on a real infected PC; see [What is not verified yet](#what-is-not-verified-yet).
> The project was written with AI assistance; read what it is about to do before you approve it.

---

## Get it

**Download:** the latest release zip from
[Releases](https://github.com/pupontech/screenconnect-cleanup/releases/latest), check it against the
`.sha256` next to it, and **extract the whole zip**. You get:

```
screenconnect-cleanup\
  START-HERE-GUI.bat     <- double-click this
  files\                 <- everything else (do not separate it from the launcher)
```

**Or one line in PowerShell** (downloads the latest release to `Desktop\ScreenConnect-Cleanup\<version>\`,
checks its SHA-256 and opens the window):

```powershell
irm https://raw.githubusercontent.com/pupontech/screenconnect-cleanup/main/install-latest.ps1 | iex
```

Read [`install-latest.ps1`](install-latest.ps1) first if you prefer; it only downloads, verifies,
extracts and launches. Running it again with the same version just opens the existing copy.

**Needs:** Windows 10 or 11, an administrator account (the launcher asks once through UAC), PowerShell
5.1 (built in). Internet only for the Online half and Stage tools.

---

## Using the window

Double-click `START-HERE-GUI.bat`, approve the administrator prompt, pick what to run and press Start.

![Start screen: choose Offline, Online, Detect only or Stage tools](docs/images/gui-start.png)

| Choice | Internet | What it does |
|---|---|---|
| **Offline** | not needed | The cleanup: preflight, before snapshot, detection, removal of the ScreenConnect you choose, persistence review, optional power-options repair, after snapshot + diff, local report. Downloads and uploads nothing. |
| **Online** | needed | Downloads and runs KVRT, ESET Online Scanner and Malwarebytes, checks startup items again after the scans, optional AV uninstall, shares the report. Continues this PC's last Offline run if there is one. |
| **Detect only** | not needed | Preflight, snapshot, detection and the report. Changes nothing. Use it to look before you decide. |
| **Stage tools** | needed | Downloads the scanners into the tool folder for later. Changes nothing on the PC. |

The left column shows every step and its state (done, skipped and why, failed). The console at the
bottom shows the scripts' own output live. **Open log** opens the full log; **Open RIT-SCC folder**
(top right) opens `C:\RIT-SCC`, where every run is kept.

When it finishes you see each ScreenConnect instance as a card. The relay host is the line that
matters: a host you do not recognise is the scammer's.

![Finished run: one card per ScreenConnect instance, relay host first](docs/images/gui-results.png)

### The usual job

1. **Take the PC off the network** (unplug the cable, turn Wi-Fi off) if a session might still be live.
2. Run **Offline**. For each ScreenConnect instance choose **Remove** (the default) or **Keep** (for
   example the customer's own support agent). Type `REMOVE` to confirm; the button stays disabled
   until you do.

   ![Removal confirmation: lists REMOVE and KEEP per instance, needs REMOVE typed](docs/images/gui-confirm-remove.png)

3. Read the report. It opens by itself and a copy is left on the Desktop.
4. **Reconnect** and run **Online**. Say yes to continuing the offline run; run the scanners you want.
   The sanitized report is shared at the end and the link appears in the window and in the report.

A PC that must stay offline: run only **Offline**. Everything stays in `C:\RIT-SCC\<PC>-<id>\` and
nothing is shared.

### What you are asked, and what happens if you close the box

| Question | Default |
|---|---|
| Keep or remove each ScreenConnect instance | Remove, then typed `REMOVE` |
| Remove flagged startup items (scheduled tasks, Run keys, startup files) | nothing selected; typed `REMOVE` |
| Open the review windows (evidence folders, Services, Task Scheduler) | No |
| Repair power options | asks |
| Which scanners to run (Online) | asks |
| Uninstall other antivirus products (Online) | No |

**Closing any question box always means no.** While a removal, AV uninstall or power repair is
running, the window cannot be closed. Closing the window during a scan stops the step but leaves the
scanner open.

---

## What you get

Every run has its own folder, `C:\RIT-SCC\<PC>-<id>\` (locked to administrators, so nothing running as
the user can tamper with it between the two halves):

| File / folder | What it is |
|---|---|
| `report.html` | The investigation report (also copied to the Desktop). Instances, relay hosts, install dates, startup items found, before/after diff, scanner results, a credential-reset checklist. |
| `report-after-scans.html` | Online half: the report rebuilt after the scanners. This is the one that is shared. |
| `connectwise-report.zip` | Sanitized package (report JSON, technician summary, manifest) for the ConnectWise Trust Center. **Never sent automatically.** |
| `quarantine\...`, `removal-manifest.json` | Everything removed, **moved here, never deleted**, with original path and hash. |
| `detect\`, snapshots, `logs\` | Raw evidence, before/after snapshots and every step's log. |

**Sharing.** The Online half posts the sanitized report to the MicroBin server in
`files\microbin-url.txt` (read-only, expires after one week) and puts the link at the top of the
report. It contains relay hosts, thumbprints, file names and hashes, and install dates; it does
**not** contain raw config, evidence, account names, credentials or keys. The Offline half and
Detect only never upload anything.

---

## Why relay host, and what it does not do

ScreenConnect is legitimate signed software: signature, publisher and hash are the same whether it
belongs to the customer's IT or to the scammer, and no antivirus will flag it. What differs is the
**relay server** each instance is configured to call, so the tool reads that from every instance and
puts it first.

- **The scanners are for the other malware** that came along. They do not replace the ScreenConnect step.
- **Removing the agent does not undo the access.** Passwords, browser sessions, mail rules and new
  accounts may be compromised; the report ends with a credential-reset checklist for that reason.
- **Other remote tools** (AnyDesk, TeamViewer, RustDesk and 11 more) are detected and listed, not
  removed. Turn them on in `files\targets.json`.

---

## Console launchers

Everything in the window is also available without it, in `files\`:

| Launcher | Same as |
|---|---|
| `START-HERE-OFFLINE.bat` | Offline (steps 1-7). Asks `Keep any ScreenConnect? [y/N]`, then one typed `y`. |
| `START-HERE-ONLINE.bat` | Online (steps 1-5). |
| `START-HERE.bat` | The original full run in one go (1-9); `--stage` = Stage tools. |
| `Run-DetectRemoteAccess.bat` | Detection only, results to `Desktop\RemoteAccessScan\`. |

Use them if the window will not open on a PC. How the two halves hand over and how they differ from
the full run: [OFFLINE-ONLINE-SPLIT.md](OFFLINE-ONLINE-SPLIT.md).

---

## What is not verified yet

The window is tested on Windows 11 with stub scripts in place of the destructive parts; the scanner
downloads and the report upload were also run for real. **Not yet done on a real PC:** a full removal of a real
ScreenConnect through the window, Windows 10, a PC with the UTF-8 system locale, a real 125% / 150%
scaled laptop, UAC turned off. The list and how to test it:
[docs/14-gui-architecture.md, section 12.4](docs/14-gui-architecture.md).

If something goes wrong, send the run folder from `C:\RIT-SCC` (or just its `logs\` and `detect\raw\`).

---

## More

| Document | For |
|---|---|
| [DEPLOY.md](DEPLOY.md) | What is in the package, requirements, building a release |
| [OFFLINE-ONLINE-SPLIT.md](OFFLINE-ONLINE-SPLIT.md) | The two halves in detail, keeping instances in the console |
| [docs/14-gui-architecture.md](docs/14-gui-architecture.md) | How the window drives the scripts, its tests |
| [docs/12-post-av-persistence.md](docs/12-post-av-persistence.md) | The startup-item (persistence) review |
| [docs/06-safety-model.md](docs/06-safety-model.md) | Why removal is gated the way it is |
| [CHANGELOG.md](CHANGELOG.md) | Every release |

**Developers:** PowerShell 5.1, pure ASCII, no BOM in every script (`tests/ci/Test-HouseRules.ps1`).
GUI tests are in `tests/gui/`; the window must never gain removal logic of its own.

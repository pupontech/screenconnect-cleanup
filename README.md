# ScreenConnect Cleanup Tool

Windows technician tool for investigating and cleaning up **unauthorized remote-access
software** on client machines — typically after a tech-support scam, where the client
was talked into letting someone remote in.

Shaped like the [Tron script](https://github.com/bmrf/tron): a staged orchestrator that
drives existing tools rather than reimplementing them. Roughly **90% orchestration,
10% original code** — the original code being the ScreenConnect module, because no
existing tool answers the question that actually matters.

> **Status: proof of concept.** Only Stage 2 (detection) exists so far, and it is
> **read-only**. There is no removal code yet. See [Status](#status) below.

---

## The problem this solves

Finding ScreenConnect on a PC is trivial — it installs a named service in a named
directory. The hard question is:

> **Is this instance ours, the client's own IT's, or the scammer's?**

Signature, publisher, product name and file hash are **identical** across all three,
because it is the same signed commercial software. None of them can answer it.

What *can* answer it is the **instance identity** — the relay server the client is
configured to call home to, carried in the client's launch parameters:

```
Instance: a1b2c3d4e5f6a7b8
  RELAY HOST    : support.example.com      <-- the decision key
  Relay port    : 8041
  Session type  : Access (unattended)      <-- Access is far more serious than Support
  Server key    : fingerprint a3f9c1...    <-- corroborates the host
  Custom props  : "Acme IT", "Site-3"      <-- often names the operator outright
  Installed     : 2026-08-14 14:22         <-- inside the incident window?
```

Two further consequences worth stating plainly:

- **No malware scanner will flag ScreenConnect.** It is legitimate signed software, so
  KVRT / ESET / Defender walk straight past it. The scanners are here for the *commodity
  malware that came along with it*, which is a separate job. Neither half substitutes
  for the other.
- **Removing the agent is not the same as remediating the incident.** If someone had an
  interactive session, the exposure is credentials, browser session cookies, saved
  passwords, mail rules, and new accounts. The report ends with a credential-reset
  checklist for exactly this reason.

---

## Status

| Stage | What it does | State |
|---|---|---|
| 0 — Preflight | admin check, restore point, working dir, tool pack | **built** (Linux-verified; Win-only paths unverified) |
| 1 — Snapshot (before) | services, tasks, autoruns, processes, connections, + retro artifacts | **built** (Linux-verified; Win-only content unverified) |
| **2 — Detection** | **ScreenConnect instance identity + other RAT presence** | **PoC works** (verified on a real machine) |
| 3 — Technician review | approval gate — nothing is removed without it | **stub** (gate present & logged, no real approval UI yet) |
| 4 — Remove / quarantine | stop, uninstall, quarantine, clean persistence | **not started** (stubbed, skipped by default via `-sr`) |
| 5 — Scanners | Defender, KVRT, ESET (AdwCleaner, MSERT not built) | **built** (3 adapters, Linux-verified WhatIf; real exec unverified) |
| 6 — Procmon (targeted) | "something reinstalled it — what?" | **not started** (opt-in stub only) |
| 7 — Snapshot (after) + diff | prove it is gone, catch resurrections | **built** (Linux-verified) |
| 8 — Report | HTML + JSON + tech summary | **built** (XSS + empty-case verified) |
| — Top-level runner | `sc-cleanup.ps1` ties all 9 stages together | **built** (Linux end-to-end, detect stubbed) |

Deliberate build order: **every non-destructive stage ships before any destructive one.**
Removal comes last, on top of machinery already proven in the field.

> **Agent-build status (2026-08-23 integration pass).** Every script parses
> clean (0 errors), is pure ASCII, and has no BOM. Functional verification was
> run on Linux/pwsh where possible; Windows-only code paths are proven only for
> *error handling*, not for *correct Windows content*. The single item that
> needs a **Windows VM / live lab** — and is explicitly **out of scope for
> agents** — is **M0: live ScreenConnect install validation** of the relay-key
> map. See `docs/07-roadmap-open-questions.md` and `docs/08-work-log.md`.

---

## Usage

Everything here is currently **read-only**. Nothing is stopped, changed or deleted.

Double-click `Run-DetectRemoteAccess.bat` (right-click *Run as administrator* for the
full picture), or from a shell:

```
powershell -NoProfile -ExecutionPolicy Bypass -File .\detect-remote-access.ps1
```

### Options

| Flag | Effect |
|---|---|
| `-ListTargets` | show what it can look for, and what is currently on/off |
| `-Target screenconnect,anydesk` | scan only these |
| `-All` | scan every known target, ignoring the on/off flags |
| `-SelfTest` | run the parser against synthetic samples and exit |
| `-OutRoot <path>` | where results go (default: Desktop\RemoteAccessScan) |
| `-NoZip` | skip zipping the output folder to the Desktop |
| `-NoPause` | do not wait for Enter (unattended runs) |

### What you get

```
RemoteAccessScan\<HOST>_<timestamp>\
  findings.json     structured results (feeds the report generator)
  SUMMARY.txt       the console output, saved
  raw\              verbatim evidence - config files, service/process/program dumps,
                    service-install (7045) events
```

Plus a zip of the whole folder on the Desktop, matching the convention the
`remote-diagnostics` log pullers already use.

### Choosing what to look for

`targets.json` controls it. ScreenConnect is on by default; 14 other remote-access
products are defined but off:

AnyDesk, TeamViewer, UltraViewer, Supremo, RustDesk, Splashtop (incl. SOS),
LogMeIn / GoTo, Zoho Assist, Atera, DWAgent, MeshCentral, NetSupport,
Remote Utilities, VNC family.

Flip `"enabled": true` to add one permanently, or use `-Target` / `-All` for one run.

ScreenConnect gets a **deep module** (full instance identity extraction). The others are
**presence-only** — service, process, directory and installed-program matches — which is
enough to tell a tech "there is also an AnyDesk here, go look."

`targets.json` is optional: the same defaults are embedded in the script, so a single
copied `.ps1` works on its own on a machine that has nothing else.

---

## Proof-of-concept caveat — read this before trusting the output

The ScreenConnect launch-parameter key map (`h` = relay host, `e` = session type, and so
on) is **assumed, not confirmed**. Validating it against a real install is the entire
point of this PoC.

The script is built to fail usefully rather than silently:

- It captures **raw evidence even when parsing succeeds** — service ImagePath and every
  `.config` file verbatim, into `raw\`.
- It finds parameter blobs with a **generic** "3 or more `key=value&` pairs" regex rather
  than hunting for keys we assume exist, so an unexpected format is still captured.
- Any key not in the map is preserved under **`UnknownParams`** and printed as
  `Unmapped keys:` rather than discarded.
- Instances where extraction fails are reported loudly under **PARSE PROBLEMS**, with the
  raw sources attached.

**If you run this on a machine with a real ScreenConnect install, send back the
`raw\` folder and the PARSE PROBLEMS section.** That is what corrects the parser.

`-SelfTest` proves the code is internally consistent with those assumptions. It does not
prove the assumptions are right — only a live install can.

---

## Design notes

### Read-only now, approval-gated later

Detection and removal are deliberately separate. When Stage 4 lands, removal will consume
an **approved plan file** produced by the Stage 3 review — the destructive code will not
be reachable without a technician having seen the evidence and said yes. There will be no
flag that detects and removes in one step.

### Quarantine, never delete

Nothing gets deleted. Artifacts are moved to a quarantine folder with their original path
and hash recorded. It costs nothing and covers the one time we are wrong.

### Uninstall before surgery

Always run the vendor's own uninstaller (from the registry `UninstallString`) before
touching services or directories manually. Manual removal is the fallback, not the
default.

### Before/after diff

Stage 1 runs again as Stage 7 and the two are diffed. This is what catches the failure
mode that actually brings clients back: **something reinstalled the agent.** When the
diff shows a resurrection, that is what Stage 6 (targeted Procmon) is for — filtered to
the one path that came back, which turns Procmon from a gigabyte firehose into a
one-line answer.

### Not copied from Tron

Tron's cleanup ordering is `clean -> debloat -> disinfect`. Ours is inverted:
**snapshot -> detect -> remove -> scan -> verify**, with temp cleanup omitted entirely.
Tron is optimizing a slow PC; we are investigating an incident, and its temp cleanup
would delete the scammer's installer out of `%TEMP%` before anyone looked at it.

Also not copied: batch/CMD implementation, the debloat/optimize/repair stages, registry
"optimization", clearing event logs, and delete-without-quarantine.

---

## Conventions

- **PowerShell 5.1 compatible, pure ASCII, no BOM.** PS 5.1 reads a BOM-less non-ASCII
  file as Windows-1252. Same rule as `provisioning/`.
- `.bat` launchers alongside each `.ps1`, matching `remote-diagnostics/`.
- Output zipped to the Desktop, same as the log pullers.
- **Windows-only**, by nature — a documented exception to the repo's Windows+WSL2
  mandate. The report generator is the portable half: it consumes `findings.json` and
  needs no live system.

### Verifying a change

Every `.ps1` here must pass both:

```powershell
$p='.\detect-remote-access.ps1'; $e=$null; $t=$null
[System.Management.Automation.Language.Parser]::ParseFile($p,[ref]$t,[ref]$e) | Out-Null
if ($e.Count -eq 0) { 'PARSE OK' } else { $e | ForEach-Object { $_.Message } }
```

```
py -c "import io;b=io.open('detect-remote-access.ps1','rb').read();print(sum(1 for c in b if c>127))"
```

The second must print `0`.

---

## Related

- `remote-diagnostics/` — event log pullers and network state capture. Same conventions,
  same technician workflow; use those for crash/boot/connectivity questions.
- `.claude/skills/windows-system-diagnostics` — reference for which command, event ID or
  threshold to reach for on a given Windows symptom.
- `.claude/skills/eset-activation-troubleshooting` — relevant when the ESET scanner leg
  will not activate.

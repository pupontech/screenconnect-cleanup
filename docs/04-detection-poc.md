# Stage 2 detector — the built proof of concept

File: `detect-remote-access.ps1` (v0.1.0-poc, ~49 KB)
Launcher: `Run-DetectRemoteAccess.bat`
Config: `targets.json`

**Status: built, executed, and unit-tested. Read-only. Nothing is stopped, changed or
deleted.**

---

## Purpose

Answer one question: **can we reliably pull the relay identity out of a live
ScreenConnect install?**

Everything else it does is secondary. It is built to **fail usefully** rather than
silently, because the key map it relies on is assumed rather than confirmed (see `03`).

---

## Usage

```
powershell -NoProfile -ExecutionPolicy Bypass -File .\detect-remote-access.ps1
```

| Flag | Effect |
|---|---|
| `-ListTargets` | show what it can look for and what is on/off |
| `-Target screenconnect,anydesk` | scan only these |
| `-All` | scan every known target regardless of on/off flags |
| `-SelfTest` | run the parser against synthetic samples and exit |
| `-OutRoot <path>` | where results go (default `Desktop\RemoteAccessScan`) |
| `-NoZip` | skip zipping output to Desktop |
| `-NoPause` | do not wait for Enter (unattended) |
| `-TargetsFile <path>` | alternate targets.json |

Admin is **not** required. Without it the System event log (7045 service-install history)
is usually unreadable; the tool warns and records this in `EventLogError` rather than
failing.

---

## How ScreenConnect detection works

Instances are enumerated from **five independent sources**, then merged into one record
per instance keyed by the instance identifier:

| # | Source | What it gives |
|---|---|---|
| 1 | Windows services | service name/state/start mode/account, **ImagePath (often carries the param blob)** |
| 2 | Install directories | install path, directory creation time |
| 3 | Uninstall registry (3 roots) | display name, version, publisher, **UninstallString** (needed for proper removal later) |
| 4 | Running processes | PID, PPID, exe path, **command line (may carry the blob)** |
| 5 | Event ID 7045 | historical installs, incl. instances since removed |

Merging is by the identifier parsed out of `ScreenConnect Client (<identifier>)`. If no
identifier is available, it falls back to a source-prefixed synthetic key
(`svc:`/`dir:`/`reg:`/`proc:`) so nothing is silently dropped.

### Blob extraction order

`service ImagePath` -> `process CommandLine` -> `*.config` files in the install dir.

The winning source is recorded in `ParamBlobSource` — important for the live test, since
it tells us where the data actually lives on real builds.

### Extraction hedges (see `03` for why)

- Generic regex: any run of 3+ `key=value&` pairs, preferring one with `h=` or a known
  session type. It does **not** hunt for keys we assume exist.
- URL-decodes all values.
- Unknown keys preserved under `UnknownParams`, shown as `Unmapped keys:`.
- `.config` files copied **verbatim** into `raw\` **even when parsing succeeds**.
- Failures reported loudly under `PARSE PROBLEMS` with raw sources attached.
- Server key hashed to a 16-char SHA-256 fingerprint (`ServerKeyFingerprint`) so it is
  usable as a comparable ID without dumping the whole blob.

Also collected per instance: file version info, SHA-256, Authenticode status and signer,
install directory creation time, live TCP connections for its PIDs, and matching 7045
events.

---

## Other remote-access products

**Presence-only** (D5: toggleable, ScreenConnect is the focus). Matches on service name,
process name, directory path, and installed-program display name.

15 products defined in `targets.json`; ScreenConnect on, 14 off by default: AnyDesk,
TeamViewer, UltraViewer, Supremo, RustDesk, Splashtop (incl. SOS), LogMeIn/GoTo,
Zoho Assist, Atera, DWAgent, MeshCentral, NetSupport, Remote Utilities, VNC family.

`targets.json` is **optional** — the same defaults are embedded in the script (D6:
must run standalone).

---

## Output

```
RemoteAccessScan\<HOST>_<timestamp>\
  findings.json     structured results, feeds the report generator
  SUMMARY.txt       console output, saved
  raw\
    services.csv
    processes.csv
    installed-programs.csv
    service-install-events-7045.csv
    <instance>__<name>.config     verbatim client config files
```

Plus a zip on the Desktop, matching the `remote-diagnostics` log-puller convention.

`findings.json` top-level keys: `Tool`, `Version`, `GeneratedUtc`, `ComputerName`,
`RunAsUser`, `IsAdmin`, `OSCaption`, `PSVersion`, `TargetsSource`, `TargetsSelected`,
`EventLogError`, `ScreenConnect`, `OtherTargets`.

`ScreenConnect` contains `Instances`, `ParseIssues`, `Historical`, `RawFilesSaved`.
`OtherTargets` is an array of `{ Id, Name, Hits, Count }`.

---

## Test evidence

All of the following was actually executed, not assumed.

### Parse + ASCII

```
detect-remote-access.ps1   PARSE OK   non-ascii=0
```

### Live run on the development machine

`-All`, 15 targets. Inventory collected: 304 services, 370 processes, 104 installed
programs, 31 service-install (7045) events.

Real detections (this machine genuinely has these):

- **TeamViewer** — 4 artifacts (service, process, directory, installed program)
- **Splashtop** — 8 artifacts (2 services, 3 processes, directory, 2 installed programs)
- **AnyDesk** — 1 artifact (leftover `%APPDATA%\AnyDesk` directory)
- **ScreenConnect** — 0 instances (none installed here)

`findings.json` validated as well-formed JSON. All raw CSVs written.

### Parser self-test (`-SelfTest`)

Because no ScreenConnect exists on the dev machine, the parser was proven against
synthetic samples:

| Sample | Result |
|---|---|
| Service ImagePath, Access/unattended | All 14 keys mapped. URL-decoding confirmed (`%20`->space, `%3d%3d`->`==`). Identifier `a1b2c3d4e5f6a7b8` extracted from the path. |
| Config fragment, Support/one-shot, port 443 | Blob correctly extracted from inside XML. All keys mapped. |
| Deliberately unknown keys | `h=` still mapped; `zz`, `qq`, `ww` correctly captured as `UNMAPPED` rather than discarded. |
| No blob present | Clean "(none found)", no crash. |

The self-test prints its own caveat: passing proves the **code is consistent with our
assumptions**, not that the assumptions are right.

---

## Bugs found by testing (both fixed)

Worth recording because both were silent-wrong-answer bugs, not crashes.

**1. PowerShell 5.1 single-element array unwrapping.**
`.Count` on a single-element result returned `$null`, printing a blank count. It showed up
as `artifacts found:` (blank) for AnyDesk's single hit. **This would have misreported the
one-ScreenConnect-instance case — the most common real scenario.** Detector counts were
fixed by forcing array context (`@(...)`) at all 11 counting sites. The report renderer had
the same PowerShell 5.1 boundary issue; v1.7.37 now preserves the normalized instance array
before rendering both the summary count and the ScreenConnect section heading.

**2. `-Target a,b` broken through the .bat launcher.**
`powershell.exe -File` passes `a,b` as a single string, not an array, so the whole thing
was treated as one unknown target id and the scan silently selected nothing. Fixed by
splitting on commas defensively inside the script.

Lesson for whoever continues: **run it, don't reason about it.** Both bugs parse fine and
look correct on inspection.

---

## The outstanding live test — top priority

The detector has never seen a real ScreenConnect install.

**What to do:** install ScreenConnect from a test cloud instance into a VM, run the
detector, and check:

1. Was a `ParamBlob` found at all? From which source (`ParamBlobSource`)?
2. Do the mapped fields (`RelayHost`, `RelayPort`, `SessionType`, `SessionId`) contain
   sensible values?
3. What appears under `Unmapped keys:`? Those are real keys our map is missing.
4. Anything under `PARSE PROBLEMS`?
5. Is the `ServerKeyFingerprint` stable if you reinstall from the same server? **This is
   the key question of the whole project.**
6. Uninstall, re-run, and confirm the instance shows up under `Historical` via 7045.

**Send back the `raw\` folder and the `PARSE PROBLEMS` section.** That is what corrects
the parser. Everything downstream depends on it.

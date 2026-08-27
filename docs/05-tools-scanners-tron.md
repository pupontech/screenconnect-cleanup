# Tools, scanners, and the Tron analysis

---

## Rule zero for this file

**Do not invent command-line flags, exit codes, log paths, or download URLs.** Every
scanner's switches must be read from current official vendor documentation before an
adapter relies on them. Flags drift between versions.

Where this document is uncertain, it says so. A stub adapter that honestly reports
`NotVerified` is worth more than a plausible-looking one built on invented switches that
fires on a paying client's machine.

**The scanner line-up is KVRT + ESET Online Scanner + Malwarebytes** (owner
update 2026-08-27). `tools/Get-AVTools.ps1` stages `KVRT.exe`,
`esetonlinescanner.exe`, and `MBSetup.exe` from official vendor URLs.
`Invoke-GUIScanner.ps1` launches each as a normal visible GUI window and blocks
until the technician closes it, so later snapshots and the report are taken
AFTER any GUI-driven cleaning has actually finished. The pipeline never invents
silent-scan flags. AdwCleaner and Microsoft Defender remain removed from the
scanner line-up.

---

## The scanner reality check

**No malware scanner will flag ScreenConnect.** It is legitimate signed commercial
software. At best a PUA / RemoteAdmin classification, and often only with PUA detection
explicitly enabled.

So the tool has two halves that do **not** overlap:

- **Our ScreenConnect module** handles ScreenConnect (Stage 2)
- **The scanners** handle the commodity malware that came along with it (Stage 5)

Neither substitutes for the other. Do not let a clean scan be reported as "the machine is
clean."

Also: three full AV scans is hours of wall clock and risks conflicting with the resident
AV. Stage 5 is therefore **skippable** (`-sa`) and runs **after** the core work, not
before it.

---

## Scanner inventory

| Tool | Role | Automation status | Licensing |
|---|---|---|---|
| **Defender `MpCmdRun.exe`** | Baseline scan | **REMOVED from the line-up 2026-08-26 (owner decision).** Adapter (`scanners/Invoke-DefenderScan.ps1`) deleted; Stage 5 no longer offers it. | Present on every machine. Removed by owner anyway. |
| **KVRT** | Kaspersky removal tool | Staged from Kaspersky's official current KVRT download URL and launched attended via `Invoke-GUIScanner.ps1` (`-Scanner KVRT`). No silent scan/clean flags are passed. | **APPROVED by the owner (decision D2).** Do not block on licensing. |
| **ESET Online Scanner** | On-demand scan | Staged from ESET's official Online Scanner URL and launched attended via `Invoke-GUIScanner.ps1` (`-Scanner ESET`). GUI-only in this workflow; no invented unattended flags. | **APPROVED (D3)** — the MSP's ESET license covers technician scans. |
| **AdwCleaner** | PUP / adware / junk | **REMOVED from staging 2026-08-26 (owner decision):** not needed for this tool's workflow. Documented CLI existed (`/eula /scan /clean /noreboot /path`) but the policy is GUI-attended operation; AdwCleaner was dropped entirely rather than kept as a GUI tool. | Free. |
| **MSERT** (Microsoft Safety Scanner) | Free Microsoft second opinion, self-expiring | Verify switches; log believed to be `%SystemRoot%\debug\msert.log`. | Likely none. Verify. |
| **Malwarebytes** | Install via winget (`winget install -e --id Malwarebytes.Malwarebytes`); uninstall via winget (`winget uninstall -e --id Malwarebytes.Malwarebytes`), fallback to the vendor uninstaller GUI when winget is absent (owner directive 2026-08-27). | Paid, per-endpoint. Not approved for automation. |
| **RKill** | Kill malware processes before scanning (Tron's stage-0 trick) | Minimal CLI documentation. | Verify commercial-use terms. |
| **TDSSKiller** | **RECOMMEND EXCLUDING** | — | Deprecated by Kaspersky, and reportedly abused by threat actors in 2024 to disable EDR — meaning dropping it on a client machine may trip the client's own security stack. Bad trade. **[VERIFY the reporting, but the recommendation stands.]** |

Realistic Stage 5 line-up (2026-08-27, owner update): **KVRT + ESET Online Scanner** attended GUI launches + **Malwarebytes via winget** (install/uninstall).

---

## Sysinternals tools

Bundling is permitted by the owner, so `tools/Get-ToolPack.ps1` downloads and
hash-verifies the pack rather than shipping stale binaries in git.

| Tool | Role |
|---|---|
| **autorunsc64** | **The most valuable tool in the pack.** CSV output, hashes, signature verification, every autostart category in one pass. `-accepteula -a * -c -h -s -t -nobanner`. |
| **sigcheck64** | Signature/publisher/version checks on specific files. `-c` CSV, `-h` hashes, `-u` unsigned only. **Note: the VirusTotal switches upload data — do not use them without an explicit client-confidentiality decision.** |
| **Procmon** | Targeted respawn investigation only — see below. |
| **TCPView** | Optional deep-dive on connections. |

Official download pattern is believed to be
`https://download.sysinternals.com/files/<Name>.zip` — **verify before relying on it**,
and never use a third-party mirror.

---

## Procmon — scoped correctly

An earlier design pass argued Procmon should be cut entirely. That was too dismissive.
The correct position:

**Procmon is wrong as a detection tool.** It captures the present; a technician always
arrives after the event. It produces gigabytes with no realistic automated analysis path.
It cannot tell you about the past.

**Procmon is excellent for exactly one job here:** *"I removed it and something put it
back — what?"* That is a live, present-tense question, which is its strength.

Design:

```
1. Confirm removal; note the exact path/service/key that came back
2. Start Procmon:
     /AcceptEula /Quiet /Minimized /BackingFile <path> /LoadConfig <filter.pmc>
3. Filter NARROWLY - the specific path, service name, and registry key
4. Run for a bounded window, or trigger the resurrection deliberately
5. /Terminate, then /SaveAs CSV, filtered
6. Report which process created the file/service/key
```

**The filter is the entire trick.** Unfiltered Procmon produces gigabytes and no answers;
filtered to one path it produces one line and the whole answer.

Also worth having: **boot logging**, which captures early-boot activity no live tool can
see — the right tool if something reappears before you can log in. Requires a reboot
cycle, so it is opt-in.

**[VERIFY]** the current Procmon switch list, and whether boot logging can be enabled
non-interactively (it is set via the GUI Options menu; a CLI equivalent is unconfirmed).

**Not recommended: Sysmon.** Installing it during an investigation yields zero retroactive
data. Deploying it fleet-wide as a preventive measure is a worthwhile but entirely
separate project.

---

## Tron analysis

Tron (`github.com/bmrf/tron`) is the architectural reference the owner asked for. It is a
staged batch script that orchestrates third-party tools for mass PC cleanup.

### Take

| Tron pattern | Why it fits |
|---|---|
| Single entry point + skip flags (`-sa`, `-np`, ...) | Techs must be able to skip the multi-hour scan stage. Non-negotiable. |
| Numbered, self-contained stage folders | Add/remove/reorder a stage without touching the runner |
| One master log + per-tool log subdirectory | Master log for the timeline, raw tool output kept for awkward cases |
| Resume across reboots (RunOnce + stage marker) | Service removal and scanners both need reboots |
| Restore point + registry backup before changes | Cheap insurance, correctly default-on |
| Safe-mode-with-networking option | Useful when something will not die in normal mode |
| Hash-verified tool pack | We verify downloads instead of a shipped pack, same principle |
| End-of-run summary + "reboot required" flag | The tech reads three lines, not three thousand |
| Refuses to run on Server OS by default | Same guard, same reason |

### Leave

| Tron pattern | Why not |
|---|---|
| Batch/CMD implementation | Unmaintainable for anything with structured output |
| Debloat / optimize / repair stages (OEM removal, defrag, pagefile tweaks, registry "optimization") | Out of scope, and a real way to break a client machine while "cleaning" it |
| `sfc /scannow` + `DISM /RestoreHealth` + Windows Repair | Long, noisy, unrelated to the job |
| **Temp cleanup running BEFORE disinfect** | **Actively destroys the evidence we came for** — it would delete the scammer's installer out of `%TEMP%` before anyone looked at it |
| Clearing event logs | Same. 7045 is one of our best sources. |
| Delete-without-quarantine | We quarantine. Costs nothing, covers the one time we are wrong. |
| Log-only output, no structured results | We need JSON for the report and the diff |
| TDSSKiller | See the scanner table |

### The core inversion

Tron: `clean -> debloat -> disinfect`.
Ours: **`snapshot -> detect -> remove -> scan -> verify`**, with temp cleanup omitted.

Tron is optimizing a slow PC. We are investigating an incident. Same machinery, opposite
priorities.

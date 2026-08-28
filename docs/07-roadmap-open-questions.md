# Roadmap and open questions

---

## Build order principle

**Every non-destructive stage ships before any destructive one.** Removal — the risky
part — comes last, on top of machinery already proven in the field. This is the opposite
of how Tron grew, and it is the right order for a tool that runs on paying clients'
machines.

M1 through M4 are all independently useful. A read-only "what remote access is on this
box" tool has value on day one.

---

## Milestones

| | Milestone | Deliverable | State |
|---|---|---|---|
| **M0** | **Live lab validation.** Install ScreenConnect from a test cloud instance in a VM. Confirm the relay-identity extraction. Uninstall, document remnants. | Corrected key map | **PARTIAL (field, 2026-08-26):** real removal on INPIRON4SANITY2 confirmed instance identity via DisplayName + install-dir match and the no-UninstallString surgery fallback end-to-end. Relay-key extraction (Q1/Q2) still needs a test-cloud install lab run |
| **M1** | Stages 0, 1, 8 — snapshot + report, read-only | Usable immediately, cannot hurt anything | **Built & Linux-verified** (Windows content paths still unverified — see below) |
| **M2** | Stage 2 — ScreenConnect + RAT detection | `-sr` detect-only mode | **PoC DONE** (verified on a real machine) |
| **M3** | Stage 8 — after-snapshot + diff | Catches resurrections | **Built & Linux-verified** |
| **M4** | Stage 5 — scanners (KVRT/ESET/Malwarebytes) | Optional, skippable | **Built** — `Get-AVTools.ps1` stages KVRT/ESET from official URLs, `Invoke-GUIScanner.ps1` launches them attended (GUI launch-and-wait); Malwarebytes install/uninstall via winget (v1.7.3+). AdwCleaner + Defender remain removed from scope. |
| **M5** | Stages 3, 4 — approval gate + removal + quarantine + reboot resume | **Only after heavy VM-snapshot testing** | **LIVE-VALIDATED (field, 2026-08-26):** full removal executed with ExecuteMode=true on INPIRON4SANITY2 via the manual-surgery path (quarantine + service delete + uninstall-key cleanup), manifest truthful after the UninstallFallback fix. 3010 reboot-resume path still needs a lab run |
| **M6** | Stage 7 — targeted Procmon | Respawn investigation | **Not started** (opt-in stub only) |
| **M7** | Top-level `sc-cleanup.ps1` stage runner tying it together | The actual product | **Built & Linux end-to-end verified** (detect-remote-access stubbed on Linux) |

### Recommended before M5

Run M5's plan generation in **shadow mode**: generate removal plans on real cases, have
technicians remediate manually, and compare what they did against what the tool proposed.
That comparison is the only honest test of whether automated removal is safe to build.

---

## Current file state — verify before trusting

All components were built by agents and then **independently executed and re-verified**
on a Linux/pwsh host (pwsh 7.6.5). Every `.ps1` parses cleanly (0 errors), is
pure ASCII, and has no BOM. **Parsing cleanly is not the same as working on
Windows** — see the "Needs a Windows VM" column below.

| File | Size | Parse | ASCII | Linux-verified? | Needs a Windows VM to fully prove |
|---|---|---|---|---|---|
| `detect-remote-access.ps1` | 49 KB | OK | clean | **Yes** — live run on a real machine, self-test passed, 2 bugs found+fixed | — (the only fully Windows-verified module) |
| `New-InvestigationReport.ps1` | 34 KB | OK | clean | **Yes** — XSS escaping (0 raw `<script>`, 43 escaped) + empty/null cases all pass | — (portable, consumes `findings.json`) |
| `collect-snapshot.ps1` | 57 KB (v2) | OK | clean | **Yes** — runs rc=0, schema correct; Win-only collectors exercise the error path | Services/Tasks/Processes/Connections/Accounts/Firewall/WMI/registry/hosts content + the 5 retro decoders (ShimCache offsets, BAM/DAM P/Invoke, UserAssist offset, Prefetch naming, SRUM live-copy) |
| `tools/Get-ToolPack.ps1` | 11 KB | OK | clean | **Yes** — download+manifest+`-Verify` pass against a synthetic local pack | the live `download.sysinternals.com` endpoint |
| `preflight.ps1` | 17 KB | OK | clean | **Yes** — `-SelfTest` rc=0, full run fail+succeed paths | Checkpoint-Computer, reg.exe hive save, elevation, Win32_OperatingSystem, C:\ free space |
| `diff-snapshots.ps1` | 9.8 KB | OK | clean | **Yes** — real pair CLEAN rc=0; synthetic resurrection test rc=1; pytest suite | Windows-only section content (same caveat as Stage 1) |
| `sc-cleanup.ps1` | 33 KB | OK | clean | **Yes** — full pipeline end-to-end rc=0; flags `-sa/-sr/-np/-offline/-WhatIf` functional | real Stage 2/4/5/6 Windows execution |
| `Invoke-GUIScanner.ps1` | - | OK | clean | **Yes** - launches KVRT/ESET GUIs (and Malwarebytes via winget) and blocks until closed (4h cap) | real attended scanner runs |

**Action for whoever continues:** the read-only half of the pipeline (Stages 0,1,2,7,8
+ the orchestrator) is built and proven on Linux to the extent a non-Windows host allows.
Treat every **Windows content path** as unverified until a real box runs it. The single
item that needs a **live ScreenConnect install in a VM** — and is **out of scope for
agents** — is **M0** (validating the relay-key map). Do not assume the key map is right
until a real install corrects it.

---

## Open questions

### Q1 — Is the server key stable per server? [OPEN — no longer blocks M5]
The whole "which server is this" model leans on it. If the encoded server key is not
stable across reinstalls from the same server, the fallback is relay host + custom
properties, which is weaker. The 2026-08-26 field removal ran on instance identity
(DisplayName + install-dir match) rather than the key map, so removal no longer blocks
on this; the relay-key extraction itself still needs the M0 test-cloud lab.

### Q2 — Where does the parameter blob actually live on current builds?
Service ImagePath, process command line, or `.config` file? The detector tries all three
and records which won (`ParamBlobSource`). One live run answers this.

### Q3 — What is the supported uninstall path?
MSI product code? A documented client-side uninstall switch? Server-initiated only? And
what does it deliberately leave behind? Determines how much of Stage 4 is vendor
uninstaller versus manual surgery.

### Q4 - Which scanner CLI switches are real?
Current Stage 5 does **not** rely on scanner CLI switches. KVRT and ESET Online
Scanner are staged from official download URLs and launched as visible attended
GUIs through `Invoke-GUIScanner.ps1`; Malwarebytes is installed via winget
(`winget install -e --id Malwarebytes.Malwarebytes`, v1.7.3+) and uninstalled
via winget in the AV-uninstall step. The technician drives the
scanner UI. **Do not restore CLI adapters or invent scan/clean flags without
fresh vendor documentation and a separate owner decision.**

> **Status (2026-08-27):** KVRT/ESET downloads + attended GUI launches and the
> Malwarebytes winget install/uninstall path are built. MSERT is still not
> built, and AdwCleaner + Microsoft Defender remain removed from the scanner
> line-up by owner decisions. A real-box run is still required to confirm each
> vendor GUI behaves correctly in the field.

### Q5 — Sysinternals download URL pattern
Believed to be `https://download.sysinternals.com/files/<Name>.zip`. Unconfirmed. Never
use a third-party mirror.

### Q4b — Integration review findings (2026-08-23)
From the independent module review (t_f2f5e295), carried to the integration pass:

1. **HIGH / safety — FIXED (then moot).** `Invoke-DefenderScan.ps1` defaulted to a
   `-ScanType 1` quick scan and dropped `-DisableRemediation`, allowing Defender to
   silently remediate (violating the read-only default, docs/06). **Resolved:** the
   adapter always used a custom scan (`-ScanType 3`) of the system drive with
   `-DisableRemediation`; re-verified no `-ScanType 1` present. **Moot since
   2026-08-26:** the Defender adapter was removed from the line-up by owner decision.
2. **HIGH / scope — Amcache missing.** The Stage 1 retrospective expansion implements
   Prefetch, ShimCache, BAM/DAM, UserAssist, SRUM but **no Amcache** collector, schema
   field, or diff class. Either implement Amcache or formally revise scope. **Open**
   (formally kept in scope 2026-08-28; revisit after M0).
3. **MEDIUM / semantics — Defender historical detections (moot).** `Get-ThreatDetections`
   read all of `Get-MpThreatDetection` history and reported it as this run's
   `Detections`; a pre-existing detection could be mis-attributed. Also copied Support
   logs without parsing a scanner log, partly conflicting with the docs/02 "read the
   log, never stdout" rule. **Moot since 2026-08-26:** the Defender adapter was
   removed from the line-up by owner decision.
4. **MEDIUM / validation — Windows-only decoders unverified.** ShimCache offsets,
   BAM/DAM P/Invoke, UserAssist offset, Prefetch naming, SRUM live-copy all need a
   real-box cross-check against known-good forensic tooling. **Open.**
5. **LOW / robustness — scanner detection parsers heuristic.** KVRT/ESET report/log
   parsers are best-effort against docs, not sample logs. Keep copied logs; require a
   real-box eyeball before trusting counts. **Open.**

### Q6 — Procmon boot logging non-interactively
It is set via the GUI Options menu. Whether a CLI equivalent exists is unconfirmed.
Affects Stage 7's design.

### Q7 — Client confidentiality on reputation lookups
`sigcheck`'s VirusTotal switches upload data. Submitting a client's file hashes — let
alone files — to a third party is a policy decision, not a technical one. Decide it
deliberately rather than discovering it inside an adapter. Hash-only is the maximum
defensible position; file submission should be a firm no.

### Q8 — Repository placement long-term
Currently loose scripts at `screenconnect-cleanup/`, matching `remote-diagnostics/`. If
this grows a build pipeline it may deserve its own repo, like `rinv-chat`. Fine as-is for
now.

---

## Not yet built but worth considering later

**Retrospective execution artifacts.** Prefetch, Amcache, ShimCache, BAM/DAM, UserAssist,
and especially **SRUM** (which records per-application bytes sent/received, quantifying
how much data actually moved). These are far more valuable than live monitoring, because
a technician always arrives after the fact. Natural Stage 1 expansion, and the single
highest-value addition after the live test.

**Incident window as a first-class input.** Asking the client "when did the call happen?"
and weighting everything created or first-executed inside that window is the cheapest,
strongest signal available. `collect-snapshot.ps1` accepts `-IncidentWindowDays`, and
the orchestrator now passes it through from `-IncidentDate` in Stages 1 and 8
(defaults to today, never prompted).

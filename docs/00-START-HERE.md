# START HERE — ScreenConnect Cleanup Tool handoff

You are picking up a Windows tool that is **partly built**. This folder is the complete
context transfer. Read this file first, then the numbered files in order.

---

## What the project is, in one paragraph

A Windows technician tool for investigating and cleaning up **unauthorized remote-access
software** on client PCs — typically after a tech-support scam where the client was
talked into letting a stranger remote in. It is architected like the **Tron script**: a
staged orchestrator that drives **existing tools** (Sysinternals, Defender, KVRT, ESET,
Procmon) rather than reimplementing them. Roughly 90% orchestration, 10% original code.
The original code is the ScreenConnect detection module, because no existing tool answers
the question that matters.

**It is NOT** an antivirus engine, NOT a full incident-response/forensics platform, and
NOT a general PC cleanup utility. An earlier design pass over-scoped it in exactly those
directions and was explicitly rejected by the project owner. Do not re-expand it.

---

## The single most important technical insight

Detecting ScreenConnect is trivial — it installs a named service in a named directory.
The hard question is:

> **Is this instance ours, the client's own IT's, or the scammer's?**

Signature, publisher, product name and file hash are **identical across all three**,
because it is the same signed commercial software. None of them can answer it.

What answers it is the **instance identity** — the relay server the client calls home to,
carried in the client's launch parameters (`h=` host, `k=` server key, `e=` session type).

Two corollaries that shape the whole design:

1. **No malware scanner will flag ScreenConnect.** It is legitimate signed software.
   KVRT / ESET / Defender walk straight past it. The scanners exist to catch the
   *commodity malware that came along with it* — a separate job. Neither half substitutes
   for the other.
2. **Removing the agent is not remediating the incident.** If someone had an interactive
   session, the real exposure is credentials, browser session cookies, saved passwords,
   mail rules, new accounts. The report must end with a credential-reset checklist.

---

## Current state

| Stage | Purpose | State |
|---|---|---|
| 0 Preflight | admin check, restore point, working dir, tool pack | not started |
| 1 Snapshot (before) | services, tasks, autoruns, processes, connections | draft written, **UNVERIFIED** |
| **2 Detection** | **ScreenConnect instance identity + other RAT presence** | **BUILT + TESTED** |
| 3 Technician review | approval gate — nothing removed without it | not started |
| 4 Remove / quarantine | stop, uninstall, quarantine, clean persistence | not started |
| 5 Scanners | Defender, KVRT, ESET, AdwCleaner, MSERT | **not started, no files** |
| 6 Procmon (targeted) | "something reinstalled it — what?" | not started |
| 7 Snapshot (after) + diff | prove removal, catch resurrections | not started |
| 8 Report | HTML + JSON + tech summary | draft written, **UNVERIFIED** |

**Critical caveat.** Four subagents were building components in parallel and were stopped
mid-flight. Three left files on disk. All four files **parse cleanly and are ASCII-clean**,
but only `detect-remote-access.ps1` has been functionally tested — the others were killed
during their verification step, and `tools/Get-ToolPack.ps1` is **known broken** (manifest
not populating). **Parsing cleanly is not the same as working. Treat the drafts as
drafts.** Per-file state is in `07-roadmap-open-questions.md`.

Deliberate build order: **every non-destructive stage ships before any destructive one.**
Removal is last, on top of machinery already proven in the field.

---

## Files in the project

```
screenconnect-cleanup/
  detect-remote-access.ps1        Stage 2 detector. BUILT, TESTED, read-only.
  targets.json                    What to look for. 15 products, toggleable.
  Run-DetectRemoteAccess.bat      Double-click launcher.
  README.md                       User-facing readme.
  docs/                           <- you are here
  scanners/                       Stage 5 adapters        (agent was building)
  tools/                          Sysinternals pack       (agent was building)
  collect-snapshot.ps1            Stage 1/7               (agent was building)
  New-InvestigationReport.ps1     Stage 8                 (agent was building)
```

---

## Read in this order

| File | What it gives you |
|---|---|
| `01-brief-and-decisions.md` | The original ask, and the 7 decisions the owner has already made. **Read before proposing anything** — several options are already closed. |
| `02-architecture.md` | The staged pipeline, flags, module contracts. |
| `03-screenconnect-intelligence.md` | What we KNOW / ASSUME / MUST VERIFY about ScreenConnect. Confidence-labelled. |
| `04-detection-poc.md` | What the built detector does, how it works, test results, bugs found. |
| `05-tools-scanners-tron.md` | Scanner inventory + licensing, the Procmon position, the Tron analysis. |
| `06-safety-model.md` | The rules that keep this from being a destructive script. |
| `07-roadmap-open-questions.md` | Milestones and what is still unanswered. |
| `08-work-log.md` | Exactly what was done, in order, with test evidence. |

---

## Rules for whoever continues this

1. **Do not invent command-line flags, APIs, file hashes, IP addresses, or capabilities.**
   Everything uncertain in these docs is explicitly labelled. Keep that discipline —
   a documented gap is useful, a fabricated flag is a liability that will fire on a
   paying client's machine.
2. **Do not re-expand scope.** No AV engine, no forensic platform, no PC optimizer.
3. **Windows PowerShell 5.1 compatible, pure ASCII, no BOM.** PS 5.1 reads a BOM-less
   non-ASCII file as Windows-1252. Non-negotiable house rule (see `06`).
4. **Verify by running, not by claiming.** Every `.ps1` must pass the parse check and the
   ASCII check in `06-safety-model.md`, and must actually be executed before being called
   done.
5. **The key map in `03` is ASSUMED.** Validating it against a live ScreenConnect install
   is the top open item. Do not build removal logic that depends on it until it is
   confirmed.

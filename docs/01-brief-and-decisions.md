# Brief and decisions already made

## The owner's brief

Build a Windows tool that investigates and cleans up unauthorized, unwanted, suspicious
or malicious **ScreenConnect / ConnectWise Control** installations on client computers.

Context: this is an MSP (Rubin IT, Israel). Clients sometimes allow remote technicians,
scammers, or unknown third parties onto their machines, who install ScreenConnect or
other remote access tools. The tool must:

- Detect ScreenConnect installations and remnants
- Identify suspicious or unauthorized remote-access components
- Investigate persistence mechanisms
- Collect evidence before remediation
- Run established malware scanners and correlate results
- Safely remove or quarantine confirmed unwanted components
- Produce a technician report

**Explicit constraint from the owner, stated twice:**

> "we arent creating the worlds first antivirus we are utilizing tools like kvrt and
> procmon etc to do the heavy lifting"
> "i said to use tron to look at a tool that has parts of removal in the script as we
> are building something close to that"

A first design pass proposed a three-binary incident-response platform with chain of
custody, a Velociraptor dependency, an exposure/credential module, and a trust catalog.
**That was rejected as over-scoped.** The correct altitude is a **Tron-style staged
PowerShell orchestrator**. Do not re-expand it.

---

## Decisions already made (D1–D7)

These were asked and answered. **They are closed. Do not reopen them or re-present the
options.**

### D1 — Validate the ScreenConnect config extraction
> "creat proof of concept with what you currently think and then we will test"

Build the PoC on current best assumptions, then test against a real install.
**Status: PoC built and unit-tested. Field validation (2026-08-26) confirmed instance
identity via DisplayName + install-dir match and the no-UninstallString surgery
fallback end-to-end; the relay-key map itself still needs the M0 test-cloud lab
(see docs/07, milestone M0).**

### D2 — KVRT licensing
> "you are allowed to use it"

KVRT is approved for use. Do not block on its licensing question.

### D3 — ESET
> "yes we can"

The MSP's ESET license covers technician scans. The ESET command-line scanner is
approved.

### D4 — Allowlisting / trust catalog
> "no allowlisting for now"

**No allowlist, no trust catalog, no AUTHORIZED/TRUSTED classification in v1.** The tool
reports what it finds with full evidence (relay host, session type, install time) and the
**technician** decides. Do not build a trust-classification engine.

### D5 — Which remote-access products to detect
> "only it should be toggleable what we are looking for"

ScreenConnect is the focus, but the target list must be **toggleable**. Implemented as
`targets.json` with 15 products; ScreenConnect on by default, the rest off, plus
`-Target` / `-All` flags.

### D6 — Where it lives
> "it will live there but should be able to be run locally as well"

Lives in this repo at `screenconnect-cleanup/`, alongside `remote-diagnostics/`. **Must
also run standalone** — a single copied `.ps1` has to work on a client machine with
nothing else present. This is why target defaults are embedded in the script as well as
in `targets.json`.

### D7 — Repo access tier
> "yes it will be full accs"

This is a `FULL_ACCESS=true` install, so committing and pushing is permitted.
**Nothing has been committed yet** — the work is uncommitted in a git worktree.

### Bundling third-party tools
> "please keep in mind you are allowed to bundle the tools"

Redistribution concerns are waived by the owner. Tools may be bundled. The
`tools/Get-ToolPack.ps1` downloader exists to *build* the bundle with hash verification;
`tools/.gitignore` keeps the binaries out of git while keeping `manifest.json` in.

---

## Repo context a new model needs

- Repo root contains `CLAUDE.md` with house rules. Read it.
- Sibling tool `remote-diagnostics/` — event log pullers, network state capture. Same
  conventions (`.bat` launcher per `.ps1`, output zipped to Desktop). Follow its style.
- `provisioning/README.md` establishes the **PowerShell 5.1 compatible + pure ASCII**
  rule. It applies here too.
- The repo has a **Windows AND WSL2 cross-platform mandate**. This tool is Windows-only
  by nature — a documented exception. The report generator is the portable half (it
  consumes JSON, needs no live system).
- Auto-sync rule in `CLAUDE.md` scopes automatic commits to `CLAUDE.md` and
  `.claude/skills/`. This folder is outside that scope, so commits here should be
  explicit, not automatic.

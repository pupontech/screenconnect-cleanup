# Agent Handoff — ScreenConnect Cleanup Tool (2026-08-30, state at v1.7.31)

Handoff for a NEW agent taking over this project. Read this first, then the
docs listed. Absolute paths, no assumptions. **PROVEN vs WRITTEN-BUT-UNVERIFIED
is distinguished throughout — trust only what the notes say was executed.**

## Identity & location

- Repo (PRIVATE, owner pupontech): `github.com/pupontech/screenconnect-cleanup`
- Local checkout (NOTE: **path contains spaces** — always quote shell paths):
  `/root/screenconnect cleanup tool/repo/screenconnect-cleanup`
- `gh` authenticated as **pupontech** (verified). Releases published from here.
- Latest release: **v1.7.31** (sha256 `2a3b7d48…`, byte-verified, Windows CI
  green on win-2022 + win-2025). HEAD on main: `a9a4ced`.
- Deploy bundle: `/root/screenconnect cleanup tool/repo/screenconnect-cleanup-v1.7.31.zip`

## What this tool is

Windows PowerShell 5.1 technician tool, Tron-style staged orchestrator for
removing ScreenConnect remote-access agents from incident machines. 10 stages
(0–9): Preflight / Snapshot-before / Detect / Review-plan / Contain+Remove /
Scanners (KVRT, ESET, Malwarebytes via winget — attended GUIs) / Uninstall AV /
Procmon (opt-in) / Snapshot-after+Diff / Report. All scripts are **pure ASCII,
no BOM, PS 5.1 compatible**. Owner tests live on Windows himself; agents do
Linux-verifiable checks only (parse, ASCII, self-tests, synthetic runs) and
DOCUMENT what needs live Windows testing.

## Verification baseline (run these before touching anything)

```bash
cd "/root/screenconnect cleanup tool/repo/screenconnect-cleanup"
pwsh -NoProfile -File ./tests/ci/Test-HouseRules.ps1            # 46 files ASCII/no-BOM/JSON
pwsh -NoProfile -File ./tests/ci/Test-Parse.ps1                 # 20 scripts parse
pwsh -NoProfile -File ./tests/ci/Test-PipelineLauncherContracts.ps1  # C1-C7 (incl. debug logger C7)
pwsh -NoProfile -File ./tests/ci/Test-ScannerProcessContracts.ps1   # scanner line-up + UAC/reparent guards
pwsh -NoProfile -File ./tests/ci/Test-RemovalRuntimeContracts.ps1   # 32 removal runtime checks
pwsh -NoProfile -File ./tests/test_report_scanner_section.ps1       # report scanner-status section
```
Linux e2e of sc-cleanup.ps1 dies at Stage 2 (no CIM on Linux) — documented
limitation, NOT a regression. Bundle: `bash make-deploy-bundle.sh` → reads
`VERSION`; release convention: byte-verified zip + GitHub Release + CI.

## What shipped in this session (v1.7.18 → v1.7.31, all CI green)

1.7.18 SPEC-review fixes (results.json stage bug; `-procmon` inversion;
scanner-status section in report w/ `-ScannerSummary`/`-ScannersSkipped`;
dead `-safemode`/`-resume` removed). 1.7.19 KVRT launch-grace probe
(60s + child hand-off; **field-confirmed fixed by owner**). 1.7.20
install-latest.ps1 same-version re-run = no-op launch. 1.7.21 **M6 Procmon
stage built** (`-procmon`, bounded capture, `.pml` to logs\Procmon) +
**Amcache collector** (schema + diff class; progress 18/18) + docs/10
field-test pack. 1.7.22 **NAS/internal-share fallback removed** (official
URLs only; contract test bans 10.0.0.5/InternalShare forever). 1.7.23
**loud download failures** (exit 1 "FAILED to stage") + browser UA (found
via Windows VM probe). 1.7.24 winget `--accept-package-agreements
--accept-source-agreements`; **preflight always runs** (Step 2 unprompted);
**UAC-disabled = prompt-and-wait** (Y/F) instead of abort. 1.7.25 **BITS-first
downloads** (progress suppressed). 1.7.26 **`-Debug` logger** (console
transcript to <WorkDir>\logs\debug.log + per-stage Write-Dbg hooks +
unhandled-error trap; C7 contract). 1.7.27 KVRT no-UAC: pre-launch UAC
warning + `UacDisabled` in result JSON + **reparenting-race fix** in the
hand-off check (family-name/start-time fallback). 1.7.28 BITS **async +
poll live progress line**; 1.7.29 size-info polish (both field-confirmed
FASTER than old IWR method in owner's VMs). 1.7.30 **scanner prompts
[Y/n] default-YES** (KVRT "skipped when UAC disabled" was the bat's
default-NO prompt, NOT UAC logic). 1.7.31 fixed the duplicate preflight
`-Debug` parameter; owner field confirmation also established that KVRT works
with UAC disabled.

## Windows VM probe (scanner-launch-probe.yml — reusable diagnostic)

- Workflow: `.github/workflows/scanner-launch-probe.yml` (workflow_dispatch +
  paths trigger). Stages KVRT+ESET fresh, launches each via Invoke-GUIScanner,
  reports rc + hand-off evidence. Run: `gh workflow run scanner-launch-probe.yml`.
- Results: ESET launches+stays-alive on win-2022/2025. KVRT launches on
  win-2022 (self-extractor: parent exits ~7-8s, random-named child keeps
  running; hand-off check waits on it). **Kaspersky CDN
  (devbuilds.s.kaspersky-labs.com) 403s GitHub runner IPs** — vendor-side
  IP blocking (UA irrelevant); tool reports loudly since 1.7.23; real
  networks unaffected (proven).

## Owner field items remaining (agents MUST NOT do live Windows/VM/ScreenConnect work)

1. 3010 reboot-resume lab run — docs/09 §7.2; still unconfirmed.
2. Windows forensic decoder cross-check — docs/07 Q4b#4; targeted comparison
   against known-good forensic output is recommended, but no parser rewrite is
   currently proposed.
3. Decision: Q7 VirusTotal policy is deferred as a future idea.
4. GUI-revision branch PR review/merge is deferred while the owner continues
   GUI work.

## Open / known issues to be aware of

- **"Done. GUI scanners … CommandAlreadyExists"** (owner report, full text
  not yet captured): NOT reproducible from the CLI tool (statically verified:
  every stage is child-process isolated; zero Function:-drive/alias/
  session-state writes on main; the one Add-Type is idempotent-guarded).
  Almost certainly the **GUI rebuild branch** (`gui-revision-screenconnect-cleaner`)
  — it has a 4-runspace pool (Scc.Evidence.psm1) + in-process module imports
  (Scc.Scanners imports Get-AVTools in-process), the known CommandAlreadyExists
  family. Needs the full error text or the owner confirming it's the GUI app.
- Kaspersky 403 on runner IPs (above) — expected in probe runs.
- Repo path with spaces — quote everything.
- START-HERE.bat must stay CRLF + ASCII (house rules enforce; the bat
  contract C3/C4 checks elevation + prompts).
- docs/07 Q4b#2 Amcache: IMPLEMENTED (1.7.21) but real-box cross-check
  against known-good forensics still pending (same caveat as other retro
  decoders).
- GUI branch gotchas (memory): 3-arg Join-Path is PS6+-only; module
  scriptblocks into bare runspaces corrupt session state — re-parse with
  [scriptblock]::Create() inside the runspace.

## Durable memory (already stored, new agent inherits)

Mnemosyne task:progress `screenconnect-cleanup` = full state above;
global insight: Kaspersky CDN 403 on GitHub IPs; canonical entries cover
lane policy, Ghost/Echo setup, weekly backups (unrelated projects).

## Docs map (read when needed)

docs/01 brief+decisions · docs/02 architecture (flags, stages, schema) ·
docs/05 scanners/Tron · docs/06 safety model (rules 9-10: skipped/failed
scanners must appear in report) · docs/07 roadmap+open questions (Q1-Q7) ·
docs/09 Windows live-test matrix (current for v1.7.31) · docs/10 field-test
pack (owner items) · CHANGELOG.md (1.7.18-1.7.31 entries).

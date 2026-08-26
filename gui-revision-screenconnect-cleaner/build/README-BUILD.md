# Build, Verify, and Release - ScreenConnect Cleaner (portable)

This document covers the CI + packaging tooling owned by the M10 CI/packaging
engineer:

- `build/Build-Portable.ps1` - stage a portable folder and produce a hashed zip.
- `build/Install-Scc.ps1`     - optional Program Files install + Start Menu.
- `.github/workflows/gui-revision-ci.yml` - CI (linux-static + windows-dynamic).

All artifacts live under `gui-revision-screenconnect-cleaner/`. The CI YAML is
the only new file at the repo root (`.github/workflows/`); nothing else there is
touched.

## 1. Building the portable package (locally)

Requires PowerShell (Windows PowerShell 5.1 or pwsh 7+).

```powershell
# From the gui-revision-screenconnect-cleaner/ directory:
pwsh build/Build-Portable.ps1

# Common overrides:
pwsh build/Build-Portable.ps1 -OutDir D:\out -Version 1.2.3 -Zip $true -IncludeConfigs $true
pwsh build/Build-Portable.ps1 -Version 1.2.3 -Zip $false   # staged folder only, no zip
```

### What it produces

Under `<OutDir>` (default `build/output/`):

```
ScreenConnectCleaner-<Version>/
  Scc.Cleaner.ps1
  Start-ScreenConnectCleaner.bat
  src/            (all Scc.* modules)
  config/         (scc-config.json, targets.json, trusted-relays.json)  [if -IncludeConfigs]
  docs/           (ARCHITECTURE.md, ...)
  tools/          (optional helper scripts, if present)
  README.md / LICENSE / CHANGELOG.md   (optional top-level, if present)
  SHA256SUMS.txt  (SHA256 of every file, relative paths)
ScreenConnectCleaner-<Version>-portable.zip
ScreenConnectCleaner-<Version>-portable.zip.sha256   (hash of the zip)
```

Excluded from the staged tree: `tests/`, `build/`, `audit/`, `DEVIATIONS*` files,
`.gitignore`, `VERSION`.

### Resilience

Optional files that do not exist yet (`README.md`, `LICENSE`, `CHANGELOG.md`,
`tools/`) are skipped with a warning - the build still succeeds. This keeps CI
green while sibling modules are still landing in the shared worktree.

### Verify a build locally

```powershell
# Integrity (PowerShell / Windows):
Expand-Archive -LiteralPath ScreenConnectCleaner-<Version>-portable.zip -DestinationPath .\verify -Force
Test-Path .\verify\ScreenConnectCleaner-<Version>\SHA256SUMS.txt

# Or on Linux where unzip exists:
unzip -t ScreenConnectCleaner-<Version>-portable.zip
```

Recompute any file hash and compare against `SHA256SUMS.txt`:

```powershell
(Get-FileHash -Algorithm SHA256 -LiteralPath .\verify\ScreenConnectCleaner-<Version>\Scc.Cleaner.ps1).Hash
```

## 2. Installing (optional, Windows)

**Default is a PREVIEW - nothing is written unless you pass `-Install`.**

```powershell
# Preview only (safe, no changes):
pwsh build/Install-Scc.ps1

# Actually install to %ProgramFiles%\ScreenConnectCleaner:
pwsh build/Install-Scc.ps1 -Install          # or -WhatIf to keep previewing

# Remove only what this script installed:
pwsh build/Install-Scc.ps1 -Uninstall
```

The installer:
- Copies the portable tree to `%ProgramFiles%\ScreenConnectCleaner`.
- Writes a machine config stub at `%ProgramData%\ScreenConnectCleaner\config\scc-config.json`.
- Creates two Start Menu shortcuts (app -> `Start-ScreenConnectCleaner.bat`,
  docs -> `docs\ARCHITECTURE.md`).
- `-Uninstall` removes ONLY the `ScreenConnectCleaner` program/data directories
  and Start Menu folder. It never touches anything else.

On a non-Windows host the script only prints a preview and makes no changes.

## 3. What the CI covers

Two jobs (see `.github/workflows/gui-revision-ci.yml`):

### linux-static (ubuntu-latest, pwsh)
- House rules: pure ASCII / no BOM / valid JSON / CRLF .bat / no committed binaries.
- Parse check of every `.ps1`/`.psm1` under the new tree.
- Pester 6.1.0 unit tests (`tests/Unit/*`).
- Pester 6.1.0 integration tests (`tests/Integration/*`).

### windows-dynamic (matrix windows-2022 + windows-2025)
- House rules + parse check under BOTH PowerShell 5.1 (`powershell`) and pwsh.
- Pester unit tests (pwsh).
- Module self-tests (`tests/ci/Test-SelfTests.ps1`).
- Headless smoke: `Scc.Cleaner.ps1 -Headless -Mode DetectOnly -SkipScanners -Config <temp>`
  (read-only, deterministic, exits 0).
- Malformed-config guard: a broken JSON config is passed; the run must NOT hang
  and must exit cleanly (the entry point's `Get-SccConfig` swallows bad JSON and
  falls back to defaults - exit 0, NOT exit 2).
- Build: `build/Build-Portable.ps1 -OutDir <runner.temp> -Version <from GITHUB_REF>`.
- Verify: `Expand-Archive` opens the zip and expected dirs/files are present.
- Upload: the zip + `.sha256` sidecar as workflow artifacts.

Triggers: push to branch `gui-revision-screenconnect-cleaner`, pull_request,
workflow_dispatch. `timeout-minutes: 45`, `fail-fast: false` on the matrix.

## 4. Release steps (human)

1. Tag a release: `git tag vX.Y.Z` and push the tag. CI derives the version from
   the tag and produces `ScreenConnectCleaner-X.Y.Z-portable.zip`.
2. Download the `ScreenConnectCleaner-portable-*` artifacts from the workflow run
   (one per Windows matrix OS; identical content, pick either).
3. Verify the `.sha256` sidecar against the zip:
   - Windows: `(Get-FileHash -Algorithm SHA256 file.zip).Hash` should equal the
     sidecar value.
   - Linux: `sha256sum -c file.zip.sha256`.
4. Publish the zip; keep `SHA256SUMS.txt` inside it for downstream verification.
5. The portable folder needs no install - extract and run
   `Start-ScreenConnectCleaner.bat` (or `Scc.Cleaner.ps1` directly).

## 5. What must be live-tested by a human (cannot run in CI)

Per ARCHITECTURE.md sec. 10, these stay manual on a disposable lab VM / real
Windows box:

- WPF GUI launch and workflow on a real machine.
- Real KVRT / MSERT execution and log parsing.
- Real ScreenConnect uninstall path (vendor uninstaller + manual surgery).
- ACL quarantine behavior (`SYSTEM` + Administrators only).
- NAS access from a domain-joined box.
- Install-Scc.ps1 actual Program Files copy + Start Menu shortcut creation
  (Windows-only COM; guarded, not exercised on Linux).
- Restore-point verification before first change.

## 6. Notes / deviations

See `DEVIATIONS.md` (section "2026-08-26 - CI workflow + packaging") for the
full decision log, including why the headless smoke uses DetectOnly (not Full),
the real malformed-config behavior (exit 0, not exit 2), and the 3 Pester unit
failures that live in sibling modules (Scc.Scanners, Scc.UI) outside this
engineer's assigned paths.

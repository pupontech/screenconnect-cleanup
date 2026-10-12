# Proposal

## Why

The current technician workflow is console-driven and requires interactive prompts across a ten-stage PowerShell investigation. PR #15 proposes a second engine that diverges from the maintained CLI and its newer safety/reporting work; a small native presentation layer can improve usability without replacing the authoritative scripts.

## What Changes

- Add a four-view .NET 10 WPF desktop client over the current PowerShell engine and current-run artifacts.
- Add a versioned, atomic presentation-state contract and a narrow noninteractive adapter for known technician decisions.
- Preserve the existing CLI, ten-stage ordering, detection/removal/scanner/report scripts and all-instance removal policy.
- Separate ordinary unelevated presentation from protected elevated remediation, with independent approval and provenance validation.
- Add safe Windows CI and packaging; leave destructive acceptance to an explicitly authorized disposable lab.
- Mark outdated architecture guidance as historical; do not merge or delete PR #15.

## Capabilities

### New Capabilities
- `technician-gui`: Four-view investigation, review, results and history experience over real run artifacts, with fail-closed presentation.
- `gui-execution`: Versioned status, noninteractive stage orchestration and explicit privileged approval over the existing scripts.

### Modified Capabilities

None (there are no existing OpenSpec capabilities in this repository).

## Impact

New `gui/`, `gui-bridge/`, `docs/GUI-CONTRACT.md`, `tests/gui/` and focused Windows CI steps. Only small, backward-compatible changes to `sc-cleanup.ps1` and existing engine scripts where needed. Existing `START-HERE.bat`, standalone CLI and artifact schemas remain supported. No live destructive testing in CI.

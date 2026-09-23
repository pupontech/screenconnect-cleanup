# Design

## Context

See `proposal.md` and `docs/GUI-ARCHITECTURE-AUDIT.md`. Current CLI has ten stages in `sc-cleanup.ps1`; it launches most children out of process but blocks on prompts, buffers process output and labels some partial operations successful. Guided `START-HERE.bat` is a separate flow. Existing artifacts and the signed/pinned deployment trust anchor are constraints, not schemas to redesign.

## Goals / Non-Goals

**Goals:** Keep one engine and a thin, testable adapter; render run-relative artifacts accurately; prevent any presentation file or stale findings from authorizing destruction. Let the GUI stay responsive under long scanner sessions.

**Non-Goals:** A second PowerShell module tree, in-WPF runspace execution, trusting status files as capabilities, an automatic relay trust classifier, per-instance approval, a database or silent scanner automation.

## Decisions

1. **One WPF project, four views.** Bind simple `ObservableObject` view models and commands using CommunityToolkit.Mvvm. Use Windows system resources for theme and standard controls; avoid a style framework. Synthetic fixtures only in Phase 1. Alternative (reuse PR #15's PowerShell WPF/runspace shell) duplicates the pipeline and has an unimplemented removal gate.
2. **Contract before integration.** `docs/GUI-CONTRACT.md` defines strict statuses, version and paths. A testable reader treats malformed, missing and outdated files as incomplete; writes use same-directory atomic replacement. The state file is presentation only. Existing engine artifacts retain their fields; the detector needs optional additive `CollectionComplete`/`CollectionErrors` metadata to distinguish provider failure from zero findings.
3. **Read-only detection is its own operation.** Spawn `detect-remote-access.ps1 -NoPause -NoZip -NoReportShare` from a fixed script location; never emulate `-WhatIf` as detection. UI receives actual nested findings. The detector must report provider failures before zero findings is considered valid. No invocation from paths supplied by artifacts.
4. **Shared full pipeline.** Adapt the existing orchestrator with an opt-in GUI noninteractive path and named decisions; preserve interactive defaults. Each operation launches Windows PowerShell 5.1 in a child process, writes bounded log/status, and does not block UI dispatch. The ten-stage table remains in the engine. Do not split the stages into a competing C# workflow.
5. **Privilege boundary.** Ordinary GUI launches unelevated. The same executable can enter a *narrow* elevated helper mode from a protected Program Files installation, after UAC; it validates installation ACLs, trusted manifest/signature, fixed operation, a one-use protected run binding and findings digest before delegating to `remove-screenconnect.ps1` with its existing plan gate. The elevated helper—not an untrusted request JSON—shows the single confirmation dialog for all current ScreenConnect instances and writes the approved plan. `UseShellExecute=true` for RunAs means no redirected streams, hence state/log artifacts provide observation; standard child processes may redirect streams. Portable copy cannot request privileged remediation. A companion executable is unnecessary unless Windows verification proves this boundary unworkable.
6. **Recovery and packaging.** Recover by reading existing run folders, never replaying removal automatically. Publish WPF self-contained `win-x64` initially, bundle scripts unchanged, and install protected copy through an admin-controlled installer that verifies ACL and pins every executable script. Don't claim this trust anchor exists before its Windows test.

## Risks / Trade-offs

- [Detector currently masks provider failure] -> Add narrowly scoped error metadata and negative tests before representing zero findings as clean.
- [UAC cancellation and no redirection] -> Never infer success from process launch; observe protected endpoint status and treat an absent/expired acknowledgement as Incomplete.
- [Writable run root] -> Status/artifacts untrusted for authorization; privileged endpoint re-reads original current-run findings/plan and snapshot/rollback evidence under protected code.
- [No signing certificate] -> Do not pretend a manifest next to a portable copy proves integrity. Protect install ACLs and pin against a separate administrator-controlled trust root; otherwise disable remediation pending signed deployment.
- [Linux host cannot run WPF] -> Compile with Windows targeting locally, then build and smoke Windows 2022/2025 CI; owner validates real desktop/UAC/live removal only on disposable lab.
- [CLI Stage 0 and Stage 6 side effects] -> Never present a full investigation as read-only; detect-only invokes detector alone. Keep scanner and AV approval explicit.

## Migration Plan

Land additive OpenSpec/contract/UI first; retain `main` scripts and existing CLI launchers. Enable GUI detection after negative artifact tests. Add opt-in noninteractive mode only with Windows 5.1 CLI regressions. Enable removal UI only after protected installation and refusal tests. Package as separate GUI distribution plus original CLI; rollback by removing GUI distribution, leaving the original CLI and run artifacts intact. PR #15 remains open and untouched.

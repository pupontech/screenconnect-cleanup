# Tasks

## 0. Audit and contract

- [x] 0.1 Compare current main, PR #15 and official platform documentation; verify `docs/GUI-ARCHITECTURE-AUDIT.md` against exact refs and scripts.
- [x] 0.2 Define statuses, artifact binding and privilege boundary in `docs/GUI-CONTRACT.md`; validate OpenSpec with `openspec validate minimal-wpf-gui --strict`.

## 1. Static four-view WPF shell

- [ ] 1.1 Create a single .NET 10 WPF project with MVVM toolkit and synthetic Home/Investigation/Review/Results data; verify `dotnet build` and Windows CI compilation.
- [ ] 1.2 Wire keyboard navigation, accessible labels, system theme, DPI layout and command-state tests; verify Windows UI smoke and unit tests without any PowerShell invocation.

## 2. Read-only detection

- [ ] 2.1 Add optional detector `CollectionComplete`/`CollectionErrors` metadata and a fail-closed current-run findings reader; verify failing-then-passing fixtures for zero/multiple/invalid/provider failures and legacy files.
- [ ] 2.2 Integrate the existing detector in a fixed isolated read-only process; verify Windows PS 5.1 execution and no removal invocation on Detect Only.

## 3. Shared pipeline and status

- [ ] 3.1 Add atomic GUI state writer and transition validation, with interrupted-write/malformed/version tests.
- [ ] 3.2 Adapt existing ten-stage orchestration for explicit noninteractive decisions and progress/log without changing CLI defaults; verify CLI regression suite and Windows PS 5.1.

## 4. Review and protected removal

- [ ] 4.1 Implement a protected elevated dialog collecting the sole all-instance confirmation (ordinary UI requests review, not approval); test missing/stale/modified findings, forged requests and current-run binding on Windows.
- [ ] 4.2 Implement protected elevated operation and independently verify script integrity, snapshot, rollback and plan prerequisites before invoking existing remover; test refusal, UAC cancellation, quarantine manifest and incomplete outcomes (no destructive CI).

## 5. Attended scanners and AV

- [ ] 5.1 Integrate KVRT/ESET/Malwarebytes attended launch/skip and findings statuses; test timeouts, failures, missing/unparseable reports without false clean.
- [ ] 5.2 Integrate explicit third-party AV uninstall approval/skip and results; verify Windows process behavior and exclusions.

## 6. Verification and reporting

- [ ] 6.1 Surface after-snapshot, diff, resurrection and Procmon states from existing artifacts; test incomplete evidence paths.
- [ ] 6.2 Open existing HTML report and show sanitized-only MicroBin destination/status/link; verify failed share and no raw upload.

## 7. Recovery and packaging

- [ ] 7.1 Discover prior runs and recover interrupted state without automatic stage replay; verify crash/restart fixtures.
- [ ] 7.2 Publish portable self-contained WPF bundle and protected-install remediation path; test paths with spaces/apostrophes, ACL/integrity refusal and package on Windows 2022/2025.
- [ ] 7.3 Run the full existing suite and targeted GUI Windows tests, document exact CI SHA and owner-only disposable-VM destructive validation; verify README retains the vibe-coded statement.

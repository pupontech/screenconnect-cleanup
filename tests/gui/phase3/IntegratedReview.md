# GUI Phase 3 integrated adapter safety review

Verdict: CHANGES_REQUESTED

Scope: read-only review of all uncommitted Phase 3 files (`sc-cleanup.ps1`, `gui-bridge/GuiState.ps1`, `gui-bridge/Invoke-GuiStage.ps1`, `gui/Services/RunStateReader.cs`, Phase 3 tests/project, and `.github/workflows/gui-phase3-ci.yml`), plus `docs/GUI-CONTRACT.md` and existing CLI contract tests. No production or test implementation files were changed. No live stage or removal script was run.

## Findings

### F1 — Medium: duplicate-property rejection is not based on decoded JSON names

Locations: `gui-bridge/Invoke-GuiStage.ps1:50-58, 130-135`; prior-state parsing in `gui-bridge/GuiState.ps1:382-421`.

The request guard counts only raw literal spellings such as `"operation":`, then calls `ConvertFrom-Json`. JSON permits escaped characters in property names, so a duplicate can use a second spelling such as `"oper\u0061tion"`. The raw regex does not count that spelling. `Assert-GuiStateFields` checks the converted object's fields, but it cannot recover a duplicate if PowerShell 5.1 `ConvertFrom-Json` has already collapsed duplicate decoded names; the regression currently tests only two identical literal keys (`InvokeGuiStageTests.ps1:88-90`). The writer has the same uncertainty for an existing `gui-state.json`: it converts raw JSON to an object before validating fields, so a parser that collapses duplicate keys can accept and overwrite an ambiguous prior state. The C# reader does explicitly reject duplicate properties, leaving the PowerShell writer/request boundary weaker.

Correction: reject duplicates using a JSON-token parser that compares decoded member names before materializing a PowerShell object (or an equivalent parser configured to reject duplicates). Add escaped-name duplicate cases under Windows PowerShell 5.1 for both requests and prior state, and assert the state file remains unchanged after rejection. Until that runtime behavior is verified, do not claim strict duplicate-key rejection for PS 5.1.

### F2 — Medium: the adapter does not enforce one writer/run under concurrent requests

Locations: `gui-bridge/Invoke-GuiStage.ps1:397-405`; `gui-bridge/GuiState.ps1:487-495, 514-541`.

The adapter checks whether `<OutRoot>/<runId>` exists and then calls `Directory.CreateDirectory`; that check-then-create is not exclusive, and `CreateDirectory` succeeds when another caller has already created the directory. `Write-GuiState` similarly reads and validates the current JSON, compares its bytes, and later replaces it without a lock/CAS around the whole compare-and-replace interval. Two adapter processes using the same runId can therefore both execute against one run root, overwrite shared artifacts, and race state publications; the byte comparison does not serialize concurrent writers. This violates the contract's one-writer-per-run and unique-directory assumptions and can leave `gui-state.json` inconsistent with the artifacts or active process.

Correction: acquire an exclusive per-run ownership lock before creating/publishing the initial state and hold it for the adapter run, rejecting a second owner. Keep publication atomic for readers; add a synthetic concurrency regression that races two invocations with the same runId and proves only one enters stage execution.

## Verified controls and scope notes

- The new `GuiRequestPath` parameter is appended to the existing CLI parameter list and GUI dispatch is gated by `PSBoundParameters.ContainsKey('GuiRequestPath')` (`sc-cleanup.ps1:54, 62-75`). Bare invocation still falls through to the existing pipeline. Existing CLI output contracts remain source-based checks rather than an end-to-end invocation test, so Windows CI should remain a gate.
- Adapter requests use a fixed operation allowlist and exact per-operation fields. Arbitrary script paths, PowerShell expressions, stdin, and unknown fields are not passed through. Only `DetectOnly` and `FullInvestigation` execute; the other recognized operation names are rejected as not implemented (`Invoke-GuiStage.ps1:21-47, 379-385`). That is a capability limitation, not an unsafe fallback.
- Child process paths and arguments are fixed in code, use `-NoProfile -NonInteractive`, disable stdin, and select `powershell.exe` on Windows. `FullInvestigation` pauses at stage 3 `NeedsAction`; it does not enter removal (`Invoke-GuiStage.ps1:193-245, 443-479`). The synthetic tests assert stage 4 remains pending.
- The state writer and reader agree on the ten stage names/order and allowed statuses. The reader rejects duplicate JSON properties, validates run/computer identity and artifact paths, downgrades interrupted `Running`, and checks that `Completed` has only completed/skipped stages (`RunStateReader.cs:114-139, 211-295`). Windows state handles include delete sharing, compatible with replacement (`:776-784`); a Windows replacement test is present.
- The Phase 3 workflow runs the synthetic PowerShell tests under Windows PowerShell 5.1 on Windows 2022/2025, builds the GUI, and requires all 36 C# reader cases (`.github/workflows/gui-phase3-ci.yml:18-123`). No workflow defect was found by inspection.

## Verification and limitations

- `git diff --check`: passed for tracked changes.
- Attempted `pwsh -NoLogo -NoProfile -NonInteractive -File tests/gui/phase3/GuiStateTests.ps1`: blocked by the terminal safety gate before execution. No local PowerShell test result is claimed.
- `dotnet` is not installed in this environment, so the C# suite/build could not be run locally. Windows PowerShell 5.1 and Windows process/file-sharing behavior were not available for runtime verification.
- The parent handoffs report focused writer/adapter tests and 36 C# cases passing in prior runs; those results are not an independent execution in this review run. Windows CI remains the required runtime gate.

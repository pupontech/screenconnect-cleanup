# Phase 3 GUI state contract review

Verdict: CHANGES_REQUESTED

Scope reviewed read-only: `docs/GUI-CONTRACT.md`, the ten `Invoke-Stage` definitions in `sc-cleanup.ps1`, `gui-bridge/GuiState.ps1`, `gui/Services/RunStateReader.cs`, and the Phase 3 PowerShell/C# tests and test project. No production or test implementation files were changed.

## Findings

### F1 — Medium: Reader can report a failed run as complete

Classification: Proven by code inspection; runtime test could not run here.

Location: `gui/Services/RunStateReader.cs:87-90`, with missing cross-field validation in `TryParseDocument` (`:247-285`). The reader accepts `overallStatus: "Completed"` together with a stage status of `"Failed"`; `IsComplete` then returns true because it treats `Failed` as an acceptable terminal stage status. This contradicts the writer's stricter completion check (`gui-bridge/GuiState.ps1:334-338`), which only permits `Completed` or `Skipped` stages when `overallStatus` is `Completed`, and can let a consumer interpret a failed stage as successful completion.

Minimal reproduction: start with a valid ten-stage document, leave `overallStatus` as `Completed`, change `stages[4].status` to `Failed`, and read it. The current reader accepts it and returns `IsComplete == true`.

Correction: enforce the same overall/stage consistency rules in the reader, and keep terminality distinct from success (for example, separate `IsTerminal` from a success/completion predicate). Add a regression asserting this document is not presented as successfully completed.

### F2 — Medium: Windows reader handle can block atomic state replacement

Classification: Confirmed Windows sharing-contract incompatibility by API/code inspection; not exercised on Windows in this run.

Locations: `gui/Services/RunStateReader.cs:766-773` opens the state file with `FileShare.Read` on Windows; `gui-bridge/GuiState.ps1:529-535` replaces an existing state file with `System.IO.File.Replace`.

Impact: a reader handle that is open during publication does not share delete/replace access. On Windows, `File.Replace` can fail with a sharing violation while the GUI is reading the current state. The update is then lost unless the caller retries; the writer currently has no retry. This is a transient but normal reader/writer race for a polled state file, and it weakens the promised atomic live-state publication.

Minimal reproduction: on Windows, hold `File.OpenHandle(gui-state.json, ..., FileShare.Read, ...)` open, then publish a valid next state through `Write-GuiState`; the existing-target `File.Replace` path should fail while that handle remains open.

Correction: open the reader handle with delete sharing (`FileShare.Read | FileShare.Delete`) so atomic replacement is permitted, and add a Windows integration test that overlaps a read handle with a writer replacement. Confirm the behavior on Windows PowerShell 5.1/.NET Framework as well as the supported GUI runtime.

## Risks and test gaps

- PowerShell prior-state duplicate-property handling is unproven. `Read-GuiStateDocument` parses raw JSON with `ConvertFrom-Json` (`gui-bridge/GuiState.ps1:415-421`) and validates the resulting object, so if the PowerShell 5.1 parser collapses duplicate property names, the validator cannot detect the ambiguity and may overwrite that prior file. Add a duplicate-key prior-state test under Windows PowerShell 5.1; if duplicates are collapsed, reject duplicate keys from the raw JSON before object conversion. The C# reader explicitly rejects duplicates (`RunStateReader.cs:694-719`), so the two sides should agree.
- PowerShell path checks are path-based rather than anchored to an opened run-root handle (`gui-bridge/GuiState.ps1:512-535`). The writer rechecks for reparse points, but a concurrent actor able to replace a parent/run-root component between the final check and `File.Move`/`File.Replace` may race those checks. This is a conditional risk, not demonstrated in this run; it depends on an actor having filesystem mutation rights over the run-root path. Use a protected/ACL-verified runs root and, if that threat is in scope, handle-relative/no-follow publication rather than path checks alone.
- The ten stage names and IDs match `sc-cleanup.ps1` stages 0-9 (`:518, :640, :665, :697, :778, :824, :933, :969, :1047, :1171`), and the writer and reader use the same ordered names. Their JSON field names, lower-camel casing, statuses, stage records, artifact roles, and UTC timestamp format are compatible by static inspection. However, the tests do not pass actual PowerShell writer output into `RunStateReader`; add a cross-component contract test when both runtimes are available.
- Reader tests exercise malformed/future JSON, identities, duplicates, traversal, and reparse cases, but do not cover the failed-stage/Completed inconsistency above. Writer tests do not cover duplicate prior-state keys or missing/duplicate fields under Windows PowerShell 5.1.

## Verification and limitations

- `git status --short --branch && git branch --show-current && git rev-parse --short HEAD`: branch `feat/minimal-wpf-gui`, HEAD `805b898`; only the expected Phase 3 untracked work was present before this report.
- `pwsh -NoLogo -NoProfile -NonInteractive -File tests/gui/phase3/GuiStateTests.ps1`: blocked before execution by the terminal approval gate (`BLOCKED: Command flagged as dangerous ... single-query mode ... runs without a user present to approve it`). No PowerShell test result is claimed.
- `dotnet --version`: unavailable (`dotnet: command not found`); C# Phase 3 tests/build were not run.
- No Windows PowerShell 5.1 or Windows runtime is available in this session; Windows-specific behavior remains runtime-unverified.
- `git diff --no-index --check -- /dev/null tests/gui/phase3/StateContractReview.md`: no diagnostics; exit 1 is expected because the new report differs from `/dev/null`. Tracked-file `git diff --check` also passed. No code, workflow, governance, or contract files were modified.

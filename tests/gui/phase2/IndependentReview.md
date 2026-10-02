# GUI Phase 2 independent review

Verdict: CHANGES_REQUESTED

Scope reviewed: `docs/GUI-CONTRACT.md`; `detect-remote-access.ps1`; `gui/Services/FindingsReader.cs`; `tests/gui/phase2/DetectorCollectionTests.ps1`; `tests/gui/phase2/FindingsReaderTests.cs`; existing findings consumers `Invoke-ReviewAndRemove.ps1` and `Submit-ConnectWiseReport.ps1`.

## Required changes

1. False-clean remains possible when install-directory enumeration fails. In `detect-remote-access.ps1:251-263`, `Get-DirsMatching` treats a missing/inaccessible parent as an empty source and suppresses `Get-ChildItem` errors with `-ErrorAction SilentlyContinue`; its catch also returns an empty list. `CollectionComplete` at `detect-remote-access.ps1:1088` only reflects `$script:CollectionErrors`, which this source never updates. An inaccessible ScreenConnect install-directory source can therefore yield zero instances and a complete/clean artifact. Preserve results from other sources, but record genuine provider/enumeration failures in `CollectionErrors` (distinguish an absent optional directory from an access/provider error) and make the result incomplete. Also decide whether `Get-ConnectionsForPids` (`detect-remote-access.ps1:460-477`) belongs to completeness: it still swallows TCP provider errors, so at minimum document that it is excluded or record the failure while retaining any positive instances.

2. Reparse-point containment is lexical and has a check/use gap. `FindingsReader.TryResolveArtifactPath` uses `Path.GetFullPath` (`gui/Services/FindingsReader.cs:210,223-228`) and checks only the final run root plus `detect`, nested run directory, and findings file (`:211,234-236`). It does not validate reparse/symlink ancestors of `runRoot`; a root reached through a symlinked parent is accepted. The subsequent `File.ReadAllBytes` (`:130`) also occurs after separate attribute checks, so a writable run tree can be swapped to a symlink/reparse point between check and open. A supplemental Linux probe confirmed that a findings file below a symlinked ancestor is accepted as clean. Resolve against a trusted runs-root boundary and validate physical paths, and open the artifact without following reparse points (or otherwise validate the opened handle's final path) to close both ancestor escape and check/use race. Add tests for a symlinked ancestor and a replacement race/handle-safe open, in addition to the existing nested-directory symlink test.

3. Empty objects are accepted as empty arrays in safety-critical fields. `ValidateCollectionStatus` accepts `CollectionErrors: {}` at `gui/Services/FindingsReader.cs:414-438` and `ScreenConnect.ParseIssues: {}` at `:441-457` because `IsEmptyObject` is treated as empty. With `CollectionComplete: true` and no findings, both malformed documents currently produce `IsClean == true` (confirmed by supplemental probes). The contract requires malformed evidence to be Incomplete and specifies `CollectionErrors` as an array. Require the documented array shape unless a Windows PowerShell 5.1-produced artifact proves this exact encoding is necessary; if it is necessary, lock it down with a PS5.1 golden fixture and an explicit, narrowly scoped compatibility rule rather than accepting arbitrary object-shaped empties.

## Checks

- Phase 2 reader tests: 14/14 passed in an isolated temporary .NET 10 test project; three supplemental probes reproduced the empty-object and symlinked-ancestor behaviors above (17 tests total including probes).
- Detector collection regression script: passed all assertions under PowerShell 7.6.6, including empty success, service/process/registry errors, partial positive preservation, metadata serialization, and EventLogError separation.
- Existing detector connection regression script: passed under PowerShell 7.6.6.
- Phase 1 tests: 17/17 passed.
- GUI cross-build: succeeded with 0 warnings and 0 errors.
- `git diff --check`: passed.
- Windows PowerShell 5.1 and Windows filesystem/runtime behavior were unavailable here; Windows CI/runtime verification remains required. The PS7 serialization test does not establish PS5.1's empty-array encoding.

No source or test under review was modified. The reviewed reader is read-only and adds no removal path; detector metadata changes are additive to the existing findings fields. Windows CI is still required after the requested fixes/integration.

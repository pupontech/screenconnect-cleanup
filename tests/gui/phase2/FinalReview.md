# GUI Phase 2 final independent review

Verdict: PASS for the three reviewed findings on the current Linux working tree. This does not clear the separate Windows CI/runtime gate.

Scope: `docs/GUI-CONTRACT.md`, the P2D detector change and collection tests, and the P2E `FindingsReader` change and tests. No reviewed source or test files were changed by this review.

## Findings rechecked

1. Detector false-clean on install-directory errors — addressed. `Get-DirsMatching` now treats a missing optional parent separately from access/provider errors, uses terminating enumeration errors, and records failures with `Add-CollectionError` (`detect-remote-access.ps1:251-287`, `386-397`). The final artifact derives `CollectionComplete` from that error list while keeping `EventLogError` separate (`1112-1116`). Mocked regressions cover absent parent, inaccessible parent, enumeration failure, and preserving a positive process finding during enumeration failure (`tests/gui/phase2/DetectorCollectionTests.ps1:158-213`); the existing provider/registry tests also check positive-result and `EventLogError` preservation (`215-276`).

   `Get-ConnectionsForPids` still suppresses TCP-provider errors (`detect-remote-access.ps1:485-502`), but it only enriches already-identified process instances (`742-756`); no path from that failure to an otherwise empty detection result was found. The exclusion rationale currently appears in the test mock comment (`DetectorCollectionTests.ps1:98-104`), not as a runtime assertion. Treat connection-detail completeness as a documented limitation if that field is intended to promise complete enrichment; it does not reproduce the reviewed false-clean case.

2. Reader path boundary and replacement race — addressed in the inspected implementation. `Read` requires the trusted runs root (`FindingsReader.cs:103-123`). Resolution checks ancestors for reparse points and holds trusted-root/run-root handles, then compares physical paths (`241-279` and following resolution checks). The artifact is opened as a handle, its final path is checked before parsing and rechecked after reading (`129-149`); Linux uses `O_NOFOLLOW`, and Windows uses an opened-handle final-path check. Regression cases reject a symlinked run-root ancestor (`FindingsReaderTests.cs:233-261`) and exercise repeated artifact-to-symlink replacement (`287-353`). The latter passed on Linux; Windows handle behavior still requires Windows verification.

3. Malformed object-shaped status arrays — addressed for the safety-critical fields. `CollectionErrors` and `ScreenConnect.ParseIssues` now require arrays, and malformed objects add issues rather than permitting `IsClean` (`FindingsReader.cs:505-548`). Regression cases confirm `{}` is incomplete for both fields and malformed status does not discard positive instances (`FindingsReaderTests.cs:116-155`). No PS5.1-produced golden artifact was available, so Windows PowerShell 5.1 empty-array encoding remains unresolved; do not treat PS7 serialization as proof. The reader still has a narrowly scoped empty-object compatibility path for `OtherTargets`/`Hits` (`FindingsReader.cs:437-450`, `477-482`), also unverified against PS5.1 output.

## Verification

- Detector collection regression script: all assertions passed under Linux PowerShell using stdin invocation: `pwsh -NoLogo -NoProfile -NonInteractive - < tests/gui/phase2/DetectorCollectionTests.ps1`.
- Focused reader xUnit harness linked to the current source/tests: 20/20 passed, including empty-object rejection, symlinked-ancestor rejection, and the artifact replacement-race test. The pre-existing scratch harness contains an obsolete supplemental probe with the old `Read` signature, so the successful run excluded only that stale probe file.
- `git diff --check`: passed.
- No removal path was added: the reader opens and reads findings only; detector edits collect metadata and serialize the findings artifact. No removal/uninstaller execution is present in the reviewed changes.

Windows CI and runtime validation remain a distinct required gate. In particular, verify the actual Windows PowerShell 5.1 array encoding and Windows physical-handle behavior before claiming those compatibility/runtime paths are proven.
# Legacy code review and optimization candidate (v1.8.6)

## Scope and provenance

Reviewed the legacy Windows technician tool released as v1.8.5, source
`6f4aed383221f279db9115b61a09faf99f92f90f`, in a new linked worktree on
`perf/legacy-review-185`. The approved v1.8.5 release/tag/assets are unchanged.
The unfinished WPF GUI and original worktree's local files are untouched.

Two freshly smoke-tested lithosai / zai-org/GLM-5.3-Flash auditors inspected
core removal/launchers and collection/report/scanner/relay paths. Both reached
iteration limits before saving formal report files; their returned findings
were treated as leads, not as passing reviews. Parent reproduced the accepted
issues below with harmless fixtures and rejected the alleged detector-path
truncation using the exact production regex.

No agent ran a live scanner, installer, Windows collector, service operation,
remover or reboot. Tests use disposable files, synthetic providers and the real
production statements/functions. Windows PowerShell 5.1 remains the baseline.

## Confirmed findings fixed in this candidate

Line citations below refer to the v1.8.5 baseline.

1. **HIGH - audit-output overwrite:** `Show-PersistenceReview.ps1:195` opened
   `review-opened.json` with `FileMode.Create`. A pre-existing hard link caused
   the supposedly read-only review step to truncate an unrelated sentinel file.
   Fix: validate evidence-path components, refuse pre-existing output before
   launching windows, and create the record exclusively. Audit-write failure
   is nonzero. Proof: `tests/test_persistence_review_safety.ps1` failed before
   the fix; now preserves the external sentinel and rejects redirected folders.
2. **MEDIUM - false timeout from buffered progress:**
   `Invoke-PersistenceScan.ps1:127` slept 50 ms after every output line, even
   when both worker streams already had buffered data. A finished 600-line
   provider was reported incomplete after 13.570 seconds. Fix: drain ready
   lines immediately and sleep only when idle; check both deadlines every pass.
   The same local fixture completed in 1.610 seconds with the final line and
   done marker intact. This is a synthetic supervisor measurement, not a claim
   that real Windows provider collection is 8x faster.
3. **MEDIUM - report lost after collection failure:** `sc-cleanup.ps1:1137`
   threw on a failed after-snapshot; `Invoke-Stage:339` rethrew before Stage 9.
   Fix: retain an INCOMPLETE diff/failure artifact, continue to the report, and
   keep `DiffIncomplete=true` for the final nonzero pipeline outcome. Proof:
   `tests/test_after_snapshot_failure_reporting.ps1` executes the real Stage 8
   with child exit 4 and renders the real report with the failure reason.
4. **MEDIUM - unescaped HTML warning sink:**
   `New-InvestigationReport.ps1:672` interpolated AV JSON-parser exception text
   raw in a warning paragraph while the table already escaped it. Fix: use
   `Fmt` consistently. The actual warning expression now escapes synthetic
   markup. The extent of source text embedded in real parser exceptions differs
   by PowerShell engine; no exploit of a live machine is claimed.
5. **LOW - repeated traversal/hash work:**
   `Persistence.Inventory.psm1:243-259` traversed each root independently.
   Repeated/nested roots produced eight records/hashes for three files. Fix:
   track canonical lexical directories with an OS-appropriate comparer. Fixture
   directory reads fall from five to two, hashes from eight to three, with three
   unique records and no coverage error. File/time limits and reparse skips stay.
6. **LOW - single-section JSON shape drift:** `collect-snapshot.ps1:1407-1408`
   captured row arrays through statement output, serializing zero rows as null
   and singleton rows as scalars. Fix: normalize at the collection call, once.
   `tests/test_snapshot_section_shapes.ps1` covers zero/one/many rows and keeps
   SRUM's object shape. Group/parallel mode was not the defective path.

## Deferred issues and limitations

- **MEDIUM - automatic resume-task lifecycle:**
  `remove-screenconnect.ps1:1671-1673` registers a SYSTEM logon task without an
  expiry; cleanup at `:1989` is on the successful resume path, while failed
  verification at `:1942-1947` and `:1983-1986` leaves the task installed.
  A persistent failure can therefore cause repeated logon attempts. No live
  Task Scheduler behavior was exercised. Leave failure evidence intact; a
  bounded retry/expiry policy with explicit manual recovery needs a separate
  reviewed change and Windows fixtures. Do not silently delete failed-run
  evidence or choose a retention/retry policy as a performance optimization.
- Noninteractive confirmation in `Invoke-ReviewAndRemove.ps1:176` raises an
  uncaught Read-Host error. It refuses removal rather than approving it; normal
  attended mode is the supported path. Graceful unattended refusal is a
  usability follow-up, not authorization to add unattended removal.
- Some vendor-uninstall errors in `Invoke-AVUninstaller.ps1` are conveyed in
  the result JSON rather than a nonzero process exit. Caller/result semantics
  need a separate contract review before changing exit behavior.
- Actual collector coverage, scanner behavior, UAC UX, target mutation,
  quarantine restoration, and reboot-resume remain owner/live Windows gates.

## Next optimization opportunities (not implemented or claimed faster)

1. Cache PID-to-process-name lookups per connection snapshot rather than
   repeated Get-Process calls; prove names and PID-reuse behavior on Windows.
2. Replace repeated per-value registry-provider calls with one key snapshot;
   preserve native value types, errors and incident-window filters.
3. Combine ScreenConnect persistence sweeps for distinct install/service paths
   without relaxing exact identity checks or revalidation after mutation.
4. Avoid JSON serialization for primitive field comparisons in semantic diffs;
   benchmark large process/connection fixtures and preserve all verdicts.
5. Index relay receipt digests only if measured store growth justifies it;
   retain lock, durability, deduplication and encrypted-receipt semantics.

## Spec axis

`docs/06-safety-model.md:20-23,80-86` requires incomplete evidence and scanner
failures to remain visible, and `:25-68` defines technician approval, rollback,
quarantine and vendor-first removal. This patch preserves those gates and repairs
report continuation. It adds no automatic removal of unrelated services, files
or tasks. The existing resume-task lifecycle still needs a policy decision.

## Standards axis (judgement, not a new defect list)

Standalone compatibility currently duplicates path validation across scripts;
introducing a shared module only for style would change package/standalone
contracts. Keep the narrow guards for this candidate. Larger monolithic scripts
and provider-heavy functions limit test locality; continue extracting only
proven seams, not a wholesale rewrite of the approved technician workflow.

## Verdict

**FIX-FIRST for unrestricted production/reboot-resume certification.**
The narrowly scoped optimization candidate is suitable for the repository's
synthetic Windows CI and owner testing after its exact-source checks pass.
This is not an assertion that every code path or live-machine outcome was tested.

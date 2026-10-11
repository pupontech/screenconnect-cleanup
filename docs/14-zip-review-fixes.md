# Published ZIP review fixes - v1.8.10 testing candidate

This candidate fixes the scoped review of the published v1.8.9 guided-runner ZIP.
It does not change the separate WPF GUI, move the stable release tag, or certify
live cleanup. Extract the entire candidate ZIP into a fresh folder and use
`START-HERE.bat`; do not replace files inside an existing installation.

## Fixed boundaries

- Immediate verified quarantine, already-absent payload, dry-run, reboot-deferred
  move and move failure have explicit outcomes. Deferred/failed containment does
  not authorize service/uninstall-key/persistence surgery. Deferred resume must
  verify source absence, destination containment, identity and ACLs before the
  deferred metadata cleanup; vendor exit 3010 retains its existing separate path.
- Both guided report branches receive the current-run comparison artifact.
  Collection/diff failures and missing snapshots propagate a nonzero guided-run
  status while the report step continues. A missing diff is visibly unavailable;
  resurrection remains a reported finding rather than an operational error.
- The builder refuses dirty or untracked input and copies only an immutable Git
  archive. Ignored local documents cannot enter a commit-stamped package. Exact
  source SHA and per-member checksums remain mandatory.
- An explicit bare report filename works. Missing/invalid diff completeness
  metadata is unavailable, not green; contradictory CLEAN metadata becomes
  INCOMPLETE. Empty-object/null scanner threats do not fabricate a detection.

## Regression seams

`tests/test_quarantine_outcome_gates.ps1` extracts the real remover functions and
instance loop. Only harmless scratch files exist, and service/registry/vendor/
native delayed-move/ACL operations are stubbed. It covers deferred containment,
failed registration, failed source/identity/ACL resume checks, verified resume,
immediate containment and failed registry export. It never runs a real remover.

`tests/test_guided_diff_reporting.ps1` replays both real report argument lists.
On Windows it also runs the actual Step 8 batch region with only its child-launch
seam substituted, proving after-collection/diff failures and resurrection exits.

`tests/test_report_relative_output.ps1`, `tests/test_report_diff_metadata.ps1`
and `tests/test_report_threat_shapes.ps1` drive the real report writer with
synthetic input. `tests/test_bundle_provenance.py` drives the real builder in
isolated Git fixtures, including dirty/untracked refusals and ignored-file
exclusion. CI includes the new PowerShell fixtures in source and extracted-ZIP
runs under PowerShell 5.1 and pwsh on Windows Server 2022 and 2025.

## Owner-only validation remains

Native locked-file MoveFileEx behavior, real service/registry removal, reboot
continuation/task lifecycle, actual quarantine ACLs and Windows providers,
real antivirus scanners/installers, UAC and full client-machine acceptance are
not proven by synthetic CI. Use a disposable approved Windows lab for destructive
validation. Do not run lab-only automatic approval on a client machine.

The existing resume retry/expiry policy is not redesigned in this candidate.
Stable v1.8.9 remains untouched pending owner acceptance of this test build.

# GUI/backend contract (v1)

Authority: `sc-cleanup.ps1` Stage IDs 0-9 and its child scripts. This document specifies presentation and the GUI adapter only; existing `findings.json`, `plan.json`, snapshots, manifests, scanner results, `results.json` and HTML report retain their original schemas. `gui-state.json` is never an approval token.

## State file

Located at `<runRoot>/gui-state.json`, UTF-8 (no BOM); one writer per run, unique directory under the configured runs root. Schema version integer `1`. The GUI `runId` is the outer work-directory leaf (e.g. `HOST-20260923_120000`); the detector's `findings.json.RunId` is the **nested** `detect/HOST_2026-09-23_120000/` leaf and need not equal the GUI run ID. Bind both paths to the current outer run root and validate the detector ID against its nested directory leaf. Example (not a fabricated investigation result):

```json
{
  "schemaVersion": 1,
  "runId": "HOST-20260923_120000",
  "computerName": "HOST",
  "overallStatus": "Incomplete",
  "currentStage": 2,
  "stages": [
    { "id": 0, "name": "Preflight", "status": "Completed", "operation": "", "startedUtc": "2026-09-23T12:00:00Z", "endedUtc": "2026-09-23T12:00:15Z" },
    { "id": 2, "name": "Detect", "status": "Incomplete", "operation": "Collection interrupted", "startedUtc": "2026-09-23T12:01:00Z", "endedUtc": null }
  ],
  "warnings": ["Detection provider unavailable"],
  "errors": [],
  "artifacts": { "findings": "detect/HOST_2026-09-23_120000/findings.json", "log": "master.log" },
  "updatedUtc": "2026-09-23T12:01:10Z"
}
```

Writer SHALL include all ten stage records (`id` 0..9) with names copied from the engine stage table; the shortened example illustrates fields only. `overallStatus`, and every stage `status`, MUST be exactly one of `Pending`, `Running`, `NeedsAction`, `Completed`, `Warning`, `Failed`, `Skipped`, `RebootPending`, `Incomplete`. No synonyms, and no invented percentages. `currentStage` is integer 0..9 or null before/after work. `warnings` and `errors` are string arrays. `artifacts` is a map of known role to *relative*, run-root-contained path; no `..`, drive root, UNC, device path or alternate data stream. Known roles: `findings`, `beforeSnapshot`, `plan`, `removalManifest`, `scannerResults`, `avUninstallResults`, `procmon`, `afterSnapshot`, `diff`, `results`, `report`, `sanitizedPackage`, `log`. Absence is unknown, not success. An artifact path is only a pointer, never proof the artifact parsed or the operation completed.

Write via a same-directory unique temporary file, flush/close and atomic rename/replace; readers must tolerate file-not-found on first publication, unknown future schema versions, truncation/malformed JSON, missing fields, unrecognized states, read races and interrupted `Running` states by showing Incomplete rather than crashing. Validate paths after canonical resolution and refuse traversal/reparse escape; never open a report or copy a link from a path that escapes the run root. Keep warnings/errors bounded to avoid unbounded UI memory. The log is append-only; readers tail incrementally without interpreting log strings as authorization.

Transition rules: `Pending -> Running | Skipped`; `Running -> NeedsAction | Completed | Warning | Failed | Incomplete | RebootPending`; `NeedsAction -> Running | Skipped | Incomplete`; `RebootPending -> Running | Incomplete` only after trusted resume proof. Terminal states cannot be changed to Completed merely because a child process exits; correlate required artifacts and outcome fields first. Recovery from a dead producer converts Running/NeedsAction to Incomplete without replaying a stage. Determinate progress is permitted only from measured counts (e.g. scanner bytes), not elapsed time or stage index.

## Existing artifact interpretation

`findings.json`: accept only a current run child of `detect/` with matching `RunId` and machine; require `ScreenConnect.Instances` to be an array, and inspect `ParseIssues`, `EventLogError`, `CollectionComplete` and `CollectionErrors`. The current detector has no general collection-completeness field and silently returns empty inventory on some provider failures (`detect-remote-access.ps1:364-413`). Phase 2 SHALL add optional `CollectionComplete` (boolean) and `CollectionErrors` (array of `{Source, Error}`) fields to the existing findings document, preserving all prior fields and consumers. Successful zero findings requires `CollectionComplete=true` and a valid ScreenConnect result; an old document lacking it, failed provider, invalid/missing data or parse issue is Incomplete, never "0 detected / clean". Display all `OtherTargets[].Hits` as detect-only. Instance fields come from the detector (`Identifier`, `RelayHost`, `SessionType`, `ServerKeyFingerprint`, `InstallDirCreatedUtc`, `InstallDir`, `CustomProperties`, `Sources`, `UnknownParams`, `File`, etc.). Missing fields display "Not available" without manufacturing values.

`plan.json` remains PlanSchemaVersion 2 with `RunId` bound to the **detector** run directory, `SourceFindings` and `SourceFindingsSha256`; it is written only by a validated privileged operation after explicit all-instance approval. `removal-manifest.json` and reboot proof remain authoritative for removal, not an uninstaller exit code. `scanner_results.json` and `logs/scanner-*-result.json` distinguish launch/exit from scanner findings (`logs/scanner-*-findings.json`); absent/unparseable findings mean Unknown, not Clean. `snapshot_diff.json` verdict `INCOMPLETE` is not Clean; `results.json` and report share exit/status must be checked independently. A sanitized MicroBin link is exposed only when sharing succeeded and the destination is a valid configured HTTPS URL; do not parse arbitrary raw evidence into a link.

## Operations (bounded, not a general command API)

The GUI can request `DetectOnly`, `FullInvestigation`, `ContinueLowDisk`, `ContinueUacDisabled`, `ReviewAllScreenConnect`, `DeclineRemoval`, `LaunchScanner` (KVRT/ESET/Malwarebytes only), `SkipScanner`, `ApproveAvUninstall`, `SkipAvUninstall`, `AcknowledgeRestart` and `OpenExistingRun`. Adapter requests have `{schemaVersion:1, operation, runId, computerName, findingsSha256?, decision?}` with strict operation-specific validation. `ReviewAllScreenConnect` is a request to open the protected approval dialog, **not consent**; a forged request or modified plan must never authorize removal. No script path, PowerShell expression, arbitrary CLI arguments, product identifier or upload destination is accepted from UI data. The UI never supplies stdin answers to `Read-Host`.

DetectOnly invokes the existing detector in an isolated non-elevated PowerShell 5.1 process and cannot call removal. FullInvestigation follows the engine's ten-stage order through a supported noninteractive path. For destructive approval, the protected elevated GUI endpoint SHALL display the current instance count/identities, findings digest and removal/quarantine warning and collect the **one** explicit technician confirmation itself. It issues a cryptographically random per-run nonce at protected run creation and stores the binding (host, detector-run ID/path, findings SHA256, before-snapshot and rollback evidence) under administrator-owned ACLs; the nonce is consumed once on approval. Merely copying a nonce from an untrusted request file or matching a hash in a user-writable folder is insufficient. The endpoint re-reads source evidence and rechecks run identity, digest, plan, snapshot and rollback prerequisites immediately before invoking the existing remover. A cancelled UAC dialog or protected confirmation is Incomplete/NeedsAction, never consent. The ordinary GUI review presents evidence but does not collect a second removal confirmation. The lab `-ExecuteRemoval` path remains excluded. No destructive operation starts from a user-writable portable copy; protected installation must be ACL-verified on Windows and anchored by publisher signature or an independently pinned trusted manifest (a hash file beside untrusted scripts is not an integrity anchor).

CLI invocation without GUI parameters must keep its existing prompts, flags and behavior. Sharing remains sanitized-only through `Submit-ConnectWiseReport.ps1`, with destination/status visible and no raw-evidence automatic upload.

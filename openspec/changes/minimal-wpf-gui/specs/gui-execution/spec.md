# Spec Delta

## Purpose

Define a narrow, fail-closed interface between the unelevated technician UI and the authoritative Windows PowerShell 5.1 investigation pipeline.

## ADDED Requirements

### Requirement: Versioned presentation state
Each GUI run SHALL write an atomic `gui-state.json` with schema version, run identity, machine, overall and per-stage states, current stage, warnings, errors and run-relative artifact references. Allowed states SHALL be Pending, Running, NeedsAction, Completed, Warning, Failed, Skipped, RebootPending and Incomplete. Presentation data SHALL never authorize privileged actions.

#### Scenario: Interrupted write
- **WHEN** the GUI reads while a state update is written
- **THEN** it sees a complete prior or new document, not a partial success

### Requirement: Explicit noninteractive decisions
GUI execution SHALL never pipe keyboard answers to an interactive process. Low disk, disabled UAC, removal approval, scanner launch/skip, AV uninstall approval and reboot decisions SHALL be explicit, validated operations; CLI prompts remain unchanged. Detect Only SHALL not invoke removal.

#### Scenario: Missing decision
- **WHEN** a GUI operation needs an approval and no valid decision is supplied
- **THEN** it enters NeedsAction or stops incomplete without performing the protected action

### Requirement: Independent privileged validation
The ordinary GUI SHALL run unelevated. A separately elevated process SHALL run privileged operations only from protected executable/script locations and independently verify current-run binding, findings hash, exact operation, explicit approval and rollback/snapshot prerequisites. The lab-only `-ExecuteRemoval` flag SHALL NOT be used for GUI remediation.

#### Scenario: Historical findings replay
- **WHEN** approval refers to an old run or modified findings
- **THEN** elevated remediation refuses before touching the host

### Requirement: Authoritative engine and truthful outcomes
The GUI SHALL reuse the current detector, removal, scanner, snapshot, diff, report and sanitized-sharing scripts. Failed detection and unavailable/unparseable scanner artifacts SHALL not appear as clean. Uninstaller exit alone SHALL not prove removal; quarantine, manifests and reboot/resume invariants remain enforced by the engine.

#### Scenario: Scanner exits without parseable findings
- **WHEN** an attended scanner exits but no valid scan verdict exists
- **THEN** the result distinguishes launcher completion from unknown findings

### Requirement: Backward-compatible CLI
The GUI adapter SHALL preserve existing command flags and interactive CLI behavior, existing artifact schemas, and Windows PowerShell 5.1 execution.

#### Scenario: CLI invocation
- **WHEN** the original script runs without GUI-specific parameters
- **THEN** its prompt and output behavior remains unchanged

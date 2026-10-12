# Spec Delta

## Purpose

Provide technicians a native, accessible Windows presentation of the existing investigation without changing the investigation or remediation engine.

## ADDED Requirements

### Requirement: Four-view technician workflow
The application SHALL offer Home, Investigation, Review, and Results with keyboard navigation, accessible labels, DPI-aware layout and Windows light/dark support. Home SHALL show host, OS, administrator state, free space, tool version and incident date; history SHALL use existing run directories.

#### Scenario: Read-only investigation
- **WHEN** the technician starts Detect Only
- **THEN** detection can produce findings without executing removal or requiring a destructive approval

### Requirement: Evidence-based review
Review SHALL display every detected ScreenConnect instance and its known relay, session, fingerprint, installation/evidence, custom-property and parse-warning details. Other products SHALL be detect/report-only. Unknown relays SHALL not be automatically classified. One explicit decision SHALL apply to all detected ScreenConnect instances.

#### Scenario: Multiple instances
- **WHEN** a run has two instances and one other remote-access product
- **THEN** both ScreenConnect instances are shown for a single all-instance approval and the other product has no removal control

### Requirement: Honest run presentation
Investigation SHALL show the existing ten-stage ordering, stage states, warnings, elapsed time, operation and log; it SHALL use indeterminate progress without real measurements. Results SHALL separate detection, removal, scanners, verification, reboot, report and sanitized-sharing outcomes, with actions to open an existing report/run folder and copy a valid sanitized link.

#### Scenario: Missing artifact
- **WHEN** findings, scanner output or a report is missing or malformed
- **THEN** the relevant outcome is Incomplete or Failed, never clean, and the app remains usable

### Requirement: Recoverable history
The application SHALL discover existing run roots without a database and expose interrupted runs as incomplete without automatically replaying destructive stages.

#### Scenario: Interrupted run
- **WHEN** a persisted run has a Running stage but no live producer
- **THEN** the previous operation is presented as Incomplete pending technician review

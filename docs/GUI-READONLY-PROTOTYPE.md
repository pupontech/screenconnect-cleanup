# Detect-Only WPF prototype

This is a portable, self-contained Windows x64 prototype. It starts the GUI without requesting elevation; run it as the signed-in technician, not with "Run as administrator." The real action is Detect Only. Full Investigation is unavailable and disabled. The launcher rejects every operation except the exact `DetectOnly` operation before creating a request or starting PowerShell.

## Start

1. Extract the complete `gui-readonly-prototype-win-x64.zip` to a local folder.
2. Double-click `START-READONLY-GUI.bat`.
3. In the GUI, open Investigation and use Detect Only.

The app includes the .NET 10 WPF runtime. Detect Only also requires the Windows PowerShell 5.1 component included with supported Windows installations. A non-elevated run may not be able to read every event-log or system detail; incomplete collection is reported and must not be treated as a clean result.

## Data written and disclosure

Detection is read-only with respect to machine configuration: it does not stop, change, remove, quarantine, or uninstall anything. It does write evidence and logs. The GUI run is stored under `%LOCALAPPDATA%\ScreenConnectCleanup\Runs\<run-id>`. The detector also attempts to create a timestamped `detect-remote-access_*.log` transcript on the current user's Desktop and copies that transcript into the run folder. The Desktop original is preserved. Detector output includes `findings.json`, `SUMMARY.txt`, raw evidence, and `detect-remote-access.log`; evidence can contain service command lines, configuration text, installation paths, relay details, and other sensitive host information. Treat the run folder and Desktop transcript as sensitive. They are not automatically deleted.

This package invokes the detector with `-NoZip` and `-NoReportShare`. It does not create the detector's optional Desktop ZIP and does not invoke the report uploader. No findings or logs are uploaded by the GUI prototype. The build and CI tests do not run the detector against the host or run a remover.

TCP connections are optional enrichment for already-detected processes, not an independent detection provider. Connection-query errors currently produce an empty connection list; that list does not prove there were no connections. Collection completeness covers the service, process, registry, and installation-directory presence providers; event-log availability and parsing issues are shown separately.

## Package contents and limits

The ZIP contains the self-contained WPF publish output, `START-READONLY-GUI.bat`, this disclosure, and only these PowerShell scripts:

- `gui-bridge/Invoke-GuiStage.ps1`
- `gui-bridge/GuiState.ps1`
- `detect-remote-access.ps1`

The package intentionally excludes `collect-snapshot.ps1`, `sc-cleanup.ps1`, removal/uninstaller scripts, scanner/AV tooling, Phase 4/5 WIP, `targets.json`, uploader scripts, and credentials. Full Investigation stays disabled because its before-snapshot path can load and unload the HKLM Amcache hive. Do not add scripts or configuration files beside the portable app and assume the bundle is a protected installation: files in a portable folder are user-writable and this prototype is not a security boundary or an installer.

`BUILD-INFO.txt` records the exact source commit. `PACKAGE-MANIFEST.sha256` covers each other ZIP member. The CI build verifies each member hash and uploads a separate SHA-256 digest for the ZIP. CI stages only the exact reviewed commit; it does not publish a release or mirror.

## Validation boundary

Windows 2022 and 2025 CI run the existing Phase 1-3 regression suites and prototype launcher tests, publish the win-x64 self-contained GUI, and verify the ZIP members and hashes. CI then extracts that ZIP and uses UI Automation against the actual packaged window to verify its title, safety notice, enabled Detect Only control, and disabled Full Investigation control. The smoke does not click Detect Only or invoke any machine action. Hosted runners may execute as administrators; this UI smoke does not claim to validate medium-integrity/non-elevated behavior. Before wider use, perform a Windows desktop smoke as a standard user. Tests use fixtures/synthetic stage executors; they do not perform live detection, removal, scanning, or upload. No removal or elevated run is in scope.

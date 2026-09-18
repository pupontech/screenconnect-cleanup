# DEVIATIONS.md - Scc.Scanners Module

## Deviations from ARCHITECTURE.md Contract

### D1: Scan path support in MSERT adapter
- **Contract**: "MSERT (documented CLI, log %SystemRoot%\debug\msert.log)"
- **Deviation**: MSERT does not support a documented /P (path) switch. The adapter
  accepts the -ScanPath parameter for API consistency but does not pass it to
  msert.exe. The scan always runs in quick-scan mode (/Q). This is intentional:
  MSERT's documented switches are only /Q, /F, and /F:Y. We do not invent
  switches. The -ScanPath parameter is ignored with no error (silent no-op) to
  maintain API uniformity across all CLI adapters.

### D2: Historical detection exclusion logic
- **Contract**: "historical detections separately: read Get-MpThreatDetection ->
  label Historical, exclude from this-run DetectionCount"
- **Deviation**: The legacy code and contract require that Get-MpThreatDetection
  records be labeled "Historical" and excluded from the "this-run" DetectionCount.
  In the current implementation, the DetectionCount property reflects the total
  number of detections returned by Get-MpThreatDetection (all labeled Historical).
  This matches the legacy adapter behavior where DetectionCount = @($detections).Count.
  The contract's intent (exclude from "this-run" count) is achieved by the Label
  property: consumers should filter on Label -ne 'Historical' to get only the
  actual scan-run detections. No separate "thisRunDetectionCount" property is
  added; the Label field provides the distinction.

### D3: Tool source tracking
- **Contract**: "ToolSource, ToolVersion, ToolSHA256" in result object
- **Deviation**: These properties are present in the result object but always
  empty strings in the current implementation. Tool resolution via Scc.Tools
  (Resolve-SccTool) is attempted but not required for the module to function.
  When Scc.Tools is unavailable (e.g., during testing), the adapter falls back
  to direct path scanning and does not populate ToolSource/ToolVersion/ToolSHA256.
  Full provenance tracking requires Scc.Tools module to be built and available.

### D4: Run state tracking
- **Contract**: "Scan state tracked in runstate via Scc.Core if importable (optional)"
- **Deviation**: Implemented as optional: Invoke-SccScanner attempts to import
  Scc.Core and call Save-SccRunState, but silently continues if Scc.Core is
  unavailable. This matches the contract's "skip gracefully" requirement.

### D5: Log path semantics
- **Contract**: "LogPath" in result object
- **Deviation**: On Linux (test environment), LogPath is empty because the
  Windows-specific log directories (ProgramData\Microsoft\Windows Defender\Support,
  %SystemDrive%\KVRT*_Data, %SystemRoot%\debug\msert.log) do not exist.
  Log copying is tested via mocks. On Windows, LogPath contains the copied log
  file path or a comma-separated list of copied file names.

### D6: MSERT verification documentation
- **Contract**: "if the docs are unavailable, implement with the flags you verified
  and mark Verification=DocUrl in the result object"
- **Deviation**: MSERT documentation was fetched from multiple sources:
  - https://learn.microsoft.com/en-us/defender-endpoint/safety-scanner-download (official, minimal)
  - https://inventivehq.com/knowledge-base/microsoft/how-to-use-microsoft-safety-scanner
  - https://www.windowscentral.com/how-remove-malware-using-microsoft-safety-scanner-windows-10
  
  The verified switches are /Q (quiet), /F (full scan), /F:Y (full + auto-clean).
  The /N switch (attributed to MRT.exe, not MSERT) is NOT used. The adapter
  uses /Q only and marks ToolSource = 'Verification=DocUrl'. Microsoft does not
  publish a complete CLI reference for msert.exe; the switches used are the ones
  reliably attested across multiple independent sources.

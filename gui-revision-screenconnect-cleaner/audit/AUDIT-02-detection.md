# AUDIT-02: Detection Script and Targets Inventory

## 1. Scope Inventory

| File | Lines | Purpose |
|------|-------|---------|
| detect-remote-access.ps1 | 1041 | Standalone proof-of-concept (v0.1.0-poc) that detects remote-access agents on a Windows machine. Deep module for ScreenConnect extracts relay identity; generic module for 14 other products does presence-only detection. Read-only; nothing is changed, stopped, or removed. |
| targets.json | 163 | External configuration file defining 15 detection targets with service/process/path/uninstall wildcard patterns, enable/disable flags, and a deep-generic switch. Optional; embedded defaults in the .ps1 are used when absent. |

---

## 2. Full Functionality Inventory

### 2.1 Detection Targets (15 total)

| # | id | name | enabled | deep |
|---|----|------|---------|------|
| 1 | screenconnect | ScreenConnect / ConnectWise Control | true | true |
| 2 | anydesk | AnyDesk | false | false |
| 3 | teamviewer | TeamViewer | false | false |
| 4 | ultraviewer | UltraViewer | false | false |
| 5 | supremo | Supremo | false | false |
| 6 | rustdesk | RustDesk | false | false |
| 7 | splashtop | Splashtop (incl. SOS) | false | false |
| 8 | logmein | LogMeIn / GoTo (incl. Rescue) | false | false |
| 9 | zohoassist | Zoho Assist | false | false |
| 10 | atera | Atera / AteraAgent | false | false |
| 11 | dwagent | DWAgent / DWService | false | false |
| 12 | meshagent | MeshCentral agent | false | false |
| 13 | netsupport | NetSupport Manager | false | false |
| 14 | remoteutilities | Remote Utilities | false | false |
| 15 | vnc | VNC family (Ultra/Tight/Real/TigerVNC) | false | false |

### 2.2 Detection Techniques Used

**ScreenConnect deep module (Invoke-ScreenConnectModule, lines 398-665):**
- Service enumeration via Win32_Service CIM class (name, displayName, PathName, state, startMode, startName, processId, description)
- Service pattern matching against Name, DisplayName, and PathName (hardcoded "(?i)ScreenConnect" regex fallback on PathName, line 438)
- Install directory enumeration via filesystem wildcard globbing (Get-DirsMatching helper)
- Uninstall registry entry matching (HKLM uninstall keys, both native and WOW6432Node, plus HKCU)
- Process enumeration via Win32_Process CIM class (PID, parentPID, name, executablePath, commandLine, creationDate)
- Process pattern matching against Name and ExecutablePath (hardcoded "(?i)ScreenConnect" regex fallback on ExecutablePath, line 509)
- Config file reading (.config files in install directory, raw content capture)
- Service ImagePath parameter blob extraction (Find-ScParamBlob regex, line 221)
- Process CommandLine parameter blob extraction (same function, line 527-529)
- Config file content parameter blob extraction (same function, line 571-573)
- Parameter blob parsing (ConvertFrom-ScParamBlob, URL-decoded key=value pairs)
- Server key fingerprinting via SHA-256 hash (truncated to 16 hex chars, line 615)
- File facts: version info, product name, company name, SHA-256 hash, Authenticode signature status and signer subject (Get-FileFacts, lines 274-300)
- TCP connection enumeration per process PID (Get-NetTCPConnection, lines 376-393)
- Service install event log (Event ID 7045, System log, lines 357-374) matched to instances
- Historical instance detection from 7045 events with no matching live install (lines 646-657)

**Generic presence module (Invoke-GenericModule, lines 670-710):**
- Service pattern matching (Name, DisplayName)
- Process pattern matching (Name only)
- Directory wildcard matching via Get-DirsMatching
- Uninstall registry entry pattern matching (DisplayName)

**System inventory collectors (reused across all targets):**
- Get-AllServices: Win32_Service CIM (lines 305-313)
- Get-AllProcesses: Win32_Process CIM (lines 315-323)
- Get-AllUninstallEntries: Three registry roots - native Uninstall, WOW6432Node Uninstall, HKCU Uninstall (lines 325-355)
- Get-ServiceInstallEvents: Event ID 7045 from System log, max 400 events (lines 357-374)

**Detection techniques NOT currently used:**
- Firewall rule inspection
- WMI/CIM persistent event subscription
- Scheduled task enumeration
- Startup folder inspection
- Group Policy scheduled task / registry preference inspection
- Network listener (port) enumeration independent of process
- File hash comparison against a known-bad database
- Digital signature chain validation beyond status string

### 2.3 ScreenConnect Identity Information Extracted

Per-instance fields (the Get-Slot template, lines 405-431):

| Field | Source | Notes |
|-------|--------|-------|
| Key | Derived | Instance key: identifier hash or "svc:name" / "dir:path" / "reg:key" / "proc:name" |
| Identifier | Service/Dir/Reg/Proc name | Extracted via regex: "ScreenConnect Client (XXXXXXXX)" -> "XXXXXXXX" |
| InstallDir | ImagePath regex / directory scan / registry | Paths from service ImagePath, filesystem, or uninstall registry |
| Sources | Aggregate | List of source types that contributed data: "service", "directory", "uninstall-registry", "process" |
| ServiceName | Win32_Service.Name | |
| ServiceDisplayName | Win32_Service.DisplayName | |
| ServiceState | Win32_Service.State | Running/Stopped/etc. |
| ServiceStartMode | Win32_Service.StartMode | Auto/Manual/Disabled |
| ServiceAccount | Win32_Service.StartName | LocalSystem, NetworkService, etc. |
| ServiceImagePath | Win32_Service.PathName | Raw image path; contains the parameter blob on many builds |
| ParamBlob | Extracted from ImagePath, CommandLine, or .config | Raw key=value&key=value string |
| ParamBlobSource | Tracking | Which source the blob came from |
| RelayHost | Parsed (key "h") | THE decision key for authorized vs. unauthorized |
| RelayPort | Parsed (key "p") | Default believed to be 8041 |
| SessionType | Parsed (key "e") | Access (unattended) / Support (one-shot) / Meeting |
| Role | Parsed (key "y") | Typically "Guest" |
| SessionId | Parsed (key "s") | UUID-format session identifier |
| ServerPublicKey | Parsed (key "k") | Base64-encoded; used to derive fingerprint |
| ServerKeyFingerprint | SHA-256 of ServerPublicKey | Truncated to 16 hex characters |
| CustomProperties (c1-c8) | Parsed (keys "c1" through "c8") | Arbitrary custom properties set by the hosting instance |
| UnknownParams | All unrecognized keys | Preserved verbatim for learning |
| AllParams | Complete parsed key-value set | Ordered dictionary of all parsed parameters |
| MainExe | ImagePath regex / directory scan | Primary executable path |
| File | Get-FileFacts on MainExe | See file facts below |
| InstallDirCreatedUtc | Directory creation time | ISO format UTC |
| ConfigFiles | Directory scan for *.config | List of Name, Path, SizeBytes, ModifiedUtc |
| UninstallDisplayName | Registry DisplayName | |
| UninstallString | Registry UninstallString | |
| QuietUninstallString | Registry QuietUninstallString | |
| UninstallRegistryKey | Registry key path | |
| InstallDate | Registry InstallDate | |
| Publisher | Registry Publisher | |
| DisplayVersion | Registry DisplayVersion | |
| Processes | Win32_Process matches | List of PID, parentPID, name, path, commandLine, startedUtc |
| Connections | Get-NetTCPConnection per PID | List of local/remote address:port, state, owningProcess |
| ServiceInstallEvents | Event 7045 matches | List of TimeUtc, Message |

**File facts sub-structure (Get-FileFacts):**
- Path, Exists, SizeBytes, CreatedUtc, ModifiedUtc
- FileVersion, ProductName, CompanyName (from VersionInfo)
- Sha256 (file hash)
- SignatureStatus (Authenticode: Valid/NotSigned/etc.)
- SignerSubject (certificate subject DN)

**ParseIssue fields (for unresolved instances):**
- Key, Identifier, InstallDir, Issue (human-readable), ServiceImagePath, ConfigFilesSeen, ParamBlob, KeysSeen

**Historical instance fields (from 7045 events with no live install):**
- TimeUtc, Identifier, Message, Note

### 2.4 Output Structure

**findings.json top-level fields:**
- Tool, Version, GeneratedUtc, ComputerName, RunAsUser, IsAdmin
- OSCaption, PSVersion, TargetsSource, TargetsSelected (array of ids)
- EventLogError (if System log inaccessible)
- ScreenConnect (Invoke-ScreenConnectModule result): Instances[], ParseIssues[], Historical[], RawFilesSaved[]
- OtherTargets[]: each has Id, Name, Hits[], Count

**Raw evidence directory:**
- raw/services.csv
- raw/processes.csv
- raw/installed-programs.csv
- raw/service-install-events-7045.csv (if events found)
- raw/{safe_instance_key}__{config_filename} (verbatim .config file copies)

**Other output files:**
- SUMMARY.txt (log lines with timestamps)
- Transcript log on Desktop (detect-remote-access_*.log)

**Console output:**
- Structured sections with color coding
- ScreenConnect instances with all identity fields
- Parse issues highlighted in red
- Historical installs highlighted in yellow
- Generic target hits listed by kind/name/path

### 2.5 Parameters and Switches

| Parameter | Type | Default | Purpose |
|-----------|------|---------|---------|
| -OutRoot | string | "$env:USERPROFILE\Desktop\RemoteAccessScan" | Root output directory |
| -Target | string[] | (none) | Comma-separated target IDs to scan; overrides targets.json |
| -All | switch | false | Scan every known target regardless of enabled flag |
| -ListTargets | switch | false | Print target list and exit |
| -TargetsFile | string | (auto-detect from $PSScriptRoot) | Alternate path to targets.json |
| -NoZip | switch | false | Skip zipping output to Desktop |
| -NoPause | switch | false | Skip "Press Enter" at end (for unattended/piped runs) |
| -SelfTest | switch | false | Run parser against synthetic samples and exit |

### 2.6 Confidence / Severity Classifications

**Current classifications (implicit, not named):**
- No explicit confidence score or severity rating is assigned to any finding
- RelayHost presence is the primary indicator of "authorized" vs. "unauthorized" but no boolean or enum is produced
- ParseIssues are flagged as "needs attention" in red console output
- Historical instances are flagged with "possible removed or reinstalled instance" note
- Color coding: Green = none found, Yellow = found or degraded, Red = parse failure, White = informational

### 2.7 Utility Functions

| Function | Lines | Purpose |
|----------|-------|---------|
| Test-IsAdmin | 167-173 | Check if running as Administrator |
| Get-Sha256Hex | 175-184 | SHA-256 hex string of input text |
| Expand-Env | 186-190 | Expand environment variables in paths |
| Get-DirsMatching | 192-204 | Wildcard directory match (avoids Get-Item escaping issues with "Program Files (x86)") |
| Test-AnyLike | 206-211 | Test if value matches any wildcard pattern |
| Find-ScParamBlob | 223-244 | Extract longest key=value& pair blob from text; prefer blobs with h= or e=Access/Support/Meeting |
| ConvertFrom-ScParamBlob | 246-263 | Parse blob into ordered dictionary; URL-decode values |
| Get-ScIdentifier | 265-272 | Extract instance ID from "ScreenConnect Client (XXXX)" pattern |
| Get-FileFacts | 274-300 | File metadata, hash, and Authenticode signature |
| Get-AllServices | 305-313 | Enumerate all Win32_Service instances |
| Get-AllProcesses | 315-323 | Enumerate all Win32_Process instances |
| Get-AllUninstallEntries | 325-355 | Enumerate all uninstall registry entries from 3 roots |
| Get-ServiceInstallEvents | 357-374 | Fetch Event ID 7045 from System log |
| Get-ConnectionsForPids | 376-393 | TCP connections for a set of PIDs |
| Write-Log | 147-152 | Timestamped log line (console + ArrayList) |
| Write-Section | 154-162 | Console section header |

---

## 3. Per-Component Verdict Table

| Component | Verdict | Justification |
|-----------|---------|---------------|
| detect-remote-access.ps1 (??) | REFACTOR | Solid detection logic but monolithic. Needs decomposition into modules, output model cleanup, and GUI integration hooks. Core detection quality is good; architecture is the problem. |
| targets.json (??) | RETAIN -> CONFIG | Schema is clean and extensible. Should become a proper config file in the new architecture, possibly with schema validation. The `_comment` field and the embedded-fallback pattern are valuable. |
| ScreenConnect deep module | REWRITE | Logic is sound but implementation is monolithic (267 lines in one function). Needs decomposition: service scan, directory scan, registry scan, process scan, config file parse, connection lookup should be separate functions. Output model needs a PSCustomObject class or hashtables with consistent schema. |
| Generic presence module | REFACTOR | Simple and correct. Should become a reusable "generic detector" that takes any target config. Minor: the Kind/Name/Detail/Path/State/StartMode output shape is inconsistent with ScreenConnect output. |
| System inventory collectors | RETAIN | Get-AllServices, Get-AllProcesses, Get-AllUninstallEntries, Get-ServiceInstallEvents are solid and reusable. Minor: add error handling granularity and optional caching. |
| ScreenConnect parameter parser | RETAIN | The blob regex, Find-ScParamBlob preference logic, and ConvertFrom-ScParamBlob are well-designed for a PoC. URL decoding, edge-case handling of leading ?/& and empty pairs is good. The key map should move to config. |
| File facts collector | RETAIN | Get-FileFacts is clean and self-contained. Useful for any target, not just ScreenConnect. |
| Connection collector | RETAIN | Get-ConnectionsForPids is clean and reusable. |
| Output/reporting | REWRITE | Current output is a mix of console formatting, JSON serialization, and CSV dumps. The GUI architecture needs a structured data model (PSCustomObject or class) as the single source of truth, with console/JSON/GUI as consumers. |
| Zip/Transcript logic | REMOVE | Console transcript and zip-to-Desktop are PoC conveniences. The GUI app will have its own export mechanism. |
| Self-test mode | RETAIN | Synthetic test harness is valuable for regression testing the parser. Should become a unit test, not a runtime switch. |
| Logging | REFACTOR | ArrayList log accumulator is fine for PoC but needs structured logging for the GUI (event bus or callback). |

---

## 4. Notable Logic Worth Preserving Exactly

### 4.1 ScreenConnect Service/Process Detection (lines 435-469, 506-530)

The detection uses a three-tier matching approach:
1. Wildcard pattern match on Name/DisplayName via Test-AnyLike
2. Hardcoded regex fallback: `$svc.PathName -match '(?i)ScreenConnect'` (line 438) and `$p.ExecutablePath -match '(?i)ScreenConnect'` (line 509)
3. Identifier extraction via `Get-ScIdentifier` which looks for "ScreenConnect Client (XXXXXXXX)" in Name, DisplayName, PathName, ExecutablePath, CommandLine, DisplayName of uninstall entry, and InstallLocation

This triple-layer approach is important: the wildcard patterns may miss non-standard installs, but the regex fallback catches them. The identifier extraction is what enables deduplication across sources.

### 4.2 Relay/Parameter Parsing Logic (lines 131-263)

**Key map ($ScKnownKeys, lines 131-140):**
- Maps single/double-letter keys to friendly names
- Keys c1-c8 map to CustomProperties
- All unknown keys preserved in UnknownParams for learning
- Comment explicitly states this is "ASSUMED, NOT CONFIRMED" - the PoC exists to test these assumptions

**Blob extraction (Find-ScParamBlob, lines 223-244):**
- Regex: `(?i)(?:[a-z][a-z0-9]{0,3}=[^&\s"'<>\)]*&){2,}[a-z][a-z0-9]{0,3}=[^&\s"'<>\)]*`
- Requires 3+ key=value pairs (the {2,} means 2 ampersands = 3 pairs minimum)
- Preference order: (1) blobs containing `h=` or `e=Access|Support|Meeting`, (2) longest blob
- This preference logic is important - it avoids picking up unrelated query strings

**Blob parsing (ConvertFrom-ScParamBlob, lines 246-263):**
- Splits on `&`
- Handles leading `?` and `&` by trimming
- Skips empty pairs
- Finds first `=` to split key/value (handles values containing `=`)
- URL-decodes values via `[System.Uri]::UnescapeDataString()` with try/catch for malformed encoding
- Returns ordered dictionary preserving insertion order

**Edge cases handled:**
- Empty/null input: returns empty ordered dictionary (line 249)
- Leading `?` or `&`: trimmed (lines 251-252)
- Empty pairs from double `&&`: skipped (line 254)
- Values containing `=`: correctly split at first `=` only (lines 255-257)
- Malformed URL encoding: caught and value used as-is (line 259)
- Unknown keys: preserved verbatim in UnknownParams (line 609)

### 4.3 targets.json Schema and Detection Driving

The schema per target:
- `id`: unique string identifier
- `name`: human-readable display name
- `enabled`: boolean, controls default scan selection
- `deep`: boolean, if true AND id matches a hardcoded deep module, use that module
- `servicePatterns`: string array of wildcards for Win32_Service Name/DisplayName
- `processPatterns`: string array of wildcards for Win32_Process Name
- `pathPatterns`: string array of wildcards with %ENVVAR% expansion for directory matching
- `uninstallPatterns`: string array of wildcards for uninstall registry DisplayName

Important: the `deep` flag only activates the ScreenConnect module when `$t.id -eq "screenconnect"` (line 874). The deep/generic routing is hardcoded, not driven by the JSON. A new target cannot add a deep module without modifying the script.

### 4.4 Deduplication Logic

Instances are keyed by identifier (the "XXXXXXXX" from "ScreenConnect Client (XXXXXXXX)"). The Get-Slot function (lines 405-431) creates or retrieves a slot by key. Multiple sources (service, directory, uninstall-registry, process) contribute to the same slot. If no identifier is extracted, a fallback key like "svc:ServiceName" or "dir:FullPath" is used.

The Sources ArrayList tracks which detection methods found each instance, enabling confidence assessment (more sources = higher confidence).

### 4.5 Privilege Handling

- Test-IsAdmin (lines 167-173) checks elevation
- Admin warning printed at lines 829-835
- System event log (7045) may be unavailable without admin; error is captured in $script:EventLogError and reported
- All other detection (services, processes, registry, filesystem) works without admin
- Transcript and output folder creation are guarded with try/catch

---

## 5. Duplicated Code, Dead Code, Obsolete Targets, Hardcoded Paths

### 5.1 Duplicated Code

- **Pattern matching in generic module vs. deep module:** Both Invoke-ScreenConnectModule and Invoke-GenericModule iterate services and processes with similar Test-AnyLike logic. The ScreenConnect module adds extra logic (identifier extraction, blob finding) but the base iteration is duplicated. (Compare lines 435-469 with lines 675-707)

- **Install directory detection:** The service ImagePath regex (line 463) and the directory glob scan (lines 472-483) both try to locate the install directory. This is intentional redundancy for reliability, not accidental duplication, but should be documented as such.

- **Identifier extraction:** Get-ScIdentifier is called on service Name, DisplayName, PathName (lines 441-443), directory Name (line 475), uninstall DisplayName and InstallLocation (lines 489-490), process ExecutablePath and CommandLine (lines 511-512). Each source does it independently. This is correct behavior but should be a single "extract identifier from any text" call pattern.

### 5.2 Dead Code

- **None identified.** Every function is called. Every branch is reachable.

### 5.3 Obsolete Targets

- **None identified.** All 15 targets represent real, actively-used remote access products. However:
  - Zoho Assist patterns include "Zoho*" and "ZohoMeeting*" which are broad and could match non-remote-access Zoho products
  - VNC family is a catch-all that could match VNC viewers (read-only) alongside servers
  - LogMeIn patterns include "Support-LogMeInRescue*" which is a specific product variant
  - TeamViewer process pattern "tv_*" is vague

### 5.4 Hardcoded Paths and Values

- **ScriptVersion** hardcoded as "0.1.0-poc" (line 53)
- **Default OutRoot** hardcoded as "$env:USERPROFILE\Desktop\RemoteAccessScan" (line 27)
- **ScreenConnect regex fallback** hardcoded in service matching (line 438) and process matching (line 509): `(?i)ScreenConnect`
- **MainExe search pattern** hardcoded: 'ClientService' then first .exe (lines 540-545)
- **Blob regex** hardcoded (line 221)
- **SHA-256 fingerprint truncation** to 16 hex chars (line 615) - arbitrary but consistent
- **Event log max** hardcoded as 400 (line 361)
- **Zip assembly** hardcoded: System.IO.Compression.FileSystem (line 1017)
- **Event ID 7045** hardcoded (line 363)
- **Output filename conventions** hardcoded (findings.json, SUMMARY.txt, services.csv, etc.)

---

## 6. Bugs and Limitations

### 6.1 Bugs

| Line(s) | Issue | Severity |
|---------|-------|----------|
| 438, 509 | Hardcoded `(?i)ScreenConnect` regex in the service/process loop means non-SC targets that happen to have "ScreenConnect" in their path would be falsely matched as SC instances. In practice this is low-risk since no other target has that string, but it couples the deep module to the generic scan. | Low |
| 874 | Deep module routing is hardcoded: `$t.deep -and $t.id -eq "screenconnect"`. If a second deep target were added to targets.json, it would silently fall through to the generic module. The `deep` flag is a dead field for any target that is not ScreenConnect. | Medium |
| 221 | Blob regex `[a-z][a-z0-9]{0,3}` limits key length to 4 chars. If ScreenConnect ever uses a 5+ letter key, it will not be captured. This is a known assumption (line 129 says "ASSUMED, NOT CONFIRMED"). | Low (by design) |
| 326-330 | Uninstall registry enumeration does not handle the situation where a key exists but Get-ChildItem fails due to permissions. The outer try/catch (line 333) catches the failure but silently skips all entries under that root. | Low |
| 463 | Service ImagePath regex `'"?([a-z]:\\[^"]*?ScreenConnect[^"\\]*)\\([^"\\]+\.exe)'` assumes the path starts with a drive letter. Paths using UNC (\\server\share) or relative paths would not match. | Very Low |
| 596-597 | When no blob is found, the ParseIssue lists ConfigFilesSeen via ForEach-Object in an array subexpression. If $slot.ConfigFiles is empty, this produces an empty array. The issue message is clear but the ConfigFilesSeen field would be an empty array, not $null. | Very Low |
| 715 | Transcript path uses Get-Date at script start, not at output folder creation. If the script runs across midnight, the transcript and output folder timestamps could differ. | Very Low |
| 259 | `[System.Uri]::UnescapeDataString()` can throw on malformed percent-encoding (e.g., "%zz"). The try/catch preserves the raw value, but a malformed value like "%zz" would remain URL-encoded in the output rather than being flagged. | Low |

### 6.2 Limitations

| Area | Limitation |
|------|------------|
| No firewall rule detection | ScreenConnect and many other tools open firewall rules. This is not checked. |
| No scheduled task detection | Some remote access tools install scheduled tasks for persistence. Not checked. |
| No WMI persistence detection | WMI event subscriptions are a common persistence mechanism. Not checked. |
| No startup folder detection | Startup folder shortcuts are a simple persistence mechanism. Not checked. |
| No listener/port detection | Active listening ports (netstat) are not correlated with processes independently of the connection collector. |
| No signature chain validation | Authenticode status is recorded but not evaluated. A valid signature from a known publisher is not distinguished from an invalid one in output. |
| No confidence scoring | There is no numeric or categorical confidence level. The Sources list implicitly provides this but it is not surfaced as a rating. |
| No historical baseline comparison | Each run is standalone. There is no mechanism to compare against a previous scan to detect changes. |
| No cross-machine aggregation | Output is per-machine. The GUI should eventually support multi-machine views. |
| 7045 event log size limit | Hardcoded max of 400 events. A heavily-used machine could have more. |
| Process command line may be empty | Win32_Process.CommandLine requires elevation on some processes. Without admin, the blob may not be found from process data. |
| Config file glob | Only *.config files are read. ScreenConnect may store data in other file types in future versions. |
| Embedded defaults are not live-synced with targets.json | If someone edits targets.json, the embedded defaults in the .ps1 become stale. This is by design for standalone operation but creates a maintenance burden. |
| No macOS/Linux detection | Script is Windows-only (CIM, registry, event log). This is expected for the use case but should be documented. |

---

## 7. Mapping Suggestion: Old Component -> New Modules

### 7.1 detect-remote-access.ps1 -> New Module Structure

| Old Component | New Module | Action |
|---------------|------------|--------|
| $ScKnownKeys (parameter key map) | Configuration/ScreenConnectKeyMap.psd1 | Move to external config/data file. Remove hardcoded hashtable. |
| Find-ScParamBlob + ConvertFrom-ScParamBlob | Detection/ScreenConnect/ParameterParser.ps1 | Retain as-is. These are the core extraction functions. Export both. |
| Get-ScIdentifier | Detection/ScreenConnect/IdentifierExtractor.ps1 | Retain as-is. Single-responsibility function. |
| Get-FileFacts | Detection/Common/FileFacts.ps1 | Retain as-is. Useful for any target, not just SC. |
| Get-AllServices | Detection/Common/ServiceInventory.ps1 | Retain as-is. |
| Get-AllProcesses | Detection/Common/ProcessInventory.ps1 | Retain as-is. |
| Get-AllUninstallEntries | Detection/Common/UninstallInventory.ps1 | Retain as-is. |
| Get-ServiceInstallEvents | Detection/Common/EventLogCollector.ps1 | Retain as-is. Consider making Event ID configurable. |
| Get-ConnectionsForPids | Detection/Common/ConnectionCollector.ps1 | Retain as-is. |
| Test-IsAdmin | Common/PrivilegeHelper.ps1 | Retain as-is. |
| Test-AnyLike, Expand-Env, Get-DirsMatching | Common/PatternHelper.ps1 | Retain as-is. Utility functions. |
| Get-Sha256Hex | Common/CryptoHelper.ps1 | Retain as-is. |
| Invoke-ScreenConnectModule | Detection/ScreenConnect/Scanner.ps1 | REWRITE. Decompose into: Scan-Services, Scan-Directories, Scan-UninstallEntries, Scan-Processes, Scan-ConfigFiles, Parse-Blob, Resolve-Instances, Scan-Connections, Scan-EventLog. Each returns structured data. A coordinator function calls them in sequence. |
| Invoke-GenericModule | Detection/RemoteAccess/GenericScanner.ps1 | REFACTOR. Make target-config-driven. Accept any target object with the standard schema. |
| Console output/reporting | Presentation/ConsoleReporter.ps1 | REWRITE for GUI. The JSON output model becomes the data contract. Console output is optional. |
| findings.json serialization | Output/JsonExporter.ps1 | REWRITE. Define a formal output schema. Use PSCustomObject or class. |
| Transcript + Zip | REMOVE | GUI has its own export. |
| Self-test mode | Tests/ParserSelfTest.ps1 | RETAIN. Move to a test script. |
| Main orchestration | Detection/Detector.ps1 (orchestrator) | REWRITE. Import modules, load config, run selected targets, return structured results. |
| Write-Log, Write-Section | Common/Logging.ps1 | REFACTOR. Provide callback mechanism for GUI log sink. |

### 7.2 targets.json -> New Configuration

| Section of targets.json | New Location | Notes |
|--------------------------|--------------|-------|
| Target definitions (the targets array) | Configuration/Targets.json | Keep as JSON. Add a $schema field. Consider splitting ScreenConnect into its own config section since it has deep detection. |
| Embedded defaults in .ps1 ($DefaultTargetsJson) | REMOVE from code | The new architecture should require the config file. Standalone operation is a PoC feature, not a production one. |
| _comment field | Keep in JSON or move to a separate README | Comments in JSON require a convention; _comment is fine. |

### 7.3 What Should Become Config Files vs. Code

**Config files (external, editable):**
- targets.json (target definitions) -> Configuration/Targets.json
- ScreenConnect key map ($ScKnownKeys) -> Configuration/ScreenConnectKeyMap.psd1 or embed in Targets.json under the screenconnect target
- Output directory defaults -> Configuration/Defaults.psd1
- Event log IDs to query -> Configuration/EventLogConfig.json (currently hardcoded 7045)

**Code (not config):**
- All detection logic (scanners, parsers, extractors)
- All inventory collectors
- All utility functions
- Output serialization logic
- Orchestration/coordinator logic

### 7.4 Priority for Migration

1. Parameter parser (Find-ScParamBlob, ConvertFrom-ScParamBlob) - highest value, most fragile, test thoroughly
2. Identifier extractor (Get-ScIdentifier) - simple but critical for deduplication
3. System inventory collectors - solid, reusable, low risk
4. ScreenConnect scanner decomposition - high effort but necessary for GUI integration
5. Generic scanner - low effort, make config-driven
6. Output model - define schema first, then implement exporters
7. Configuration migration - straightforward JSON move
8. Remove PoC conveniences (transcript, zip, pause, standalone embedded defaults)

---

DONE

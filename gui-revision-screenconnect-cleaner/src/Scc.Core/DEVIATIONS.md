# Scc.Core - Deviations from ARCHITECTURE.md contract

This file records places where Scc.Core diverges from the strict module
contract (docs/ARCHITECTURE.md section 3.1) and the house rules, with the
reason for each. All deviations are additive (extra optional parameters) and
do not change the documented behavior of the specified parameters.

## 1. Extra parameter `-ReportRoot` on `New-SccRun`
- Contract lists: `[-IncidentDate] [-Technician] [-Client] [-ForceServer]`.
- Added: `[-ReportRoot <string>]` (optional).
- Reason: the task requires the run directory to be placeable under a temp
  dir for Linux CI tests ("point reportRoot at a temp dir through config").
  Without an override, `New-SccRun` uses `config.paths.reportRoot`, which on
  Linux is an unexpanded `%USERPROFILE%` placeholder and not writable in CI.
  `-ReportRoot` lets tests (and callers) direct the run root explicitly.
- Behavior: when omitted, falls back to the resolved `config.paths.reportRoot`
  exactly as the contract describes.

## 2. Extra parameter `-ReportRoot` on `Get-SccRunState` and `Find-SccRecentRuns`
- Contract lists `Get-SccRunState -RunId` and `Find-SccRecentRuns [-MaxAgeDays 7]`.
- Added: `[-ReportRoot <string>]` (optional) to both.
- Reason: `runstate.json` lives under `<reportRoot>\<RunId>`. When a run was
  created with `-ReportRoot` (or the default), the state lookup must use the
  same root. The default behavior resolves `config.paths.reportRoot` via
  `Resolve-SccEnv`, so the contract's no-arg usage still works. The extra
  parameter only makes the root explicit for test consistency.

## 3. Extra parameter `-Run` on `Invoke-SccSafe`
- Contract lists: `-ScriptBlock -Stage -Component -Operation [-Throttle]`.
- Added: `[-Run <run>]` (optional).
- Reason: the contract says `Invoke-SccSafe` "records errors in run state".
  Recording into run state requires the run object; the listed signature had
  no way to pass it. `-Run` is used to call `Save-SccRunState` on failure.
  When omitted, errors are still logged via `Write-SccLog` and the section is
  isolated (never kills the run), exactly as specified.

## 4. JSON serialization does not use `-MaxJsonLength`
- `ConvertTo-SccJson` intentionally omits `ConvertTo-Json -MaxJsonLength`.
  That switch exists in Windows PowerShell 5.1 but was removed from
  PowerShell (Core / pwsh), so using it breaks the cross-version (5.1 + 7.x)
  requirement. The 2 MB default is ample for all Scc payloads. Single-element
  arrays are serialized correctly by always passing the value to
  `ConvertTo-Json -InputObject` (the classic pipeline-unwrap bug is avoided).

## 5. `Get-SccComputerInfo` implementation notes
- Purely portable. On non-Windows hosts it derives OS caption, free space
  (`/`), total memory (`/proc/meminfo`), uptime (`/proc/uptime`), and domain
  (`WORKGROUP`) without throwing. Windows-only fields are filled via CIM when
  available. Cached per process in `$script:SccComputerInfo` as required.

## 6. `Test-SccInternet` / `Test-SccNas` are network/IO only
- `Test-SccInternet` performs a HEAD request to https://www.microsoft.com with
  a 10s timeout and returns `{Reachable, Detail}` (never throws).
- `Test-SccNas` uses `Test-Path` (no >15s hang). On non-Windows hosts a
  missing remote/UNC path returns `Reachable = 'unknown'`; a missing local
  path returns `$false`. A present path returns `$true`. No write/read probe
  runs off Windows (per the task's "skip on Linux" instruction).

## 7. Stage-0 preflight (`Invoke-SccPreflightStage`)
- Exported (the task requires it to be exported even though it is outside the
  3.1 export list). Performs: admin check, OS-role/Server refusal honoring
  `config.safety.serverOsRefusal`, disk-space check, a silently-skipped
  restore-point/registry-hive step on non-Windows (remediation owns that),
  and a tool-status snapshot via `Scc.Tools` when importable (empty array
  otherwise). Returns a structured result object and logs each check.

## 8. Config file precedence
- Merge order: embedded defaults <- machine file <- user file <- `-Path`
  (highest). A config file that is not a JSON *object* (e.g. a JSON array or a
  malformed string) is ignored with a WARNING and defaults are used, matching
  the "malformed JSON -> defaults + warning" rule.

----
15. v1.7.13 - last step opens the report folder + report (owner directive:
    "on the last step the folder with the report should be opened and the
    report itself should be opened as well")
- START-HERE.bat Step 10: explorer /select + start "" after report written.
- sc-cleanup.ps1 Stage 9: Start-Process explorer.exe /select + Start-Process
  report.html, both non-fatal (WARN log on failure).
- CI C5 contract added (both paths asserted). Suite green, bat CRLF kept.
----
14. v1.7.12 - snapshot collection in parallel waves (owner directive: "can it
    be refactored to speed up faster")
- New: waves B (services/processes/accounts/WMI), C (autoruns/installed
  programs/BAM/DAM/UserAssist), D (prefetch/ShimCache/startup folders) on top
  of wave A (scheduled tasks/connections/firewall, since v1.7.6). Bounded at
  4 concurrent jobs per wave; every job = one -Section process with one-line
  JSON envelope; sequential fallback on any failure; -NoParallel unchanged.
- -Section mode extended from 3 to 14 sections (window args passed to jobs).
- RecentFiles kept serial (cap-flag semantics); SRUM kept serial (needs the
  snapshot dir); RDP/hosts serial (instant).
Verified: Linux end-to-end rc=0 with all 18 sections, -Section smoke for
Services/RegistryAutoruns/Prefetch/StartupFolders, wave overlap proof
(4x3s = 4.6s vs 12s), full CI green. Real gain on Windows = live test.
----
13. v1.7.11 - snapshots automatic in the guided runner (owner directive:
    "keep them both but do it automatically withouth yes no toggles it
    should just be done")
- START-HERE.bat Steps 3 + 9: prompts removed, both collect-snapshot runs
  unconditional; Step 3 gained an errorlevel WARN; stale "step 8" text fixed.
- sc-cleanup.ps1 was already promptless for snapshots.
Verified: no set /p in either step block, both -Label lines unconditional,
all-CRLF (275 lines), full CI suite green.
----
12. v1.7.10 - Step 1 skips already-downloaded AV scanners (owner directive:
    "check first of the tools are already downloaded if they are dont
    download them again")
- Get-ToolPack.ps1 already skipped via manifest; Get-AVTools.ps1 fetched
  fresh every run. Now: Ensure-Tool keeps a valid copy (>= 1 MB) and skips;
  corrupt/partial copies are removed + re-downloaded; -Force overrides;
  -Verify flags <1 MB as CORRUPT (shared Test-ToolUsable rule).
Verified: harness A (skip both, no download), B (0-byte KVRT re-downloaded,
EOS skipped), C (-Verify CORRUPT + exit 1), D (valid -> exit 0), E (-Force
re-downloads); full CI suite green. Real KVRT download completed during test
B/E - the fresh-fetch path is live.
NOT proven on Windows: live Step 1 run - second run should print
"already present (N MB) - skipping download" for both scanners.
----
11. v1.7.9 - Malwarebytes launches after install (owner directive:
    "it should launch malwarebytes after install")
- Step 6c (bat): winget ok -> locate mbam.exe (PF, then PF(x86)) ->
  start "" "%MBAMEXE%"; winget error -> skip with WARN; not found -> WARN.
  goto-style only, zero nested paren blocks, all-CRLF kept.
- Invoke-GUIScanner.ps1 Malwarebytes branch: after winget exit 0, start
  mbam.exe and wait for the UI to close (same cap/timeout model as KVRT/ESET);
  missing/launch-failure = visible WARN. ${env:ProgramFiles(x86)} braced form.
- CI: Test-ScannerProcessContracts Section 2 + new Section 4 (bat launch).
Verified: 3-scenario fake harness (launch+wait / missing->WARN / winget-fail
->no launch), house rules, parse, 32 removal-runtime tests, pipeline launcher.
NOT proven on Windows: live 6c run - winget install, then the Malwarebytes UI
should open automatically; drive a scan, close it, continue.
# Work log — what was actually done

Chronological record of the session that produced this project, with test evidence.
Written so a new model can distinguish **what was proven** from **what was merely
written**.

Session date: 2026-08-23. Git worktree, branch `claude/screenconnect-cleanup-architecture-573011`.
**Nothing has been committed.**

---

## 1. Design pass one — rejected

Produced a full incident-response platform architecture: three separated binaries
(Collect / Analyze / Remediate), chain-of-custody evidence sealing, a signed trust
catalog, a credential-exposure module, a Velociraptor dependency, and a C# implementation
recommendation.

**The owner rejected this as over-scoped**, restating that the tool should orchestrate
existing tools (KVRT, Procmon) in the manner of the Tron script, not become a bespoke
forensics platform.

Kept from that pass: the core insight that instance identity — not signature or hash — is
the only discriminator, and that scanners cannot detect ScreenConnect.

## 2. Design pass two — accepted

Re-pitched at the correct altitude: a staged PowerShell orchestrator, Tron's shape, with
one bespoke module (ScreenConnect detection) and everything else driving existing tools.
Included a Tron take/leave analysis and a corrected position on Procmon (narrow, targeted
use rather than cut entirely).

Owner answered decisions D1–D7 (see `01-brief-and-decisions.md`) and authorised bundling
third-party tools.

## 3. Built the Stage 2 detector

`targets.json`, `detect-remote-access.ps1`, `Run-DetectRemoteAccess.bat`.

**Testing performed — all actually executed:**

| Step | Result |
|---|---|
| Parse check | `PARSE OK` |
| ASCII check | `0` non-ASCII bytes |
| `-ListTargets` | 15 targets listed correctly, on/off states correct |
| `-All` live run | 304 services, 370 processes, 104 programs, 31 x 7045 events collected |
| Real detections | TeamViewer (4 artifacts), Splashtop (8), AnyDesk (1 leftover dir) — all genuinely present on the dev machine |
| ScreenConnect | 0 instances — none installed on the dev machine |
| `findings.json` | validated as well-formed JSON |
| `-SelfTest` | 4 synthetic samples: full key mapping, URL-decoding, identifier extraction, unknown-key capture, graceful no-match — all correct |

**Bugs found by running it, both fixed:**

1. **PS 5.1 single-element array unwrapping** — `.Count` returned `$null` on a one-item
   result, printing a blank count. Would have misreported the **one-ScreenConnect-instance
   case**, the most common real scenario. Fixed at 11 sites with `@(...)`.
2. **`-Target a,b` broken via the `.bat` launcher** — `powershell -File` passes it as one
   string, so the scan silently selected nothing. Fixed by splitting on commas in-script.

Also hit and fixed: a `-replace` inside a hashtable literal needing parentheses (parse
error), and Bash heredocs collapsing double backslashes, corrupting JSON escaping and
Windows paths (worked around by writing files with a dedicated tool / Python).

**Both runtime bugs parse cleanly and look correct on inspection.** This is the argument
for executing rather than reasoning.

## 4. Wrote `README.md`

User-facing readme: purpose, stage status table, usage, the PoC caveat, design notes,
conventions.

## 5. Parallel agent fan-out — then stopped by the owner

At the owner's request, four subagents were spawned to build components in parallel, each
owning exactly one file to avoid collisions. Each received the shared contracts (adapter
return shape, snapshot schema with stable diff keys), the PS 5.1 + pure-ASCII rule, an
explicit "do not invent CLI flags" instruction, and a verification checklist to actually
run.

| Agent | Model | Target | Outcome when stopped |
|---|---|---|---|
| Scanner adapters | Sonnet | `scanners/` | Still researching official docs. **Wrote no files.** |
| Report generator | Sonnet | `New-InvestigationReport.ps1` | **File written (34 KB).** Had generated a report from real sample JSON. Killed before the XSS-escaping and empty-case tests. |
| Snapshot collector | Sonnet | `collect-snapshot.ps1` | **File written (33 KB).** Killed before it was ever executed. |
| Tool pack | Haiku | `tools/Get-ToolPack.ps1` | **File written (11 KB) + `.gitignore`.** Agent reported the manifest was not populating correctly and was mid-fix when stopped. **Known broken.** |

The owner then asked to pause the running tasks; all four were stopped.

**Post-stop verification actually run on all four files:**

```
detect-remote-access.ps1      PARSE OK   non-ascii=0
New-InvestigationReport.ps1   PARSE OK   non-ascii=0
collect-snapshot.ps1          PARSE OK   non-ascii=0
tools\Get-ToolPack.ps1        PARSE OK   non-ascii=0
```

**Parsing cleanly is not the same as working.** Only `detect-remote-access.ps1` has been
functionally tested. See `07-roadmap-open-questions.md` for the per-file state.

## 6. Wrote this documentation set

`docs/00` through `docs/08`, at the owner's request, for handoff to another model.

---

## Honest status summary

**Proven:**
- Stage 2 detector works end-to-end on a real machine
- The parameter parser handles the assumed format correctly, including URL-decoding and
  unknown-key capture
- Multi-source instance enumeration, raw evidence capture, JSON output, zip output

**Written but unproven:**
- Report generator, snapshot collector

**Proven (tool pack):**
- `tools/Get-ToolPack.ps1` -- fixed the manifest-population bug (see section 8);
  download + hash-verify + `-Verify` all pass against a synthetic local pack
  served over HTTP (real `Invoke-WebRequest`/`Expand-Archive` path, no network
  to sysinternals).

**Not started:**
- Scanner adapters, preflight, approval gate, removal, quarantine, Procmon stage,
  before/after diff, top-level stage runner

**Never validated against reality:**
- **The ScreenConnect key map.** No real ScreenConnect install has ever been seen by this
  code. This is the top priority and everything downstream depends on it.

---

## 7. M4 first adapter: Microsoft Defender (scanners/Invoke-DefenderScan.ps1)

Written by the M4 task. One adapter only, per plan -- KVRT/ESET/AdwCleaner deliberately
not started.

### Switches verified against official docs (Q4 rule: nothing from memory)

Sources, cited in the script header:
- MpCmdRun documented switches and exit codes:
  https://learn.microsoft.com/en-us/defender-endpoint/command-line-arguments-microsoft-defender-antivirus
  (`-Scan -ScanType <0|1|2|3>`, `-File`, `-DisableRemediation` custom-scan-only,
  exit 0 = clean/remediated, exit 2 = not remediated / errors; exe locations:
  `C:\Program Files\Windows Defender` and newest under
  `C:\ProgramData\Microsoft\Windows Defender\Platform\<version>`)
- Get-MpThreatDetection / MSFT_MpThreatDetection properties:
  https://learn.microsoft.com/en-us/powershell/module/defender/get-mpthreatdetection

### Design decisions

- Detect-only by default: targeted scans use `-ScanType 3 -DisableRemediation`
  (documented as "actions are not applied after detection"), honoring safety rule
  "quarantine, never delete" / Stage 3 approval gate. No-path default is a quick scan;
  `-DisableRemediation` is NOT passed there because it is documented valid for custom
  scans only -- noted in a comment in the code.
- Follows the scanner adapter contract in docs/02 (param block + single return object,
  all contract fields present, hard timeout via Process + deadline loop, log files from
  `%ProgramData%\Microsoft\Windows Defender\Support` copied to `-LogDir`).
- `-WhatIf` genuinely runs nothing: resolves tool, reports command line, returns
  Status=Skipped.

### Verification actually run

```
PARSE OK   non-ascii=0   no BOM   CRLF line endings
pwsh execution:
  - WhatIf on host with no Defender -> clean NotInstalled result object, correct shape
  - Synthetic WhatIf with fake ToolPath + ScanPath ->
      Available=True, Status=Skipped,
      CommandLine="...\MpCmdRun.exe" -Scan -ScanType 3 -File "C:\temp\sample" -DisableRemediation
```

NOT yet verified (needs a real Windows box): an actual scan invocation, threat-history
detection mapping against real Get-MpThreatDetection output, Support-folder log copy.

---

## 8. M1 -- fix `tools/Get-ToolPack.ps1` manifest bug

Task `t_9999bd5c`. Reported broken by the prior agent ("manifest not populating
correctly", mid-fix). Only this file + this work log were touched.

### The bug (reproduced, not guessed)

In DOWNLOAD mode the code extracted each zip into the **shared** `$ToolDir`, then
found exes with `Get-ChildItem -Path $ToolDir -Filter '*.exe'` and filtered only by
"created in the last 5 minutes". Because all four downloads happen back-to-back
within 5 minutes, every tool's manifest entry **accumulated every exe extracted so
far**. Reproduced against a synthetic local pack served over HTTP (real
`Invoke-WebRequest`/`Expand-Archive` path, no network to sysinternals):

```
# BROKEN manifest entry for Sigcheck claimed it owned 3 files:
"Sigcheck": { "files": { autoruns64.exe, autorunsc64.exe, sigcheck64.exe } }
# ...and ProcessMonitor 4, TCPView 5. None of those tools downloaded those files.
```

So the tool's count rose 2/3/4/5 instead of 2/1/1/1, and the manifest asserted
ownership of files the tool never downloaded -- which also breaks `-Verify`
(verification searched the whole ToolDir for files that may not even be there).

### The fix

- Extract each zip into its own subfolder (`$ToolDir\<ToolName>`) and scan **only
  that subfolder's** `*.exe` for the manifest. Each tool's entries are now scoped
  to exactly what its zip contained.
- Updated VERIFY-mode file resolution to `$ToolDir\<ToolName>\<file>` to match.
- Hardened the empty-manifest guard from `$manifest.Count -eq 0` to
  `@($manifest.PSObject.Properties).Count -eq 0`, because a `PSCustomObject` has
  no `.Count` on **PS 5.1** (house rule: PS 5.1 compatible) -- the old guard was
  dead code on 5.1 and would never catch an empty/missing manifest.

No new CLI flags or URLs invented; the documented sysinternals URL pattern is
unchanged. Pure-ASCII, no BOM (confirmed).

### Verification actually run (pwsh 7.6.5, synthetic pack over local HTTP)

Four throwaway test copies were used (real script's base URL + ToolDir default
swapped for a local server only in the copies); the shipped file's URL and params
are unchanged.

```
DOWNLOAD  rc=0
  Autoruns: Extracted 2   Sigcheck: Extracted 1
  ProcessMonitor: Extracted 1   TCPView: Extracted 1      # correct, no accumulation

POSITIVE  -Verify  rc=0
  Autoruns: OK - autorunsc64.exe / autoruns64.exe
  Sigcheck: OK - sigcheck64.exe
  ProcessMonitor: OK - Procmon64.exe
  TCPView: OK - tcpview.exe

NEGATIVE  -Verify (tampered file)  rc=1
  Autoruns: MISMATCH - autorunsc64.exe (got <new hash>, expected 238FF13...)

NO-MANIFEST GUARD  rc=1
  ERROR: manifest.json not found or empty. Cannot verify.

SHIPPED FILE:
  PARSE OK   BOM=False   non_ascii=0
```

Result: download populates a correctly-scoped manifest, `-Verify` passes cleanly
against it, correctly flags tampering, and refuses to verify when the manifest is
absent. The prior "manifest not populating correctly" failure is resolved.

**Not verified:** a real run against `download.sysinternals.com` (URL pattern
believed `https://download.sysinternals.com/files/<Name>.zip`, unconfirmed per
docs; no third-party mirror used). The download/extract/hash/verify mechanics are
proven against a faithful local stand-in; only the live endpoint is unconfirmed.

---

## Stage 1: collect-snapshot.ps1 - verification + bug fix (M1, t_aa45f269)

`collect-snapshot.ps1` was parsed-clean (PARSE OK, non-ascii=0) but had **never
been executed**. Running it on this Linux/pwsh box reproduced two real, fatal bugs
that blocked the script from ever producing output.

### Bug 1 (FATAL): `CollectionErrors` array wrap crashes the whole run

`CollectionErrors` is declared as `System.Collections.Generic.List[object]`
(a typed list). The script built the result hashtable with:

    CollectionErrors = @($script:CollectionErrors)

On **PowerShell 7 on Linux** (and likely PS 5.1 too), `@(<Generic.List>)` throws
`ArgumentException: Argument types do not match` — you cannot wrap a generic
`List`1 in the array constructor the way you can a plain array. Because this line
sits in the final `$result = [ordered]@{ ... }` assembly, the exception aborts
the entire script **before** `ConvertTo-Json` / file write, so no snapshot file
is ever produced. Reproduced 100% of runs on this box.

**Fix:** added `Get-CollectionErrorsArray` which copies the typed list into a
plain `object[]` via `.CopyTo(...)` and returns that. Result line now reads
`CollectionErrors = Get-CollectionErrorsArray`. Verified: snapshot JSON now
writes correctly, with the error list intact.

### Bug 2 (FATAL on non-Windows): `$env:COMPUTERNAME` is null -> `$null` in output

`ComputerName` was `$env:COMPUTERNAME`. On this Linux box that env var is unset,
so the field emitted `null` and the default OutFile path collapsed to
`snapshot__<timestamp>.json` (double underscore, blank host). Not a crash, but it
makes the output non-portable and the filename ambiguous.

**Fix:** added `Get-HostNameSafe` — resolves `$env:COMPUTERNAME`, falls back to
`$env:HOSTNAME`, then `[System.Net.Dns]::GetHostName()`, then `'unknown'`. Used
for both `ComputerName` and the default OutFile name. PS 5.1 compatible (no
null-conditional / ternary / `??`).

### House rules re-verified after the fixes

- PARSE OK, non-ascii=0, no BOM (confirmed).
- PS 5.1-compatible constructs only (no `??` / `?.` / `? :` / `&&` / `||`).
- No new CLI flags, env vars, or URLs invented.

### Verification actually run (pwsh 7.6.5 on Linux)

```text
parse check        PARSE OK      (Parser::ParseFile, 0 errors)
ascii check        non-ascii=0
run 1  -Label test -IncidentWindowDays 0   rc=0  snapshot written
run 2  -Label before -IncidentWindowDays 7  rc=0  snapshot written
        -> RecentFiles section populated by Get-RecentFilesSection
           (stack-walk over /root and env roots; correctly empty here,
            no crash, no infinite loop)
output schema      matches docs/02-architecture.md Snapshot schema:
        SchemaVersion, Label, ComputerName, CollectedUtc, IsAdmin,
        OSCaption, IncidentWindowDays, CollectionErrors[],
        Sections{ Services[], ScheduledTasks[], RegistryAutoruns[],
                   StartupFolders[], Processes[], Connections[],
                   InstalledPrograms[], LocalAccounts[], FirewallRules[],
                   WmiPersistence[], RecentFiles[], RecentFilesCapHit,
                   SystemSettings{ RdpEnabled, HostsFileLines[] } }
```

### Checks that could NOT be run here (need a real Windows host / VM)

The collectors are Windows-only cmdlets/CIM classes. On Linux/pwsh they all
gracefully record a `CollectionErrors` entry and continue (the per-section
try/catch + `Invoke-Section` wrapper works as designed). The following produced
a `CollectionErrors` entry on this box and were therefore **not validated for
correct Windows behaviour**:

| Section | Windows dependency | Status on Linux |
|---|---|---|
| OSInfo | `Get-CimInstance Win32_OperatingSystem` | recorded as error, skipped |
| Services | `Get-CimInstance Win32_Service` | recorded as error, skipped |
| ScheduledTasks | `Get-ScheduledTask` | recorded as error, skipped |
| Processes | `Get-CimInstance Win32_Process` + `GetOwner` | recorded as error, skipped |
| Connections | `Get-NetTCPConnection` | recorded as error, skipped |
| LocalAccounts | `Get-CimInstance Win32_UserAccount` / `Win32_GroupUser`, `net localgroup` | recorded as error, skipped |
| FirewallRules | `Get-NetFirewallRule` + filters | recorded as error, skipped |
| WmiPersistence | `Get-CimInstance root\subscription\*` | recorded as error, skipped |
| RegistryAutoruns | registry provider `HKLM:/`, `HKCU:/` | partially: `$env:*` null -> StartupFolders HostsFileLines `Path` null error path exercised |
| StartupFolders | `$env:ProgramData`/`$env:APPDATA` paths | null env -> `Path` null error path exercised |
| SystemSettings | `$env:WINDIR` hosts file | null env -> `Path` null error path exercised |

The error-handling *path* (catch -> `CollectionErrors` -> continue -> still
emit `[]`) is proven. The *content* of each section on a real Windows machine is
**unverified** and must be checked on a Windows VM before this collector is
trusted in the pipeline.

---

## Stage 8: New-InvestigationReport.ps1 - verification (M1, t_b2ffa8c6)

The report generator was parsed-clean but unverified. Three runs with pwsh
7.x on Linux, against hand-built findings.json files matching the exact schema
detect-remote-access.ps1 writes at its findings.json block:

### Run 0 - hostile findings.json (TEST A: XSS)
Input: every string field poisoned with `<script>alert(N)</script>`, event-
handler attributes (`onerror=`, `onload=`, `onmouseover=`), `javascript:` hrefs,
and raw `& " '` characters - in ComputerName, instance identity/relay/service/
file fields, CustomProperties/UnknownParams keys and values, Processes,
Connections, ServiceInstallEvents, ConfigFiles, ParseIssues, Historical,
RawFilesSaved, and OtherTargets hits.

Result:
- exit 0
- raw `<script>` occurrences in output HTML: **0**
- `&lt;script&gt;` escaped renderings: 43 (every payload rendered as text)
- no unescaped onerror/onload/onmouseover/javascript: anywhere

PASS.

### Run 1 - zero-instance / empty findings.json (TEST B)
Input: Instances=[], ParseIssues=[], Historical=[], Hits=[] everywhere,
blank OSCaption, ScreenConnect fully clean.

Result:
- exit 0
- all four summary stat cards show 0
- sane "None found." sections for ScreenConnect, other agents, historical

PASS.

### Run 2 - degenerate input robustness
Input: minimal JSON with `"ScreenConnect": null` and `"OtherTargets": null`
(the shape a scan can produce when a target group is absent).

Result: exit 0, report renders with placeholder text. PASS. (This is the case
Get-Items/Get-Prop were built for; confirmed live.)

### House rules check
- PS 5.1 compatibility constructs used throughout (Get-Prop/Get-Items shims for
  ConvertFrom-Json quirks); no pwsh-only syntax in the file.
- Source is pure ASCII (grep -P '[^\x00-\x7F]' = no matches), no BOM (first
  bytes are `<#`), output written UTF-8 without BOM via UTF8Encoding($false).

No bugs found; no changes to the script were required this stage.

**Note for the detect-remote-access.ps1 owner (out of scope here):** a live run
on Linux/pwsh reaches the results block but crashes at line ~973
(`Get-CimInstance Win32_OperatingSystem` does not exist on pwsh/Linux) BEFORE
findings.json is written, so sample findings.json had to be hand-built to match
the schema at lines 976-992. On Windows 5.1 this line works as intended.

## Stage 7: after-snapshot + before/after diff (M3, t_13869e03)

Built `diff-snapshots.ps1`: reads two collect-snapshot.ps1 output files
(before/after), matches every array section item by its stable `Key` field
(per docs/02-architecture.md), and reports Removed / Added / Changed per
section. Writes a JSON diff report (UTF-8 no BOM) next to the after file.

Design:
- Sections classified: STABLE (Services, ScheduledTasks, RegistryAutoruns,
  StartupFolders, InstalledPrograms, LocalAccounts, FirewallRules,
  WmiPersistence, Prefetch, ShimCache, BamDam, UserAssist) vs VOLATILE
  (Processes, Connections, RecentFiles). Object sections (Srum,
  SystemSettings) are compared by serialized value.
- Verdict: any item ADDED in the after snapshot of a STABLE section ->
  RESURRECTION (exit 1); otherwise CLEAN (exit 0). Volatile churn never
  flips the verdict; only Added/Removed there are informational. Usage or
  unreadable input -> exit 2.
- Changed fields reported per key (field-name list), including added/removed
  properties (`+Field` / `-Field`).
- Warns if ComputerName differs between the two snapshots (cross-machine
  diff is meaningless).
- PS 5.1 constructs only; pure ASCII, no BOM (verified byte-level).

Verification on pwsh 7.6.5 (Linux):
1. Real run pair: two live snapshots (-Label before / -Label after,
   IncidentWindowDays 0), both rc=0; diff verdict CLEAN rc=0 with all
   sections 0/0/0 (Windows collectors empty on this host - expected).
2. Synthetic end-to-end test (tests/test_diff_synthetic.py): injects into
   real snapshot JSONs a removed service, a resurrected scheduled task, a
   changed registry autorun value, and volatile process churn. All checks
   PASS: verdict RESURRECTION rc=1, ResurrectionsAdded=1, services
   Removed list exact, task Added list exact, autoruns Changed=['Value'],
   volatile process add/remove does not count toward resurrections.
3. Error path: missing before file -> exit 2.
4. Encoding: BOM=False, non-ascii=0 for both new files; PARSE OK.

Known limits: Windows-only section content still unverified (needs a Windows
VM, same caveat as Stage 1); Key-based matching assumes collectors keep
emitting stable Keys - the synthetic test pins the contract.
Files touched: diff-snapshots.ps1 (new), tests/test_diff_synthetic.py (new),
snapshots/before.json + snapshots/after.json + snapshots/after.diff.json
(local verification artifacts), this log.

---

## Stage 1 expansion: retrospective execution artifacts (t_bb37e59a)

Extended `collect-snapshot.ps1` (SchemaVersion 1 -> 2) with five new Sections.
Decision taken per the task brief: **extended the existing collector rather
than adding a sibling module** - the new sections are pure Stage 1 snapshot
material and reuse its Invoke-Section / Sort-ByKey / CollectionErrors plumbing;
a sibling would have duplicated the JSON emitter and schema.

### New sections

| Section | Source | Key (stable diff identity) |
|---|---|---|
| Prefetch | `%WINDIR%\Prefetch\*.pf` inventory (name, exec name parsed from `<NAME>-<HASH>.pf`, timestamps). Binary .pf body deliberately NOT parsed (format varies by Windows version; version-proof approach). Absent dir is not an error. | .pf file name |
| ShimCache | `HKLM\SYSTEM\...\AppCompatCache` REG_BINARY decoded in-script for Win8.1/10 entry layouts (types 0x30/0x10 behind a 48-byte '10ts' header). Unrecognized signature -> explicit CollectionError + empty section (never wrong paths); pre-Win8 formats not supported. | lower-cased cached path |
| BamDam | `bam`/`dam` `State\UserSettings\<SID>` values; "when" read via key last-write time through a small advapi32 P/Invoke (`SCC.RegKeyTimes`) that degrades to blank timestamp if Add-Type is unavailable. | service|SID|value-name |
| UserAssist | HKCU `...\UserAssist\<GUID>\Count`: ROT13-decoded value names + RunCount from payload offset 4. Unknown GUIDs still collected as `UnknownGuid`. | GUID|decoded name |
| Srum | NOT an identity-diffed array: single object with SRUDB.dat presence, SHA-256 (diffable between snapshots), file inventory, best-effort READ-ONLY offline copy beside the snapshot, and an explicit Limitations list. The ESE DB itself is NOT parsed (held exclusively open by Windows; parsing requires VSS/offline copy + an ESE reader) - recorded, never silently skipped. | n/a (diff on DatabaseSha256) |

**IncidentWindowDays now consumed:** Prefetch, ShimCache and BamDam rows carry
an `InIncidentWindow` bool computed against the window ending at collection
time. Rows are never filtered out (keys must stay stable across before/after);
the flag only marks what matters to the incident.

### Verification actually run (pwsh 7.6.5 on Linux)

```text
parse check        PARSE OK (Parser::ParseFile, 0 errors)
ascii check        non-ascii=0, no BOM
PS 5.1 scan        0 hits for ?? / ?. / && / ||
full run x3        rc=0 each (-IncidentWindowDays 0 and 7)
                   new sections present in JSON; stable across back-to-back runs
unit tests         ROT13 round-trip correct (URYYB.EXE <-> HELLO.RKR)
                   Test-InIncidentWindow: True(now,7) False(8d ago,7) False(w=0) False(null ts)
                   Get-FileSha256Safe("abc") = ba7816bf...15ad (correct)
                   ShimCache decoder against synthetic Win10 blob ('10ts' hdr,
                     one 0x30 entry w/ filetime + one 0x10 entry): both paths
                     decoded correctly, filetime round-trips exactly
                   Get-SrumSection against fake WINDIR tree: inventory=2 files,
                     sha256 correct, offline copy byte-identical (hash match),
                     Limitations emitted
```

One real bug found during verification and fixed: on pwsh 7.6.5,
`@($list)` inside a hashtable literal where `$list` is a
`System.Collections.Generic.List[object]` throws "Argument types do not
match" (reproduced standalone). Changed to `[object[]]$inventory.ToArray()`.
Note this pattern already exists elsewhere in the repo's scripts written on
other hosts; flagged here so future authors avoid it.

Also fixed during authoring: a malformed PSTypeName `if (...)` condition that
the parser caught (11 parse errors) before any run.

### Checks that could NOT be run here (need a live Windows host)

All five new collectors are Windows-only. On Linux they record CollectionErrors
(Prefetch/Srum: null `$env:WINDIR`; ShimCache: registry path absent; BamDam/
UserAssist: registry paths absent) and emit `[]`, which exercises the failure
path but proves nothing about real content. Specifically unverified on real
Windows:

- ShimCache binary layout: written from published forensic references, NOT
  checked against a live hive. First run on a real box must be compared
  against a known tool (e.g. Eric Zimmerman's AppCompatCacheParser) before
  its output is trusted. Wrong-offset decoding fails safe (signature check +
  per-entry try/catch + bounded entry count), but could yield garbage rows
  without crashing - hence the cross-check requirement.
- BAM/DAM key-last-write P/Invoke: never executed against advapi32 (Linux has
  no registry). Verify timestamps populate on Windows; blank means Add-Type or
  the import failed.
- UserAssist RunCount offset 4 assumption unverified against live data.
- SRUM offline copy of the LIVE SRUDB.dat: the FileShare ReadWrite open may be
  refused by ESE's actual sharing mode; OfflineCopyError captures it either way.
- Prefetch `-Filter '*.pf'` behaviour and ExecutableName regex against real
  .pf names (e.g. names containing dashes).
- Everything else inherited from the v1 collector remains unverified per the
  earlier work-log entries above.

### M4: KVRT + ESET scanner adapters (t_d9cb6c49)

Added `scanners/Invoke-KVRTScan.ps1` and `scanners/Invoke-ESETScan.ps1`,
following the Defender adapter pattern (same param block, same 14-field
return object per docs/02-architecture.md).

Every switch was taken from vendor documentation fetched during authoring,
not from memory (docs Q4 rule):

- KVRT: "Managing the application from the command line", KVRT 2024 help,
  ID 269475 (https://support.kaspersky.com/kvrt2024/269475). Adapter uses
  `-accepteula -silent -dontencrypt -details -d <dir>` plus optional
  `-customonly -custom <path>`. Critically it does NOT pass `-processlevel`:
  per that doc, without a threat level KVRT only detects and logs -- which is
  what keeps the adapter read-only. `-adinsilent` is never used (it disinfects
  AND reboots). Exit-code semantics are NOT published in that doc, so the
  adapter does not map numeric codes to outcomes; status comes from
  timeout/completion and detections come from parsing the unencrypted reports.
- ESET: "Command line scanner", ESET Endpoint Security 12 help
  (https://help.eset.com/ees/12/en-US/advanced_cmd.html) and KB3417
  (https://support.eset.com/en/kb3417-eset-command-line-scanner-parameters-eclsexe-5x-and-later,
  ecls.exe location + example line). Adapter uses `/base-dir`, `/subdir`,
  `/log-file`, `/no-log-console` with drive roots as FILES... targets. It
  deliberately omits `/auto` (scans AND cleans) and any `/clean-mode`
  override: default clean-mode is "none" = detect-only. Full exit-code table
  documented there (0/1/10/50/100, >100 = not scanned) and mapped in-script.
  Per contract, outcome parses the log FILE, never stdout.

Licensing/approval recorded in headers per docs/05-tools-scanners-tron.md:
KVRT approved per D2 ("do not block on licensing", but Kaspersky's own
commercial-use terms remain undocumented -- flagged), ESET approved per D3
(MSP license covers technician scans; standalone use of ecls without an
endpoint product remains a verify item). ESET surfaces Status=Unlicensed when
its log mentions license/activation on a failed run.

Verified with pwsh on Linux:
- Parser clean for both files (0 errors).
- Pure ASCII, no BOM (byte-level check).
- WhatIf runs are genuinely safe: report availability + full command line,
  execute nothing (Status=Skipped when a tool path resolves; NotInstalled
  when the explicit -ToolPath does not exist).
- Synthetic no-tool runs return NotInstalled with correct contract shape
  (all 14 fields present) and non-fatal error text.
- Found and fixed during verification: unparenthesized Get-Date call inside a
  string concat (parse errors); null $env:TEMP on Linux broke Join-Path (added
  TEMP->TMP->cwd fallback via Get-TempRoot); Join-Path against a nonexistent
  Windows-style drive threw under StrictMode on Linux (ErrorAction guards).

Checks that could NOT be run here (need a live Windows host):
- Real kvrt.exe / ecls.exe execution, real exit codes, real log/report formats.
  The detection parsers (KVRT report lines, ecls log CSV-ish threat lines) are
  best-effort heuristics written against documentation, not sample logs. First
  run on a real box must have its copied logs eyeballed before DetectionCount
  is trusted; wrong parsing fails safe (empty detections + Errors note), but
  proves nothing about correctness.
- KVRT discovery heuristic (name-matching kvrt*.exe in common drop folders) --
  docs/05 warns the data-directory name varies by version; the exe name may
  too. Prefer passing -ToolPath explicitly until verified.

## Independent review: newly completed modules (t_f2f5e295)

Review scope: `scanners/Invoke-KVRTScan.ps1`, `scanners/Invoke-ESETScan.ps1`,
`scanners/Invoke-DefenderScan.ps1`, the Stage 1 execution-artifact expansion in
`collect-snapshot.ps1`, and `diff-snapshots.ps1`.

### Checks actually run

- Byte-level source checks: all five files have zero non-ASCII bytes and no BOM.
  `Invoke-DefenderScan.ps1` is CRLF; the other four are LF. Neither violates the
  pure-ASCII/no-BOM rule.
- PowerShell parser check with installed `pwsh`: all five files returned `PARSE OK`.
- PS 5.1 forbidden-token scan: no executable `??`, `?.`, `&&`, or `||` syntax was
  found; matches were only explanatory comments.
- `collect-snapshot.ps1` executed on this Linux/pwsh host: rc=0, SchemaVersion=2,
  all implemented sections emitted, and expected platform-specific failures were
  recorded in `CollectionErrors` (16 entries).
- Scanner adapters with nonexistent explicit tool paths returned non-fatal,
  contract-shaped `NotInstalled` results. Real scanner execution was not possible
  without Windows binaries.
- Vendor spot-check: KVRT and ESET cited URLs document the switches used. Microsoft
  Defender documentation confirms `-DisableRemediation` is valid only for custom
  scans, and that quick scans are normally invoked with `-ScanType 1`.
- The repository's `pytest` executable was unavailable in this environment, so the
  Stage 7 synthetic test suite could not be run here.

### Findings for the integration reviewer

1. **High, design/safety: Defender quick-scan branch is not read-only.** In
   `Invoke-DefenderScan.ps1`, the no-`ScanPath` branch initially adds
   `-DisableRemediation`, then removes it at lines 234-237 and runs `-Scan -ScanType
   1`. Microsoft documents `-DisableRemediation` as custom-scan-only, but the
   resulting quick scan can perform the product's normal remediation. This conflicts
   with docs/06's read-only default and the adapter header. Resolve by choosing an
   explicitly safe supported scan mode or by changing the adapter contract/design;
   do not leave the current silent-remediation behavior.

2. **High, scope: Amcache is absent from the Stage 1 expansion.** The requested
   retrospective set includes Prefetch, Amcache, ShimCache, BAM/DAM, UserAssist, and
   SRUM. `collect-snapshot.ps1` implements five new named sections but has no
   Amcache collector, schema field, or diff classification. Either implement and
   document Amcache or explicitly revise the task scope before integration.

3. **Medium, contract/semantics: Defender detections are not tied to this scan.**
   `Get-ThreatDetections` reads all active and past detections via
   `Get-MpThreatDetection`, which Microsoft describes as historical/local threat
   detections, then reports them as this adapter's `Detections`. A pre-existing
   detection can therefore be attributed to the current run. The adapter also copies
   Support files but does not parse a scanner log, so the docs/02 rule "read the
   scanner's log file, never parse stdout" is not clearly satisfied. Preserve the
   distinction between historical evidence and scan-specific results in the return
   shape or document an approved exception.

4. **Medium, validation gap: Windows-only artifact decoders remain unverified.**
   ShimCache offsets/signature, BAM/DAM key-last-write P/Invoke, UserAssist payload
   offset, Prefetch naming, and SRUM live-copy behavior were not exercised on Windows.
   The code records graceful errors on Linux, but that does not validate Windows
   content. Cross-check the first Windows run against known-good forensic tooling.

5. **Low, robustness: scanner detection parsers are heuristic and untested against
   real logs.** KVRT and ESET real report/log formats and exit behavior remain
   unverified; the current parsers can produce empty or over-broad detections. Keep
   the copied logs and require a real-box eyeball/test before trusting counts.

No mechanical fixes were made to implementation files during this review: all source
files passed the requested encoding and parser gates. These findings are design-level
and are intentionally left for the integration reviewer.

## Stage 0: preflight.ps1 - build (M1, t_5ba4d839)

Built `preflight.ps1` per docs/02-architecture.md Stage 0. Sequence:
admin check (hard fail on Windows when not elevated; warn-only on
non-Windows dev hosts so CI can exercise the rest) -> OS role check
(refuse Windows Server unless -Force) -> disk space (default min 10 GB,
-MinFreeGB) -> working dir C:\RIT-SCC\<host>-<timestamp>\ with
logs\quarantine\snapshots\registry\ subdirs + master.log ->
technician/client/incident-date prompt (overridable via params for
unattended runs) -> System Restore point + registry hive export
(reg.exe save of HKLM\SOFTWARE, HKLM\SYSTEM, HKCU, plus SAM/SECURITY
best-effort), skippable via -np / -SkipRestore and loudly logged either
way -> tool pack presence check by invoking tools\Get-ToolPack.ps1
-Verify and honoring its exit code.

Restore-point safety per docs/06-safety-model.md: probes whether System
Restore is enabled/readable before attempting Checkpoint-Computer; if it
cannot be confirmed the stage FAILS rather than silently continuing ("a
silently-failed restore point is worse than none"). A failed restore
point aborts with exit 1.

On success emits a one-line machine-readable JSON handoff on stdout
(Stage/Status/WorkingDirectory/MasterLog/Tech/Client/IncidentDate/
RestorePointSkipped) for the future sc-cleanup.ps1 orchestrator.

Verified on pwsh 7.6.5 (Linux):
- parse: PARSE OK; pure ASCII (non-ascii=0); no BOM.
- -SelfTest passes: hostname helper non-empty, OS-caption helper
  non-empty, Server-OS regex hits "Windows Server 2019" and not
  "Windows 10 Pro", admin helper returns bool, free-space numeric.
- Full run against real tools\Get-ToolPack.ps1 (no manifest present):
  verify correctly fails rc=1 -> preflight rc=1, working dir created.
- Full run with a synthetic verify-success stub: rc=0, JSON handoff
  emitted, master.log written with all fields, all four subdirs created.

NOT verifiable here (needs Windows): Checkpoint-Computer, reg.exe save,
elevation check, Win32_OperatingSystem caption, DriveInfo on C:\. All
those code paths are guarded with try/catch and were reviewed but never
executed; first real run must confirm the SR-enabled probe behaves on a
machine where System Restore is disabled.

---

## Integration review pass (t_45e04506, 2026-08-23)

Final pass over the whole repo after all build tasks completed. Scope: run every
script's parse + ASCII + BOM gate, run whatever functional checks are possible on
Linux/pwsh, fix what was fixable, and record what still needs a Windows VM / live lab
(especially M0, which is explicitly out of scope for agents).

### Gates run on all 10 .ps1 files (pwsh 7.6.5)

| File | Parse | ASCII | BOM |
|---|---|---|---|
| collect-snapshot.ps1 | 0 err | 0 | no |
| detect-remote-access.ps1 | 0 err | 0 | no |
| diff-snapshots.ps1 | 0 err | 0 | no |
| New-InvestigationReport.ps1 | 0 err | 0 | no |
| preflight.ps1 | 0 err | 0 | no |
| sc-cleanup.ps1 | 0 err | 0 | no |
| tools/Get-ToolPack.ps1 | 0 err | 0 | no |
| scanners/Invoke-DefenderScan.ps1 | 0 err | 0 | no |
| scanners/Invoke-KVRTScan.ps1 | 0 err | 0 | no |
| scanners/Invoke-ESETScan.ps1 | 0 err | 0 | no |

### Functional checks actually executed on Linux

- `detect-remote-access.ps1 -SelfTest` -> rc=0 (assumptions-consistency only; live
  Windows run still the only real proof of the key map).
- `preflight.ps1 -SelfTest` -> rc=0; full fail-path rc=1 and success-path rc=0 runs.
- `collect-snapshot.ps1 -Label verify -IncidentWindowDays 0` -> rc=0, valid JSON,
  SchemaVersion=2, all sections present, Windows collectors correctly recorded
  CollectionErrors and continued.
- `New-InvestigationReport.ps1` -> rc=0 on a hostile+null findings.json (XSS escaping
  and degenerate-input paths confirmed by the earlier t_b2ffa8c6 run).
- `diff-snapshots.ps1` real pair -> CLEAN rc=0; `tests/test_diff_synthetic.py` -> all
  PASS (resurrection rc=1, services-removed, task-added, autorun-changed, volatile-not-
  counted). Note: pytest is not installed in this env, so the suite was run directly
  with `python3 tests/test_diff_synthetic.py` (all assertions PASS).
- `tools/Get-ToolPack.ps1 -Verify` against the already-present local manifest -> rc=0
  (matches the synthetic-pack proof from task t_9999bd5c).
- `scanners/Invoke-DefenderScan.ps1 -WhatIf -ToolPath <fake exe>`,
  `Invoke-KVRTScan.ps1 -WhatIf`, `Invoke-ESETScan.ps1 -WhatIf` -> all return correctly
  shaped contract objects, run nothing.
- `sc-cleanup.ps1` full pipeline (with a stubbed detect-remote-access.ps1) -> end-to-end
  rc=0; `-WhatIf` gates every stage (no child processes spawned); `-sa/-sr/-np/-offline`
  honoured.

### Bug fixed during this pass (HIGH, safety)

`scanners/Invoke-DefenderScan.ps1` violated the read-only safety model (docs/06):
its default (no `-ScanPath`) branch used `-ScanType 1` (quick scan) and then **dropped
`-DisableRemediation`**, so a default run would let Defender silently remediate --
exactly what the approval gate is supposed to prevent. This was flagged as finding #1
by the independent review (t_f2f5e295) and left for the integration pass.

Fix: the adapter now ALWAYS runs a custom scan (`-ScanType 3`) with `-DisableRemediation`.
The default path scans the system drive root (`$env:SystemDrive`, `C:` fallback); a
targeted `-ScanPath` scans only that path. Quick scans are never used. Re-verified:
both default and targeted command lines carry `-DisableRemediation` and contain no
`-ScanType 1`. (Also updated the script header safety note to explain *why* quick
scans are avoided.)

### Findings carried forward (open, need a real Windows box)

From t_f2f5e295, recorded in docs/07 (Q4b):
1. FIXED above — Defender silent-remediation.
2. OPEN — Amcache collector is absent from the Stage 1 retrospective expansion
   (Prefetch/ShimCache/BAM-DAM/UserAssist/SRUM implemented, Amcache not). Implement
   or formally revise scope.
3. OPEN — Defender `Get-ThreatDetections` reports all historical detections as this
   run's; pre-existing detections can be mis-attributed, and Support-log copy without
   scanner-log parsing partly conflicts with docs/02 "read the log, never stdout".
4. OPEN — Windows-only forensic decoders (ShimCache offsets, BAM/DAM P/Invoke,
   UserAssist offset, Prefetch naming, SRUM live-copy) validated only for graceful
   error handling, not correct Windows output. Cross-check first real run against
   known-good tooling (e.g. Zimmerman utilities).
5. OPEN — KVRT/ESET detection parsers are doc-based heuristics; eyeball real logs
   before trusting counts.

### What is PROVEN vs UNPROVEN (commit-ready summary)

PROVEN (executed, not just parsed):
- All 10 scripts: parse clean, pure ASCII, no BOM.
- Stage 2 detector: real-machine run + self-test (the only Windows-fully-verified module).
- Stage 0/1/7/8 + orchestrator: run end-to-end on Linux; logic, error handling, and
  contract shapes correct. Stage 1 schema matches docs/02.
- Tool pack: download/manifest/verify mechanics proven against a synthetic local pack
  (live sysinternals endpoint still unconfirmed).
- Report: XSS-safe + empty/null cases.
- Defender safety fix: re-verified command lines.

UNPROVEN — requires a Windows VM / live lab (cannot be done by agents on Linux):
- M0: live ScreenConnect install validating the relay-key map (top priority, out of scope).
- Correct Windows *content* of every Stage 1 collector + the 5 retro decoders.
- Real execution of KVRT/ESET/Defender scans, and their detection/exit-code mappings.
- preflight's Checkpoint-Computer, reg.exe hive save, elevation, Win32_OperatingSystem,
  C:\ free space.
- The live `download.sysinternals.com` URL.
- Stages 3 (real approval UI), 4 (actual removal), 6 (Procmon) — built only as stubs;
  M5 explicitly requires heavy VM-snapshot testing before removal is built.

## M5a: remove-screenconnect.ps1 (Stage 4, ScreenConnect-only) — BUILT

Task `t_d039f878`. New file `remove-screenconnect.ps1` (Stage 4 containment +
removal). PS 5.1 compatible, pure ASCII, no BOM, parse-clean, synthetic dry-run run.

### What it does (per docs/06 safety-model.md + docs/02 architecture contract)
- Consumes an **approved plan.json** produced by Stage 3 (no detect-and-remove flag).
  Default is DRY-RUN; requires explicit `-Execute` to act. Required behavior (1)-(5)
  all implemented: stop service + kill process, run vendor uninstaller via registry
  `UninstallString` / `msiexec /x {ProductCode}` (MSI auto-detected, `/qn /norestart`
  appended only when absent), manual-surgery fallback (move to quarantine — NEVER
  delete — recording original path + SHA256 in the manifest), delete service
  registration, clean persistence (scheduled tasks, Run/RunOnce keys, WMI
  `__FilterToConsumerBinding` referencing the install dir), write `removal-manifest.json`,
  reboot-resume via RunOnce + `MoveFileEx` for in-use files, System Restore point before
  first change (safety rule 4).
- **Owner policy binding enforced:** `ScreenConnectInstances` is the only removal
  surface; AnyDesk/TeamViewer/RustDesk/all other targets are excluded by design. The
  plan schema only carries ScreenConnect instances.
- Safety rules honored: quarantine-not-delete, uninstall-before-surgery, restore point
  + registry-hive export (the latter is driven by preflight/sc-cleanup, not here),
  no invented CLI flags (uninstall string taken verbatim from registry at runtime),
  every action recorded in the manifest with result + exit code.

### Verification actually run (pwsh 7.6.5 on Linux)
```
parse check        PARSE OK   (Parser::ParseFile, 0 errors)
ascii check        non-ascii=0, no BOM
synthetic dry-run  rc=1 (3 "Failed" entries = Get-Service/Get-CimInstance/Get-ScheduledTask
                         do not exist on Linux pwsh; on Windows these would execute)
                         manifest written, valid JSON, 6 entries with correct Actions/Results
```
A schema example is at `docs/plan-schema-example.json` for the Stage 3 author.

### Bugs found + fixed during build (all reproduced, not guessed)
1. **PS 5.1 single-element array unwrapping (house-rule trap):** `Force-Array` originally
   used `return @($InputObject)`, which collapses a 1-item array to a scalar — the main
   loop then hit "The property 'Count' cannot be found". Fixed: return the array as-is
   when already `[System.Array]`, else build a real `object[]` via ArrayList.
2. **Colon-after-variable parse errors:** `$ServiceName:`, `$exitCode:`, `$pid:` inside
   double-quoted strings break PS 5.1 parsing. Fixed with `${var}` delimiters.
3. **Duplicate `-Verbose` switch parameter** (collided with common parameter): renamed
   to `-VerboseLog`.

### Checks that could NOT be run here (need a Windows host/VM)
- All Windows cmdlets (`Get-Service`, `Get-CimInstance`, `Get-ScheduledTask`,
  `Checkpoint-Computer`, `sc.exe`, `Stop-Process`, WMI subscription cmdlets) — gracefully
  recorded as `Failed` in the manifest on Linux; on a real Windows box they execute.
- Actual service stop / process kill / uninstaller invocation / quarantine move / reboot
  resume. The logic is wired but unexercised against a live ScreenConnect install.

### Not modified
- `sc-cleanup.ps1` left untouched (Stage 4 wiring is task `t_stage4wire`).

Repo is git-init-free; nothing is committed.

Ready for: (a) the Stage 3 review-gate author to emit the approved plan.json against
`docs/plan-schema-example.json`, (b) `t_stage4wire` to call this script from the runner,
(c) VM-snapshot testing on a Windows box with a real ScreenConnect install before trusting
removal in production.

## 8. Wired Stage 3 review gate and Stage 4

`sc-cleanup.ps1` now loads `findings.json`, prompts for each ScreenConnect instance with
KEEP as the default, and writes only explicitly selected ScreenConnect instances to
`plan.json`. Other remote-access products remain detect-only by owner policy. Stage 4
invokes `remove-screenconnect.ps1 -PlanJson`; `-Execute` is added only after the exact
`REMOVE SCREENCONNECT` confirmation and is never reachable through `-sr`. The removal
manifest is carried into Stage 7 and Stage 8, whose report includes removed/quarantined
items and a credential-reset checklist reminder. Parsing, ASCII/no-BOM checks, and a
synthetic pwsh dry-run remain required before Windows validation.

## 9. Post-adoption reconciliation closure (2026-08-26, ox-alpha)

After upstream adopted all agent fixes (d71d40a..0004d30) and closed draft PR #1 as
superseded, a final sweep confirmed nothing was dropped:

- Worker branches (`crash-audit` @014f0fd, `deadlock-worker` @9d5b677, `fix-worker`
  @cdd9890) diffed against main: strictly additive — only new tests/CI files and the
  owner's own extensions; zero reversions of our fixes.
- Spot-proof of adoption on main: `Get-EntryPropertySafe` x29 call sites,
  `Run-BoundedProcess` present, QuietUninstallString-only registration covered in
  `tests/ci/Test-WindowsIntegration.ps1`.
- Release asset verification: rebuilt bundle from 0004d30 vs published
  v2026-08-26-crash-fixes zip — 29/29 files SHA256-identical. The stale-release root
  cause ("GitHub download broken") is closed.

Agent-side work is COMPLETE. Remaining is human-only: M0 live lab validation per
docs/09-windows-live-test-matrix.md.

## 10. Live-run fixes v1.7.1 (2026-08-27, main)

Two bugs observed live on DESTROYERLTC202 (2026-08-27) and fixed on main:

1. **removal-report.txt StrictMode crash.** The human-readable report referenced
   `$successCount/$failedCount/$dryRunCount/$deferredCount/$verifFailCount`
   before they were assigned (they were computed AFTER the report block).
   Under `Set-StrictMode -Version 2.0` this threw "The variable
   '$successCount' cannot be retrieved because it has not been set." - the
   manifest was written but the run exited 1 with 4/4 actions successful.
   Fix: compute the counts before the report block (single assignment site,
   shared with the final summary). PROVEN on Linux: a StrictMode tail-harness
   (manifest + report + summary section of the real script) against `HEAD`
   reproduces the exact error + exit 1; against the fix it writes the report,
   prints 4 successful / 0 failed / 1 verification-failure, exits 0.
   Regression contract: Test-RemovalRuntimeContracts.ps1 Test 10.

2. **"Scanner not found" after successful staging.** `Get-AVTools.ps1` stages
   into its default `tools\AV\`, but `Invoke-GUIScanner.ps1` (repo root) only
   searched `AV\`, the script root, `..\tools\AV`, Downloads and %TEMP% - the
   staging sibling was never checked, so freshly downloaded KVRT/ESET were
   "not found" (exit 3). Fix: `tools\AV\` is now the FIRST candidate. PROVEN
   on Linux: synthetic layout (repo root + `tools/AV/KVRT.exe` = /bin/true)
   - fixed resolves + launches (exit 0, Status Completed); `HEAD` version
   exits 3 with the user's exact message. Regression contract:
   Test-ScannerProcessContracts.ps1 (tools\AV candidate check).

NOT yet proven on Windows: the fixed scanner launch path against real
KVRT/ESET GUIs (needs the owner's live test), and the full CI matrix on
windows-2022/2025 (push will run it). The GUI-revision branch
(gui-revision-screenconnect-cleaner) still carries the pre-fix report ordering
and must pick up the same fix before it merges.

## 11. v1.7.2 - bundle the General Fix tool (2026-08-27, main)

Owner report: "tikun" (the General Fix / Tikun HaKlali tool) was not working on
a live machine; suspected NAS dependency. Verified: `tools/GeneralFix/תיקון
הכללי v10.bat` is fully self-contained - no UNC paths, no `net use`, no URLs;
it only uses built-in Windows commands plus embedded VBS/WSF jobs. The real
cause: `tools/.gitignore` (a `*` whitelist) excluded the folder, so it never
shipped in any deploy zip and had to be staged manually (e.g. from the dead
\\10.0.0.5 share).

Fix: un-ignored `tools/GeneralFix/` in git, `make-deploy-bundle.sh` now copies
the folder into the bundle (warning if absent), bat ships with original name
and byte layout (CRLF + cp1255, self-sets `chcp 1255`). PROVEN on Linux: zip
contains the bat byte-identical to the worktree (427 CRLF intact, cp1255
decodes), VERSION 1.7.2, both v1.7.1 fixes still present in the zip.
Test-HouseRules.ps1 already excluded `tools/GeneralFix\` from the pure-ASCII
scan (intentional third-party cp1255 batch).

NOT proven on Windows: the bat's behavior on a live machine (batch/VBS hybrid
semantics cannot be validated from Linux; owner live-tests). If it still fails
after shipping in the zip, suspect copy mangling (line endings/name) or the
embedded WSF self-elevation being blocked.

## 12. v1.7.3 - Malwarebytes via winget (2026-08-27, main)

Owner directive: "change malwarebytes to installing and uninstalling via winget
via winget install -e --id Malwarebytes.Malwarebytes". No more MBSetup.exe
staging or GUI-installer launch.

Changes:
- `tools/Get-AVTools.ps1` stages KVRT.exe + esetonlinescanner.exe ONLY; the
  Malwarebytes download (downloads.malwarebytes.com) and the InternalShare
  MBSetup fallback are gone. -Verify checks only the two remaining tools.
- `Invoke-GUIScanner.ps1 -Scanner Malwarebytes` resolves winget and runs
  `winget install -e --id Malwarebytes.Malwarebytes` (visible console, bounded
  wait, JSON result Tool="Malwarebytes.Malwarebytes (winget install)"; exit 3
  with a clear message when winget is missing; -ToolPath still overrides).
  KVRT/ESET keep the staged-EXE launch + tools\AV search.
- `Invoke-AVUninstaller.ps1` uninstalls Malwarebytes via `winget uninstall -e
  --id Malwarebytes.Malwarebytes` (result gains Method=winget + ExitCode); when
  winget is absent it falls back to the vendor uninstaller GUI. All other AV
  products still open their vendor uninstaller attended.
- `START-HERE.bat` Step 6c = winget install (warns when winget missing);
  Steps 1/6/8 wording updated. Docs + CI contracts updated.

PROVEN on Linux (synthetic):
- fake `winget` on PATH -> `-Scanner Malwarebytes` runs EXACTLY
  `install -e --id Malwarebytes.Malwarebytes` (args captured to file), JSON
  Status=Completed rc=0.
- extracted Open-Uninstaller harness with a Malwarebytes product -> winget
  branch selected, result Method=winget ExitCode=0; with winget removed from
  PATH -> fallback message + vendor-uninstaller path attempted.
- Get-AVTools -Verify passes with only KVRT + EOS staged (rc=0).
- Full local CI suite green (house rules, parse, scanner contracts incl. new
  winget assertions, removal runtime Test 10, pipeline launcher).

NOT proven on Windows: real winget install/uninstall of Malwarebytes (needs
the owner's live test - winget presence, package id validity, agreement
prompts, and the Malwarebytes uninstall behavior via winget are all
vendor/environment dependent).

## 13. v1.7.4 - guided runner: no prompts, just run+remove+log (2026-08-27, main)

Owner directive: "remove the prompts asking to check for screenconnect and
just run and remove and log".

Changes:
- START-HERE.bat Step 4: no [y/N] prompt - always runs the full detection
  scan (detect-remote-access.ps1 -All -NoPause).
- START-HERE.bat Step 5: no [Y/n] prompt - always runs
  Invoke-ReviewAndRemove.ps1 -Yes (auto-mark every ScreenConnect instance
  REMOVE, -Execute, log to manifest + report). The -Yes banner still prints
  prominently before removal; quarantine-never-delete and ScreenConnect-only
  targeting are unchanged.
- Invoke-ReviewAndRemove.ps1: -Yes is now the guided-runner automatic mode
  (banner reworded; was "LAB USE ONLY"). Interactive gate + typed
  confirmation remain for direct runs without -Yes and for sc-cleanup.ps1
  Stage 3 (untouched).
- Docs: README, docs/06-safety-model.md (owner-directive exception to the
  Stage-3 gate), 00-START-HERE.md, 09-windows-live-test-matrix.md updated.

PROVEN on Linux: synthetic findings with 2 instances + -Yes -WhatIfOnly ran
to completion with ZERO Read-Host prompts (60s timeout canary - a leftover
prompt would have hung), both instances auto-marked REMOVE, plan.json written
Decision=ALL_REMOVE RemovalConfirmed=true rc=0. Full CI suite green.

NOT proven on Windows: the full auto-remove run on a live machine (needs the
owner's live test); sc-cleanup.ps1 Stage 3 gate is unchanged.

## 14. v1.7.5 - AV-uninstall leftover sweep (2026-08-27, main)

Owner report: "eset uninstaller doesnt seem to work maybe it should just remve
the shortcuts and folder". The ESET vendor uninstaller fails/leaves stuff
behind on the live machine.

Fix: Invoke-AVUninstaller.ps1 now sweeps leftovers after every uninstall
attempt (vendor GUI or winget) and MOVES them to
<LogDir>\av-uninstall-quarantine\<product>-<stamp>\ - never deleted
(quarantine-never-delete invariant), every move logged:
- Clear-ProductLeftovers: keyword-matched sweep of Start Menu (ProgramData +
  current user APPDATA), install folder (registry InstallLocation, else a
  *kw* folder directly under Program Files / Program Files (x86)), and the
  matching temp folder (covers "ESET Online Scanner" runtime dir).
- Auto-runs per product; -NoLeftoverSweep opt-out; results gain
  LeftoversMoved + Leftovers[]; JSON root gains QuarantineRoot; report gains
  a Leftovers column + quarantine note.
- Discovery now also captures InstallLocation (StrictMode-safe getter).

PROVEN on Linux (synthetic): fake Start Menu/PF/TEMP with ESET leftovers +
a decoy other-vendor folder -> 3 moves (ESET start menu dir, PF\ESET,
TEMP\ESET Online Scanner), decoy untouched, all parked in the timestamped
quarantine dir. The harness caught a real parse bug in my first cut
($env:'ProgramFiles(x86)' is invalid PS; fixed to ${env:ProgramFiles(x86)}).
Full CI suite green (new scanner-contract asserts: Clear-ProductLeftovers
exists, quarantine destination, -NoLeftoverSweep, no Remove-Item anywhere).

NOT proven on Windows: live ESET leftover sweep on a real machine (folder
locks, actual ESET layout, report rendering) - owner live-test per
docs/09-windows-live-test-matrix.md 6c.

## 15. v1.7.6 - no tech tags/dates + faster snapshots (2026-08-27, main)

Owner: "remove the technician tags and dates and what not I dont need that
step" + "remind me what the before and after snapshots do/show and can you
speed them up or are they limited by windows".

Tags removed:
- preflight.ps1: Invoke-PromptTechInfo (technician/client Read-Host prompts)
  deleted; -TechName/-ClientName/-IncidentDate params gone; master-log
  technician/client/incident lines gone; handoff JSON carries only
  Stage/Status/WorkingDirectory/MasterLog/RestorePointSkipped.
- sc-cleanup.ps1: Prompt-IfMissing + its calls gone; -TechName/-ClientName
  params gone; Stage-0 result, Stage-3 plan.json and the final summary no
  longer carry TechName/ClientName. IncidentDate stays as a never-prompted
  internal anchor (defaults to today) for the snapshot recent-files window.
- Invoke-ReviewAndRemove.ps1 plan.json: TechName/ClientName/IncidentDate
  removed; ComputerName kept. docs/plan-schema-example.json + 02-architecture
  updated. Grep confirms zero remaining references.

Snapshot speedup (collect-snapshot.ps1):
- The 3 slowest independent collectors (ScheduledTasks, FirewallRules,
  Connections - all CIM/API-bound) now run in Start-Job background jobs by
  default; results merge back; ANY job failure falls back to the sequential
  in-process path. -NoParallel disables. New -Section mode emits one section
  as JSON for the jobs.
- Get-NetFirewallRule filtered server-side (Direction/Action/Enabled) instead
  of enumerating all rules then filtering.
- RecentFiles already budgeted (120s / 40k dirs / depth 6; instant when
  window=0).

PROVEN on Linux: fake-section harness (parallel success -> merged FAKE row;
broken job -> SEQ fallback; -NoParallel -> sequential), and the real script
end-to-end with parallel ON (rc=0, 18 sections, 16 graceful section errors on
the Windows-only collectors). Full CI suite green.

NOT proven on Windows: real parallel wall-clock gain and per-section
correctness on a live machine (job spawn overhead, CIM behavior) - owner
live-test per docs/09-windows-live-test-matrix.md.

## 16. v1.7.7 - crash after Malwarebytes step (2026-08-27, main)

Owner live report: "it crashes right after the malwarebytes running step".
Owner asked to test in a VM - NOT possible per standing policy (agents never
set up VMs; owner does live testing). Static analysis + harnesses instead.

Root-cause candidates found in the Malwarebytes neighborhood (v1.7.3 code):
1. Invoke-GUIScanner.ps1 launched winget via Start-Process -FilePath on
   $wingetCmd.Source. On Win10/11 winget is an App Execution Alias - a 0-byte
   WindowsApps reparse stub. PS 5.1 Start-Process on the stub is unreliable:
   silent $null process handle or 'not a valid Win32 application'. The next
   statement called $proc.WaitForExit(...) with NO null guard - an unhandled
   MethodInvocationException killed the launcher right after the Malwarebytes
   launch (in the pipeline path; the bat path ran winget directly).
   FIX: winget launches via cmd.exe /c (OS resolves the alias; console
   visible); null-process guard exits 2 LaunchFailed cleanly.
2. START-HERE.bat Step 6c nested if/else paren block with parens in an echo
   line - fragile cmd class (the same class that killed the WPD v0.3.0 bat).
   FIX: goto-style rewrite, no nested blocks, winget errorlevel echoed;
   Step 9 echoes after-snapshot errorlevel (!errorlevel! - delayed expansion).

PROVEN on Linux: fake cmd.exe harness captures the exact argv
(/c winget install -e --id Malwarebytes.Malwarebytes) and completes rc=0;
KVRT launch path regression-checked rc=0; bat paren/CRLF scan clean; full CI
suite green; new scanner-contract asserts (wingetViaCmd + null guard).

NOT proven on Windows: the actual winget alias behavior on the owner's
machine - needs their live re-test. If it still crashes, the new [WARN]
errorlevel echoes in Step 6c/9 pinpoint the failing command.

## 17. v1.7.8 - KVRT "no longer launches" diagnostics (2026-08-27, main)

Owner live report: "kvrt no longer launcher son this latest vesrion".
Investigation: the KVRT launch path (START-HERE 6a -> Invoke-GUIScanner
-Scanner KVRT -> candidate search -> Start-Process) is BYTE-IDENTICAL to
v1.7.6 where KVRT ran. Zip==tree confirmed for all 4 relevant files; KVRT
download URL verified alive (HTTP 200); synthetic KVRT launch rc=0. So the
failure is environmental and was SILENT:
- Step 6a's only gate is `if exist tools\AV\KVRT.exe` - passes for a
  0-byte/partial exe; Start-Process then fails with no errorlevel echo and
  the bat just continued, looking like "doesn't launch".
- Most likely cause: a corrupt/partial KVRT.exe from an earlier staging run
  (Get-AVTools never verified the download size).

Fix:
- 6a/6b echo `[WARN] ... errorlevel N` on launch failure.
- Get-AVTools.Get-DownloadFile rejects <1MB downloads (delete + FAILED +
  "re-run staging") so a broken exe can't be staged silently.
Verified: KVRT launcher rc=0, -Verify rc=0 with staged fakes, reject
threshold logic, bat scan clean, full suite green.

NOT proven on Windows: the user's actual staging state - re-run Step 1, then
6a; the new WARN lines will name the failure if it persists.

# REVIEW Scc.Tools (ToolManager) - independent security/robustness review

Reviewer: independent (did NOT author this module).
Module:  src/Scc.Tools/Scc.Tools.psm1 + Scc.Tools.psd1
Tests:   tests/Unit/Scc.Tools.Tests.ps1
Contract: ARCHITECTURE.md sections 3.5 + 8 (+ common rules 1,2,5,6,8,9)
Legacy:  tools/Get-AVTools.ps1, tools/Get-ToolPack.ps1, tools/manifest.json

## Verification gates actually run

| Gate | Command | Result |
|------|---------|--------|
| Parse check (0 errors) | Parser::ParseFile on Scc.Tools.psm1 | PASS - 0 parse errors |
| ASCII byte check | python3 byte scan of .psm1 + .psd1 | PASS - 0 non-ASCII bytes in both |
| Forbidden PS7 constructs | grep for `?:`/`??`/`?.`/`&&`/`\|\|`/`$matches`/`AsHashtable` | PASS - only matches are a URL query string (line 66) and a regex char-class (line 835); no PS7 operators |
| Module import | Import-Module Scc.Tools.psd1 | PASS - imports clean |
| Exported surface | Get-Command -Module Scc.Tools | PASS - exactly the 6 contract functions (Get-SccToolCatalog, Get-SccToolStatus, Resolve-SccTool, Save-SccToolToCache, Test-SccToolIntegrity, Write-SccToolProvenance) |
| Pester 6 | Invoke-Pester tests/Unit/Scc.Tools.Tests.ps1 -PassThru | PASS - 22/22 passed, 0 failed |

## Per-checklist result

1. Acquisition order (local -> nas -> official, config nas.priorityOrder honored; NAS before download on cache miss)
   PASS. `Resolve-SccTool` (psm1:752) walks `@($cfg.PriorityOrder)` in order; default `local,nas,official`
   (Get-SccNormalizedPriorityOrder psm1:235, used at psm1:279/307/846-850). Tests prove ordering:
   "falls through to NAS when the local cache file is corrupt" (tests:123) and "warns on unreachable NAS
   but is not fatal and falls back to a mocked official download" (tests:149).

2. NAS never trusted blindly (same validation as downloads)
   PASS. NAS file is run through `Test-SccToolIntegrity` (psm1:802) exactly like an official download, and
   rejected when it fails. Proven by "rejects a NAS file whose hash does not match, then falls back to a
   mocked official download" (tests:177) and the corrupt-cache fallthrough (tests:123).

3. Official downloads: HTTPS enforced, FinalUrl recorded, download only when allowed, failure non-fatal
   PASS. All catalog URLs are https (tests:49). `FinalUrl`/`Redirects` recorded in Get-SccWebDownload
   (psm1:511-515) and copied to provenance (psm1:838). Official skipped unless `DownloadAllowed`
   (psm1:821). Failure -> Source=None + warning, never throws (psm1:841-848, test "records a failure and
   returns Source=None on an official HTTP error" tests:229).

4. Signature validation not bypassable (a failed signature must not be marked Verified)
   PARTIAL FAIL (see Finding B1). `Test-SccToolIntegrity` (psm1:623-646) fails on `Invalid`, `HashMismatch`,
   `NotSigned` (correctly). But `NotTrusted`, `UnknownError`, `NotSupported` and any `catch -> Error` fall
   through to the `default` branch (psm1:643) which sets the reason to "...accepted" WITHOUT setting
   `$passed = $false`. On a Windows host a binary whose signature chain does not reach a trusted root
   (NotTrusted) is therefore cached and reported as Verified (CacheVerified = chk.Passed, psm1:924).
   The distinction is NOT enforced for those states. This violates the contract's "signature validation
   not bypassable" rule.

5. Version check (FileVersion >= MinVersion when catalog specifies MinVersion)
   PARTIAL FAIL (see Finding B2). Enforced at psm1:648-661 for Malwarebytes (MinVersion '5.0.0.0').
   However when `$facts.FileVersion` is empty the code only appends "version unknown for <Tool>"
   (psm1:659) and does NOT set `$passed = $false`, so an unversioned binary with a MinVersion still
   passes. The only MinVersion tool (Malwarebytes) always carries a file version, so it is not triggered
   by the current catalog, but the contract ("enforced when catalog specifies MinVersion") is not met
   for the empty-FileVersion case.

6. Cache manifest schema + Save-SccToolToCache refuses invalid input + no path traversal
   PASS. Entry carries Name/Version/SHA256/Size/Publisher/SignatureStatus/CachedUtc/Source
   (psm1:711-721, superset of contract). `Save-SccToolToCache` returns $false and warns when
   `Test-SccToolIntegrity` fails (psm1:696-700); test "refuses an invalid file and caches nothing"
   (tests:271). Manifest path is `<ToolCacheDir>/tool-cache-manifest.json` (psm1:390/427), inside the
   userData/tools cache dir; file name is the catalog FileName joined via Join-Path (no caller-supplied
   path), so no traversal. Round-trip test (tests:278) confirms integrity.

7. Provenance (CandidatesTried, DownloadUrl, FinalUrl, Warnings)
   PASS. `Resolve-SccTool` builds `$prov` (psm1:762-768) and populates all four fields; multiple tests
   assert DownloadUrl/FinalUrl/Warnings (tests:172,198,218,244). `Write-SccToolProvenance` persists the
   array (psm1:981).

8. Catalog URLs match legacy exactly; Sysinternals from download.sysinternals.com only
   PASS. KVRT = https://devbuilds.s.kaspersky-labs.com/kvrt/latest/full/KVRT.exe (matches
   Get-AVTools.ps1:100); Malwarebytes = https://downloads.malwarebytes.com/file/mb-windows/ (matches
   Get-AVTools.ps1:122). Sysinternals OfficialUrls use download.sysinternals.com/files/<Zip>.zip and the
   four ExpectedSha256 baselines match tools/manifest.json entries exactly (autorunsc64
   093D1C6B...87D96F, sigcheck64 A2EFFF8D...6C6281, Procmon64 78D7148E...6C9AF1, tcpview64
   0CBCB7EC...22CFC1). ESET/download.eset.com and AdwCleaner/downloads.malwarebytes.com also match legacy.
   MSERT (go.microsoft.com/fwlink/?LinkId=212732) is the one URL with no legacy counterpart - this is a
   documented DEVIATIONS.md item 1, not an invented flag. All URLs https.

9. Hash loop (SHA256 once per candidate per resolve)
   MINOR FAIL (see Finding B3). `Test-SccToolIntegrity` already hashes the candidate via `Get-SccToolFacts`
   (psm1:359); `Resolve-SccTool` then calls `Save-SccToolToCache` which calls `Test-SccToolIntegrity`
   AGAIN on the same path (psm1:696 vs psm1:862/805). The SHA256 is computed twice for the same file in
   one resolve. Not a security issue; a redundant-hash performance nit against the "no redundant hashing"
   spirit of house rule 8 / checklist 9.

10. No unconditional web calls at import or Get-SccToolStatus
    PASS. Module top-level has no web calls. `Get-SccToolStatus` (psm1:909) uses `Test-Path` for the NAS
    check (psm1:936) and local `Test-SccToolIntegrity` (file reads only). `Get-SccWebDownload` (the only
    web wrapper) is reached solely from the `official` branch of `Resolve-SccTool`.

11. PS 5.1 compatible + pure ASCII + parses
    PASS. See Verification gates table above. No `?:`/`??`/`?.`/`&&`/`||`, no `ConvertFrom-Json
    -AsHashtable`, no `$matches` variable, no PS7-only cmdlets. Single-element-array traps handled
    (psm1:397, Get-SccCacheManifest; DEVIATIONS.md item 8). `@($x).Count` used throughout.

12. Tests: corrupt-NAS, NAS-down-fallback, signature-fail, hash-fail exist and pass
    PARTIAL FAIL (see Finding B4). Present and passing: local-cache-valid (tests:109),
    corrupt-cache->NAS fallthrough (tests:123), NAS-resolve+copy (tests:138),
    NAS-unreachable->official fallback (tests:149), NAS-hash-mismatch->official (tests:177),
    official-cache+provenance (tests:202), official-HTTP-failure->None (tests:229),
    tamper-vs-baseline hash-fail (tests:256), empty-file-fail (tests:264),
    Save-refuses-invalid (tests:271). MISSING: a dedicated signature-fail test that proves a tool whose
    Authenticode status is Invalid/NotSigned/NotTrusted is rejected (Finding B1 is therefore unverified
    by the suite). The contract checklist requires this test to exist and pass.

## Findings

| # | Severity | File:Line | Issue | Suggested fix |
|---|----------|-----------|-------|---------------|
| B1 | HIGH (blocking) | Scc.Tools.psm1:623-646 (default at 643; Error at 640) | Signature statuses `NotTrusted`, `UnknownError`, `NotSupported` and the `catch`->`Error` case are accepted as Verified (Passed=$true) instead of failed. On Windows a binary whose signature does not chain to a trusted root is cached and reported Verified. Violates "signature validation not bypassable". | Add explicit `NotTrusted`/`UnknownError`/`NotSupported` cases that set `$passed = $false` (mirror `Invalid`). Keep `Error` fail-or-warn deliberately, but never silently mark Verified - at minimum record and gate on it. |
| B2 | MEDIUM (blocking per checklist 5) | Scc.Tools.psm1:648-661 (empty branch at 659) | When `FileVersion` is empty but `MinVersion` is set, integrity still Passes (only a note is appended). MinVersion is not enforced for unversioned binaries. | In the `else` (no FileVersion) branch, set `$passed = $false` when `$cat.MinVersion` is set (unless a valid catalog SHA256 baseline already provides equivalent assurance). |
| B3 | LOW | Scc.Tools.psm1:696 vs 805/862 | `Save-SccToolToCache` re-runs `Test-SccToolIntegrity` (and thus re-hashes) on a path `Resolve-SccTool` already validated, doubling SHA256 work per resolve. | Have `Resolve-SccTool` pass the already-computed `$check` into `Save-SccToolToCache` (add an optional `-Integrity` parameter) so the hash is computed once. |
| B4 | HIGH (blocking - checklist 12) | tests/Unit/Scc.Tools.Tests.ps1 (no signature-fail block) | No Pester test asserts a failed/NotTrusted/NotSigned signature is rejected. Without it, B1's acceptance behavior is unverified and the contract's required test matrix is incomplete. | Add a test (Mock `Get-AuthenticodeSignature` / `Get-SccToolFacts` to return SignatureStatus='NotSigned' or 'NotTrusted') proving `Test-SccToolIntegrity` and `Resolve-SccTool` refuse the binary. |

## FIXES-APPLIED

None. This is an independent review; no code was modified (per task rules). No trivial mechanical
behavior-preserving fixes were required.

## Notes (non-blocking observations)

- `Get-SccToolRuntimeConfig` imports Scc.Core on demand (psm1:269-271). If Scc.Core is importable it
  drives ToolCacheDir/Nas/Download config; otherwise embedded defaults are used. This is reasonable and
  keeps the module usable standalone (testable on Linux). The import is wrapped in try/catch and does not
  perform any network call.
- `Test-SccToolIntegrity` accepts `NotChecked` (non-Windows) with an explicit note (psm1:634). This is the
  documented, intentional Linux-test split (DEVIATIONS.md item 5) and is acceptable; the security concern
  (B1) is specifically about the WINDOWS NotTrusted/UnknownError/Error states, which are distinct from
  NotChecked.
- Manifest entry schema is a superset of the contract (adds DownloadUrl). Fine.

## Verdict

REVIEW Scc.Tools: FAIL (2 blocking findings)

Blocking: B1 (signature NotTrusted/UnknownError/Error accepted as Verified) and B4 (required signature-fail
Pester test missing). B2 (MinVersion not enforced for unversioned binaries) is a contract-compliance gap
called out per checklist 5; B3 is a non-blocking performance nit. Core acquisition order, NAS validation,
HTTPS enforcement, provenance, manifest safety, URL fidelity and all parse/ASCII/PS5.1/import gates pass.
The module is well-structured and solid on the happy path; the blocking items are in the signature-trust
and test-coverage areas and should be fixed before the module is marked done.

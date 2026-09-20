# REVIEW-Scc.Detection.md

Independent regression review of Scc.Detection (ScreenConnect parameter parser
and detection port from legacy detect-remote-access.ps1 v0.1.0-poc).

Reviewer: independent (did not write the code).
Environment: Linux pwsh 7.6.5, Pester 6.1.0.
New module: src/Scc.Detection/Scc.Detection.psm1 (+ .psd1), tests/Unit/Scc.Detection.Tests.ps1.
Legacy: /root/screenconnect-cleanup/detect-remote-access.ps1.
Audit: audit/AUDIT-02-detection.md (sec 2.3, 4.1-4.4).

Verdict line is at the end of this file.

================================================================================
CHECKLIST (PASS / FAIL + evidence)
================================================================================

1. BLOB REGEX IDENTICAL
   PASS.
   Legacy line 221:
     (?i)(?:[a-z][a-z0-9]{0,3}=[^&\s"''<>\)]*&){2,}[a-z][a-z0-9]{0,3}=[^&\s"''<>\)]*
   New line 109: identical byte-for-byte.
   DEVIATIONS.md (sec "Source behavior preserved exactly") documents it as copied
   verbatim. Grep diff: no difference.

2. PREFERENCE LOGIC IDENTICAL
   PASS.
   Both: prefer a blob whose value matches (^|&)h= or (^|&)e=(Access|Support|
   Meeting); if none, return the longest match. Legacy Find-ScParamBlob
   (lines 231-243) vs New Find-ScParamBlob (lines 174-186) - same branching,
   same ordering. Side-by-side test "prefers a blob carrying h=/e=" confirms.

3. ConvertFrom-ScParamBlob IDENTICAL BEHAVIOR
   PASS (with a documented, behavior-preserving addition).
   - leading ? trim: legacy line 251 / new line 197  -> both $b.TrimStart('?')
   - leading & trim: legacy line 252 / new line 198  -> both $b.TrimStart('&')
   - empty pair skip: legacy line 254 / new line 200 -> both `continue`
   - first-= split (values with = preserved): legacy lines 255-257 / new 201-204
   - URL decode with try/catch: legacy line 259 / new line 209
   ADDITION (New only): Test-MalformedPercentEncoding + a deterministic warning
   when a `%` is not followed by 2 hex digits (new lines 205-208, helper 139-155).
   This is documented in DEVIATIONS.md #2. Behavior check: on the malformed-% blob
   `%zz`, [System.Uri]::UnescapeDataString does NOT throw in .NET, so legacy ALSO
   leaves the value raw. Confirmed by side-by-side run 3 (RelayHost identical in
   both: relay%zz%zz.example.com). So no silent regression; the addition only adds
   a ParserWarnings entry (new behavior, not a break).

4. KEY MAP COMPLETENESS + CAVEAT
   PASS (one documented rename, see finding F2).
   - All legacy known keys present in New $script:ScKnownKeys (lines 98-107):
     e,y,h,p,s,k,c1-c8. Complete.
   - c1-c8 -> CustomProperties: legacy line 606 / new line 474 (Custom* branch).
   - Unknown keys -> UnknownParameters: legacy line 609 / new line 477.
   - "ASSUMED, NOT CONFIRMED" caveat: carried verbatim in New comment
     (lines 91-97), same wording as legacy lines 125-130.
   - DEVIATION: 'k' friendly name is 'ServerKey' in New vs 'ServerPublicKey' in
     legacy (F2). This matches ARCHITECTURE.md 3.2 field name "ServerKey (encoded)"
     so it is contract-driven, not an accidental regression. Field data (the 'k'
     value) is preserved identically and the fingerprint is derived from it.

5. IDENTIFIER EXTRACTION IDENTICAL
   PASS.
   Legacy Get-ScIdentifier regex (line 269):
     (?i)ScreenConnect Client \(([^)]+)\)
   New Get-ScIdentifier (line 220): identical. Same fallback order in resolve:
   svc Name -> DisplayName -> PathName; dir Name; reg DisplayName -> InstallLocation;
   proc ExecutablePath -> CommandLine. Keys: svc:/dir:/reg:/proc: prefixes preserved.

6. DEDUP ACROSS SOURCES
   PASS.
   New Resolve-SccScInstances uses [ordered]@{} keyed by identifier (or svc:/dir:/
   reg:/proc: fallback), Get-Slot merges. Same as legacy Get-Slot (lines 405-431).
   Verified: side-by-side test + test "resolves 2 services + 1 process + 1
   uninstall into 1 deduped instance" -> 1 instance.

7. FINGERPRINT IDENTICAL
   PASS.
   Legacy line 614-615: Get-Sha256Hex(ServerPublicKey).Substring(0,16), lowercase
   x2. New line 480-483: Get-Sha256Hex(ServerKey).Substring(0,16). Same input
   (the 'k' value), same SHA256, same 16-char lowercase hex. Side-by-side runs
   1,2,3,4,5 show identical fingerprints (e.g. 09bec753b7e27bc9, b80026d579eb33a7).

8. 7045 EVENT MATCHING
   PASS.
   - Event ID 7045, LogName System, max 400 events: legacy line 363 / new line 313
     (param [int]$MaxEvents = 400).
   - Historical handling: events with ScreenConnect mention but no matching live
     instance -> Historical[] with same fields (TimeUtc, Identifier, Message, Note).
     Legacy lines 646-657 / New lines 684-696.
   - Per-instance association by identifier (or ServiceName fallback): legacy
     lines 635-642 / New lines 674-682. Same.

9. DETECTION SOURCES ALL PRESENT
   PASS.
   - Service: Name/DisplayName pattern (Test-AnyLike) + hardcoded (?i)ScreenConnect
     regex on PathName. Legacy lines 436-438 / New lines 508-510. Present.
   - Process: Name/ExecutablePath pattern + (?i)ScreenConnect regex on ExecutablePath.
     Legacy lines 508-509 / New lines 573-574. Present.
   - Directory glob: ProgramFiles(x86), ProgramFiles, ProgramData patterns via
     Get-SccScDirs/Expand-Env (New lines 344-363, 544-554). Matches legacy
     Get-DirsMatching (lines 192-204) + pathPatterns. Present.
   - Uninstall: 3 roots incl WOW6432Node + HKCU. Legacy lines 326-330 / New
     lines 276-280. Present.
   - Config file blob: Find-ScParamBlob over .config content. Legacy lines 548-573
     / New lines 600-614. Present.

10. LEGACY BUGS INTENTIONALLY FIXED / IMPROVEMENTS
    Improvements found (verified, not behavior breaks):
    - I1: Malformed percent-encoding is now detected deterministically and a
      ParserWarnings entry is recorded (New lines 139-155, 205-208; DEVIATIONS #2).
      Legacy relied solely on UnescapeDataString throwing, which it does not always
      do, so the warning could be silently missed. Behavior of the stored value is
      unchanged (left raw), confirmed by side-by-side run 3.
    - I2: ParserWarnings surfaced to the public instance object and rolled into the
      top-level Invoke-SccDetection Warnings[] (DEVIATIONS #1). Legacy only printed.
    - I3: Tests run cross-platform on Linux pwsh; the legacy -SelfTest had no
      automated assertion harness.
    No UNC-path fix was applied (both still use the [a-z]:\\ drive-letter regex,
    legacy line 463 / new line 532). This is the legacy "Very Low" bug left as-is;
    not a regression, just not improved. No other behavior breaks detected.

11. FIELD COVERAGE (vs AUDIT-02 sec 2.3)
    FAIL - data-loss regression. See finding F1.
    Compared every legacy 2.3 per-instance field against the New instance object
    (New-ScInstanceTemplate lines 423-463 + merge in Resolve-SccScInstances):

      Legacy field                 | New field                  | Status
      -----------------------------|----------------------------|------------------
      Key                          | Key                        | OK
      Identifier                   | Identifier                 | OK (renamed from contract InstanceId - F4, non-blocking)
      InstallDir                   | InstallPath                | OK (renamed)
      Sources                      | Sources                    | OK
      ServiceName/DisplayName/     | ServiceName/DisplayName/   | OK
        State/StartMode/Account/   |   State/StartMode/Account/ |
        ImagePath                  |   ImagePath                |
      ParamBlob                    | RawLaunchParameters        | OK (renamed)
      ParamBlobSource              | ParamBlobSource            | OK
      RelayHost/Port/SessionType/  | RelayHost/Port/SessionType/ | OK
        Role/SessionId            |   Role/SessionId           |
      ServerPublicKey              | ServerKey                  | OK (renamed, F2)
      ServerKeyFingerprint         | ServerFingerprint          | OK (renamed)
      CustomProperties             | CustomProperties           | OK
      UnknownParams                | UnknownParameters (array) | OK
      AllParams                    | ParsedParameters           | OK (renamed)
      MainExe                      | ExecutablePath             | OK (renamed/merged)
      File sub-struct              | SignatureStatus/FileVersion/ProductVersion (flattened) | OK
      InstallDirCreatedUtc         | InstallTimestampUtc        | OK (renamed; also folds registry InstallDate)
      ConfigFiles                  | ConfigFiles                | PARTIAL (see F3)
      UninstallDisplayName         | (none)                    | MISSING  <-- F1
      UninstallString              | (none)                    | MISSING  <-- F1
      QuietUninstallString         | (none)                    | MISSING  <-- F1
      UninstallRegistryKey         | (none)                    | MISSING  <-- F1
      InstallDate                  | InstallTimestampUtc       | OK (folded)
      Publisher/DisplayVersion     | Publisher/DisplayVersion  | OK
      Processes                    | AssociatedProcesses       | OK (renamed)
      Connections                  | NetworkConnections        | OK (renamed)
      ServiceInstallEvents         | ServiceInstallEvents      | OK (dynamic member)

    The four Uninstall* fields are collected by Get-SccUninstallInventory (New
    lines 296-298) but DROPPED during the instance merge in Resolve-SccScInstances
    (New lines 557-569 only copy Publisher, DisplayVersion, InstallTimestampUtc).
    This is a data-loss regression vs legacy 2.3 and should be restored.

12. PS 5.1 COMPAT + PURE ASCII + PARSE
    PASS.
    - No forbidden syntax: no ?:, ??, ?., &&, ||, no ConvertFrom-Json -AsHashtable.
      Confirmed by inspection + parse check below.
    - ASCII byte check (python3): psm1=0, psd1=0, tests=0 non-ASCII bytes.
    - Parse check: [System.Management.Automation.Language.Parser]::ParseFile on
      all three files -> 0 errors.

13. TESTS
    PASS.
    - New: pwsh -NoProfile -Command "Invoke-Pester <tests> -PassThru" -> all
      passed, 0 failed (parser, identifier, fingerprint, confidence, orchestration
      mock, trust, Invoke-SccDetectionSelfTest returns 0 failures).
    - Legacy: pwsh -NoProfile -Command "./detect-remote-access.ps1 -SelfTest
      -NoPause" -> exit 0, parser self-test clean.
    - New: Invoke-SccDetectionSelfTest -> 0 failures.

14. SIDE-BY-SIDE (6 synthetic blobs, legacy parser vs new module)
    PASS (all 6 match field-for-field). See table below.

================================================================================
SIDE-BY-SIDE TABLE (legacy Apply-Legacy vs new Apply-ScParameters)
================================================================================

Each row: blob fed to BOTH legacy Find-ScParamBlob+ConvertFrom-ScParamBlob+
key-map and new Find-ScParamBlob+ConvertFrom-ScParamBlob+Apply-ScParameters.

RUN 1 - normal (service ImagePath, URL-encoded c1, k=KEY%3d)
  RelayHost    OK  leg=support.example.com  new=support.example.com
  ServerKey    OK  leg=KEY=                 new=KEY=
  Fingerprint  OK  leg=09bec753b7e27bc9     new=09bec753b7e27bc9
  SessionType  OK  leg=Access               new=Access
  Role         OK  leg=Guest                new=Guest
  RelayPort    OK  leg=8041                 new=8041
  SessionId    OK  leg=1111-2222            new=1111-2222
  Custom       OK  leg=Custom1,Custom2      new=Custom1,Custom2
  Unknown      OK  leg=(none)               new=(none)

RUN 2 - URL-encoded (h=relay%2eexample%2ecom)
  RelayHost    OK  leg=relay.example.com    new=relay.example.com
  ServerKey    OK  leg=KEY123               new=KEY123
  Fingerprint  OK  leg=b80026d579eb33a7     new=b80026d579eb33a7
  SessionType/Role/Port/Id  OK (Access/Guest/8041/1111-2222)
  Custom/Unknown  OK (none/none)

RUN 3 - malformed % (h=relay%zz%zz.example.com)
  RelayHost    OK  leg=relay%zz%zz.example.com  new=relay%zz%zz.example.com
  ServerKey    OK  leg=KEY                   new=KEY
  Fingerprint  OK  leg=5ca24005b740717b      new=5ca24005b740717b
  (UnescapeDataString does not throw on %zz, so legacy also leaves it raw.
   New additionally emits a ParserWarnings entry; legacy does not - additive.)

RUN 4 - unknown keys (zz=1&qq=hello&h=host.example.net&ww=3)
  RelayHost    OK  leg=host.example.net      new=host.example.net
  ServerKey    OK  leg=KEY                   new=KEY
  Fingerprint  OK  leg=5ca24005b740717b      new=5ca24005b740717b
  Unknown      OK  leg=zz,qq,ww              new=zz,qq,ww   (preserved verbatim)

RUN 5 - values with = (k=a=b=c)
  RelayHost    OK  leg=host.example.com      new=host.example.com
  ServerKey    OK  leg=a=b=c                 new=a=b=c   (first-= split preserved)
  Fingerprint  OK  leg=7986b7a514f6eafc      new=7986b7a514f6eafc
  Unknown      OK  leg=x                     new=x

RUN 6 - empty
  All fields empty in both. OK.

CONCLUSION: 6/6 blobs match field-for-field. No parser regressions.

================================================================================
FINDINGS TABLE
================================================================================

| ID  | Severity | File / Line(s)                                  | Issue                                                                 | Suggested fix |
|-----|----------|-------------------------------------------------|-----------------------------------------------------------------------|---------------|
| F1  | Medium   | Scc.Detection.psm1 557-569 (Resolve-SccScInstances section 3) | Uninstall evidence dropped during merge: UninstallDisplayName, UninstallString, QuietUninstallString, UninstallRegistryKey are collected by Get-SccUninstallInventory but never copied onto the instance. Data-loss regression vs AUDIT-02 2.3. | In section 3, copy $u.DisplayName -> slot.UninstallDisplayName, $u.UninstallString -> slot.UninstallString, $u.QuietUninstallString -> slot.QuietUninstallString, $u.RegistryKey -> slot.UninstallRegistryKey. Add these fields to New-ScInstanceTemplate. |
| F2  | Low      | Scc.Detection.psm1 104 vs legacy 137            | 'k' friendly name is 'ServerKey' (New) vs 'ServerPublicKey' (legacy). Matches ARCHITECTURE 3.2 but diverges from legacy map. No data loss (same 'k' value). | Acceptable as contract-driven; document in DEVIATIONS that the rename was deliberate. No code change required. |
| F3  | Low      | Scc.Detection.psm1 600-616                      | ConfigFiles list is only populated when no blob was found yet. Legacy populates ConfigFiles for every instance with an existing install dir regardless of blob source. Minor evidence-completeness gap (file inventory list may be empty when blob came from service). | Move the ConfigFiles enumeration out of the `if (-not $slot.RawLaunchParameters ...)` guard so it runs for every instance that has an existing InstallPath. |
| F4  | Low/Obs  | Scc.Detection.psm1 424 vs ARCHITECTURE 3.2      | Instance field named Identifier (matches legacy 2.3) while contract 3.2 lists InstanceId. Not a data loss; only a naming mismatch with the contract field list. | Either rename to InstanceId or note in DEVIATIONS that Identifier is the chosen name. Non-blocking. |

No High-severity findings. F1 is the only blocking (data-loss) finding.

================================================================================
FIXES-APPLIED
================================================================================

None. This is a review-only pass; no code in Scc.Detection was modified.
(Only temporary comparison scripts were created under /tmp/opencode and are not
part of the module.)

================================================================================
VERDICT
================================================================================

The ScreenConnect parameter parser port is behaviorally faithful: blob regex,
preference logic, ConvertFrom-ScParamBlob (trim/skip/split/URL-decode), key map
coverage, identifier extraction, dedup, and fingerprint are all identical, proven
by the 6/6 side-by-side match and a clean legacy+new self-test. The only blocking
issue is a data-loss regression (F1): four uninstall-evidence fields are dropped
during the instance merge and should be restored.

REVIEW Scc.Detection: FAIL (1 blocking finding)

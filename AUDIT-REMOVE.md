# Safety audit: remove-screenconnect.ps1

Audited against docs/06-safety-model.md plus the five binding audit policies.
Audit date: 2026-08-23.

## Summary

| # | Check | Verdict |
|---|-------|---------|
| 1 | ScreenConnect-only removal targets | FAIL (design) - guard present but not enforced |
| 2 | Quarantine-never-delete | PASS - no filesystem delete found; sequencing caveats |
| 3 | Plan file + -Execute required, inert dry-run default | PASS - one caveat |
| 4 | Runtime-read registry UninstallString, no hardcoded vendor switches | PASS |
| 5 | PS 5.1 syntax / pure ASCII / no BOM / parse | FAIL then FIXED (PS7-only ternary removed); all sub-checks now PASS |

## Check 1 - Only ScreenConnect instances may be removal targets

Verdict: FAIL (design flaw; not mechanically fixable, reported only).

Plan filtering trace (lines 196-202):

    196: $scInstances = @()
    197: if ($plan.ScreenConnectInstances) {
    198:     $scInstances = Force-Array $plan.ScreenConnectInstances
    199: } elseif ($plan.Instances) {
    201:     $scInstances = Force-Array ($plan.Instances | Where-Object {
                 $_.TargetId -eq 'screenconnect' -or $_.Type -eq 'screenconnect' })
    202: }

- Fallback path (plan.Instances) filters by product id/type: correct.
- PRIMARY path (line 198) trusts the property name and does NO per-entry product
  validation. An entry carrying AnyDesk's ServiceName/InstallDir placed inside
  plan.ScreenConnectInstances (buggy Stage 3 output or tampered plan) would be
  stopped, killed, uninstalled, quarantined, and its persistence deleted. No
  downstream cross-check against ScreenConnect identity exists.
- Lines 738-742: inst.UninstallRegistryKey from the plan is read directly and fed
  to Run-VendorUninstaller without validating the key's DisplayName is
  ScreenConnect-like. A crafted plan can aim it at another product's Uninstall key.
- Mitigating evidence:
  - targets.json is never read by this script; other products there are detect-only
    and no code path derives removal targets from it.
  - Registry helper is bounded to DisplayName patterns *ScreenConnect* /
    *ConnectWise Control* (lines 281-290).
  - Persistence cleanup is bounded to paths under each approved instance's
    InstallDir (lines 628, 666, 691), so scope follows the (unvalidated) plan entry.

Recommendation (NOT applied per audit scope): validate every instance against a
ScreenConnect identity allowlist (service name pattern, install path pattern,
uninstall DisplayName) before processing, refuse non-matching entries loudly, and
validate UninstallRegistryKey points at a ScreenConnect-named key.

## Check 2 - Quarantine-never-delete

Verdict: PASS. No filesystem deletion of any kind exists in the script.

Complete destructive inventory (grep-verified):

    398:   sc.exe delete $ServiceName          registry service key (allowed)
    580:   Move-Item ... -> quarantine        move into quarantine (allowed)
    571:   MoveFileEx MOVEFILE_DELAY_UNTIL_REBOOT  deferred quarantine move (allowed)
    633:   Unregister-ScheduledTask           persistence entry (allowed category)
    669:   Remove-ItemProperty                Run-key value = persistence (allowed)
    694-698: Remove-CimInstance x3             WMI subscription = persistence (allowed)
    257:   Checkpoint-Computer                restore point, non-destructive

No Remove-Item on files/dirs, no del/rd/rmdir, no .NET File.Delete anywhere.
SHA-256 and original path recorded per quarantined item (lines 548, 576, 579).

Caveats (design, reported not fixed):

- C2a Quarantine result not verified before dependent deletions: line 777 ignores
  Move-ToQuarantine's return value; Delete-ServiceRegistration (781) runs even when
  quarantine FAILED or was DEFERRED to reboot. Policy requires deletion only AFTER a
  verified quarantine copy.
- C2b Lines 783-788 (InstallDir absent): service registration deleted with no
  quarantine copy existing at all.
- C2c Quarantine folder created with plain New-Item (lines 153-160). Safety rule 3
  requires an ACL-locked quarantine folder; no ACL restriction applied anywhere.
- C2d SHA256/original path embedded in free-text Details strings rather than
  structured manifest fields.

## Check 3 - Plan file AND -Execute required; default run inert dry-run

Verdict: PASS, one caveat.

- Line 38: PlanFile is Parameter(Mandatory = true); script cannot start without the
  approved-plan artifact. There is no detection stage here at all - everything comes
  from the plan, so no detect+remove-in-one-step path exists.
- Every mutating operation sits behind if ($Execute):
  Stop-Service (306), Stop-Process (360), sc.exe delete (393), uninstaller process
  start (482), quarantine move + Set-RunOnceResume (550, 575),
  Unregister-ScheduledTask (632), Remove-ItemProperty (668), Remove-CimInstance (693).
- Default run logs "[DRY-RUN] Would ..." for each action (lines 312, 371, 407, 520,
  589, 638, 674, 701) and ends with the re-run-with--Execute reminder (line 861 area).

Caveat (design): lines 252-260 call Checkpoint-Computer even WITHOUT -Execute, so the
default run mutates system state and is not strictly inert. Restore-point-before-
first-change belongs to the Execute run. Dry-run also creates WorkDir/quarantine/
and writes removal-manifest.json plus master.log (non-destructive writes; acceptable,
noted).

Related gap: reboot-resume is half-built. resume-marker.json is read at lines
237-246 but nothing ever writes it; Set-RunOnceResume writes only the RunOnce key.
Resume therefore relies solely on pending MoveFileEx operations.

## Check 4 - Runtime-read registry UninstallString, no hardcoded vendor switches

Verdict: PASS.

- Lines 430-446: reads QuietUninstallString / UninstallString from the registry entry
  at runtime and uses them as-is; no vendor-specific switches are invented.
- Lines 455-470: MSI detected via ProductCode regex; appends only standard msiexec
  flags /qn and /norestart when absent - sanctioned by safety rule 5
  ("msiexec /x {ProductCode} /qn").
- Lines 471-477: non-MSI uninstaller deliberately runs as-is; comment documents the
  no-invented-flags policy.

Minor notes: $psi.Verb='runas' (line 491) is inert because UseShellExecute=false;
stdout/stderr are drained sequentially which can deadlock a chatty uninstaller;
WaitForExit(300000) result ignored so ExitCode may be meaningless on timeout.

## Check 5 - PS 5.1 compatible, pure ASCII, no BOM, parses clean

Mechanical violations FOUND AND FIXED:

- Line 861 was: exit ($overallSuccess ? 0 : 1)
  PS7-only ternary operator - hard parse error in Windows PowerShell 5.1, explicitly
  forbidden by docs/06-safety-model.md. Fixed mechanically to:

      if ($overallSuccess) { exit 0 } else { exit 1 }

  This also mattered functionally: Set-RunOnceResume (line 600) re-invokes this
  script via powershell.exe (5.1), so resume-after-reboot would have failed to parse.

Verification results (after fix):

- Pure ASCII: 0 bytes above 127 (python byte scan) - PASS
- BOM: none (file starts with '<#') - PASS
- Parse: pwsh -NoProfile parser check reports PARSE errors=0 - PASS
- Remaining PS7-only constructs (??, ?., pipeline && and ||): none found - PASS
- Single-element array trap: .Count uses are Force-Array-wrapped (@() coercion) -
  PASS on inspection

Caveat on method: the mandated verification command runs under pwsh (PowerShell 7),
which ACCEPTS PS7-only syntax, so it cannot prove 5.1 compatibility - the ternary
passed pwsh while being broken on 5.1. Recommend adding a real powershell.exe 5.1
parse gate before ship.

Convention violations observed (reported, not fixed):

- Line 274 assigns $matches as its own ArrayList variable; docs/06 bans using the
  automatic variable $matches as a user variable. Works today only because that
  function performs no -match beforehand; line 459 relies on genuine $matches[1].
- Line 359 uses $pid as loop variable, shadowing automatic $PID (case-insensitive).
- Lines 627-628 use $args, shadowing the automatic $args variable.
- Main instance loop (725-802) has no per-instance try/catch; under StrictMode 2.0 +
  ErrorActionPreference Stop, one malformed plan entry (missing ServiceName etc.)
  aborts the whole run mid-way, violating the wrap-each-section convention.
- Add-Type Kernel32 (lines 564-567) executes per locked file; second invocation
  throws "type already exists", so multi-file reboot-deferral misreports failure.
- WMI filter lookups (lines 689-690) query Name= with $b.Filter, which is a reference
  string, not a bare name - subscriptions will effectively never match (fails safe,
  feature silently dead).
- Kill fallback (lines 346-352) kills processes whose COMMAND LINE merely contains
  "ScreenConnect" (e.g. a browser showing a ScreenConnect URL) - overreach within
  ScreenConnect scope.

## Actions taken

1. FIXED (mechanical): PS7-only ternary at former line 861 replaced with if/else.
2. Verified post-fix: 0 non-ASCII bytes, no BOM, PARSE errors=0.
3. All design findings above reported WITHOUT code changes.

## Post-fix verification transcript

    python3 byte scan : non-ascii bytes: 0 / BOM: False
    grep PS7 operators: no matches for ?? ?. ternary && ||
    pwsh parse        : PARSE errors=0

## FIXES-APPLIED (second pass - code changes, superseding "reported not fixed")

Date: 2026-08-23. Scope limited to the four required design fixes; everything
else untouched. All line references below are to the post-edit
remove-screenconnect.ps1 (now 1203 lines).

### FIX 1 - CRITICAL per-entry product verification

New verification block inserted immediately after the plan filter block:

- Lines 215-452: new functions.
  - `Get-ScreenConnectIdentity` (line 227): identity pattern set; loads
    servicePatterns/processPatterns from the `screenconnect` entry of
    targets.json at runtime (line 236-249), hardcoded safe fallbacks when
    targets.json is absent/unreadable. Binary allowlist always includes
    ServiceScreenConnect.exe plus the ScreenConnect client patterns.
  - `Get-EntryPropertySafe` (263) / `Get-PlanInstanceId` (274): StrictMode-safe
    plan-entry property reads (missing fields no longer throw).
  - `Get-PathBinaryLeaf` (283): platform-neutral leaf-name extraction handling
    quoted paths ("C:\...\x.exe" /args), trailing arguments, and '/'-separated
    input.
  - `Test-ScreenConnectInstance` (318): re-verifies each entry is genuinely
    ScreenConnect before any action. Gate A: some candidate path
    (ServiceImagePath/ImagePath/InstallDir, env-vars expanded) sits under a
    ScreenConnect directory segment. Gate B: binary name matches
    ServiceScreenConnect.exe or the targets.json client patterns (directory-only
    entries corroborated by an on-disk binary scan). Gate C: ServiceName, when
    supplied, matches ScreenConnect service patterns. Any failed gate = reject.
  - `Get-VerifiedUninstallEntry` (397): validates a plan-supplied
    UninstallRegistryKey by actually running Get-ItemProperty on it and
    accepting it ONLY when the key's DisplayName is ScreenConnect-like AND at
    least one value on the key references the SAME verified install dir
    (case-insensitive). Unreadable/foreign/mismatched keys are rejected with a
    manifest `ValidateUninstallKey`/`Rejected` entry.

Loop integration (main loop):

- Lines 1048-1058: every instance passes through Test-ScreenConnectInstance
  BEFORE stop/kill/uninstall/quarantine. Failures are logged as
  `ProductVerification`/`PRODUCT_VERIFICATION_FAILED` in the manifest
  (1052-1054), the instance is skipped (`continue`), and is never uninstalled.
  Passing entries get a `ProductVerification`/`Passed` manifest record (1058).
- Lines 1065-1070: plan UninstallRegistryKey is consumed only via
  Get-VerifiedUninstallEntry; on rejection the pre-existing bounded registry
  lookup (DisplayName *ScreenConnect*/*ConnectWise Control*) still applies as
  fallback (1072-1079), otherwise manual surgery path is used.
- Lines 1181, 1187: summary now counts/logs verification failures.

### FIX 2 - reboot-resume made real

- Line 463: `$resumeMarkerPath = <WorkDir>\resume-marker.json`.
- Lines 471-546: marker state + functions. `Write-ResumeMarker` (481) writes
  UTF8-no-BOM JSON listing every instance + status (+ phase/timestamps);
  `Initialize-ResumeMarker` (502) seeds all instances Pending (preserving
  Completed from a prior run); `Update-ResumeStatus` (518) updates one instance
  and persists. Writes occur ONLY in Execute mode (dry-run never touches the
  file).
- Lines 530-547: `-Resume` now really reads resume-marker.json and collects
  Completed InstanceIds into `$script:CompletedInstanceIds` (replaces the old
  read-only stub that nothing ever wrote).
- Line 1026: marker initialized at start of Execute-mode removal;
  line 1041-1046: already-completed instances are skipped with a
  `ResumeSkip`/`Skipped` manifest entry; per-instance status persisted after
  every instance (1132 Completed, 1138 Failed/PRODUCT_VERIFICATION_FAILED at
  1054), final `session-complete` write at 1144. RunOnce deferral wiring
  (Set-RunOnceResume, MoveFileEx retry) unchanged and now backed by real state.

### FIX 3 - per-instance try/catch in the main loop

- Lines 1024-1142: main foreach restructured. Instance id resolved defensively
  BEFORE the try (1036, via Get-PlanInstanceId) so failures stay attributable;
  entire per-instance body wrapped in try/catch (1038/1133-1141). A malformed
  or failing entry logs `Unhandled error processing instance ... continuing`
  (Error), records `ProcessInstance`/`Failed` + reason in the manifest (1137),
  marks the resume status Failed (1138), sets $overallSuccess=$false, and
  continues to the next instance. Direct `$inst.<prop>` accesses inside the
  loop were replaced by StrictMode-safe reads (1060-1061, 1067, 1124).

### FIX 4 - Checkpoint-Computer only in Execute mode

- Line 556: condition changed from
  `if (-not $NoRestorePoint -and -not $Resume)` to
  `if ($Execute -and -not $NoRestorePoint -and -not $Resume)`. The default
  dry-run no longer mutates system state (closes the Check 3 caveat).

### Verification (post-fix)

- pwsh parse check: PARSE errors=0 (Parser::ParseFile).
- python byte scan: non-ascii bytes=0, BOM=False.
- PS7-only construct scan (??, ?., ternary, &&, ||): none found.
- No NEW automatic-variable shadowing introduced ($matches/$pid/$args). Two
  PRE-EXISTING shadowing assignments remain intentionally untouched (out of
  scope per instructions): line 576 ($matches in Get-UninstallEntriesForInstance)
  and line 931 ($args in Clean-Persistence); plus pre-existing `$pid` loop
  variable in Kill-ProcessesForInstance.
- Synthetic functional tests (pwsh on Linux, AST-extracted functions):
  - Genuine ScreenConnect entry (test_plan.json shape) -> Verified=True.
  - ServiceScreenConnect.exe with quotes+arguments -> Verified=True.
  - Smuggled AnyDesk entry placed in ScreenConnectInstances -> Verified=False.
  - ScreenConnect-named directory with foreign binary name -> Verified=False.
  - Foreign service name with SC-looking path -> Verified=False.
  - Malformed empty entry and null entry -> Verified=False without throwing.
- Full dry-run of this script against test_plan.json: completes end-to-end,
  manifest shows ProductVerification Passed then normal pipeline; poisoned-plan
  dry-run produces ONLY the PRODUCT_VERIFICATION_FAILED manifest entry and zero
  removal actions; no restore-point activity occurs in dry-run (FIX 4).
- Resume-marker lifecycle test: initial Pending statuses written (no BOM),
  per-instance updates persisted, -Resume skip list rebuilt correctly,
  Completed preserved across re-init while failed instances reset to Pending,
  dry-run provably never mutates the marker.

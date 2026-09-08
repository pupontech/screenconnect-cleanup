# REVIEW - Scc.Remedy (independent security review)

Reviewer: dsflash (independent; did not author this module)
Date: 2026-08-26
Scope: /root/screenconnect-cleanup/gui-revision-screenconnect-cleaner/src/Scc.Remedy/
       (Scc.Remedy.psm1, Scc.Remedy.psd1) + tests/Unit/Scc.Remedy.Tests.ps1
       + tests/Unit/_SccRemedyHelpers.ps1
Contract: ARCHITECTURE.md sections 3.7 + 9 (plus 1,2,5,6,8)
Legacy:   /root/screenconnect-cleanup/remove-screenconnect.ps1,
          AUDIT-REMOVE.md, gui-revision-screenconnect-cleaner/audit/AUDIT-03-removal.md

Method: read-only review plus runtime verification on Linux pwsh 7.6.5 / Pester 6.1.0.
No source files were modified. No git commands were run.

Commands run (gates):
  parse  : Parser::ParseFile -> 0 errors for psm1, psd1, Tests.ps1, _SccRemedyHelpers.ps1
  ascii  : python3 byte scan -> 0 non-ASCII bytes and no BOM in all four files
  import : Import-Module Scc.Remedy.psd1 -> Clean (exports exactly the 5 contract functions)
  pester : Invoke-Pester tests/Unit/Scc.Remedy.Tests.ps1 -PassThru -> 18 total,
           15 passed, 3 FAILED (stable across 3 consecutive clean runs)

================================================================================
CHECKLIST  (PASS / FAIL / PARTIAL with evidence)
================================================================================

1. No one-step detect-and-remove flag ......... PASS
   The module has no detection anywhere. Public surface is exactly:
   New-SccPlan(Findings,Decisions), Test-SccPlan(Plan), Invoke-SccRemediation(Plan,Execute),
   Restore-SccQuarantineItem(ItemId), Clear-SccQuarantine(Approved,ConfirmText).
   Invoke-SccRemediation requires a Plan and acts only on REMOVE items inside it; there is no
   detection+removal in one step. Evidence: psm1:688-695 (param blocks), psm1:718-782 (loop only
   over plan items), psm1:842-848 (Export-ModuleMember limited to the 5 functions).

2. Plan gate; default KEEP; SC-only REMOVE, enforced in code ... PARTIAL (FAIL on identity re-check)
   - New-SccPlan defaults every finding to Action=KEEP unless Decisions[$fid]=='REMOVE': psm1:609-614.
   - Only Product 'screenconnect' may be REMOVE: enforced at psm1:617-620 (New-SccPlan throws on
     refusal) AND independently at the execution site psm1:728-731 (smuggled/hand-crafted plan with a
     non-SC Product REMOVE item is skipped with a recorded SkipItem, no destructive primitive runs).
   - Poisoned-plan proof: the file WILL reject a plan whose item Product != screenconnect. The Pester
     smuggling test ("poisoned plan with an AnyDesk REMOVE item performs ZERO destructive actions",
     Tests.ps1:89-132) PASSES and asserts no Stop/Kill/Uninstall/Quarantine primitive is invoked.
   - GAP: the plan does not have to be a plan.json artifact. Resolve-SccPlan (psm1:187-199) accepts a
     plan OBJECT as well as a file path, so a programmatic caller can reach destructive code with an
     in-memory plan. More importantly the identity re-check is weak against a VALUE-poisoned plan that
     sets Product='screenconnect' but points ServiceName/InstallDir at arbitrary targets - see item 4.

3. Dry-run default; no mutation without -Execute ... PASS
   Invoke-SccRemediation returns the preview and exits before any primitive when -Execute is absent:
   psm1:705-708. All nine destructive primitives (stop service, kill processes, uninstall, delete
   service, delete task, delete run key, delete firewall rule, quarantine) are called strictly inside
   the -Execute branch, after psm1:709, in the block psm1:747-774. The primitives are private, are not
   exported, and are only reachable through Invoke-SccRemediation's gate. Pester dry-run test PASSES
   (Tests.ps1:134-156). Evidence for every primitive being gated: only Invoke-SccRemediation invokes
   them, always after the gate.

4. Per-item re-verification actually re-checks the live target ... FAIL (HIGH)
   Test-SccScreenConnectTarget (psm1:229-247) is the tamper guard and it can be satisfied without
   contacting the live system. It sets $hint=true if ANY single plan-declared string matches
   (ServiceName -like 'ScreenConnect*', InstallDir -like '*\ScreenConnect*', MainExe -like
   '*ScreenConnect*'), psm1:237-239. Only when NO string hint matched does it query Get-Service
   (psm1:240-245). Consequences:
   - A value-poisoned plan with Product='screenconnect', ServiceName='<any real service>',
     InstallDir='C:\...\ScreenConnect\fake' passes re-verification via the InstallDir hint alone, and
     then Remove-SccTargetService runs `sc.exe delete "<ServiceName>"` verbatim (psm1:405-423, invoked
     at psm1:759-760 with $svc straight from the item), so an arbitrary named service can be deleted.
   - QuarantinePaths is taken verbatim from the plan item (psm1:766-769) and Move-SccTargetToQuarantine
     (psm1:531-581) will move ANY path the attacker lists into quarantine (data-integrity/DoS).
   - Legacy used an AND of three gates (directory segment AND binary name AND service name,
     remove-screenconnect.ps1:417-494); the new logic is an OR of hints - a strict regression.
   - The re-verification gate test exists and passes (Tests.ps1:212-259), but it only exercises the
     Product-level guard and a mocked return, not a value-poisoned plan. No test tries to delete a
     service named by a poisoned plan.

5. Uninstall-first ordering; runtime registry read; no hardcoded switches ... PASS (ordering)
   Sequence is stop service -> kill procs -> vendor uninstall -> validate -> cleanup -> quarantine
   (psm1:747-774). The uninstaller is read from the registry at runtime (Get-SccTargetUninstallData,
   psm1:310-325: UninstallString/QuietUninstallString/ProductCode) and is not hardcoded. The msiexec
   fallback (psm1:363-364) is built from ProductCode read from the key, with /qn /norestart. Pester
   ordering test PASSES (Tests.ps1:182-208). No invented silent flags; non-MS inline policy is to run
   as-is. See item 8 for the validation gap on the invoked command.

6. Quarantine-never-delete; delete requires double-confirm ... PASS
   The only permanent-delete path is Clear-SccQuarantine (psm1:819-837), which requires BOTH
   -Approved AND -ConfirmText 'PERMANENTLY DELETE' (psm1:826-828), otherwise it throws. Deletion is
   never automatic. All artifact handling defaults to Move-SccTargetToQuarantine. Pester test PASSES
   (Tests.ps1:472-487).

7. Quarantine safety (manifest/ACL/restore/traversal) ... FAIL (HIGH - traversal unhandled)
   - Manifest fields: Add-SccQuarantineManifestEntry records ItemId, OriginalPath, QuarantinePath,
     SHA256, SizeBytes, MovedUtc, FindingId, Reason, ActionType, RestoreInstructions (psm1:562-572).
     PASS for schema.
   - ACL hardening: best-effort icacls on Windows / chmod 700 elsewhere (psm1:555-560). PASS.
   - Restore refuses to overwrite: Restore-SccQuarantineItem throws when destination exists
     (psm1:806-808). PASS.
   - Path traversal: FAIL. Restore-SccQuarantineItem (psm1:787-817) takes dest = manifest OriginalPath
     with NO canonicalization/containment check. A manifest entry whose OriginalPath is
     'C:\Windows\System32\evil.exe' or '..\..\evil.exe' would be restored there (moved out of
     quarantine back to that path). There is no check that OriginalPath is under a safe root, that the
     manifest entry belongs to the current run, or that the path cannot traverse. Per the review
     instructions, an unhandled traversal is a HIGH finding. No traversal test exists in the file.
   - Additional: the quarantine unit tests themselves are RED on this host (see item 12), so the
     manifest/restore behavior is not currently verified green.

8. Command injection / process launch hygiene ... FAIL (HIGH - uninstaller validation missing)
   No shell is used: Invoke-SccUninstallCommand splits the command into exe + remainder and launches
   via ProcessStartInfo with UseShellExecute=$false (psm1:327-351) - so no cmd.exe/%VAR%/&/|/^ shell
   interpolation (the legacy no-shell property is preserved). However:
   - The executable path is taken verbatim from the registry UninstallString/QuietUninstallString and
     is executed with NO validation: no leaf-name allowlist, no containment check that the exe lives
     under the verified install dir, no file-exists check, no signature check. The FULL remainder of
     the string is passed as Arguments (psm1:341).
   - The registry UninstallString is attacker-influenceable (a rogue product wrote it; the checklist
     flags exactly this). The legacy engine enforced allowlist + under-install-dir + file-exists and
     ran the executable with NO arguments, and fail-closed to manual surgery otherwise
     (remove-screenconnect.ps1:1003-1031). The new module dropped all of that, so an arbitrary
     attacker-controlled executable can be launched with the technician's elevated token and arbitrary
     arguments. Regression vs legacy - HIGH.

9. Failure isolation; every action recorded ... PASS
   Every primitive is wrapped in try/catch and returns a bool; item failures accumulate in
   $itemHadFailure and continue to the next item (psm1:742-781). stopOnFail is config-gated default
   false (psm1:710-715). Add-RemediationAction records Action/Target/Command/Result/Error/StartedUtc/
   EndedUtc to remediation.json (psm1:102-128). One failed item does not abort the plan. Pester tests
   confirm ordering and skip behavior.

10. Report/trace feeds Scc.Core logging ... PASS
   Every action is written to remediation.json and every entry also goes through Write-SccRemedyLog ->
   Write-SccLog (psm1:58-63, 126, 575, 775, 815, 827, 835), feeding the Scc.Core JSONL + master log
   per contract section 3.1.

11. PS 5.1 compatible + pure ASCII + parses ... PASS
   Parse: 0 errors on all four files. ASCII: 0 non-ASCII bytes, no BOM, on all four files. No ?:/??/?./&&/||
   or ConvertFrom-Json -AsHashtable. The one `$cmd = if(...){...}else{...}` (psm1:362) is the PS5.1-legal
   if-expression assignment, not the forbidden ternary. Verified by running.

12. Tests: Pester run; smuggling + traversal tests ... FAIL
   Ran `pwsh -NoProfile -Command "Invoke-Pester tests/Unit/Scc.Remedy.Tests.ps1 -PassThru"` (Pester 6.1.0):
   18 total, 15 passed, 3 FAILED, and the 3 failures are stable across three consecutive clean runs.
   Failing:
     - "moves a real file, records correct manifest fields, and removes the original" (Tests.ps1:367-407)
     - "restores a quarantined item and refuses when the destination already exists" (Tests.ps1:417-470)
     - "Clear-SccQuarantine refuses without -Approved..." (Tests.ps1:472-487)
   Root cause (verified by direct reproduction): on Linux, Scc.Core Get-SccPaths resolves %ProgramData%
   to the synthetic /tmp/scc-fake-ProgramData (Scc.Core.psm1:136-143). Get-SccRemedyQuarantineRoot
   (psm1:78-96) only falls back to RunDir\Quarantine when the resolved root is empty or still contains
   a '%' (psm1:88). The synthetic path has neither, so the module quarantines + writes the manifest
   under /tmp/scc-fake-ProgramData/ScreenConnectCleaner/Quarantine/<RunId>/q/ while the tests hardcode
   <RunDir>/Quarantine (Tests.ps1:393, helper 44-58). The documented testability fallback never
   triggers. This is a genuine module<->Scc.Core<->test contract mismatch: the tests are RED on the
   required Linux gate and would also be RED on Windows (real ProgramData path, not RunDir).
   - Smuggling test EXISTS and PASSES (Tests.ps1:89-132): poisoned anydesk plan -> zero destructive actions.
   - Traversal test DOES NOT EXIST, and the Restore traversal path is unhandled (item 7) -> HIGH.

13. Compare vs legacy remove-screenconnect.ps1 - missing safety mechanisms ... FAIL (several missing)
   Present in Scc.Remedy: plan-gated dry-run, SC-only product enforcement, quarantine-never-delete,
   no-shell uninstaller (shell-injection part), per-item error isolation, collision-safe quarantine
   naming (psm1:545-548, SHA256-prefix on name collision).
   MISSING vs legacy:
   - Admin / elevation gate: legacy -Execute requires an elevated shell (remove-screenconnect.ps1:80-87,
     exit 2). Scc.Remedy has NO elevation check. [MEDIUM]
   - Self-protection in process kill: legacy walks the parent PID chain and refuses to kill the tool's
     own process tree (remove-screenconnect.ps1:815-834). New Stop-SccTargetProcesses (psm1:278-308)
     has no such guard. [MEDIUM]
   - Reboot-resume: legacy resume-marker.json + RunOnce + MoveFileEx deferred move for in-use files
     (remove-screenconnect.ps1 around 596-691, 1214-1239). Scc.Remedy has no resume marker, no RunOnce,
     no MoveFileEx fallback; a locked in-use file just records Quarantine Failed. [MEDIUM]
   - Vendor uninstaller validation (allowlist + under-install-dir + file-exists, run with no args;
     remove-screenconnect.ps1:1003-1031). Missing - see item 8. [HIGH]
   - Reparse-point skip + per-file directory hashing to CSV during quarantine
     (remove-screenconnect.ps1:1099-1130). New code runs Get-FileHash on the whole path (fails for a
     directory) and moves a directory wholesale; junctions/symlinks are not skipped. [MEDIUM]
   - Uninstall registry key export-before-delete (remove-screenconnect.ps1:1540-1574). New module does
     not delete orphaned uninstall keys at all. [LOW/capability]
   - WMI persistence cleanup (remove-screenconnect.ps1:1327-1355). Not present; legacy version was
     effectively dead (AUDIT-03-removal.md section 6.1). [LOW]
   - Restore-point creation is handled outside this module (Stage 0 / Scc.Core per ARCHITECTURE section 9.4), so not counted as a regression.

================================================================================
FINDINGS TABLE
================================================================================
| # | Severity | File:Line | Issue | Suggested fix |
|---|----------|-----------|-------|---------------|
| F1 | HIGH | Scc.Remedy.psm1:229-247 (used at 733-740) | Re-verification trusts plan-declared identity strings; any single ScreenConnect string hint passes without a live re-check, so a value-poisoned plan (Product=screenconnect + arbitrary ServiceName / QuarantinePaths) can delete arbitrary named services (`sc.exe delete` at 405-423 with verbatim item ServiceName) and quarantine arbitrary files (766-769). Legacy used an AND of three gates. | Re-verify against the LIVE target: all present identity fields must independently check out (service exists AND its path/name matches, install dir exists on disk under a ScreenConnect segment AND the binary is present), and quarantine/service targets must be validated to resolve inside the finding's verified scope. Restore the legacy AND-of-gates. |
| F2 | HIGH | Scc.Remedy.psm1:327-351 (built at 353-383) | Attacker-influenceable registry UninstallString/QuietUninstallString is executed with arbitrary exe path AND full argument string, no allowlist/containment/file-exists/signature validation - arbitrary code exec with the elevated token. Regression vs remove-screenconnect.ps1:1003-1031. | Reintroduce legacy validation: non-MS exe leaf must match the ScreenConnect allowlist, must reside under the verified install dir, must exist on disk (optionally Authenticode-checked), and run with curated/no arguments; else fail-closed to manual surgery. |
| F3 | HIGH | Scc.Remedy.psm1:787-817 | Restore-SccQuarantineItem blindly restores to any OriginalPath from a (tamperable) manifest, incl. '..\..' or system paths; no traversal/containment/run-ownership check; no traversal test. | Canonicalize and verify OriginalPath is a safe absolute path inside the original remediation scope (no '..' components, no unresolved env symlinks, rejected if it escapes quarantine context), and tie each manifest entry to the run + an authenticated quarantine dir. Add a traversal unit test. |
| F4 | MEDIUM | Scc.Remedy.psm1:78-96 vs Scc.Core.psm1:136-143 + Tests.ps1 | Quarantine root on Linux (and behaviourally on Windows) resolves to the ProgramData-derived path, so the module's testability fallback to RunDir\Quarantine never triggers and the 3 quarantine/restore/clear Pester tests are RED (15/18 green). | Fix the module/test contract: either make Get-SccRemedyQuarantineRoot fall back to RunDir/Quarantine on non-Windows regardless of '%' (platform check, not '%' check), or update the tests to locate the manifest at the resolved root (like the helper's ProgramData candidate already does). Add a platform check, not a '%' heuristic. |
| F5 | MEDIUM | Scc.Remedy.psm1:278-308 | Process kill lacks the legacy self-protection (parent-PID-chain walk); a poisoned/edge path could terminate the tool's own host mid-remediation. | Re-add the ancestor-chain guard used by remove-screenconnect.ps1:815-834. |
| F6 | MEDIUM | Scc.Remedy.psm1: (module has no admin gate) | No elevation check before -Execute (legacy had one, remove-screenconnect.ps1:80-87); partial mutations can pass as success if non-elevated. | Add a Test-IsAdmin gate before any -Execute mutation (mirror legacy exit-2/abort). |
| F7 | MEDIUM | Scc.Remedy.psm1:531-581 | No reboot-resume (no resume-marker.json, no RunOnce, no MoveFileEx deferred move); in-use/locked files fail quarantine and are lost to cleanup on reboot gaps; quarantine records file hash but not per-file directory CSV, and reparse points (junctions/symlinks) are not skipped. | Port legacy MoveToQuarantine deferred-move + resume-marker/RunOnce, per-file CSV hashing for directories, and reparse-point skip. |
| F8 | LOW | Scc.Remedy.psm1 (no orphaned-key handling) | Orphaned uninstall registry keys are not exported/deleted as in legacy. | Optional: add export-before-delete for orphaned uninstall keys, or document as intended scope reduction in DEVIATIONS.md. |
| F9 | INFO | Scc.Remedy.psm1:31-38 | Soft-dependency bootstrap loads Scc.Core into the module session but does not expose Scc.Core functions to the caller session after Import-Module Scc.Remedy; harmless to the module's own function but surprising for callers and worth a comment. | Not a defect; optional: document that Scc.Core must be imported separately for interactive use. |

================================================================================
FIXES-APPLIED
================================================================================
None. This is a read-only independent review; no source or test files were modified.
No trivial ASCII/BOM/parse fixes were needed (all four files already parse clean,
pure ASCII, and no BOM). Run-time reproduction used throwaway temp directories and
temp fixture cleanup only.

================================================================================
VERDICT
================================================================================
REVIEW Scc.Remedy: FAIL (3 blocking findings)

Blocking (HIGH): F1 re-verification does not robustly re-check the live target and
permits arbitrary service deletion / file quarantine via a value-poisoned plan;
F2 uninstaller invocation runs an unvalidated, attacker-influenceable registry
executable + full argument string with the elevated token; F3 restore path traversal
is unhandled and untested. Additionally the module is not green on the required
Linux Pester gate (15/18; the 3 quarantine tests fail on a quarantine-root
resolution mismatch), the traversal test required by the checklist does not exist,
and legacy safety mechanisms (admin gate, process-kill self-protection, reboot-resume,
reparse-point/dir-hash quarantine, uninstaller allowlist) are missing.
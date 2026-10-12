# Protected install/store: next implementation slice

Status: proposal, not installation approval. Full cleanup remains disabled.

## Verified baseline

- Source: 688523a744a1232d2c1af6aaf3d51c592a3d3572, branch feat/minimal-wpf-gui, private PR25.
- Foundation Windows run: https://github.com/pupontech/screenconnect-cleanup/actions/runs/37198087022 . All four Windows 2022/2025 x PowerShell 5.1/7 jobs succeeded. Parent downloaded exact job logs and verified actual 360/48/191/231 assertion outputs plus 23-case schema/runtime parity. PowerShell 7 also executed the legacy root-array regression.
- Independent bounded source review accepted the repaired 16 MiB/member, four-member, 64 MiB-total manifest relationship at 83315f28ecd8a6dae0fa71eec9e0ea4734462683. Production validators/schema are unchanged in 688523a; the later change fixes the fixture-reader array shape and adds its regression.
- Foundation cards t_443dd56a and t_68d8335b are completed by the parent. All current PR checks passed after the separate Windows relay loopback test rerun. The first transport abort remains evidence of a possible flake, not a repaired product defect.
- None of this proves a protected installation, authenticated evidence producer, native filesystem protection, rollback acquisition, approval host, durable store or removal.

## Authority and ownership

`GUI-FULL-WORKFLOW-DECISIONS.md` governs. Earlier readiness reports' scanner/share defaults are superseded: include accepted scanner workflows, keep AV installed, share only sanitized reports to the existing configured service, no automatic reboot or Procmon. Agents do not perform live installation/removal/scanning/sharing. Actual installation and destructive acceptance remain owner-only.

Native writer card t_fc961178 owns only `gui-bridge/ProtectedWindowsTrust.ps1` and `tests/gui/phase4/ProtectedWindowsTrustTests.ps1`. Do not edit those while its raw worker owns them. Its API and native proof are pending, not an established trust contract. The read-only install/store design card is t_ff61b882; its scratch report is `/root/.hermes/cache/scratch/sc-gui-protected-install-store-design.md`.

## Required technical boundaries

1. **Authenticate bootstrap before executing it.** A manifest pin authenticates manifest bytes only after a trusted caller supplies it. A bootstrap cannot authenticate itself with an adjacent digest. Define a trusted separate-channel launch instruction/loader that checks and executes the same bounded byte snapshot before any elevation or installation write. No publisher, signing identity or certificate is assumed. A separately delivered trusted pin may be transported as a parameter; a parameter by itself does not establish the source's authenticity.
2. **Inventory the whole protected payload.** Manifest v1 presently allows exactly four foundation PowerShell files, not a complete future host/runtime. Expand/version its fixed reviewed catalog and schema explicitly before using it for installation. Reject missing, extra, duplicate, case-colliding, traversal, device, UNC, ADS, link and unsupported entries. Verify every raw member and exact manifest digest before creating a destination or changing any ACL.
3. **Use native same-object protection evidence.** Production checks must derive actual owner/DACL, effective access, file/volume identity and reparse/ancestor evidence from retained Windows handles. Callback booleans, user-supplied SID/path, hash strings or a PSCustomObject claiming trust are not authentication. Hash/parse/load the same bytes; do not separately hash a path and reopen it to execute. Native leases and race-safe create/open/publication semantics still require implementation and proof.
4. **First installer is absent-only.** Refuse existing/squatted destinations and unsupported policy. Stage already-verified bytes in an exclusively created, correctly protected tree; flush, read back, verify exact member set and identities, and publish without replacement. Unknown writes/publication or partial failure is RecoveryRequired, never success or automatic repair. Upgrade, repair, adoption, uninstall and rollback of an installed version are separate later policies, not implied by one-time installation.
5. **First store is inert.** Only Created/RecoveryRequired/Corrupt/NotFound and bounded non-authorizing transitions are in scope. No Approved/ConsumedForRemoval state, approval nonce or remover invocation. Generate IDs inside the trusted process; never reuse caller-selected roots/IDs/SIDs as authority. Use exclusive creation, cross-process exclusion, expected-sequence/state compare-exchange and same-directory durable publication. Torn/ambiguous records or acknowledgments cause no automatic stage replay.
6. **Separate presentation from authority.** Authenticate future clients with actual OS identity/session evidence. An ordinary GUI projection omits secret bindings and cannot mutate protected state. Alternate-admin elevation must not silently export that administrator's HKCU as the initiating user's evidence; unsupported identity cases fail closed.

## Root-policy conflict to verify, not silently resolve

The existing pure path policy derives `C:\ProgramData\ScreenConnectCleanup\Transactions\<canonical GUID>` and returns CandidateOnly. The governing protection rule rejects relevant-parent ordinary write/delete/ownership control. Default ProgramData ancestors may permit ordinary create-child rights; this must be measured with the native implementation on hosted Windows, not inferred from an injected flag.

If the strict ancestor rule fails, do not weaken it, change the fixed root or broadly rewrite ProgramData/drive-root ACLs. Possible proposals are a pre-administered compliant baseline, an explicitly approved alternative root, or an explicitly reviewed distinction between safe sibling creation and rights that can replace/delete/mutate the protected child. No proposal is approved here. Final roots/principal policy and the exact supported parent-right interpretation must be reconciled before production writes. Conventional SYSTEM/Administrators identities are possible technical defaults, not fabricated publisher identities; their actual effective rights still need proof.

## Next file-disjoint tickets and gates

- Native read-only verifier: current writer; real Windows positive/refusal/identity/reparse/rights tests, native handle cleanup, explicit unsupported/non-Windows refusal. Synthetic fixture ACL changes only under a test-created runner-temp GUID directory, never protected/system roots.
- Trusted bootstrap/catalog: new implementation/test files; manifest expansion owned separately from native writer. Prove wrong/untrusted pins and any catalog mismatch cause zero elevation/write/execution calls. Prove exact verified bytes reach the writer/loader.
- Atomic absent-only installer: depends on accepted root/principal policy, bootstrap/catalog and native leases. Exercise synthetic fixtures and crash/order/refusal cases; never run the production installer in CI.
- Inert transaction store: separate new source/test files; depends on the native lease and fixed-root policy. Prove concurrent create/CAS, replay, corruption, uncertain publish, lock abandonment and no automatic recovery/removal.
- Parent wiring: exact-commit Windows 2022/2025 x PowerShell 5.1/7, existing foundation regressions, native/fixture proofs, independent review. Linux skips and green older commits are not native evidence. No production approval, merge or new full-cleanup download until integration/package gates are met.

The current owner download stays v0.2.0 DetectOnly. No installation, filesystem trust or full-workflow claim is made by this document.

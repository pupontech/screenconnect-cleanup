# Full GUI workflow: accepted scope and release gates

## Owner decisions

- One Start action begins the full investigation and cleanup workflow. Mode changes affect presentation only: concise progress/results by default, expandable technical details.
- ScreenConnect removal requires one explicit protected approval displaying the current instance set and quarantine consequences. Start, UAC acceptance, a UI state file, a plan flag or a hash alone is not removal approval.
- Include existing KVRT/ESET/Malwarebytes scanner workflows automatically. Downloads/installations are authorized as part of this workflow; vendor interfaces may still require attended operation. Do not add scanner auto-clean switches.
- Keep existing antivirus installed. Never invoke the third-party AV uninstall stage or its leftover quarantine sweep.
- Automatically share only the existing sanitized report to the existing configured MicroBin service. Never upload raw findings, logs, configuration, screenshots or binaries; do not invent/change the destination or bundle live credentials.
- Build a one-time administrator-installed component with an independently verified integrity manifest. Everyday WPF stays non-admin. No code-signing identity or certificate is assumed.

## Protected installation policy

Use an externally supplied expected manifest digest verified through a separate trusted delivery channel. An adjacent manifest/digest or user-writable payload cannot establish its own trust. The admin installer verifies the expected digest, every allowlisted payload member, fixed relative paths and versions before any installation write. Reject reparse points and ordinary-user write/delete/ownership rights on every relevant parent, code and protected-state object. Use actual Windows effective-access evidence, not an injectable callback assertion presented as production trust. Implementation must not depend on a fabricated publisher/certificate.

Installation authorization is not authorization for the agents to install or remove software on this host. Agents exercise synthetic tests and hosted Windows CI; owner performs actual Windows installation/UAC/removal acceptance. Do not provision a VM or run the live detector/remover/scanners.

## Workflow defaults

- Preflight/rollback: collect genuine rollback evidence, fresh protected before-snapshot and findings. Stop on unavailable or uncertain prerequisites; no restore-point waiver or UAC-disabled force bypass.
- Refuse unsupported server execution rather than silently forcing it.
- Protected approval binds host, outer and nested detector run identities, exact findings/snapshot bytes, verified rollback evidence and code provenance. Consume a one-use protected binding atomically after final revalidation.
- Decline/close/UAC cancellation must cause zero removal calls. Continue only the already-authorized non-removal workflow; report removal as declined/skipped, not successful cleanup.
- Scanners can be attended; launching or exiting one is not proof of a clean scan. Missing/unparseable scanner output remains unknown/incomplete.
- AV uninstall and Procmon live capture stay disabled. No automatic reboot. Display reboot-pending outcomes and require owner action; no untrusted automatic resume.
- After snapshot/diff/local report/sanitized sharing follow the accepted policy. Share failures remain explicit and do not erase local output.

## Existing state and missing work

Last shipped read-only prototype: v0.2.0, commit 5fdf3dcef7995869953ce45062581830e4ec6e45. Full GUI cleanup is NOT available. The adapter stops FullInvestigation at NeedsAction before removal. Untracked ProtectedEvidence/ProtectedPathPolicy/ProtectedRollbackProof and Phase4/5 tests are pre-existing unverified WIP, not a protected host, installer or approval system.

Audits: sc-gui-full-protected-readiness.md and sc-gui-full-orchestration-readiness.md under the current Hermes scratch workspace. Their findings are source evidence, not executed Windows proof. Preserve unrelated openspec/tasks and Phase4/5 WIP; stage only specifically reviewed paths.

## Dependency order

1. Reconcile and test the existing pure-validator findings; implement strict manifest/integrity validation as a separate file-disjoint foundation.
2. Verify those foundations independently and on Windows PowerShell 5.1/7. Do not expose cleanup yet.
3. Implement actual protected installation/ACL verification, transaction store and fresh evidence/rollback producers.
4. Implement protected one-confirmation host and atomic binding consume; test forged/stale/replayed/modified/parallel/crash refusal with zero fake-remover calls.
5. Integrate full fixed stage orchestration and concise GUI with the protected host. Preserve CLI defaults. Package only after all prerequisites are real.
6. Exercise synthetic Windows process, ACL, installer refusal, state/recovery, scanner/report contract and extracted-package UI proof on the exact commit. No destructive CI or live installation.
7. Independent security review, immutable ZIP/manifest/sidecar inspection, GitHub and public byte verification; clearly state owner-only installation/UAC/rollback/removal/reboot acceptance still pending.

No full-cleanup release, automatic live side effect, merge, production approval or destructive acceptance is implied by passing a foundation card.

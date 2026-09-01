# Independent Security, Architecture & Correctness Audit
## ScreenConnect Cleaner — `gui-revision-screenconnect-cleaner` rebuild

- **Audit date:** 2026-08-27
- **Auditor:** Independent static audit (read-only; no GUI or removal executed)
- **Scope:** `src/Scc.*`, `Scc.Cleaner.ps1`, `build/*.ps1`, `tests/`, `docs/`, `config/`
- **Method:** `pwsh 7.6.5` static inspection, targeted `grep`/file reads, line-level citation. No source modified.

---

## Executive Summary

**Headline: No Critical safety violation enabling unintended removal was found.** All five safety invariants hold in the sense that *no destructive action is reachable from any shipped entry point* (GUI or headless). `Invoke-SccRemediation` requires an explicit `-Execute` switch; neither the GUI (`Scc.UI.psm1` stage 4) nor the headless entry point (`Scc.Cleaner.ps1`) ever passes it, and there is no `-ExecuteRemoval` parameter exposed. The remediation engine itself is well-constructed: it is fail-closed (per-item re-verification, admin gate, ScreenConnect-only restriction, quarantine-never-delete, and a path-traversal guard on restore).

However, the audit surfaced **two High-severity issues and several Medium/Low cohesion/correctness defects** that must be addressed before the tool can be shipped as a *functional* "Cleaner":

1. **The GUI cannot perform remediation and has no implemented confirmation gate.** The approval/execute buttons live in `Findings.xaml` / `RemediationPreview.xaml`, which `Start-SccApp` never loads or wires. This is currently *fail-safe* (nothing runs) but is a **latent Critical**: the moment someone enables removal by passing `-Execute`, there is no confirmation dialog to satisfy safety invariant #2.
2. **Detection is fail-open.** The ScreenConnect/remote-access inventory functions silently swallow CIM/registry/event-log errors and return empty collections. A failed query therefore produces a false "clean" result with no log entry — the worst failure mode for a detection tool.

Severity counts: **Critical 0 / High 2 / Medium 3 / Low 3 / Info 2.**

---

## Severity-rated findings (summary)

| ID | Sev | Area | Title |
|----|-----|------|-------|
| SCC-001 | High | A / C | Remediation unreachable from GUI & headless; no GUI confirmation gate implemented (latent Critical when `-Execute` is later enabled) |
| SCC-002 | High | E | Detection inventory silently swallows errors and returns empty (fail-open false-negative) |
| SCC-003 | Medium | C | GUI progress/status dead: `$script:ActiveJob` never assigned; job never cleared from `$script:Jobs` (no feedback; second run throws) |
| SCC-004 | Medium | B | Relay trust-bypass via relay-name spoofing (empty default fingerprint skips fingerprint check) |
| SCC-005 | Medium | F | Scanners config handling fragile: `.ContainsKey()`/`['scanners']` on `PSCustomObject`; default name mismatch (`Defender` vs `MicrosoftDefender`) |
| SCC-006 | Low | F | Duplicated helper functions across modules (admin check, SHA256, file facts) |
| SCC-007 | Low | F | `Report.psm1` is a 1604-line single-function god-module |
| SCC-008 | Low | A / D | Self-elevation forwards unbound args verbatim and rebuilds arg list by string join |
| SCC-009 | Info | B | Param-blob parsing is read-only; values never reach a shell → no command-injection vector (positive context) |
| SCC-010 | Info | A | Invariants #3/#4/#5 verified intact (positive context) |

---

## A. Safety invariants

**Invariant 1 — Default detect-only / read-only; removal opt-in.**
HOLDS. `Invoke-SccRemediation` (`Scc.Remedy.psm1:884-904`) returns a dry-run preview unless `-Execute` is present. The GUI stage 4 (`Scc.UI.psm1:233`) calls `Invoke-SccBackendRemediation` **without** `-Execute`. The headless entry point (`Scc.Cleaner.ps1:11-22`) exposes no `-ExecuteRemoval` switch and never passes `-Execute`. Removal is therefore unreachable from both front-ends. See SCC-001 for the latent risk of this being "fixed" without a confirmation gate.

**Invariant 2 — No destructive action without explicit GUI confirmation.**
HOLDS *vacuously today* (no destructive action runs in the GUI). The intended confirmation UI — `BtnApprovePlan` (`Findings.xaml:44`) and `BtnExecuteRemediation` (`RemediationPreview.xaml:29`) — is **never loaded or wired** by `Start-SccApp`, which only loads `Dashboard.xaml` (`Scc.UI.psm1:672`). There is no confirmation gate in code. This is SCC-001.

**Invariant 3 — Fail-closed on uncertainty.**
HOLDS. `Invoke-SccRemediation` enforces: admin gate (`Scc.Remedy.psm1:908`), ScreenConnect-only (`930-933`), per-item re-verification against live system (`Test-SccScreenConnectTarget`, `935-941`), quarantine-never-delete (`Move-SccTargetToQuarantine`), and a traversal/target-scope guard on restore (`Test-SccRestorePathSafe`, `989-1010`). `Clear-SccQuarantine` requires both `-Approved` and the literal `"PERMANENTLY DELETE"` (`1050-1068`). All destructive primitives record `Failed` on exception and continue — no abort, no silent success.

**Invariant 4 — No off-box transmission without consent.**
HOLDS. No `Invoke-WebRequest`/`Send-MailMessage`/SMTP/webhook exists in Detection, Evidence, Remedy, Report, or Scanners. The only network egress is (a) `Test-SccInternet` HEAD probe in `Scc.Core.psm1:858` and (b) documented, opt-in tool downloads in `Scc.Tools.psm1`. Reports are written locally. See SCC-010.

**Invariant 5 — Evidence collection is copy-only.**
HOLDS. `New-SccSnapshot` (`Scc.Evidence.psm1:775-940`) only reads (CIM, registry, filesystem); it writes only its own output JSON, not the system under investigation. Quarantine *moves* live in Remedy, not Evidence. See SCC-010.

---

## B. Command injection / parameter spoofing

**B1 — Relay trust-bypass (SCC-004, Medium).** `Test-SccTrustedRelay` (`Scc.Detection.psm1:881-912`) compares the attacker-supplied `RelayHost` against trusted relays. When the trusted entry's `fingerprint` is empty/missing (the **embedded default** `Scc.Core.psm1:94-105` and `config/trusted-relays.json` ship `fingerprint:""`), the fingerprint comparison is skipped and a name match alone yields `TrustMatch = 'Known'`. An attacker who points a rogue client at a hostname matching a "trusted" entry (e.g. `support.example.com`) would be classified as an authorized relay. This does **not** evade removal (any ScreenConnect instance is still remediated) but creates a false sense of safety in the report. Recommendation: require a non-empty fingerprint for `Known` verdicts; treat empty-fingerprint entries as "name-only hint, not trusted."

**B2 — `h=`/`k=` parameter values (SCC-009, Info).** `Find-ScParamBlob` / `ConvertFrom-ScParamBlob` (`Scc.Detection.psm1:174-222`) parse the launch-parameter blob and percent-decode values with `[Uri]::UnescapeDataString`. These values are used only for *trust matching and reporting* — they are never concatenated into a shell command or passed to a process. Consequently there is **no command-injection vector** from a malicious `h=`/`k=` value. The blob regex (`Scc.Detection.psm1:117`) excludes spaces, quotes, `<`, `>`, `)`, `&`, which limits both injection and legitimate-value fidelity (a relay containing those characters is truncated) but is not exploitable.

**B3 — Scanner `ScanPath` (Info).** Defender/KVRT/MSERT adapters interpolate `ScanPath` into an argument array consumed via `ProcessStartInfo.Arguments` (`Scc.Scanners.psm1:604-611, 775-779, 952-953`). `ProcessStartInfo` does not invoke a shell, so quoting/`"` in `ScanPath` cannot inject. In the current code `ScanPath` is never supplied from external/GUI input (only system-root or empty), so exploitability is nil. Retain array-based invocation; do not switch to `cmd.exe /c`.

---

## C. GUI threading / runspace safety

**C1 — Dead progress/status + concurrency lockup (SCC-003, Medium).** `Start-SccJob` returns a light handle, but the three dashboard click handlers **discard** it (`$null = Start-SccJob ...`, `Scc.UI.psm1:686, 693, 700`). The module-level `$script:ActiveJob` (`Scc.UI.psm1:28`) is **never assigned** (the prior shipped build `build/output/.../Scc.UI.psm1:515` did `$script:ActiveJob = $handle`). The `DispatcherTimer` tick (`Scc.UI.psm1:708-711`) polls `Update-SccJob -Handle $script:ActiveJob`, which is therefore a permanent no-op → the operator receives **no progress/state feedback** while the workflow runs in the background. Compounding this, the runspace remains in `$script:Jobs` forever (only `Reset-SccJob` clears it, and nothing calls it), so a **second** button click throws `"Only one concurrent Scc job is allowed"` (`Scc.UI.psm1:475-478`). Regression vs. the 0.1.0-final build.

**C2 — No cross-thread control access observed.** The click handlers create the workflow and start the job but do not directly mutate WPF controls from the background runspace; the (intended) update path is the timer → handle object, not controls. So no `InvalidOperationException` cross-thread crash was found. The defect is the *dead* update path (C1), not a race.

**C3 — Evidence runspace race (resolved).** `Scc.Evidence.psm1` previously used a runspace pool but reverted to inline collection (`Invoke-SectionParallel`, `753-769`) because module-internal functions are invisible inside a separate runspace. `$script:CollectionErrors` is reset per `New-SccSnapshot` and guarded by `[System.Threading.Monitor]` in `Add-CollectionError` (`26-45`); since collection is now single-threaded, the lock is defensive and harmless. No live race.

---

## D. Privilege / elevation

**D1 — Self-elevation (SCC-008, Low).** `Scc.Cleaner.ps1:45-80` relaunches itself with `-Verb RunAs` when not admin, guarded by an `SCC_ELEVATED` env marker to prevent a relaunch loop. The rebuilt argument list string-joins tokens and wraps the script path and a few values in quotes (`53-65`), but forwards `$MyInvocation.UnboundArguments` **verbatim** (`63-65`). If a wrapper `.bat` passed unusual tokens they would be appended unquoted; low practical risk but should be reviewed.

**D2 — Remediation privileged writes.** `Get-SccPaths` resolves `QuarantineRoot` under `%ProgramData%\ScreenConnectCleaner` and Remedy deletes HKLM run-keys / services — all privileged, but only under `-Execute` + admin gate + re-verification. Acceptable.

**D3 — `Test-SccIsAdmin` on non-Windows returns `$true`** (`Scc.Remedy.psm1:874-882`), intentionally so tests can run on Linux; removal is still gated by re-verification and the other checks. Acceptable.

---

## E. Error handling / fail-open

**E1 — Detection is fail-open (SCC-002, High).** The inventory functions return empty on any exception with **no logging**:
- `Get-SccServiceInventory` — `Scc.Detection.psm1:265-272` (`catch { return @() }`)
- `Get-SccProcessInventory` — `:273-281`
- `Get-SccUninstallInventory` — `:282-313` (inner `catch { }` and outer `catch { }`)
- `Get-SccServiceInstallEvents` — `:315-331` (`catch { return @() }`)
- `Get-SccConnectionsForPids` — `:333-350` (`catch { return @() }`)

If WMI is corrupted, the registry is inaccessible, or the event log query fails (all realistic on a compromised/triaged host), detection reports **no instances** and the operator sees a clean bill of health. This is the most dangerous failure mode for a triage tool and must be made fail-closed: surface the error (log + findings `Warnings`/`ParseIssue`) and never silently downgrade to "clean." Contrast with `Scc.Evidence.psm1`, which correctly records every section error into `CollectionErrors` and re-throws to `Invoke-Section`.

**E2 — Remediation is fail-closed (positive).** Every destructive primitive in `Scc.Remedy.psm1` records a `Failed`/`Skipped` action and continues; the workflow stage is marked `Failed` but the run continues (`Scc.UI.psm1:377-381`). No destructive step reports success on exception.

---

## F. Architecture cohesion

**F1 — No API leakage (positive).** Every module `.psd1` uses an explicit `FunctionsToExport` list (no `'*'` wildcard). Private helpers (e.g. `Get-Prop`, `Write-SccRemedyLog`, `Apply-ScParameters`, `Invoke-Section`) are correctly unexported. Good encapsulation.

**F2 — Fragile scanner config (SCC-005, Medium).** `Get-SccScannerList` does `$Config.ContainsKey('scanners')` (`Scc.Scanners.psm1:322`) and `Invoke-SccScanner` indexes `$config['scanners']` (`:388-396`). `Get-SccConfig` returns a `PSCustomObject`, which has **no** `.ContainsKey` method and does not support `['key']` indexing → these paths throw if a real config object is passed. Additionally, the Core default config lists `"enabled": ["Defender", "KVRT", "MSERT"]` (`Scc.Core.psm1:61-64`) while the scanners module's authoritative names are `MicrosoftDefender`/`KVRT`/`MSERT` (`Scc.Scanners.psm1:25-29, 327-329`); a full config merge would therefore disable every scanner. Fix: normalize scanner names and use `PSObject.Properties.Name -contains` / member access.

**F3 — Duplicated helpers (SCC-006, Low).** Three admin checks (`Test-SccAdmin` `Scc.Core.psm1:461`, `Test-SccIsAdmin` `Scc.Remedy.psm1:874`, `Test-IsAdmin` `Scc.Evidence.psm1:111`); two SHA256 helpers (`Get-Sha256Hex` `Scc.Detection.psm1:123`, `Get-SccSha256Hex` `Scc.Remedy.psm1:73`); two file-fact collectors (`Get-FileFacts` `Scc.Detection.psm1:233`, `Get-SccFileFacts` `Scc.Core.psm1:524`). Consolidate into `Scc.Core`.

**F4 — God module (SCC-007, Low).** `Scc.Report.psm1` is 1604 lines exposing a single `New-SccReport` function. Consider splitting per-section builders (exec-summary, SC findings, scanners, persistence, provenance) for maintainability and testability.

---

## G. Test coverage gaps

- **Removal paths:** Strong. `Scc.Remedy.Tests.ps1` (26 `It`) covers dry-run, poisoning, re-verification (F1), uninstaller validation (F2), restore traversal (F3), process-kill self-protection (F5), admin gate (F6), quarantine reboot-resume (F7).
- **Scanner process spawning:** Strong. `Scc.Scanners.Tests.ps1` (43 `It`) covers adapters, timeout, failure-is-non-fatal, result shape.
- **Relay trust:** Partial. `Scc.Detection.Tests.ps1:318-346` covers happy-path + one evil relay, but **does not test the empty-fingerprint spoofing** described in SCC-004.
- **Detection fail-open (SCC-002):** **Not covered.** No test asserts that an inventory error is surfaced/logged rather than silently yielding an empty result. This gap let the High finding ship.
- **GUI runspace/ActiveJob (SCC-003):** `Scc.UI.Tests.ps1` tests `Start-SccJob` in isolation but **does not assert `$script:ActiveJob` is assigned** or that the timer would poll, so the dead-status bug is invisible to CI. GUI button wiring cannot be tested on Linux.
- **Headless `-PlanPath` end-to-end:** `Scc.Cleaner.ps1` headless path is exercised by `Headless-Smoke.Tests.ps1` (9 `It`), but only the dry-run/awaiting-review outcome is validated (consistent with removal being unreachable — see SCC-001).

---

## Prioritized remediation checklist

1. **[High / SCC-001]** Before enabling any `-Execute` path, implement and wire the GUI confirmation gate: load `Findings.xaml` + `RemediationPreview.xaml`, bind `BtnApprovePlan`/`BtnExecuteRemediation`, and have the execute handler pass `-Execute` *only after* an explicit modal confirm. Add a unit/integration test that proves removal cannot run without the confirm dialog.
2. **[High / SCC-002]** Make detection fail-closed: in `Get-SccServiceInventory`/`Get-SccProcessInventory`/`Get-SccUninstallInventory`/`Get-SccServiceInstallEvents`/`Get-SccConnectionsForPids`, on exception record the error (log + add to `Invoke-SccDetection` `Warnings`) instead of returning `@()`. Add a test that an injected CIM failure surfaces as a warning, not a clean result.
3. **[Medium / SCC-003]** Assign `$script:ActiveJob = $handle` in `Start-SccApp` (or pass the handle into the timer closure) and call `Reset-SccJob` when a run completes/fails so the DispatcherTimer polls real state and a second run is possible. Restore parity with the 0.1.0-final build.
4. **[Medium / SCC-004]** Require a non-empty `fingerprint` for a `Known` trust verdict; treat empty-fingerprint trusted entries as name-only hints. Add a regression test for relay-name spoofing.
5. **[Medium / SCC-005]** Fix scanner config handling: use `PSObject.Properties` checks and member access instead of `.ContainsKey()`/`['key']`; reconcile scanner names between `Scc.Core` default config and `Scc.Scanners` (`Defender` → `MicrosoftDefender`).
6. **[Low / SCC-006, SCC-007]** Consolidate duplicated helpers into `Scc.Core`; split `Scc.Report.psm1` into per-section builders.
7. **[Low / SCC-008]** Quote/validate forwarded unbound arguments in the self-elevation relaunch.

---

*Audit performed read-only. No source files were modified; all findings cite the actual code at the line references given.*

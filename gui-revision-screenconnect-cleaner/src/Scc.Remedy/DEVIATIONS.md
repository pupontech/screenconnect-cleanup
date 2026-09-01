# Scc.Remedy - DEVIATIONS.md

Module: Scc.Remedy (remediation engine, highest safety bar).
Branch: gui-revision-screenconnect-cleaner.
Ported from: remove-screenconnect.ps1, Invoke-ReviewAndRemove.ps1, AUDIT-03-removal.md.

This file records deliberate decisions and divergences from the legacy engine
that could not be encoded in code comments alone, plus notes for the live
Windows test owner. Everything here is ASCII, no BOM, no emoji.

## D1. Quarantine root on Linux (test harness) resolves to RunDir/Quarantine
The contract (ARCHITECTURE.md sec. 5 / Scc.Core Get-SccPaths) places the
quarantine root at %ProgramData%\ScreenConnectCleaner\Quarantine\<runid>. On a
Linux test host there is no real ProgramData, and Scc.Core's resolved path
(even when present) is a fake/throwaway directory the test helpers do not read.
Get-SccRemedyQuarantineRoot now uses a PLATFORM check (not a '%' string
heuristic) to fall back to RunDir\Quarantine on non-Windows. The Windows path
is resolved from Scc.Core Get-SccPaths when available. On Windows, the '%'
fallback is still present as a secondary guard for misconfigured hosts. The
Pester helpers and tests expect the manifest at
<RunDir>/Quarantine/quarantine-manifest.json.

## D2. ACL hardening: Windows vs Linux
Contract 3.7 requires ACL hardening on the quarantined artifact. Implemented as
two paths inside Move-SccTargetToQuarantine:
  - Windows: icacls.exe <path> /inheritance:r /grant:r SYSTEM:(F)
    Administrators:(F) /remove:g *S-1-1-0  (SYSTEM + Admins full, Users removed)
  - Linux (best effort): chmod 700 <path>, logged as a note.
Windows-only behavior is isolated in a try/catch and degrades to a recorded
note; tests run on Linux and assert the file MOVED correctly, not the ACL.

## D3. Re-verification: AND-of-gates (restored from legacy, F1 fix)
Test-SccScreenConnectTarget now uses AND-of-gates: every identity field present
in the plan item (ServiceName, InstallDir, MainExe) must independently verify
against the live system. The service must exist and its name must start with
'ScreenConnect*'; the install dir must exist on disk and its path must contain
'\ScreenConnect'; the main exe must exist on disk under the verified install
dir. If none of the three fields is present, verification fails closed. This
matches legacy remove-screenconnect.ps1 Gates A/B/C and prevents a
value-poisoned plan from targeting arbitrary services or files.

## D4. Vendor uninstaller execution: validated + no arguments (F2 fix)
Legacy Run-VendorUninstaller validated non-MSI executables: leaf matched an
allowlist (ScreenConnect|App_|unins*.exe), resided under the verified install
dir, and existed on disk; otherwise it refused and fell back to manual surgery.
Scc.Remedy now restores this validation via Test-SccUninstallExeValid before
execution. Non-MSI uninstallers run with NO arguments (legacy behavior; the
full registry string is logged but NOT executed). The msiexec /x {ProductCode}
/qn /norestart fallback is retained for MSI-based uninstalls.

## D5. Plan smuggling is structurally impossible to actuate
Any plan item whose Action=REMOVE but Product != 'screenconnect' is skipped with
a recorded "non-ScreenConnect product refused" action (both in Invoke-SccRemediation
directly and in Test-SccScreenConnectTarget re-verification). A poisoned plan
file (e.g. an AnyDesk REMOVE item) therefore performs ZERO destructive calls -
asserted by the smuggling Pester test (0 invocations of every destructive mock).

## D6. Reboot-resume (resume-marker.json) partial port (F7 fix)
Move-SccTargetToQuarantine now handles in-use file failures by recording a
resume-marker.json (phase: quarantine-pending) and writing a PendingReboot
manifest entry. On Linux this is a best-effort record; on Windows the legacy
full RunOnce + MoveFileEx path would be added as a follow-up. The resume-marker
is sufficient for the headless CI workflow and is testable on Linux.

## D7. Export-before-delete not applied to Run keys / scheduled tasks
Legacy quarantined an orphaned uninstall registry key only after exporting it
via reg.exe export (export-first, fail-safe). Scc.Remedy's leftover cleanup
deletes scheduled tasks (Unregister-ScheduledTask), Run-key values
(Remove-ItemProperty), firewall rules (Remove-NetFirewallRule) and the
service registration (sc.exe delete) WITHOUT a pre-deletion export. Per
AUDIT-03 sec. 5.4 these are system-generated artifacts, not forensic evidence,
and the risk is rated Low; the contract 3.7 lists them as plain cleanup steps
without an export requirement. remediation.json records every action for audit.

## D8. Firewall rule removal ADDED (was missing in legacy)
ARCHITECTURE.md sec. 3.7 requires "firewall rule removal" in the cleanup step.
AUDIT-03 sec. 2.3 notes the legacy engine never implemented it. Scc.Remedy adds
Remove-SccTargetFirewallRule (Get-NetFirewallRule +
Get-NetFirewallApplicationFilter + Remove-NetFirewallRule) so the cleanup step
matches the contract. It degrades safely on Linux (cmdlet absent -> Skipped).

## D9. Single-element array discipline
All arrays are forced through @(...) context before .Count, and the automatic
$matches variable is never used as a user variable (regex Match().Groups is used
instead). Conforms to house rule 4.

## D10. Module is importable standalone
Scc.Remedy soft-imports Scc.Core from the sibling module directory if
Write-SccLog is not already available, so the parse/import gates and unit tests
pass on a bare Linux pwsh without a pre-seeded PSModulePath. On a Windows host
the real Scc.Core (with Write-SccLog structured logging) is used instead.

## D11. Admin gate (F6 fix)
Invoke-SccRemediation checks Test-SccIsAdmin before any -Execute mutation. On
Windows, this verifies the caller is elevated (mirrors legacy remove-
screenconnect.ps1:80-87). On non-Windows, the check is gated on $env:OS so it
always returns $true and tests pass. The check is a fail-closed guard: if the
admin status cannot be determined, it returns $false and the mutation is
refused.

## D12. Path traversal guard on restore (F3 fix)
Restore-SccQuarantineItem validates the manifest OriginalPath before restoring:
it must be absolute, must not contain '..' components, must resolve to the same
path after canonicalization, and must not be inside the quarantine root. This
prevents a tampered manifest from restoring files to arbitrary system locations.

## D13. Ancestor-PID self-protection (F5 fix)
Stop-SccTargetProcesses builds an ancestor PID chain (up to 12 generations)
and refuses to kill any PID in that chain. This matches legacy
remove-screenconnect.ps1:815-834 and prevents the tool from terminating its
own host process mid-remediation.

## D14. Directory quarantine with reparse-point skip (F7 fix)
When quarantining a directory, Move-SccTargetToQuarantine hashes each file
individually (the legacy per-file CSV approach) and skips reparse points
(junctions/symlinks) to prevent following attacker-planted junctions. The
hash summary is recorded in the manifest SHA256 field.

## D15. F8/F9: Scope reduction decisions
- F8 (orphaned uninstall key export): Not implemented. These are system-
  generated artifacts, not forensic evidence. remediation.json provides a
  complete audit trail. Live Windows test owner may add as follow-up if
  needed.
- F9 (Scc.Core soft-dependency exposure): Not a defect. Scc.Core functions
  are module-private; callers needing them should import Scc.Core separately.
  Documented here for awareness.

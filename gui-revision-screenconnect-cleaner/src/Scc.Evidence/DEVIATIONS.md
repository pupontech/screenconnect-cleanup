# DEVIATIONS.md - Scc.Evidence + Scc.Snapshots

## Deviations from ARCHITECTURE.md

1. **Concurrency on Linux**: ARCHITECTURE.md section 3.3 specifies "independent
   sections may collect via runspaces (max 4)". On Linux (our test environment),
   runspaces are available but WMI/CIM cmdlets that the collectors call are not.
   The module detects non-Windows via `Test-IsWindows` (checks `$IsWindows` on
   PS7 or `$env:OS -eq 'Windows_NT'` on PS5.1) and runs sections inline on
   non-Windows. On Windows, sections run via a runspace pool capped at 4.

2. **ScInstallations section**: The contract requires importing Scc.Detection to
   populate this section. Since Scc.Detection is not yet implemented, the section
   gracefully returns an empty array and records no error when the module is not
   importable. This matches the contract's "try import, skip section on failure"
   behavior.

3. **RecentFiles budget**: The legacy collect-snapshot.ps1 has extensive budget
   controls (MaxDirs=40000, TimeBudgetSeconds=120, CapCount=500, skipDirNames).
   These are preserved exactly in the port. On Linux the section produces no
   results since the environment variables (TEMP, WINDIR, APPDATA, etc.) are
   typically absent or irrelevant.

4. **Schema v2 additions**: The contract adds SccAppVersion and ScInstallations
   to the legacy schema v2. SccAppVersion is populated from the module's
   Version property if available, empty string otherwise. ScInstallations is
   populated from Scc.Detection if importable.

5. **Run object shape**: The modules accept either a string path or a PSCustomObject
   with a RunDir property. The full Run object from Scc.Core (with RunId, RunDir,
   subdirectory creation, etc.) is not yet available, so modules are lenient in
   their input validation. When Scc.Core is implemented, New-SccSnapshot should
   use Run.RunDir to locate the snapshots directory.

6. **Diff field comparison**: The contract specifies Changed entries should record
   Field, Before, After. The implementation records Field names only (matching the
   legacy diff-snapshots.ps1 behavior). Recording Before/After values for each
   changed field would require storing the full before/after items in the diff,
   which the legacy code does not do. This is a minor deviation noted for future
   enhancement.

7. **Test-SccResurrection patterns**: The resurrection detector uses the pattern
   list from the ARCHITECTURE.md contract plus patterns observed in the legacy
   code (AnyDesk, TeamViewer, etc.). The list is maintained as a private array
   within the function.

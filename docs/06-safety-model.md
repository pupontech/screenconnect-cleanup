# Safety model and coding conventions

The tool must never operate as a blind "delete anything suspicious" script. These are the
rules that prevent that.

---

## Safety rules

### 1. Stage 1 runs first and cannot be skipped
Snapshot before you touch. It is also what makes the Stage 7 diff possible, so it pays
for itself twice.

### 2. Stage 3 is a hard approval gate
Nothing is removed without a technician seeing the finding and its evidence. **There is
no unattended removal mode, and no flag that detects and removes in one step.** This is
the single rule that separates this tool from a destructive script.

When Stage 4 is built, it must consume an **approved plan file** produced by Stage 3 —
the destructive code should not be reachable without that artifact existing.

### 3. Quarantine, never delete
Move to an ACL-locked quarantine folder, preserve the original path, record the SHA-256.
Deletion is a separate, later, explicitly-invoked operation. Costs nothing, covers the
one time we are wrong.

### 4. Restore point + registry export before the first change
Default on, `-np` to skip. **Check System Restore is actually enabled** — it frequently
is not, and a silently-failed restore point is worse than none.

### 5. Uninstall before surgery
Always run the vendor's own uninstaller (from the registry `UninstallString` /
`QuietUninstallString`, or `msiexec /x {ProductCode} /qn`) before touching services or
directories manually. Manual removal is the fallback, not the default.

### 6. Do not clean temp before you look at it
The scammer's installer in `%TEMP%` is often the best provenance evidence on the machine.
There is no temp-cleanup stage, deliberately. Do not add one.

### 7. Do not clear event logs
Event ID 7045 survives uninstall and is one of the best sources available.

### 8. Server OS refuses by default
Detect the OS role in preflight and refuse unless `-force`.

### 9. Scanner failure is non-fatal AND reported as failure
Never silently swallowed into a "clean" verdict. A skipped or failed scanner must appear
as such in the report.

### 10. The report must say what it did NOT check
If `-sa` skipped the scanners, the report says "scanners skipped" — never "no malware
found."

### 11. Verification re-collects
Post-remediation verification must read the system fresh (ideally after reboot), not
consult the actor's own record of what it thinks it did.

### 12. Removal is not remediation
If a scammer had an interactive session, the exposure is credentials, browser session
cookies, saved passwords, mail-forwarding rules, and new accounts. The report must end
with a **credential-reset checklist**. Stage 1 already collects most of what it needs.
This is a report section, not a module — keep it proportionate, but do not omit it.

---

## Coding conventions

### PowerShell 5.1 compatible — mandatory

The tool runs on client machines as-found. Windows PowerShell 5.1 is the baseline.

**Forbidden (PowerShell 7 only):**
- ternary `? :`
- null-coalescing `??`, null-conditional `?.`
- `&&` / `||` pipeline chain operators
- `ConvertFrom-Json -AsHashtable`

**Known PS 5.1 traps that have already caused real bugs here:**

- **Single-element arrays are unwrapped.** `.Count` on a one-item result returns `$null`,
  not `1`. Always force array context: `@($x).Count`. This produced a silent
  wrong-answer bug in the detector — see `04`.
- **`powershell.exe -File` does not parse arrays.** `-Target a,b` arrives as one string.
  Split defensively inside the script.
- **`ConvertFrom-Json` returns PSCustomObject**, not a hashtable.
- **`-replace` inside a hashtable literal** needs parentheses, or the comma before the
  replacement is parsed as a hashtable separator. This caused a parse error here.
- **`$matches` is an automatic variable.** Never use it as your own variable name.

### Pure ASCII, no BOM — mandatory

PowerShell 5.1 reads a BOM-less non-ASCII file as Windows-1252. No emoji, no smart
quotes, no box-drawing characters, no accented characters in any `.ps1`. Same rule as
`provisioning/` in this repo.

(Output *files* the scripts write may be UTF-8. The rule is about the source.)

### Verification — run it, do not reason about it

Every `.ps1` must pass both checks before being called done:

```powershell
$p='.\detect-remote-access.ps1'; $e=$null; $t=$null
[System.Management.Automation.Language.Parser]::ParseFile($p,[ref]$t,[ref]$e) | Out-Null
if ($e.Count -eq 0) { 'PARSE OK' } else { $e | ForEach-Object { "$($_.Extent.StartLineNumber): $($_.Message)" } }
```

```
py -c "import io;b=io.open('detect-remote-access.ps1','rb').read();print(sum(1 for c in b if c>127))"
```

The second must print `0`.

**Both bugs found in the detector parse cleanly and look correct on inspection.** Passing
the parse check is necessary, not sufficient — the script must actually be executed.

### Other conventions

- `.bat` launcher alongside each `.ps1`, with CRLF line endings, matching
  `remote-diagnostics/`. Pattern:
  `powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0<script>.ps1" %*`
- Output folder per run, zipped to the Desktop.
- Read-only scripts must be genuinely read-only: no `Set-`, `Stop-`, `Remove-`, `Start-`
  against system state.
- Every collector section wrapped so a failure is recorded and collection continues. One
  inaccessible section must never abort a run.
- Standalone-capable: a single copied `.ps1` must work with no other files present
  (decision D6). Embed defaults; treat config files as optional overrides.

### A note on writing these files with tooling

Bash heredocs in this environment **collapse double backslashes**, which corrupts Windows
paths and JSON escaping. Write `.ps1` and `.json` files with a dedicated file-writing
tool, or generate them via Python. This bit twice during the build.

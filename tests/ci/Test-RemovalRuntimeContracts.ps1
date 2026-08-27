# =====================================================================
# Test-RemovalRuntimeContracts.ps1 -- contract tests for Stage 4
# bounded, deadlock-safe uninstaller execution.
#
# Source/AST-contract checks only. No vendor executable is launched,
# no production cleanup control flow is executed, and nothing on the
# host is modified. A test that needs live process behavior uses an
# independently written harmless synthetic child (never production
# functions).
#
# Exit codes: 0 = all contracts pass, 1 = contract violations found.
# PowerShell 5.1 compatible. Pure ASCII, no BOM.
# =====================================================================
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$scriptPath = Join-Path $repoRoot 'remove-screenconnect.ps1'

$script:failedTests = 0
$script:passedTests = 0

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if ($Condition) {
        $script:passedTests++
        Write-Host "PASS: $Message" -ForegroundColor Green
        return
    }
    $script:failedTests++
    Write-Host "FAIL: $Message" -ForegroundColor Red
    return
}

Write-Host "=== Running Removal Runtime Contract Tests ==="
Write-Host ""

$scriptContent = Get-Content -LiteralPath $scriptPath -Raw

# ---------------------------------------------------------------------------
# TEST 1: Run-BoundedProcess function exists in source
# ---------------------------------------------------------------------------
Write-Host "--- Test 1: Run-BoundedProcess function exists in source ---"
if ($scriptContent -match '(?m)^function\s+Run-BoundedProcess\s*\{') {
    Assert-True $true "Run-BoundedProcess function exists in source"
    $funcMatch = [regex]::Match($scriptContent, '(?ms)^function\s+Run-BoundedProcess\s*\{.*?^\}')
} else {
    Assert-True $false "Run-BoundedProcess function exists in source (RED expected before implementation)"
}

# ---------------------------------------------------------------------------
# TEST 2: concurrent drain via ReadToEndAsync BEFORE the bounded wait
# ---------------------------------------------------------------------------
Write-Host "--- Test 2: ReadToEndAsync used for concurrent stream drain ---"
if ($funcMatch.Success) {
    $funcDef = $funcMatch.Value
    Assert-True ($funcDef -match 'ReadToEndAsync\(\)') "Uses ReadToEndAsync for both redirected streams"
    Assert-True ($funcDef -match 'ReadToEndAsync\(\)[\s\S]*ReadToEndAsync\(\)') "Both stdout and stderr tasks are started"
    Assert-True ($funcDef -match 'WaitForExit\(\$TimeoutMs\)') "Calls bounded WaitForExit after starting tasks"
    Assert-True ($funcDef -match '\.Kill\(\)') "Calls Kill on timeout"
    Assert-True ($funcDef -match 'WaitForExit\(1000\)') "Reaps the process after Kill with a bounded wait"
    Assert-True ($funcDef -match '\[System\.Threading\.Tasks\.Task\[\]\]@\(') "Casts stream tasks to Task[] for WaitAll overload resolution"
    Assert-True ($funcDef -match '\[System\.Threading\.Tasks\.Task\]::WaitAll\(') "Uses bounded Task.WaitAll for post-termination drain"
    Assert-True ($funcDef -match 'ReapFailed') "Carries an explicit reap-failure diagnostic"
    Assert-True ($funcDef -match 'finally') "Disposes the process in a finally block"
    Assert-True ($funcDef -notmatch 'StandardOutput\.ReadToEnd\(\)') "Does not use blocking synchronous ReadToEnd"
    Assert-True ($funcDef -notmatch 'HasExited') "Does not use HasExited polling"
} else {
    Assert-True $false "Could not extract Run-BoundedProcess function"
}

# ---------------------------------------------------------------------------
# TEST 3: timeout result contract
# ---------------------------------------------------------------------------
Write-Host "--- Test 3: Timeout result contract ---"
if ($funcMatch.Success) {
    Assert-True ($funcMatch.Value -match 'TimedOut\s*=') "Result object carries TimedOut"
    Assert-True ($funcMatch.Value -match 'ExitCode\s*=') "Result object carries ExitCode"
} else {
    Assert-True $false "Could not extract Run-BoundedProcess function"
}
Assert-True ($scriptContent -match 'timed out after 300s and was killed') "Timeout failure records an explicit killed manifest entry"

# ---------------------------------------------------------------------------
# TEST 4: exit code 3010 returns a RebootRequired result
# ---------------------------------------------------------------------------
Write-Host "--- Test 4: Exit code 3010 returns RebootRequired hashtable ---"
if ($scriptContent -match '(?m)^function\s+Run-VendorUninstaller\s*\{') {
    $uninstallerMatch = [regex]::Match($scriptContent, '(?ms)^function\s+Run-VendorUninstaller\s*\{.*?^\}')
    if ($uninstallerMatch.Success) {
        $uninstallerDef = $uninstallerMatch.Value
        Assert-True ($uninstallerDef -match 'RebootRequired\s*=\s*\$true') "3010 result carries RebootRequired = true"
        Assert-True ($uninstallerDef -match 'Success\s*=\s*\$true') "3010 result carries Success = true"
        Assert-True ($uninstallerDef -match '3010') "3010 exit code is recognized"
    } else {
        Assert-True $false "Could not extract Run-VendorUninstaller function"
    }
} else {
    Assert-True $false "Run-VendorUninstaller function not found in source"
}

# ---------------------------------------------------------------------------
# TEST 5: main loop skips manual surgery when the uninstaller succeeded
# ---------------------------------------------------------------------------
Write-Host "--- Test 5: Manual surgery skipped when uninstall succeeds (0 or 3010) ---"
$mainLoopIdx = $scriptContent.IndexOf('# 2. Run vendor uninstaller')
if ($mainLoopIdx -ge 0) {
    $mainLoopSection = $scriptContent.Substring($mainLoopIdx)
    Assert-True ($mainLoopSection -match '\$uninstallSucceeded') "Tracks uninstallSucceeded flag"
    Assert-True ($mainLoopSection -match '-not\s+\$uninstallSucceeded') "Manual surgery gated by -not uninstallSucceeded"
} else {
    Assert-True $false "Main loop section not found in source"
}

# ---------------------------------------------------------------------------
# TEST 6: 3010 defers persistence cleanup and marks RebootPending
# ---------------------------------------------------------------------------
Write-Host "--- Test 6: 3010 skips persistence cleanup and sets non-Completed status ---"
if ($mainLoopIdx -ge 0) {
    Assert-True ($mainLoopSection -match '\$rebootRequired') "Tracks rebootRequired flag"
    Assert-True ($scriptContent -match 'if \(\$installDir -and -not \$rebootRequired\)') "Clean-Persistence gated on -not rebootRequired"
    Assert-True ($scriptContent -match 'RebootPending') "Sets RebootPending status for 3010"
    Assert-True ($scriptContent -match "'RebootPending'") "RebootPending status literal is present"
    Assert-True ($scriptContent -match 'Set-RunOnceResume -InstanceId \$instanceId') "3010 path schedules a post-reboot RunOnce resume"
} else {
    Assert-True $false "Main loop section not found in source"
}

# ---------------------------------------------------------------------------
# TEST 7: reboot-resume fast path never re-runs the vendor uninstaller
# ---------------------------------------------------------------------------
Write-Host "--- Test 7: RebootPending resume skips the vendor uninstaller ---"
Assert-True ($scriptContent -match 'RebootPendingInstanceIds') "Tracks RebootPending instance IDs separately"
Assert-True ($scriptContent -match 'vendor uninstaller already succeeded|RebootPending resume') "Documents the RebootPending fast path"
Assert-True ($scriptContent -match 'Clean-Persistence -InstallDir \$installDir') "RebootPending resume still runs persistence cleanup"
Assert-True ($scriptContent -match 'RebootPendingInstanceIds -contains \$id') "Resume marker seeding preserves RebootPending status across interrupted resumes"

# ---------------------------------------------------------------------------
# TEST 8: PS 5.1 compatibility - no .NET APIs unavailable in 5.1
# ---------------------------------------------------------------------------
Write-Host "--- Test 8: PS 5.1 compatibility check ---"
if ($funcMatch.Success) {
    $ps51Issues = @()
    if ($funcMatch.Value -match 'async\s+Task|await\s') { $ps51Issues += "Uses async/await keywords (C# only, not PowerShell)" }
    if ($funcMatch.Value -match 'CancellationToken') { $ps51Issues += "Uses CancellationToken" }
    if ($funcMatch.Value -match 'ValueTask') { $ps51Issues += "Uses ValueTask (.NET Core only)" }
    if ($funcMatch.Value -match 'IAsyncEnumerable') { $ps51Issues += "Uses IAsyncEnumerable (.NET Core only)" }
    if ($funcMatch.Value -match '\[System\.Runtime\.CompilerServices\]') { $ps51Issues += "Uses CompilerServices" }
    if ($funcMatch.Value -match 'ConfigureAwait') { $ps51Issues += "Uses ConfigureAwait" }
    if ($funcMatch.Value -match 'System\.Threading\.Thread') { $ps51Issues += "Uses raw Thread (no PS runspace)" }
    if ($funcMatch.Value -match '\block\s') { $ps51Issues += "Uses 'lock' keyword (C# only, not PowerShell)" }
    if ($ps51Issues.Count -eq 0) {
        Assert-True $true "No PS 5.1 incompatible APIs detected"
    } else {
        foreach ($issue in $ps51Issues) {
            Assert-True $false "PS 5.1 incompatibility: $issue"
        }
    }
} else {
    Assert-True $false "Could not extract Run-BoundedProcess function"
}

# ---------------------------------------------------------------------------
# TEST 9: no parenthesized if-expression in the remover (parse blocker)
# ---------------------------------------------------------------------------
Write-Host "--- Test 9: remover parses with zero errors (PS 5.1 parse gate) ---"
$parseErrors = $null
$null = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$parseErrors)
if ($null -ne $parseErrors -and @($parseErrors).Count -gt 0) {
    foreach ($pe in @($parseErrors)) {
        Write-Host ("  parse error L" + $pe.Extent.StartLineNumber + ": " + $pe.Message) -ForegroundColor Red
    }
    Assert-True $false "remove-screenconnect.ps1 must parse with zero errors"
} else {
    Assert-True $true "remove-screenconnect.ps1 parses with zero errors"
}

# ---------------------------------------------------------------------------
# TEST 10: manifest counts are computed BEFORE the human-readable report is
# written. The report block references $successCount/$failedCount/etc. under
# Set-StrictMode -Version 2.0; computing them after the write threw
# "The variable '$successCount' cannot be retrieved because it has not been
# set." and forced exit 1 on an otherwise fully successful removal run
# (observed live 2026-08-27 on DESTROYERLTC202).
# ---------------------------------------------------------------------------
Write-Host "--- Test 10: report counts computed before removal-report.txt is written ---"
$countAssignMatch = [regex]::Match($scriptContent, '\$successCount\s*=\s*@')
$reportPathMatch  = [regex]::Match($scriptContent, '\$reportTxtPath\s*=')
if (-not $countAssignMatch.Success -or -not $reportPathMatch.Success) {
    Assert-True $false "Could not locate the count assignment / report block markers in source"
} else {
    Assert-True ($countAssignMatch.Index -lt $reportPathMatch.Index) "Manifest counts are assigned before the removal-report.txt block (StrictMode-safe)"
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "=== Test Summary ==="
Write-Host "Passed: $script:passedTests"
Write-Host "Failed: $script:failedTests"

if ($script:failedTests -gt 0) {
    exit 1
} else {
    exit 0
}

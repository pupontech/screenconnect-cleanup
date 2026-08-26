# =====================================================================
# Test-RemovalRuntimeContracts.ps1 -- contract tests for Stage 4
# bounded, deadlock-safe uninstaller execution.
#
# Tests:
# 1. Run-BoundedProcess function exists in remove-screenconnect.ps1
# 2. Run-BoundedProcess uses ReadToEndAsync for concurrent stream drain
# 3. Run-BoundedProcess enforces timeout and kills process
# 4. Run-BoundedProcess waits for process reaping after Kill
# 5. Exit code 3010 (reboot required) is handled correctly - does NOT
#    incorrectly trigger immediate manual surgery fallback
# 6. Failed uninstaller (non-zero, non-3010) correctly marks Failed and
#    DOES trigger manual surgery
# 7. Successful uninstaller (exit 0) marks Completed without manual surgery
# 8. 3010 path skips persistence cleanup and marks non-Completed status
# 9. PS 5.1 compatibility - no .NET APIs unavailable in 5.1
#
# Exit codes: 0 = all contracts pass, 1 = contract violations found.
# PowerShell 5.1 compatible. Pure ASCII, no BOM.
# =====================================================================
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$scriptPath = Join-Path $repoRoot 'remove-screenconnect.ps1'

$failedTests = 0
$passedTests = 0

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) {
        Write-Host "FAIL: $Message" -ForegroundColor Red
        return $false
    }
    Write-Host "PASS: $Message" -ForegroundColor Green
    return $true
}

function Assert-Equals {
    param($Expected, $Actual, [string]$Message)
    if ($Expected -ne $Actual) {
        Write-Host "FAIL: $Message (expected '$Expected', got '$Actual')" -ForegroundColor Red
        return $false
    }
    Write-Host "PASS: $Message" -ForegroundColor Green
    return $true
}

Write-Host "=== Running Removal Runtime Contract Tests ==="
Write-Host ""

$scriptContent = Get-Content -LiteralPath $scriptPath -Raw

# ---------------------------------------------------------------------------
# TEST 1: Run-BoundedProcess function exists in source (AST check)
# ---------------------------------------------------------------------------
Write-Host "--- Test 1: Run-BoundedProcess function exists in source ---"
if ($scriptContent -match '(?m)^function\s+Run-BoundedProcess\s*\{') {
    $passedTests++
    Write-Host "PASS: Run-BoundedProcess function exists in source" -ForegroundColor Green
} else {
    $failedTests++
    Write-Host "FAIL: Run-BoundedProcess function NOT found in source" -ForegroundColor Red
}

# ---------------------------------------------------------------------------
# TEST 2: Run-BoundedProcess uses ReadToEndAsync for concurrent drain
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "--- Test 2: ReadToEndAsync used for concurrent stream drain ---"
if ($scriptContent -match '(?m)^function\s+Run-BoundedProcess\s*\{') {
    $funcMatch = [regex]::Match($scriptContent, '(?ms)^function\s+Run-BoundedProcess\s*\{.*?^\}')
    if ($funcMatch.Success) {
        $funcDef = $funcMatch.Value
        $passed = $true
        $passed = Assert-True ($funcDef -match 'ReadToEndAsync\(\)') "Uses ReadToEndAsync for stdout" -and $passed
        $passed = Assert-True ($funcDef -match '\$stdoutTask\s*=') "Starts stdout task before WaitForExit" -and $passed
        $passed = Assert-True ($funcDef -match '\$stderrTask\s*=') "Starts stderr task before WaitForExit" -and $passed
        $passed = Assert-True ($funcDef -match 'WaitForExit') "Calls WaitForExit after starting tasks" -and $passed
        if ($passed) { $passedTests++ } else { $failedTests++ }
    } else {
        $failedTests++
        Write-Host "FAIL: Could not extract Run-BoundedProcess function" -ForegroundColor Red
    }
} else {
    Write-Host "SKIP: Run-BoundedProcess not yet implemented (RED expected)" -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# TEST 3: Run-BoundedProcess enforces timeout and kills process
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "--- Test 3: Timeout enforcement and process kill ---"
if ($scriptContent -match '(?m)^function\s+Run-BoundedProcess\s*\{') {
    $funcMatch = [regex]::Match($scriptContent, '(?ms)^function\s+Run-BoundedProcess\s*\{.*?^\}')
    if ($funcMatch.Success) {
        $funcDef = $funcMatch.Value
        $passed = $true
        $passed = Assert-True ($funcDef -match 'TimedOut') "Has TimedOut output field" -and $passed
        $passed = Assert-True ($funcDef -match '\.Kill\(\)') "Calls Kill on timeout" -and $passed
        $passed = Assert-True ($funcDef -match 'WaitForExit\(\$TimeoutMs\)') "Uses bounded WaitForExit" -and $passed
        if ($passed) { $passedTests++ } else { $failedTests++ }
    } else {
        $failedTests++
        Write-Host "FAIL: Could not extract Run-BoundedProcess function" -ForegroundColor Red
    }
} else {
    Write-Host "SKIP: Run-BoundedProcess not yet implemented (RED expected)" -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# TEST 4: Run-BoundedProcess waits for process reaping after Kill
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "--- Test 4: WaitForExit called after Kill for process reaping ---"
# Check directly in script content - Kill() } followed by WaitForExit(1000)
$passed = $true
$passed = Assert-True ($scriptContent -match '(?s)Kill\(\) }.*WaitForExit\(1000\)') "Reaps process after Kill with 1000ms wait" -and $passed
if ($passed) { $passedTests++ } else { $failedTests++; Write-Host "FAIL: No process reap after Kill" -ForegroundColor Red }

# ---------------------------------------------------------------------------
# TEST 5: Run-VendorUninstaller handles exit code 3010 correctly
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "--- Test 5: Exit code 3010 returns RebootRequired hashtable ---"
if ($scriptContent -match '(?m)^function\s+Run-VendorUninstaller\s*\{') {
    $passed = $true
    $passed = Assert-True ($scriptContent -match 'RebootRequired\s*=\s*\$true') "Returns RebootRequired hashtable for 3010" -and $passed
    $passed = Assert-True ($scriptContent -match 'Success\s*=\s*\$true') "Returns Success=true for 3010" -and $passed
    if ($passed) { $passedTests++ } else { $failedTests++ }
} else {
    Write-Host "SKIP: Run-VendorUninstaller not found" -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# TEST 6: Main loop defers manual surgery on 3010 (uses $uninstallSucceeded)
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "--- Test 6: Manual surgery skipped when uninstall succeeds (0 or 3010) ---"
$mainLoopIdx = $scriptContent.IndexOf('# 2. Run vendor uninstaller')
if ($mainLoopIdx -ge 0) {
    $mainLoopSection = $scriptContent.Substring($mainLoopIdx)
    $passed = $true
    $passed = Assert-True ($mainLoopSection -match '\$uninstallSucceeded') "Tracks uninstallSucceeded flag" -and $passed
    $passed = Assert-True ($mainLoopSection -match '-not\s+\$uninstallSucceeded') "Manual surgery gated by -not uninstallSucceeded" -and $passed
    if ($passed) { $passedTests++ } else { $failedTests++ }
} else {
    $failedTests++
    Write-Host "FAIL: Main loop section not found" -ForegroundColor Red
}

# ---------------------------------------------------------------------------
# TEST 7: Failed uninstaller (non-zero, non-3010) triggers manual surgery
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "--- Test 7: Failed uninstaller returns $false ---
if ($scriptContent -match '(?m)^function\s+Run-VendorUninstaller\s*\{') {
    $funcMatch = [regex]::Match($scriptContent, '(?ms)^function\s+Run-VendorUninstaller\s*\{.*?^\}')
    if ($funcMatch.Success) {
        $funcDef = $funcMatch.Value
        $passed = $true
        $passed = Assert-True ($funcDef -match 'else\s*\{\s*return\s+\$false') "Returns $false for non-zero non-3010" -and $passed
        if ($passed) { $passedTests++ } else { $failedTests++ }
    } else {
        $failedTests++
        Write-Host "FAIL: Could not extract Run-VendorUninstaller function" -ForegroundColor Red
    }
} else {
    Write-Host "SKIP: Run-VendorUninstaller not found" -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# TEST 8: Successful uninstaller (exit 0) returns $true
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "--- Test 8: Successful uninstaller (exit 0) returns $true ---
if ($scriptContent -match '(?m)^function\s+Run-VendorUninstaller\s*\{') {
    $funcMatch = [regex]::Match($scriptContent, '(?ms)^function\s+Run-VendorUninstaller\s*\{.*?^\}')
    if ($funcMatch.Success) {
        $funcDef = $funcMatch.Value
        $passed = $true
        $passed = Assert-True ($funcDef -match '\$exitCode\s*-\?eq\s*0') "Checks for exit code 0" -and $passed
        $passed = Assert-True ($funcDef -match 'if.*\$exitCode.*0.*return\s+\$true') "Returns $true for exit 0" -and $passed
        if ($passed) { $passedTests++ } else { $failedTests++ }
    } else {
        $failedTests++
        Write-Host "FAIL: Could not extract Run-VendorUninstaller function" -ForegroundColor Red
    }
} else {
    Write-Host "SKIP: Run-VendorUninstaller not found" -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# TEST 9: 3010 path skips persistence cleanup and marks non-Completed status
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "--- Test 9: 3010 skips Clean-Persistence and sets non-Completed status ---"
$mainLoopIdx = $scriptContent.IndexOf('# 2. Run vendor uninstaller')
if ($mainLoopIdx -ge 0) {
    $mainLoopSection = $scriptContent.Substring($mainLoopIdx)
    # Find the section after uninstall handling up to Clean-Persistence
    $afterUninstall = $mainLoopSection.Substring(0, [math]::Min(800, $mainLoopSection.Length))
    $passed = $true
    $passed = Assert-True ($afterUninstall -match '\$rebootRequired') "Tracks rebootRequired flag" -and $passed
    $passed = Assert-True ($afterUninstall -match 'Clean-Persistence.*\$installDir') "Has Clean-Persistence call" -and $passed
    # Check Clean-Persistence is gated by not rebootRequired or not uninstallSucceeded
    $cleanPersistIdx = $afterUninstall.IndexOf('Clean-Persistence')
    if ($cleanPersistIdx -ge 0) {
        $beforeClean = $afterUninstall.Substring(0, $cleanPersistIdx)
        $passed = Assert-True ($beforeClean -match 'if.*rebootRequired|if.*uninstallSucceeded') "Clean-Persistence gated by success flags" -and $passed
    }
    # Check status update is not Completed for 3010
    $passed = Assert-True ($scriptContent -match '3010.*Deferred|RebootRequired.*Deferred|Status.*Reboot') "Sets non-Completed status for 3010" -and $passed
    if ($passed) { $passedTests++ } else { $failedTests++ }
} else {
    $failedTests++
    Write-Host "FAIL: Main loop section not found" -ForegroundColor Red
}

# ---------------------------------------------------------------------------
# TEST 10: PS 5.1 compatibility - no .NET APIs unavailable in 5.1
# ReadToEndAsync and Task.WaitAll ARE available in .NET Framework 4.5+ (PS 5.1)
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "--- Test 10: PS 5.1 compatibility check ---"
if ($scriptContent -match '(?m)^function\s+Run-BoundedProcess\s*\{') {
    $funcMatch = [regex]::Match($scriptContent, '(?ms)^function\s+Run-BoundedProcess\s*\{.*?^\}')
    if ($funcMatch.Success) {
        $funcDef = $funcMatch.Value
        $ps51Issues = @()
        
        # These are NOT available in .NET Framework 4.x / PS 5.1:
        if ($funcDef -match '\basync\b|\bawait\b') { $ps51Issues += "Uses async/await keywords (C# only, not PowerShell)" }
        if ($funcDef -match 'CancellationToken') { $ps51Issues += "Uses CancellationToken" }
        if ($funcDef -match 'ValueTask') { $ps51Issues += "Uses ValueTask (.NET Core only)" }
        if ($funcDef -match 'IAsyncEnumerable') { $ps51Issues += "Uses IAsyncEnumerable (.NET Core only)" }
        if ($funcDef -match '\[System\.Runtime\.CompilerServices\]') { $ps51Issues += "Uses CompilerServices" }
        if ($funcDef -match 'ConfigureAwait') { $ps51Issues += "Uses ConfigureAwait" }
        if ($funcDef -match 'System\.Threading\.Thread') { $ps51Issues += "Uses raw Thread (no PS runspace)" }
        if ($funcDef -match '\block\s') { $ps51Issues += "Uses 'lock' keyword (C# only, not PowerShell)" }
        
        if ($ps51Issues.Count -eq 0) {
            $passedTests++
            Write-Host "PASS: No PS 5.1 incompatible APIs detected" -ForegroundColor Green
        } else {
            $failedTests++
            foreach ($issue in $ps51Issues) {
                Write-Host "FAIL: PS 5.1 incompatibility: $issue" -ForegroundColor Red
            }
        }
    } else {
        $failedTests++
        Write-Host "FAIL: Could not extract Run-BoundedProcess function" -ForegroundColor Red
    }
} else {
    Write-Host "SKIP: Run-BoundedProcess not yet implemented (RED expected)" -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "=== Test Summary ==="
Write-Host "Passed: $passedTests"
Write-Host "Failed: $failedTests"

if ($failedTests -gt 0) {
    exit 1
} else {
    exit 0
}
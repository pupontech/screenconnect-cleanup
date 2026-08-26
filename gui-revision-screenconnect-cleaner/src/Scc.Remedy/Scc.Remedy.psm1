<#
  Scc.Remedy.psm1  -  Remediation engine for ScreenConnect Cleaner (GUI)

  Highest-safety-bar module. Plan-gated, ScreenConnect-only removal with
  quarantine-never-delete semantics.

  Ported from:
    - remove-screenconnect.ps1  (full remediation engine)
    - Invoke-ReviewAndRemove.ps1 (plan creation flow)
    - AUDIT-REMOVE.md / AUDIT-03-removal.md (safety reference)

  Safety invariants preserved from the legacy engine:
    * Dry-run by default. -Execute is mandatory to mutate anything.
    * Only ScreenConnect product items may become Action=REMOVE.
    * Per-item re-verification before acting (plan tampering protection).
    * Vendor uninstaller is read from registry at runtime (never hardcoded).
    * Quarantine, never delete.
    * Every destructive primitive is isolated so it can be mocked/tested and
      so a failure degrades to a recorded "Failed" rather than aborting the run.

  PowerShell 5.1 compatible. Pure ASCII, no BOM. No emoji.
#>

Set-StrictMode -Version 1.0

# ---------------------------------------------------------------------------
# Soft dependency bootstrap: load Scc.Core from the sibling module directory
# if it is not already present. This keeps the module importable on its own
# (e.g. the parse/import gates) without requiring a pre-set PSModulePath.
# ---------------------------------------------------------------------------
try {
    if (-not (Get-Command -Name 'Write-SccLog' -ErrorAction SilentlyContinue)) {
        $coreMod = Join-Path $PSScriptRoot '..' 'Scc.Core' 'Scc.Core.psd1'
        if (Test-Path -LiteralPath $coreMod) {
            Import-Module $coreMod -Force -ErrorAction SilentlyContinue
        }
    }
} catch { }

# Module-scoped remediation log for the current run.
$script:remediationActions = @()
$script:remediationPath    = $null

# ===========================================================================
# Private helpers
# ===========================================================================

function Get-Prop {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    try {
        $pr = $Object.PSObject.Properties[$Name]
        if ($pr) { return $pr.Value }
    } catch { }
    return $null
}

function Write-SccRemedyLog {
    param([string]$Level = 'INFO', [string]$Stage = 'Remedy', [string]$Message)
    try {
        Write-SccLog -Level $Level -Stage $Stage -Component 'Scc.Remedy' -Operation 'Remediation' -Message $Message -ErrorAction SilentlyContinue
    } catch { }
}

function Get-SccSha256Hex {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '00000000' }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
        $hash  = $sha.ComputeHash($bytes)
        return (($hash | ForEach-Object { $_.ToString('x2') }) -join '')
    } finally {
        $sha.Dispose()
    }
}

function Get-SccRemedyQuarantineRoot {
    param($Run)
    $isWindows = ($env:OS -eq 'Windows_NT')
    $qBase = $null
    if ($isWindows) {
        try {
            $paths = Get-SccPaths -Run $Run -ErrorAction SilentlyContinue
            if ($paths -and $paths.QuarantineRoot) { $qBase = $paths.QuarantineRoot }
        } catch { }
    }
    # F4 fix: use platform check (not % heuristic) - on non-Windows always
    # fall back to RunDir\Quarantine so the module is testable on Linux.
    if (-not $isWindows) {
        if ($Run -and $Run.RunDir) { $qBase = Join-Path $Run.RunDir 'Quarantine' }
        else { $qBase = Join-Path (Get-Location).Path 'Quarantine' }
    }
    if ([string]::IsNullOrEmpty($qBase) -or $qBase -like '*%*') {
        if ($Run -and $Run.RunDir) { $qBase = Join-Path $Run.RunDir 'Quarantine' }
        else { $qBase = Join-Path (Get-Location).Path 'Quarantine' }
    }
    if (-not (Test-Path -LiteralPath $qBase)) {
        try { New-Item -ItemType Directory -Path $qBase -Force | Out-Null } catch { }
    }
    return $qBase
}

# ===========================================================================
# Remediation action recording (remediation.json)
# ===========================================================================

function Add-RemediationAction {
    param(
        $Run,
        [string]$Action,
        [string]$Target,
        [string]$Command,
        [string]$Result,
        [string]$Error,
        [string]$StartedUtc
    )
    if ([string]::IsNullOrEmpty($StartedUtc)) {
        $StartedUtc = (Get-Date).ToUniversalTime().ToString('o')
    }
    $ended = (Get-Date).ToUniversalTime().ToString('o')
    $entry = [PSCustomObject]@{
        Action    = $Action
        Target    = $Target
        Command   = $Command
        Result    = $Result
        Error     = $Error
        StartedUtc = $StartedUtc
        EndedUtc  = $ended
    }
    $script:remediationActions = $script:remediationActions + @($entry)
    Write-SccRemedyRemediationFile -Run $Run
    return $entry
}

function Write-SccRemedyRemediationFile {
    param($Run)
    $path = $script:remediationPath
    if (-not $path) {
        if ($Run -and $Run.RunDir) { $path = Join-Path $Run.RunDir 'remediation.json' }
    }
    if (-not $path) { return }
    try {
        $dir = Split-Path -Parent $path
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        [System.IO.File]::WriteAllText($path, (ConvertTo-SccJson -InputObject $script:remediationActions -Depth 10), [System.Text.Encoding]::ASCII)
    } catch { }
}

# ===========================================================================
# Quarantine manifest (quarantine-manifest.json)
# ===========================================================================

function Get-SccQuarantineManifest {
    param($Run)
    $qBase = Get-SccRemedyQuarantineRoot -Run $Run
    $mp = Join-Path $qBase 'quarantine-manifest.json'
    if (-not (Test-Path -LiteralPath $mp)) { return @() }
    try {
        $raw = [System.IO.File]::ReadAllText($mp)
        if ([string]::IsNullOrWhiteSpace($raw)) { return @() }
        $obj = ConvertFrom-Json -InputObject $raw
        return @($obj)
    } catch { return @() }
}

function Add-SccQuarantineManifestEntry {
    param($Run, $Entry)
    $qBase = Get-SccRemedyQuarantineRoot -Run $Run
    $mp = Join-Path $qBase 'quarantine-manifest.json'
    $list = @(Get-SccQuarantineManifest -Run $Run)
    $list = $list + @($Entry)
    try {
        [System.IO.File]::WriteAllText($mp, (ConvertTo-SccJson -InputObject $list -Depth 10), [System.Text.Encoding]::ASCII)
    } catch { }
}

function Remove-SccQuarantineManifestEntry {
    param($Run, [string]$ItemId)
    $qBase = Get-SccRemedyQuarantineRoot -Run $Run
    $mp = Join-Path $qBase 'quarantine-manifest.json'
    $all = @(Get-SccQuarantineManifest -Run $Run)
    $list = @($all | Where-Object { [string]$_.ItemId -ne $ItemId })
    try {
        [System.IO.File]::WriteAllText($mp, (ConvertTo-SccJson -InputObject $list -Depth 10), [System.Text.Encoding]::ASCII)
    } catch { }
}

# ===========================================================================
# Plan loading + preview
# ===========================================================================

function Resolve-SccPlan {
    param($Plan)
    if ($Plan -is [string]) {
        if (-not (Test-Path -LiteralPath $Plan)) { throw [System.InvalidOperationException]::new(('Plan file not found: ' + $Plan)) }
        $parsed = $null
        try { $parsed = ConvertFrom-SccJson -Path $Plan } catch { $parsed = $null }
        if ($null -eq $parsed) {
            throw [System.InvalidOperationException]::new(('Failed to parse plan file (malformed JSON): ' + $Plan))
        }
        return $parsed
    }
    return $Plan
}

function Get-SccPlanPreview {
    param($Plan)
    $out = @()
    foreach ($item in @($Plan.Items)) {
        $fid    = [string](Get-Prop $item 'FindingId')
        $prod   = [string](Get-Prop $item 'Product')
        $action = [string](Get-Prop $item 'Action')
        if ($action -ne 'REMOVE') {
            $out += ('KEEP ' + $fid + ' (' + $prod + ') - no action')
            continue
        }
        if ($prod.ToLowerInvariant() -ne 'screenconnect') {
            $out += ('SKIP ' + $fid + ' - product ' + $prod + ' is not ScreenConnect; removal refused by owner policy')
            continue
        }
        $svc = [string](Get-Prop $item 'ServiceName')
        $steps = 'stop service'
        if ($svc) { $steps = ('stop service ' + $svc) }
        $steps = $steps + '; kill associated processes; vendor uninstall (registry-derived); validate removal; cleanup (service/task/run-key/firewall); quarantine remaining artifacts'
        $out += ('REMOVE ScreenConnect ' + $fid + ': ' + $steps)
    }
    return $out
}

# ===========================================================================
# Re-verification (plan-tampering protection)
# ===========================================================================

function Test-SccScreenConnectTarget {
    param($PlanItem)
    $prod = Get-Prop $PlanItem 'Product'
    if ($null -eq $prod -or $prod.ToString().ToLowerInvariant() -ne 'screenconnect') { return $false }
    $svc     = [string](Get-Prop $PlanItem 'ServiceName')
    $dir     = [string](Get-Prop $PlanItem 'InstallDir')
    $mainExe = [string](Get-Prop $PlanItem 'MainExe')
    $hasSvc = (-not [string]::IsNullOrEmpty($svc))
    $hasDir = (-not [string]::IsNullOrEmpty($dir))
    $hasExe = (-not [string]::IsNullOrEmpty($mainExe))
    if (-not $hasSvc -and -not $hasDir -and -not $hasExe) { return $false }
    if ($hasSvc) {
        $svcOk = $false
        try {
            $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
            if ($null -ne $s -and $s.Name -like 'ScreenConnect*') { $svcOk = $true }
        } catch { }
        if (-not $svcOk) { return $false }
    }
    if ($hasDir) {
        $dirOk = $false
        if ($dir -like '*\ScreenConnect*' -and (Test-Path -LiteralPath $dir)) { $dirOk = $true }
        if (-not $dirOk) { return $false }
    }
    if ($hasExe) {
        $exeOk = $false
        if ($mainExe -like '*ScreenConnect*') {
            if (-not [string]::IsNullOrEmpty($dir)) {
                $exePath = Join-Path $dir $mainExe
                if (Test-Path -LiteralPath $exePath) { $exeOk = $true }
            }
        }
        if (-not $exeOk) { return $false }
    }
    if ((-not $hasSvc) -and (-not $hasDir) -and (-not $hasExe)) {
        try {
            $s = Get-Service -Name 'ScreenConnect*' -ErrorAction SilentlyContinue
            if ($null -ne $s) { return $true }
        } catch { }
        return $false
    }
    return $true
}

# ===========================================================================
# Destructive primitives (isolated for mocking + per-item failure isolation)
# Each returns $true on success/skip, $false on failure.
# ===========================================================================

function Stop-SccTargetService {
    param([string]$ServiceName, $PlanItem, $Run)
    $started = (Get-Date).ToUniversalTime().ToString('o')
    $cmd = ('Stop-Service -Name "{0}" -Force' -f $ServiceName)
    try {
        $svc = $null
        try { $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue } catch { }
        if ($null -eq $svc) {
            Add-RemediationAction -Run $Run -Action 'StopService' -Target $ServiceName -Command $cmd -Result 'Skipped' -Error 'service not present' -StartedUtc $started
            return $true
        }
        if ($svc.Status -eq 'Stopped') {
            Add-RemediationAction -Run $Run -Action 'StopService' -Target $ServiceName -Command $cmd -Result 'Skipped' -Error 'already stopped' -StartedUtc $started
            return $true
        }
        try { Stop-Service -Name $ServiceName -Force -ErrorAction Stop } catch { throw }
        Add-RemediationAction -Run $Run -Action 'StopService' -Target $ServiceName -Command $cmd -Result 'Succeeded' -Error '' -StartedUtc $started
        return $true
    } catch {
        Add-RemediationAction -Run $Run -Action 'StopService' -Target $ServiceName -Command $cmd -Result 'Failed' -Error $_.Exception.Message -StartedUtc $started
        return $false
    }
}

function Get-SccAncestorPids {
    param([int]$ProcessId)
    $chain = [System.Collections.Generic.List[int]]::new()
    $walk = $ProcessId
    for ($i = 0; $i -lt 12 -and $walk -gt 0; $i++) {
        $chain.Add([int]$walk)
        $parent = $null
        try {
            $pObj = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId=$walk" -ErrorAction SilentlyContinue
            if ($pObj) { $parent = $pObj.ParentProcessId }
        } catch { }
        if (-not $parent -or $chain.Contains([int]$parent)) { break }
        $walk = [int]$parent
    }
    return $chain
}

function Stop-SccTargetProcesses {
    param([string]$InstallDir, [string]$ServiceName, $PlanItem, $Run)
    $started = (Get-Date).ToUniversalTime().ToString('o')
    $cmd = ('kill processes under ' + $InstallDir)
    try {
        $pids = @()
        try {
            $procs = Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue |
                Where-Object { $_.ExecutablePath -and $_.ExecutablePath -like ($InstallDir + '\*') }
            foreach ($p in @($procs)) { $pids += $p.ProcessId }
        } catch { }
        if (@($pids).Count -eq 0 -and $ServiceName) {
            try {
                $s = Get-CimInstance -ClassName Win32_Service -Filter ("Name='" + $ServiceName + "'") -ErrorAction SilentlyContinue
                if ($s -and $s.ProcessId) { $pids += $s.ProcessId }
            } catch { }
        }
        if (@($pids).Count -eq 0) {
            Add-RemediationAction -Run $Run -Action 'KillProcesses' -Target $InstallDir -Command $cmd -Result 'Skipped' -Error 'no processes found' -StartedUtc $started
            return $true
        }
        # F5: self-protection - build ancestor PID chain and refuse to kill
        # ancestors of the current process (legacy remove-screenconnect.ps1:815-834).
        $selfChain = Get-SccAncestorPids -ProcessId $PID
        $skipped = @($pids | Where-Object { $selfChain.Contains([int]$_) })
        foreach ($sp in @($skipped)) {
            Add-RemediationAction -Run $Run -Action 'KillProcesses' -Target "PID $sp" -Command $cmd -Result 'Skipped' -Error 'Self/ancestor process - refused'
        }
        $pids = @($pids | Where-Object { -not $selfChain.Contains([int]$_) })
        if (@($pids).Count -eq 0) {
            Add-RemediationAction -Run $Run -Action 'KillProcesses' -Target $InstallDir -Command $cmd -Result 'Skipped' -Error 'no processes left after self-protection filter' -StartedUtc $started
            return $true
        }
        foreach ($pidVal in @($pids)) {
            try { Stop-Process -Id $pidVal -Force -ErrorAction Stop } catch { }
        }
        Add-RemediationAction -Run $Run -Action 'KillProcesses' -Target $InstallDir -Command $cmd -Result 'Succeeded' -Error '' -StartedUtc $started
        return $true
    } catch {
        Add-RemediationAction -Run $Run -Action 'KillProcesses' -Target $InstallDir -Command $cmd -Result 'Failed' -Error $_.Exception.Message -StartedUtc $started
        return $false
    }
}

function Get-SccTargetUninstallData {
    param($PlanItem)
    $key = [string](Get-Prop $PlanItem 'UninstallRegistryKey')
    if ([string]::IsNullOrEmpty($key)) { return $null }
    $resolved = $key
    if ($resolved -match '^HKEY_') { $resolved = 'Registry::' + $resolved }
    $entry = $null
    try { $entry = Get-ItemProperty -LiteralPath $resolved -ErrorAction Stop } catch { return $null }
    return [PSCustomObject]@{
        UninstallString       = [string](Get-Prop $entry 'UninstallString')
        QuietUninstallString  = [string](Get-Prop $entry 'QuietUninstallString')
        ProductCode           = [string](Get-Prop $entry 'ProductCode')
        DisplayName           = [string](Get-Prop $entry 'DisplayName')
        PSPath                = [string](Get-Prop $entry 'PSPath')
    }
}

function Invoke-SccUninstallCommand {
    param([string]$Command, $PlanItem, $Run)
    try {
        $exe  = $null
        $args = ''
        $m = [regex]::Match($Command, '^"([^"]+)"\s*(.*)$')
        if ($m.Success) { $exe = $m.Groups[1].Value; $args = $m.Groups[2].Value }
        else {
            $m2 = [regex]::Match($Command, '^(\S+)\s*(.*)$')
            if ($m2.Success) { $exe = $m2.Groups[1].Value; $args = $m2.Groups[2].Value }
        }
        if ([string]::IsNullOrEmpty($exe)) { return $false }
        $psi = [System.Diagnostics.ProcessStartInfo]::new()
        $psi.FileName               = $exe
        $psi.Arguments              = $args
        $psi.UseShellExecute        = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError  = $true
        $psi.CreateNoWindow         = $true
        $proc = [System.Diagnostics.Process]::Start($psi)
        if ($null -eq $proc) { return $false }
        $proc.WaitForExit(300000) | Out-Null
        return ($proc.ExitCode -eq 0 -or $proc.ExitCode -eq 3010)
    } catch { return $false }
}

function Test-SccUninstallExeValid {
    param([string]$ExePath, [string]$InstallDir)
    if ([string]::IsNullOrEmpty($ExePath)) { return $false }
    $leaf = [System.IO.Path]::GetFileName($ExePath)
    $allowlist = @('ScreenConnect', 'App_', 'unins')
    $leafOk = $false
    foreach ($pattern in $allowlist) {
        if ($leaf -like ('*' + $pattern + '*')) { $leafOk = $true; break }
    }
    if (-not $leafOk) { return $false }
    if ([string]::IsNullOrEmpty($InstallDir)) { return $false }
    $underInstall = $false
    if ($ExePath -like ($InstallDir + '*')) { $underInstall = $true }
    if (-not $underInstall) { return $false }
    if (-not (Test-Path -LiteralPath $ExePath)) { return $false }
    return $true
}

function Uninstall-SccTarget {
    param($PlanItem, $Run)
    $fid = [string](Get-Prop $PlanItem 'FindingId')
    $installDir = [string](Get-Prop $PlanItem 'InstallDir')
    $started = (Get-Date).ToUniversalTime().ToString('o')
    try {
        $data = $null
        try { $data = Get-SccTargetUninstallData -PlanItem $PlanItem } catch { $data = $null }
        $cmd = $null
        if ($data -and ($data.QuietUninstallString -or $data.UninstallString)) {
            $cmd = if ($data.QuietUninstallString) { $data.QuietUninstallString } else { $data.UninstallString }
        } elseif ($data -and $data.ProductCode) {
            $cmd = ('msiexec.exe /x {0} /qn /norestart' -f $data.ProductCode)
        }
        if ([string]::IsNullOrEmpty($cmd)) {
            Add-RemediationAction -Run $Run -Action 'Uninstall' -Target $fid -Command '' -Result 'Failed' `
                -Error 'manual-cleanup-only: no uninstaller discovered (no UninstallString/QuietUninstallString or ProductCode); will quarantine artifacts' -StartedUtc $started
            return $false
        }
        # F2: validate non-MSI uninstaller before execution.
        $isMsi = $cmd -like 'msiexec*'
        if (-not $isMsi) {
            $bareExe = $null
            $mm = [regex]::Match($cmd, '^\s*"([^"]+)"')
            if ($mm.Success) { $bareExe = $mm.Groups[1].Value }
            else {
                $mm2 = [regex]::Match($cmd, '^(\S+\.exe)')
                if ($mm2.Success) { $bareExe = $mm2.Groups[1].Value }
            }
            if (-not (Test-SccUninstallExeValid -ExePath $bareExe -InstallDir $installDir)) {
                Add-RemediationAction -Run $Run -Action 'Uninstall' -Target $fid -Command $cmd -Result 'Failed' `
                    -Error ('uninstaller-validation-failed: exe not validated (not an allowlisted ScreenConnect uninstaller under the verified install dir); manual surgery required. Raw: ' + $cmd) -StartedUtc $started
                return $false
            }
            # Run with NO arguments (legacy: ScreenConnect uninstallers need no registry-supplied args)
            try { $ran = Invoke-SccUninstallCommand -Command $bareExe -PlanItem $PlanItem -Run $Run } catch { $ran = $false }
        } else {
            $ran = $false
            try { $ran = Invoke-SccUninstallCommand -Command $cmd -PlanItem $PlanItem -Run $Run } catch { $ran = $false }
        }
        if ($ran) {
            Add-RemediationAction -Run $Run -Action 'Uninstall' -Target $fid -Command $cmd -Result 'Succeeded' -Error '' -StartedUtc $started
            return $true
        }
        Add-RemediationAction -Run $Run -Action 'Uninstall' -Target $fid -Command $cmd -Result 'Failed' -Error 'uninstall command reported failure' -StartedUtc $started
        return $false
    } catch {
        Add-RemediationAction -Run $Run -Action 'Uninstall' -Target $fid -Command '' -Result 'Failed' -Error $_.Exception.Message -StartedUtc $started
        return $false
    }
}

function Test-SccTargetRemoved {
    param($PlanItem, $Run)
    $fid = [string](Get-Prop $PlanItem 'FindingId')
    $started = (Get-Date).ToUniversalTime().ToString('o')
    $svc = [string](Get-Prop $PlanItem 'ServiceName')
    $removed = $true
    try {
        if ($svc) {
            $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
            if ($s) { $removed = $false }
        }
    } catch { }
    if ($removed) {
        Add-RemediationAction -Run $Run -Action 'ValidateRemoval' -Target $fid -Command '' -Result 'Succeeded' -Error '' -StartedUtc $started
    } else {
        Add-RemediationAction -Run $Run -Action 'ValidateRemoval' -Target $fid -Command '' -Result 'Failed' -Error 'target still present after remediation' -StartedUtc $started
    }
    return $removed
}

function Remove-SccTargetService {
    param([string]$ServiceName, $PlanItem, $Run)
    $started = (Get-Date).ToUniversalTime().ToString('o')
    $cmd = ('sc.exe delete "{0}"' -f $ServiceName)
    try {
        $code = -1
        & sc.exe delete $ServiceName 2>$null | Out-Null
        $code = $LASTEXITCODE
        if ($code -eq 0) {
            Add-RemediationAction -Run $Run -Action 'DeleteService' -Target $ServiceName -Command $cmd -Result 'Succeeded' -Error '' -StartedUtc $started
            return $true
        }
        Add-RemediationAction -Run $Run -Action 'DeleteService' -Target $ServiceName -Command $cmd -Result 'Failed' -Error ('sc.exe exit ' + $code) -StartedUtc $started
        return $false
    } catch {
        Add-RemediationAction -Run $Run -Action 'DeleteService' -Target $ServiceName -Command $cmd -Result 'Failed' -Error $_.Exception.Message -StartedUtc $started
        return $false
    }
}

function Remove-SccTargetScheduledTask {
    param([string]$InstallDir, $PlanItem, $Run)
    $started = (Get-Date).ToUniversalTime().ToString('o')
    if ([string]::IsNullOrEmpty($InstallDir)) {
        Add-RemediationAction -Run $Run -Action 'DeleteScheduledTask' -Target '' -Command '' -Result 'Skipped' -Error 'no install dir' -StartedUtc $started
        return $true
    }
    try {
        $found = $false
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
        foreach ($t in @($tasks)) {
            foreach ($act in @($t.Actions)) {
                $p = Get-Prop $act 'Execute'
                $a = Get-Prop $act 'Arguments'
                if (($p -and $p.ToString() -like ($InstallDir + '*')) -or ($a -and $a.ToString() -like ('*' + $InstallDir + '*'))) {
                    Unregister-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -Confirm:$false -ErrorAction Stop
                    $found = $true
                }
            }
        }
        if (-not $found) {
            Add-RemediationAction -Run $Run -Action 'DeleteScheduledTask' -Target $InstallDir -Command '' -Result 'Skipped' -Error 'no matching scheduled task' -StartedUtc $started
            return $true
        }
        Add-RemediationAction -Run $Run -Action 'DeleteScheduledTask' -Target $InstallDir -Command '' -Result 'Succeeded' -Error '' -StartedUtc $started
        return $true
    } catch {
        Add-RemediationAction -Run $Run -Action 'DeleteScheduledTask' -Target $InstallDir -Command '' -Result 'Failed' -Error $_.Exception.Message -StartedUtc $started
        return $false
    }
}

function Remove-SccTargetRunKey {
    param([string]$InstallDir, $PlanItem, $Run)
    $started = (Get-Date).ToUniversalTime().ToString('o')
    if ([string]::IsNullOrEmpty($InstallDir)) {
        Add-RemediationAction -Run $Run -Action 'DeleteRunKey' -Target '' -Command '' -Result 'Skipped' -Error 'no install dir' -StartedUtc $started
        return $true
    }
    try {
        $runKeys = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
        )
        $removed = $false
        foreach ($rk in $runKeys) {
            if (-not (Test-Path -LiteralPath $rk)) { continue }
            $vals = Get-ItemProperty -LiteralPath $rk -ErrorAction SilentlyContinue
            if ($null -eq $vals) { continue }
            foreach ($prop in $vals.PSObject.Properties) {
                if ($prop.Name -eq 'PSPath' -or $prop.Name -eq 'PSParentPath' -or $prop.Name -eq 'PSChildName' -or $prop.Name -eq 'PSDrive' -or $prop.Name -eq 'PSProvider') { continue }
                $val = $prop.Value
                if ($val -and $val -like ('*' + $InstallDir + '*')) {
                    Remove-ItemProperty -LiteralPath $rk -Name $prop.Name -Force -ErrorAction Stop
                    $removed = $true
                }
            }
        }
        if (-not $removed) {
            Add-RemediationAction -Run $Run -Action 'DeleteRunKey' -Target $InstallDir -Command '' -Result 'Skipped' -Error 'no matching Run-key value' -StartedUtc $started
            return $true
        }
        Add-RemediationAction -Run $Run -Action 'DeleteRunKey' -Target $InstallDir -Command '' -Result 'Succeeded' -Error '' -StartedUtc $started
        return $true
    } catch {
        Add-RemediationAction -Run $Run -Action 'DeleteRunKey' -Target $InstallDir -Command '' -Result 'Failed' -Error $_.Exception.Message -StartedUtc $started
        return $false
    }
}

function Remove-SccTargetFirewallRule {
    param([string]$InstallDir, $PlanItem, $Run)
    $started = (Get-Date).ToUniversalTime().ToString('o')
    if ([string]::IsNullOrEmpty($InstallDir)) {
        Add-RemediationAction -Run $Run -Action 'DeleteFirewallRule' -Target '' -Command '' -Result 'Skipped' -Error 'no install dir' -StartedUtc $started
        return $true
    }
    try {
        $found = $false
        try {
            $rules = Get-NetFirewallRule -ErrorAction SilentlyContinue
            foreach ($r in @($rules)) {
                $p = $null
                try { $p = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $r -ErrorAction SilentlyContinue } catch { }
                if ($p -and $p.Program -and $p.Program -like ('*' + $InstallDir + '*')) {
                    Remove-NetFirewallRule -InputObject $r -Confirm:$false -ErrorAction Stop
                    $found = $true
                }
            }
        } catch { }
        if (-not $found) {
            Add-RemediationAction -Run $Run -Action 'DeleteFirewallRule' -Target $InstallDir -Command '' -Result 'Skipped' -Error 'no matching firewall rule' -StartedUtc $started
            return $true
        }
        Add-RemediationAction -Run $Run -Action 'DeleteFirewallRule' -Target $InstallDir -Command '' -Result 'Succeeded' -Error '' -StartedUtc $started
        return $true
    } catch {
        Add-RemediationAction -Run $Run -Action 'DeleteFirewallRule' -Target $InstallDir -Command '' -Result 'Failed' -Error $_.Exception.Message -StartedUtc $started
        return $false
    }
}

function Write-SccResumeMarker {
    param($Run, [string]$Phase, [array]$PendingMoves)
    if (-not $Run -or -not $Run.RunDir) { return }
    try {
        $marker = [PSCustomObject]@{
            Module      = 'Scc.Remedy'
            Phase       = $Phase
            UpdatedUtc  = (Get-Date).ToUniversalTime().ToString('o')
            PendingMoves = @($PendingMoves)
        }
        $mp = Join-Path $Run.RunDir 'resume-marker.json'
        [System.IO.File]::WriteAllText($mp, (ConvertTo-SccJson -InputObject $marker -Depth 10), [System.Text.Encoding]::ASCII)
    } catch { }
}

function Move-SccTargetToQuarantine {
    param([string]$SourcePath, $PlanItem, $Run, [string]$Reason, [string]$ActionType)
    $fid = [string](Get-Prop $PlanItem 'FindingId')
    $started = (Get-Date).ToUniversalTime().ToString('o')
    try {
        if (-not (Test-Path -LiteralPath $SourcePath)) {
            Add-RemediationAction -Run $Run -Action 'Quarantine' -Target $SourcePath -Command '' -Result 'Skipped' -Error 'source not found' -StartedUtc $started
            return $true
        }
        $qBase = Get-SccRemedyQuarantineRoot -Run $Run
        $qDir  = Join-Path $qBase 'q'
        if (-not (Test-Path -LiteralPath $qDir)) { New-Item -ItemType Directory -Path $qDir -Force | Out-Null }
        $leaf = [System.IO.Path]::GetFileName($SourcePath)
        $dest = Join-Path $qDir $leaf
        if (Test-Path -LiteralPath $dest) {
            $suffix = (Get-SccSha256Hex -Text $SourcePath).Substring(0, 8)
            $dest = Join-Path $qDir ($suffix + '-' + $leaf)
        }
        $isDirectory = $false
        try { $isDirectory = (Get-Item -LiteralPath $SourcePath -Force).PSIsContainer } catch { }
        $sha  = $null
        $size = $null
        $hashNote = ''
        if ($isDirectory) {
            # F7: directory quarantine - hash each file individually, skip
            # reparse points (junctions/symlinks) per legacy 1099-1130.
            $rows = [System.Collections.ArrayList]::new()
            $reparseSkipped = 0
            try {
                $children = @(Get-ChildItem -LiteralPath $SourcePath -File -Recurse -Force -ErrorAction SilentlyContinue)
                foreach ($f in @($children)) {
                    $isReparse = $false
                    try { $attrs = $f.Attributes; $isReparse = [bool]($attrs -band [System.IO.FileAttributes]::ReparsePoint) } catch { }
                    if ($isReparse) { $reparseSkipped++; continue }
                    $fh = $null
                    try { $fh = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256 -ErrorAction Stop).Hash } catch { }
                    [void]$rows.Add([PSCustomObject]@{
                        Path   = $f.FullName
                        Length = $f.Length
                        SHA256 = $fh
                    })
                }
            } catch { }
            $hashNote = ('directory, ' + @($rows).Count + ' file(s) hashed')
            if ($reparseSkipped -gt 0) { $hashNote += ('; ' + $reparseSkipped + ' reparse point(s) skipped') }
            $sha = $hashNote
            $size = $null
            try {
                $totalLen = 0
                foreach ($r in @($rows)) { $totalLen += $r.Length }
                $size = $totalLen
            } catch { }
        } else {
            try { $sha = (Get-FileHash -LiteralPath $SourcePath -Algorithm SHA256 -ErrorAction Stop).Hash } catch { }
            try { $size = (Get-Item -LiteralPath $SourcePath -Force).Length } catch { }
        }
        # F7: try Move-Item; on failure (in-use file), record resume marker
        # + pending move instead of silently losing the artifact.
        $moveOk = $false
        try {
            Move-Item -LiteralPath $SourcePath -Destination $dest -Force -ErrorAction Stop
            $moveOk = $true
        } catch {
            # F7: record resume marker + pending move for reboot-resume.
            $pendingEntry = [PSCustomObject]@{
                FindingId   = $fid
                SourcePath  = $SourcePath
                DestPath    = $dest
                Error       = $_.Exception.Message
            }
            Write-SccResumeMarker -Run $Run -Phase 'quarantine-pending' -PendingMoves @($pendingEntry)
            # Write manifest entry for the pending move.
            $itemId = [guid]::NewGuid().ToString()
            $entry = [PSCustomObject]@{
                ItemId            = $itemId
                OriginalPath      = $SourcePath
                QuarantinePath    = $dest
                SHA256            = $sha
                SizeBytes         = $size
                MovedUtc          = (Get-Date).ToUniversalTime().ToString('o')
                FindingId         = $fid
                Reason            = $Reason
                ActionType        = $ActionType
                RestoreInstructions = ('Pending reboot - move failed (in-use): ' + $_.Exception.Message)
            }
            Add-SccQuarantineManifestEntry -Run $Run -Entry $entry
            Add-RemediationAction -Run $Run -Action 'Quarantine' -Target $SourcePath -Command ('Move-Item -> ' + $dest) -Result 'PendingReboot' -Error $_.Exception.Message -StartedUtc $started
            return $true
        }
        # ACL hardening: lock down on Windows; best-effort chmod on Linux.
        $isWin = ($env:OS -eq 'Windows_NT')
        if ($isWin) {
            try { & icacls.exe $dest /inheritance:r /grant:r 'SYSTEM:(F)' 'Administrators:(F)' /remove:g '*S-1-1-0' | Out-Null } catch { }
        } else {
            try { chmod 700 $dest } catch { }
        }
        $itemId = [guid]::NewGuid().ToString()
        $entry = [PSCustomObject]@{
            ItemId            = $itemId
            OriginalPath      = $SourcePath
            QuarantinePath    = $dest
            SHA256            = $sha
            SizeBytes         = $size
            MovedUtc          = (Get-Date).ToUniversalTime().ToString('o')
            FindingId         = $fid
            Reason            = $Reason
            ActionType        = $ActionType
            RestoreInstructions = ('Restore by moving ''' + $dest + ''' back to ''' + $SourcePath + ''' (Restore-SccQuarantineItem -Run <RunId> -ItemId ' + $itemId + ').')
        }
        Add-SccQuarantineManifestEntry -Run $Run -Entry $entry
        Add-RemediationAction -Run $Run -Action 'Quarantine' -Target $SourcePath -Command ('Move-Item -> ' + $dest) -Result 'Succeeded' -Error '' -StartedUtc $started
        return $true
    } catch {
        Add-RemediationAction -Run $Run -Action 'Quarantine' -Target $SourcePath -Command '' -Result 'Failed' -Error $_.Exception.Message -StartedUtc $started
        return $false
    }
}

# ===========================================================================
# Public API
# ===========================================================================

function New-SccPlan {
    [CmdletBinding()]
    param(
        [psobject]$Run,
        [Parameter(Mandatory = $true)]$Findings,
        [hashtable]$Decisions
    )

    $createdBy = $env:USERNAME
    if ([string]::IsNullOrEmpty($createdBy)) { $createdBy = $env:USER }
    if ([string]::IsNullOrEmpty($createdBy)) { $createdBy = 'unknown' }

    $items   = @()
    $refused = @()

    foreach ($f in @($Findings)) {
        $fid = [string](Get-Prop $f 'FindingId')
        if ([string]::IsNullOrEmpty($fid)) { $fid = 'unknown' }
        $prod = Get-Prop $f 'Product'
        if ($null -eq $prod) { $prod = '' }
        $prodStr = $prod.ToString()

        $action = 'KEEP'
        if ($Decisions -and $Decisions.ContainsKey($fid)) {
            $dec = $Decisions[$fid]
            if ($dec -and $dec.ToString().ToUpperInvariant() -eq 'REMOVE') { $action = 'REMOVE' }
            # any other (malformed) value is ignored and stays KEEP
        }

        # Owner policy: only ScreenConnect may be REMOVE. Refuse anything else.
        if ($action -eq 'REMOVE' -and $prodStr.ToLowerInvariant() -ne 'screenconnect') {
            $refused += ('{0} (Product={1})' -f $fid, $prodStr)
            continue
        }

        $targetType = Get-Prop $f 'TargetType'
        if ($null -eq $targetType -or [string]::IsNullOrEmpty($targetType.ToString())) { $targetType = 'Uninstall' }
        $detail = Get-Prop $f 'Detail'
        if ($null -eq $detail) { $detail = '' }
        $display = Get-Prop $f 'DisplayText'
        if ($null -eq $display -or [string]::IsNullOrEmpty($display.ToString())) {
            $display = ('{0} [{1}]' -f $fid, $prodStr)
        }

        $item = [PSCustomObject]@{
            FindingId           = $fid
            Product             = $prodStr
            TargetType          = $targetType.ToString()
            Action              = $action
            Detail              = $detail.ToString()
            DisplayText         = $display.ToString()
            # remediation extras (read by Invoke-SccRemediation)
            ServiceName         = [string](Get-Prop $f 'ServiceName')
            InstallDir          = [string](Get-Prop $f 'InstallDir')
            MainExe             = [string](Get-Prop $f 'MainExe')
            ServiceImagePath    = [string](Get-Prop $f 'ServiceImagePath')
            UninstallRegistryKey = [string](Get-Prop $f 'UninstallRegistryKey')
            RelayHost           = [string](Get-Prop $f 'RelayHost')
        }
        $qp = Get-Prop $f 'QuarantinePaths'
        if ($null -ne $qp) {
            Add-Member -InputObject $item -MemberType NoteProperty -Name 'QuarantinePaths' -Value @($qp)
        }
        $items += $item
    }

    if (@($refused).Count -gt 0) {
        $msg = ('Refusing to plan removal of non-ScreenConnect products (owner policy: only ScreenConnect may be REMOVE): ' + (@($refused) -join '; '))
        throw [System.InvalidOperationException]::new($msg)
    }

    $plan = [PSCustomObject]@{
        PlanVersion = '1.0'
        CreatedUtc  = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
        CreatedBy   = $createdBy
        Items       = $items
    }

    if ($Run -and $Run.RunDir) {
        try {
            if (-not (Test-Path -LiteralPath $Run.RunDir)) { New-Item -ItemType Directory -Path $Run.RunDir -Force | Out-Null }
            $planPath = Join-Path $Run.RunDir 'plan.json'
            [System.IO.File]::WriteAllText($planPath, (ConvertTo-SccJson -InputObject $plan -Depth 10), [System.Text.Encoding]::ASCII)
        } catch {
            Write-SccRemedyLog -Level WARNING -Stage 'Remedy' -Message ('Could not write plan.json: ' + $_.Exception.Message)
        }
    }

    return $plan
}

function Test-SccPlan {
    [CmdletBinding()]
    param(
        [psobject]$Run,
        [Parameter(Mandatory = $true)]$Plan
    )
    $p = Resolve-SccPlan -Plan $Plan
    return @(Get-SccPlanPreview -Plan $p)
}

function Test-SccIsAdmin {
    $isWindows = ($env:OS -eq 'Windows_NT')
    if (-not $isWindows) { return $true }
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $p = [System.Security.Principal.WindowsPrincipal]::new($id)
        return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function Invoke-SccRemediation {
    [CmdletBinding()]
    param(
        [psobject]$Run,
        [Parameter(Mandatory = $true)]$Plan,
        [switch]$Execute
    )

    $p = $null
    try { $p = Resolve-SccPlan -Plan $Plan } catch { throw }

    $script:remediationActions = @()
    $script:remediationPath    = $null
    if ($Run -and $Run.RunDir) { $script:remediationPath = Join-Path $Run.RunDir 'remediation.json' }

    $preview = @(Get-SccPlanPreview -Plan $p)

    if (-not $Execute) {
        Write-SccRemedyLog -Level INFO -Stage 'Remedy' -Message 'Dry-run: no changes made (pass -Execute to perform remediation).'
        return $preview
    }

    # F6: admin gate before any -Execute mutation (legacy remove-screenconnect.ps1:80-87).
    # On non-Windows where admin check is meaningless, gate on $env:OS so tests pass.
    if (-not (Test-SccIsAdmin)) {
        throw [System.InvalidOperationException]::new('Execute requires an elevated (Administrator) shell. Aborting remediation.')
    }

    # Config-driven "stop on first item failure" (default: continue the run).
    $stopOnFail = $false
    try {
        $config = Get-SccConfig
        if ($config -and $config.safety -and $config.safety.stopOnItemFailure) { $stopOnFail = $true }
    } catch { }

    $itemHadFailure = $false
    foreach ($item in @($p.Items)) {
        $itemHadFailure = $false
        $fid    = [string](Get-Prop $item 'FindingId')
        $prod   = [string](Get-Prop $item 'Product')
        $action = [string](Get-Prop $item 'Action')

        if ($action -ne 'REMOVE') {
            Add-RemediationAction -Run $Run -Action 'SkipItem' -Target $fid -Command '' -Result 'Skipped' -Error 'KEEP decision - no action'
            continue
        }
        if ($prod.ToLowerInvariant() -ne 'screenconnect') {
            Add-RemediationAction -Run $Run -Action 'SkipItem' -Target $fid -Command '' -Result 'Skipped' -Error ('non-ScreenConnect product refused: ' + $prod)
            continue
        }

        # Per-item re-verification (plan-tampering protection).
        $verified = $false
        try { $verified = Test-SccScreenConnectTarget -PlanItem $item } catch { $verified = $false }
        if (-not $verified) {
            Add-RemediationAction -Run $Run -Action 'ReVerify' -Target $fid -Command '' -Result 'Skipped' -Error 're-verification failed - target does not match ScreenConnect identity; item skipped'
            continue
        }
        Add-RemediationAction -Run $Run -Action 'ReVerify' -Target $fid -Command '' -Result 'Succeeded' -Error ''

        try {
            $svc = [string](Get-Prop $item 'ServiceName')
            $dir = [string](Get-Prop $item 'InstallDir')

            # 1. Stop service
            if ($svc) {
                if (-not (Stop-SccTargetService -ServiceName $svc -PlanItem $item -Run $Run)) { $itemHadFailure = $true }
            }
            # 2. Kill processes
            if (-not (Stop-SccTargetProcesses -InstallDir $dir -ServiceName $svc -PlanItem $item -Run $Run)) { $itemHadFailure = $true }
            # 3. Vendor uninstaller (registry-derived)
            if (-not (Uninstall-SccTarget -PlanItem $item -Run $Run)) { $itemHadFailure = $true }
            # 4. Validate removal
            $removed = $false
            try { $removed = Test-SccTargetRemoved -PlanItem $item -Run $Run } catch { $removed = $false }
            if (-not $removed) { $itemHadFailure = $true }
            # 5. Leftover cleanup
            if ($svc) {
                if (-not (Remove-SccTargetService -ServiceName $svc -PlanItem $item -Run $Run)) { $itemHadFailure = $true }
            }
            if (-not (Remove-SccTargetScheduledTask -InstallDir $dir -PlanItem $item -Run $Run)) { $itemHadFailure = $true }
            if (-not (Remove-SccTargetRunKey -InstallDir $dir -PlanItem $item -Run $Run)) { $itemHadFailure = $true }
            if (-not (Remove-SccTargetFirewallRule -InstallDir $dir -PlanItem $item -Run $Run)) { $itemHadFailure = $true }
            # 6. Quarantine remaining artifacts
            $arts = @()
            $qp = Get-Prop $item 'QuarantinePaths'
            if ($null -ne $qp) { $arts = @($qp) }
            elseif ($dir -and (Test-Path -LiteralPath $dir)) { $arts = @($dir) }
            foreach ($a in $arts) {
                if (-not (Move-SccTargetToQuarantine -SourcePath ([string]$a) -PlanItem $item -Run $Run -Reason 'remaining artifact after ScreenConnect remediation' -ActionType 'File')) {
                    $itemHadFailure = $true
                }
            }
            Write-SccRemedyLog -Level INFO -Stage 'Remedy' -Message ('Completed remediation item: ' + $fid)
        } catch {
            $itemHadFailure = $true
            Add-RemediationAction -Run $Run -Action 'ProcessItem' -Target $fid -Command '' -Result 'Failed' -Error $_.Exception.Message
        }

        if ($itemHadFailure -and $stopOnFail) { break }
    }

    return $preview
}

function Test-SccRestorePathSafe {
    param([string]$OriginalPath, [string]$QuarantineRoot)
    if ([string]::IsNullOrEmpty($OriginalPath)) { return $false }
    # Reject any path containing '..' as a literal component.
    $parts = $OriginalPath -replace '\\', '/' -split '/'
    foreach ($p in @($parts)) {
        if ($p -eq '..') { return $false }
    }
    $resolved = $null
    try { $resolved = [System.IO.Path]::GetFullPath($OriginalPath) } catch { return $false }
    if ($resolved -ne $OriginalPath) { return $false }
    $isAbsolute = ($resolved -match '^[A-Za-z]:\\') -or ($resolved -match '^/')
    if (-not $isAbsolute) { return $false }
    if (-not [string]::IsNullOrEmpty($QuarantineRoot)) {
        $qResolved = $null
        try { $qResolved = [System.IO.Path]::GetFullPath($QuarantineRoot) } catch { }
        if (-not [string]::IsNullOrEmpty($qResolved)) {
            if ($resolved -like ($qResolved + '*')) { return $false }
        }
    }
    return $true
}

function Restore-SccQuarantineItem {
    [CmdletBinding()]
    param(
        [psobject]$Run,
        [Parameter(Mandatory = $true)][string]$ItemId
    )
    $list = @(Get-SccQuarantineManifest -Run $Run)
    $entry = $null
    foreach ($e in @($list)) {
        if ([string]$e.ItemId -eq $ItemId) { $entry = $e; break }
    }
    if ($null -eq $entry) {
        throw [System.InvalidOperationException]::new(('Quarantine item not found: ' + $ItemId))
    }
    $src = [string]$entry.QuarantinePath
    $dst = [string]$entry.OriginalPath
    # F3: validate OriginalPath is safe - no traversal, absolute, not inside
    # quarantine scope. Canonicalize and reject if unsafe.
    $qRoot = Get-SccRemedyQuarantineRoot -Run $Run
    if (-not (Test-SccRestorePathSafe -OriginalPath $dst -QuarantineRoot $qRoot)) {
        throw [System.InvalidOperationException]::new(('Refusing to restore: OriginalPath is unsafe (traversal, non-absolute, or escapes quarantine scope): ' + $dst))
    }
    if (-not (Test-Path -LiteralPath $src)) {
        throw [System.InvalidOperationException]::new(('Quarantine file not present: ' + $src))
    }
    if (Test-Path -LiteralPath $dst) {
        throw [System.InvalidOperationException]::new(('Refusing to restore: destination already exists (no overwrite): ' + $dst))
    }
    $parent = Split-Path -Parent $dst
    if (-not [string]::IsNullOrEmpty($parent) -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    Move-Item -LiteralPath $src -Destination $dst -Force -ErrorAction Stop
    Remove-SccQuarantineManifestEntry -Run $Run -ItemId $ItemId
    Write-SccRemedyLog -Level INFO -Stage 'Remedy' -Message ('Restored quarantine item ' + $ItemId + ' to ' + $dst)
    return $true
}

function Clear-SccQuarantine {
    [CmdletBinding()]
    param(
        [psobject]$Run,
        [switch]$Approved,
        [string]$ConfirmText
    )
    if (-not $Approved -or $ConfirmText -ne 'PERMANENTLY DELETE') {
        Write-SccRemedyLog -Level WARNING -Stage 'Remedy' -Message 'Clear-SccQuarantine refused: requires -Approved and -ConfirmText "PERMANENTLY DELETE".'
        throw [System.InvalidOperationException]::new('Clear-SccQuarantine refused: both -Approved and -ConfirmText "PERMANENTLY DELETE" are required (never automatic).')
    }
    $qBase = Get-SccRemedyQuarantineRoot -Run $Run
    $qDir  = Join-Path $qBase 'q'
    if (Test-Path -LiteralPath $qDir) { Remove-Item -LiteralPath $qDir -Recurse -Force -ErrorAction Stop }
    $mp = Join-Path $qBase 'quarantine-manifest.json'
    if (Test-Path -LiteralPath $mp) { Remove-Item -LiteralPath $mp -Force -ErrorAction Stop }
    Write-SccRemedyLog -Level WARNING -Stage 'Remedy' -Message 'Quarantine permanently deleted.'
    return $true
}

# ===========================================================================
# Exports (minimal public surface)
# ===========================================================================
Export-ModuleMember -Function @(
    'New-SccPlan'
    'Test-SccPlan'
    'Invoke-SccRemediation'
    'Restore-SccQuarantineItem'
    'Clear-SccQuarantine'
)

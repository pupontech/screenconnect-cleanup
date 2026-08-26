# Scc.Scanners.psm1 - Scanner management and adapters for ScreenConnect Cleaner
#
# Exports: Get-SccScannerList, Invoke-SccScanner, Invoke-SccGuiScanner
# Private: Invoke-ProcessWithTimeout, Invoke-SccDefenderAdapter,
#          Invoke-SccKVRTAdapter, Invoke-SccMSERTAdapter,
#          New-SccScanResult, Write-SccScannerLog, Get-SccTempRoot,
#          Resolve-SccScannerToolPath, Copy-SccScanLogs,
#          Copy-SccKVRTScanLogs, Copy-SccMSERTScanLogs
#
# PS 5.1 compatible. Pure ASCII. No ternary, no ??, no &&, no -AsHashtable.

# ---------------------------------------------------------------------------
# Private: Default scanner configuration
# ---------------------------------------------------------------------------


# Ensure Microsoft.PowerShell.Utility cmdlets ([datetime]::UtcNow, New-Object, ConvertTo-Json,
# Out-Null, Add-Member, etc.) are visible inside this module's session state on every
# host. Without this, module functions fail with CommandNotFoundException on Windows
# when the module is loaded through Pester or a nested session state.
$null = Import-Module -Name 'Microsoft.PowerShell.Utility' -ErrorAction SilentlyContinue
$null = Import-Module -Name 'Microsoft.PowerShell.Management' -ErrorAction SilentlyContinue

$script:DefaultScanners = @{
    Enabled = @('MicrosoftDefender', 'KVRT', 'MSERT')
    Order   = @('MicrosoftDefender', 'KVRT', 'MSERT')
    Attended = @('AdwCleaner', 'ESETOnline', 'Malwarebytes')
    DefaultTimeoutMinutes = 120
}

# MSERT verified switches (from vendor docs; see header comment in adapter).
$script:MSERTVerifiedSwitches = @('/Q', '/F', '/F:Y', '/N')

# ---------------------------------------------------------------------------
# Private: Get-SccMpThreatDetections
#   Wrapper for Get-MpThreatDetection that is mockable in tests.
#   On non-Windows, the cmdlet doesn't exist and this returns @().
# ---------------------------------------------------------------------------
function Get-SccMpThreatDetections {
    try {
        return @(Get-MpThreatDetection -ErrorAction Stop)
    } catch {
        return @()
    }
}

# ---------------------------------------------------------------------------
# Private: Get-SccMpComputerStatusVersion
#   Wrapper for Get-MpComputerStatus that is mockable in tests.
# ---------------------------------------------------------------------------
function Get-SccMpComputerStatusVersion {
    try {
        $s = Get-MpComputerStatus -ErrorAction Stop
        if ($s -and $s.AMServiceVersion) { return [string]$s.AMServiceVersion }
    } catch { }
    return ''
}

# ---------------------------------------------------------------------------
# Private: New-SccScanResult
#   Creates the standard scanner result object per contract.
# ---------------------------------------------------------------------------
function New-SccScanResult {
    param([string]$ScannerName = '')
    [PSCustomObject]@{
        ScannerName     = $ScannerName
        ScannerVersion  = ''
        Available       = $false
        StartTimeUtc    = ''
        EndTimeUtc      = ''
        DurationSeconds = 0
        Status          = 'NotInstalled'
        ExitCode        = $null
        Detections      = @()
        DetectionCount  = 0
        LogPath         = ''
        RebootRequired  = $false
        Errors          = @()
        CommandLine     = ''
        ToolSource      = ''
        ToolVersion     = ''
        ToolSHA256      = ''
    }
}

# ---------------------------------------------------------------------------
# Private: Invoke-ProcessWithTimeout
#   Run a child process with both stdio streams redirected and a hard timeout.
#   PS 5.1-safe drain pattern from legacy adapters.
#   Returns hashtable: TimedOut, StreamDrainTimedOut, ExitCode, StdOut, StdErr
# ---------------------------------------------------------------------------
function Invoke-ProcessWithTimeout {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$ArgumentList,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds
    )

    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $FilePath
    $psi.Arguments = ($ArgumentList -join ' ')
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $proc = [System.Diagnostics.Process]::Start($psi)

    # Drain both streams concurrently to prevent pipe deadlock
    $stdoutTask = $proc.StandardOutput.ReadToEndAsync()
    $stderrTask = $proc.StandardError.ReadToEndAsync()

    $timedOut = -not $proc.WaitForExit($TimeoutSeconds * 1000)
    if ($timedOut) {
        try { $proc.Kill() } catch { }
        try { $null = $proc.WaitForExit(2000) } catch { }
    }

    $stdout = ''
    $stderrText = ''
    $streamDrainTimedOut = $false
    $streamTasks = [System.Threading.Tasks.Task[]]@($stdoutTask, $stderrTask)
    $allDrained = [System.Threading.Tasks.Task]::WaitAll($streamTasks, 5000)
    if ($allDrained) {
        try { $stdout = [string]$stdoutTask.GetAwaiter().GetResult() } catch { $stdout = '' }
        try { $stderrText = [string]$stderrTask.GetAwaiter().GetResult() } catch { $stderrText = '' }
    } else {
        $streamDrainTimedOut = $true
    }

    $exitCode = $null
    if (-not $timedOut) {
        try { $exitCode = $proc.ExitCode } catch { }
    }

    return @{
        TimedOut            = $timedOut
        StreamDrainTimedOut = $streamDrainTimedOut
        ExitCode            = $exitCode
        StdOut              = $stdout
        StdErr              = $stderrText
    }
}

# ---------------------------------------------------------------------------
# Private: Write-SccScannerLog
# ---------------------------------------------------------------------------
function Write-SccScannerLog {
    param([string]$ScannerName, [string]$Message)
    $line = ('[{0}] [{1}] {2}' -f ([datetime]::UtcNow).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss'), $ScannerName, $Message)
    Write-Verbose $line
}

# ---------------------------------------------------------------------------
# Private: Get-SccTempRoot
# ---------------------------------------------------------------------------
function Get-SccTempRoot {
    if ($env:TEMP) { return $env:TEMP }
    if ($env:TMP) { return $env:TMP }
    return (Microsoft.PowerShell.Management\Get-Location).Path
}

# ---------------------------------------------------------------------------
# Private: Resolve-SccScannerToolPath
#   Attempt to import Scc.Tools and resolve tool via Resolve-SccTool.
#   Falls back to candidate path scanning if Scc.Tools is unavailable.
# ---------------------------------------------------------------------------
function Resolve-SccScannerToolPath {
    param(
        [string]$ToolName,
        [string]$ExplicitPath,
        [string[]]$CandidatePaths
    )

    if ($ExplicitPath) {
        if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $ExplicitPath) { return $ExplicitPath }
        return $null
    }

    # Try Scc.Tools module if importable
    try {
        $sccToolsPath = Join-Path $PSScriptRoot '..\Scc.Tools\Scc.Tools.psd1'
        if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $sccToolsPath) {
            try {
                Import-Module -Name $sccToolsPath -Force -ErrorAction Stop
                $resolved = Resolve-SccTool -Tool $ToolName -ErrorAction SilentlyContinue
                if ($resolved -and $resolved.ResolvedPath -and (Microsoft.PowerShell.Management\Test-Path -LiteralPath $resolved.ResolvedPath)) {
                    return $resolved.ResolvedPath
                }
            } catch { }
        }
    } catch {
        # On non-Windows, Join-Path with relative Windows paths may fail
    }

    # Fallback: scan candidate paths
    foreach ($c in $CandidatePaths) {
        if ($c -and (Microsoft.PowerShell.Management\Test-Path -LiteralPath $c)) { return $c }
    }
    return $null
}

# ---------------------------------------------------------------------------
# Private: Copy-SccScanLogs (Defender support folder logs)
# ---------------------------------------------------------------------------
function Copy-SccScanLogs {
    param(
        [string]$DestinationDir,
        [int]$SinceMinutes
    )
    if (-not $DestinationDir) { return '' }
    try {
        if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $DestinationDir)) {
            Microsoft.PowerShell.Management\New-Item -ItemType Directory -Path $DestinationDir -Force | Out-Null
        }
        try {
            $supportRoot = Join-Path $env:ProgramData 'Microsoft\Windows Defender\Support'
        } catch {
            return ''
        }
        $cutoff = ([datetime]::UtcNow).AddMinutes(-1 * [Math]::Max($SinceMinutes, 5))
        $copied = @()
        if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $supportRoot) {
            $files = @(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $supportRoot -File -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -ge $cutoff } |
                Sort-Object LastWriteTime -Descending | Select-Object -First 10)
            foreach ($f in $files) {
                Microsoft.PowerShell.Management\Copy-Item -LiteralPath $f.FullName -Destination $DestinationDir -Force
                $copied += $f.Name
            }
        }
        return (@($copied) -join ', ')
    } catch {
        Write-SccScannerLog -ScannerName 'Defender' -Message ("Log copy failed: " + $_.Exception.Message)
        return ''
    }
}

# ---------------------------------------------------------------------------
# Private: Copy-SccKVRTScanLogs
# ---------------------------------------------------------------------------
function Copy-SccKVRTScanLogs {
    param(
        [string]$DestinationDir,
        [string]$DataDir,
        [int]$SinceMinutes
    )
    if (-not $DestinationDir) { return '' }
    try {
        if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $DestinationDir)) {
            Microsoft.PowerShell.Management\New-Item -ItemType Directory -Path $DestinationDir -Force | Out-Null
        }
        $roots = @()
        if ($DataDir) { $roots += $DataDir }
        try {
            $sysDrive = $env:SystemDrive
            if (-not $sysDrive) { $sysDrive = 'C:' }
            $wildcard = Join-Path ($sysDrive + '\') 'KVRT*_Data'
            try {
                $found = @(Microsoft.PowerShell.Management\Get-Item -Path $wildcard -ErrorAction SilentlyContinue)
                foreach ($f in $found) { $roots += $f.FullName }
            } catch { }
        } catch {
            # On non-Windows, Join-Path with drive letters fails
        }

        $cutoff = ([datetime]::UtcNow).AddMinutes(-1 * [Math]::Max($SinceMinutes, 5))
        $copied = @()
        foreach ($r in $roots) {
            if (-not $r -or -not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $r)) { continue }
            $files = @(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $r -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -ge $cutoff } |
                Sort-Object LastWriteTime -Descending | Select-Object -First 20)
            foreach ($f in $files) {
                Microsoft.PowerShell.Management\Copy-Item -LiteralPath $f.FullName -Destination $DestinationDir -Force
                $copied += $f.Name
            }
        }
        return (@($copied | Select-Object -Unique) -join ', ')
    } catch {
        Write-SccScannerLog -ScannerName 'KVRT' -Message ("Log copy failed: " + $_.Exception.Message)
        return ''
    }
}

# ---------------------------------------------------------------------------
# Private: Copy-SccMSERTScanLogs
# ---------------------------------------------------------------------------
function Copy-SccMSERTScanLogs {
    param(
        [string]$DestinationDir,
        [string]$LogFile
    )
    if (-not $DestinationDir -or -not $LogFile) { return '' }
    try {
        if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $DestinationDir)) {
            Microsoft.PowerShell.Management\New-Item -ItemType Directory -Path $DestinationDir -Force | Out-Null
        }
        if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $LogFile) {
            Microsoft.PowerShell.Management\Copy-Item -LiteralPath $LogFile -Destination $DestinationDir -Force
            try {
                return (Join-Path $DestinationDir (Split-Path -Leaf $LogFile))
            } catch {
                return $LogFile
            }
        }
    } catch {
        Write-SccScannerLog -ScannerName 'MSERT' -Message ("Log copy failed: " + $_.Exception.Message)
    }
    return ''
}

# ---------------------------------------------------------------------------
# Public: Get-SccScannerList
# ---------------------------------------------------------------------------
function Get-SccScannerList {
    [CmdletBinding()]
    param(
        [switch]$EnabledOnly,
        [hashtable]$Config
    )

    $cfg = $script:DefaultScanners
    if ($Config -and $Config.ContainsKey('scanners')) {
        $cfg = $Config['scanners']
    }

    $allScanners = @(
        @{ Name = 'MicrosoftDefender'; Type = 'Cli';    Enabled = $true;  Order = 1;  Catalog = 'Built-in (MpCmdRun.exe)' }
        @{ Name = 'KVRT';              Type = 'Cli';    Enabled = $true;  Order = 2;  Catalog = 'Kaspersky (KVRT.exe)' }
        @{ Name = 'MSERT';             Type = 'Cli';    Enabled = $true;  Order = 3;  Catalog = 'Microsoft Safety Scanner (msert.exe)' }
        @{ Name = 'AdwCleaner';        Type = 'Attended'; Enabled = $false; Order = 4; Catalog = 'Malwarebytes (adwcleaner.exe)' }
        @{ Name = 'ESETOnline';        Type = 'Attended'; Enabled = $false; Order = 5; Catalog = 'ESET Online Scanner' }
        @{ Name = 'Malwarebytes';      Type = 'Attended'; Enabled = $false; Order = 6; Catalog = 'Malwarebytes (MBSetup.exe)' }
    )

    $enabledSet = @{}
    if ($cfg.ContainsKey('Enabled')) {
        foreach ($n in @($cfg['Enabled'])) { $enabledSet[$n] = $true }
    }
    $orderMap = @{}
    if ($cfg.ContainsKey('Order')) {
        $idx = 1
        foreach ($n in @($cfg['Order'])) { $orderMap[$n] = $idx; $idx++ }
    }

    $result = @()
    foreach ($s in $allScanners) {
        $s['Enabled'] = $enabledSet.ContainsKey($s['Name'])
        if ($orderMap.ContainsKey($s['Name'])) {
            $s['Order'] = $orderMap[$s['Name']]
        }
        if ($EnabledOnly -and -not $s['Enabled']) { continue }
        $result += [PSCustomObject]$s
    }

    return $result | Sort-Object Order
}

# ---------------------------------------------------------------------------
# Public: Invoke-SccScanner
#   Main dispatcher. Runs CLI adapters via background runspace for timeout.
# ---------------------------------------------------------------------------
function Invoke-SccScanner {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][hashtable]$Run,
        [string]$ScanPath,
        [int]$TimeoutMinutes = 120
    )

    $isWhatIf = $false
    if ($PSCmdlet) {
        $isWhatIf = $WhatIfPreference -or $PSCmdlet.ShouldProcess('scan', 'run')
        $isWhatIf = -not $PSCmdlet.ShouldProcess('scan', 'run')
    }
    if ($PSBoundParameters.ContainsKey('WhatIf')) {
        $isWhatIf = $true
    }

    $errors = @()

    # Resolve the config
    $config = $null
    try {
        $corePath = (Join-Path $PSScriptRoot '..\Scc.Core\Scc.Core.psd1')
        if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $corePath) {
            Import-Module -Name $corePath -Force -ErrorAction Stop
            $config = Get-SccConfig -ErrorAction SilentlyContinue
        }
    } catch { }

    # Default timeout from config
    if ($TimeoutMinutes -lt 1) {
        if ($config -and $config.ContainsKey('scanners') -and
            $config['scanners'].ContainsKey('defaultTimeoutMinutes')) {
            $TimeoutMinutes = [int]$config['scanners']['defaultTimeoutMinutes']
        } else {
            $TimeoutMinutes = 120
        }
    }

    # Resolve log directory from run
    $logDir = ''
    if ($Run.ContainsKey('RunDir')) {
        try {
            $logDir = Join-Path $Run['RunDir'] ('scanner-results\' + $Name)
        } catch {
            # On non-Windows, Join-Path with Windows-style paths may fail
            $logDir = ''
        }
    }

    # Delegate to the appropriate adapter
    $adapterResult = $null
    try {
        switch ($Name) {
            'MicrosoftDefender' {
                $adapterResult = Invoke-SccDefenderAdapter -ScanPath $ScanPath `
                    -TimeoutMinutes $TimeoutMinutes -LogDir $logDir -WhatIf:$isWhatIf
            }
            'KVRT' {
                $adapterResult = Invoke-SccKVRTAdapter -ScanPath $ScanPath `
                    -TimeoutMinutes $TimeoutMinutes -LogDir $logDir -WhatIf:$isWhatIf
            }
            'MSERT' {
                $adapterResult = Invoke-SccMSERTAdapter -ScanPath $ScanPath `
                    -TimeoutMinutes $TimeoutMinutes -LogDir $logDir -WhatIf:$isWhatIf
            }
            default {
                $r = New-SccScanResult -ScannerName $Name
                $r.Status = 'Skipped'
                $r.Errors = @(('Unknown scanner name: ' + $Name))
                $r.StartTimeUtc = ([datetime]::UtcNow).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
                $r.EndTimeUtc = $r.StartTimeUtc
                return $r
            }
        }
    } catch {
        $errors += ('Adapter invocation failed: ' + $_.Exception.Message)
        $adapterResult = New-SccScanResult -ScannerName $Name
        $adapterResult.Status = 'Failed'
        $adapterResult.Errors = @($errors)
        $adapterResult.StartTimeUtc = ([datetime]::UtcNow).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
        $adapterResult.EndTimeUtc = $adapterResult.StartTimeUtc
    }

    # Try to record scan state in runstate via Scc.Core
    try {
        $corePath2 = (Join-Path $PSScriptRoot '..\Scc.Core\Scc.Core.psd1')
        if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $corePath2) {
            Import-Module -Name $corePath2 -Force -ErrorAction SilentlyContinue
            Save-SccRunState -Run $Run -Stage 'Scanners' -Status 'Completed' `
                -Detail ("Scan " + $Name + " completed with status " + $adapterResult.Status) `
                -ErrorAction SilentlyContinue
        }
    } catch { }

    return $adapterResult
}

# ---------------------------------------------------------------------------
# Public: Invoke-SccGuiScanner
#   Attended GUI scanner launcher. Launches visible, waits for close.
# ---------------------------------------------------------------------------
function Invoke-SccGuiScanner {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][hashtable]$Run,
        [string]$ToolPath,
        [int]$TimeoutMinutes = 240
    )

    $start = [datetime]::UtcNow
    $knownTools = @{
        'ESET'         = 'esetonlinescanner.exe'
        'Malwarebytes' = 'MBSetup.exe'
        'AdwCleaner'   = 'adwcleaner.exe'
    }

    $toolExeName = ''
    if ($knownTools.ContainsKey($Name)) { $toolExeName = $knownTools[$Name] }

    # Build candidate paths (wrapped for cross-platform safety)
    $candidates = @()
    try {
        if ($toolExeName) {
            $candidates += (Join-Path $PSScriptRoot $toolExeName)
            $candidates += (Join-Path (Split-Path -Parent $PSScriptRoot) ('tools\AV\' + $toolExeName))
        }
        if ($Name -eq 'AdwCleaner') { $candidates += 'C:\AdwCleaner\adwcleaner.exe' }
        $homeDir = ''
        if ($env:USERPROFILE) { $homeDir = $env:USERPROFILE }
        elseif ($env:HOME) { $homeDir = $env:HOME }
        if ($homeDir -and $toolExeName) { $candidates += (Join-Path $homeDir ('Downloads\' + $toolExeName)) }
        $candidates += (Join-Path (Get-SccTempRoot) $toolExeName)
    } catch {
        # On non-Windows, Join-Path with Windows-style paths may fail
    }

    $target = Resolve-SccScannerToolPath -ToolName $Name -ExplicitPath $ToolPath -CandidatePaths $candidates

    if (-not $target) {
        $end = [datetime]::UtcNow
        return [PSCustomObject]@{
            ScannerName     = $Name
            StartedUtc      = $start.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
            EndedUtc        = $end.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
            DurationSeconds = [int]($end - $start).TotalSeconds
            Result          = 'ToolUnavailable'
            ExitCode        = $null
            Error           = ('Tool not found: ' + $Name + '. Stage it first with tools/Get-AVTools.ps1 or pass -ToolPath.')
        }
    }

    # Launch visible (no CreateNoWindow, no redirects - GUI app)
    try {
        $proc = Microsoft.PowerShell.Management\Start-Process -FilePath $target -PassThru -ErrorAction Stop
    } catch {
        $end = [datetime]::UtcNow
        return [PSCustomObject]@{
            ScannerName     = $Name
            StartedUtc      = $start.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
            EndedUtc        = $end.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
            DurationSeconds = [int]($end - $start).TotalSeconds
            Result          = 'LaunchFailed'
            ExitCode        = $null
            Error           = $_.Exception.Message
        }
    }

    # Wait with timeout - process left running on timeout (owner policy)
    $timedOut = -not $proc.WaitForExit($TimeoutMinutes * 60 * 1000)

    $end = [datetime]::UtcNow
    $exitCode = $null
    if (-not $timedOut) {
        try { $exitCode = $proc.ExitCode } catch { }
    }

    $result = 'Completed'
    if ($timedOut) { $result = 'Timeout' }

    return [PSCustomObject]@{
        ScannerName     = $Name
        StartedUtc      = $start.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
        EndedUtc        = $end.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
        DurationSeconds = [int]($end - $start).TotalSeconds
        Result          = $result
        ExitCode        = $exitCode
        Error           = ''
    }
}

# ---------------------------------------------------------------------------
# Private: Invoke-SccDefenderAdapter
#   Microsoft Defender via MpCmdRun.exe.
#   Contract: -ScanType 3 + -DisableRemediation (detect-only).
#   Historical detections via Get-MpThreatDetection, labeled "Historical".
# ---------------------------------------------------------------------------
function Invoke-SccDefenderAdapter {
    [CmdletBinding()]
    param(
        [string]$ScanPath,
        [int]$TimeoutMinutes = 120,
        [string]$LogDir,
        [switch]$WhatIf
    )

    $scannerName = 'MicrosoftDefender'
    $start = [datetime]::UtcNow
    $errors = @()

    # Locate MpCmdRun.exe via centralized resolver
    $candidates = @()
    try {
        $programFiles = $env:ProgramFiles
        if (-not $programFiles) { $programFiles = 'C:\Program Files' }
        $candidates += (Join-Path $programFiles 'Windows Defender\MpCmdRun.exe')
        $candidates = @($candidates | Where-Object { $_ })
    } catch {
        # Non-Windows: join-path with drive letters fails
    }
    $tool = Resolve-SccScannerToolPath -ToolName 'MpCmdRun' -CandidatePaths $candidates

    if (-not $tool) {
        $r = New-SccScanResult -ScannerName $scannerName
        $r.Status = 'NotInstalled'
        $r.StartTimeUtc = $start.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
        $r.EndTimeUtc = ([datetime]::UtcNow).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
        $r.Errors = @('MpCmdRun.exe not found (checked Platform versions and Program Files)')
        return $r
    }

    # Version from Get-MpComputerStatus
    $version = Get-SccMpComputerStatusVersion

    # Build command line per Microsoft doc
    if (-not $TimeoutMinutes -or $TimeoutMinutes -lt 1) { $TimeoutMinutes = 120 }

    $systemDrive = $env:SystemDrive
    if (-not $systemDrive) { $systemDrive = 'C:' }

    $argList = @('-Scan', '-ScanType', '3')
    if ($ScanPath) {
        $argList += @('-File', ('"' + $ScanPath + '"'))
    } else {
        $argList += @('-File', ('"' + $systemDrive + '\\"'))
    }
    $argList += '-DisableRemediation'
    $commandLine = ('"' + $tool + '" ' + ($argList -join ' '))

    if ($WhatIf) {
        $r = New-SccScanResult -ScannerName $scannerName
        $r.Available = $true
        $r.Status = 'Skipped'
        $r.ScannerVersion = $version
        $r.StartTimeUtc = $start.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
        $r.EndTimeUtc = ([datetime]::UtcNow).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
        $r.CommandLine = $commandLine
        return $r
    }

    # Run the scan
    $run = $null
    try {
        $run = Invoke-ProcessWithTimeout -FilePath $tool -ArgumentList $argList `
            -TimeoutSeconds ($TimeoutMinutes * 60)
    } catch {
        $errors += ('Scan execution failed: ' + $_.Exception.Message)
    }

    $timedOut = $false
    $exitCode = $null
    if ($null -ne $run) {
        $timedOut = $run.TimedOut
        $exitCode = $run.ExitCode
        if ($timedOut) {
            $errors += ('Scanner did not finish within ' + $TimeoutMinutes + ' minute(s); process was terminated.')
        }
        if ($run.StreamDrainTimedOut) {
            $errors += 'Scanner output streams did not close within the drain window after termination; captured output may be incomplete.'
        }
    }

    $end = [datetime]::UtcNow
    $duration = [int]($end - $start).TotalSeconds

    # Exit code mapping per Microsoft doc
    $status = 'Failed'
    if ($timedOut) {
        $status = 'Timeout'
    } elseif ($null -ne $exitCode) {
        if ($exitCode -eq 0 -or $exitCode -eq 2) { $status = 'Completed' }
        else {
            $status = 'Failed'
            $errors += ('Unexpected exit code ' + $exitCode + ' from MpCmdRun')
        }
    }

    # Collect historical detections (labeled, never attributed to this run)
    $detections = @()
    $dets = Get-SccMpThreatDetections
    foreach ($d in $dets) {
        $res = ''
        if ($null -ne $d.Resources) { $res = (@($d.Resources) -join '; ') }
        $action = ''
        if ($null -ne $d.ActionSuccess) {
            if ($d.ActionSuccess) { $action = 'Succeeded' } else { $action = 'Failed' }
        }
        $sev = ''
        try {
            if ($null -ne $d.ThreatID) {
                $cat = Get-MpThreatCatalog -ThreatID $d.ThreatID -ErrorAction SilentlyContinue
                if ($cat -and $cat.SeverityName) { $sev = [string]$cat.SeverityName }
            }
        } catch { }
        $detections += [PSCustomObject]@{
            Path       = $res
            ThreatName = [string]$d.ThreatID
            Severity   = $sev
            Action     = $action
            Label      = 'Historical'
        }
    }

    if ($exitCode -eq 2 -and @($detections).Count -eq 0) {
        $errors += 'Exit code 2 (threats found / errors) but no threat-detection records could be read.'
    }

    $logNote = ''
    if ($status -ne 'NotInstalled' -and $LogDir) {
        $logNote = Copy-SccScanLogs -DestinationDir $LogDir -SinceMinutes ([Math]::Max($duration / 60, 5))
    }

    $r = New-SccScanResult -ScannerName $scannerName
    $r.Available = $true
    $r.ScannerVersion = $version
    $r.StartTimeUtc = $start.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
    $r.EndTimeUtc = $end.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
    $r.DurationSeconds = $duration
    $r.Status = $status
    $r.ExitCode = $exitCode
    $r.Detections = @($detections)
    $r.DetectionCount = @($detections).Count
    $r.LogPath = $logNote
    $r.RebootRequired = $false
    $r.Errors = @($errors)
    $r.CommandLine = $commandLine
    return $r
}

# ---------------------------------------------------------------------------
# Private: Invoke-SccKVRTAdapter
#   Kaspersky Virus Removal Tool. Detect-only: -accepteula -silent, no -processlevel.
#   Port exact command line from legacy adapter.
# ---------------------------------------------------------------------------
function Invoke-SccKVRTAdapter {
    [CmdletBinding()]
    param(
        [string]$ScanPath,
        [int]$TimeoutMinutes = 120,
        [string]$LogDir,
        [switch]$WhatIf
    )

    $scannerName = 'KVRT'
    $start = [datetime]::UtcNow
    $errors = @()

    # Locate KVRT.exe via centralized resolver
    $candidates = @()
    try {
        $toolsAvDir = Join-Path $PSScriptRoot '..\tools\AV'
        foreach ($root in @($toolsAvDir, $env:SystemDrive, 'C:\Users\Public\Downloads', (Get-SccTempRoot))) {
            if (-not $root) { continue }
            $driveRoot = $root
            if ($root -match '^[A-Za-z]:$') { $driveRoot = $root + '\' }
            try {
                $hits = @(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $driveRoot -Filter '*.exe' -File -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -match '^(kvrt|KVRT)' })
                foreach ($h in $hits) { $candidates += $h.FullName }
            } catch { }
        }
        $candidates = @($candidates | Where-Object { $_ } | Select-Object -Unique)
    } catch {
        # Non-Windows: path operations with drive letters fail
    }
    $tool = Resolve-SccScannerToolPath -ToolName 'KVRT' -CandidatePaths $candidates

    if (-not $tool) {
        $r = New-SccScanResult -ScannerName $scannerName
        $r.Status = 'NotInstalled'
        $r.StartTimeUtc = $start.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
        $r.EndTimeUtc = ([datetime]::UtcNow).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
        $r.Errors = @('kvrt.exe not found (checked SystemDrive root, Public Downloads, TEMP; pass -ToolPath explicitly)')
        return $r
    }

    # Version from file resource (KVRT has no documented --version)
    $version = ''
    try {
        $vi = (Microsoft.PowerShell.Management\Get-Item -LiteralPath $tool).VersionInfo
        if ($vi.ProductVersion) { $version = [string]$vi.ProductVersion }
        elseif ($vi.FileVersion) { $version = [string]$vi.FileVersion }
    } catch { }

    # Build command line per Kaspersky doc [1]
    if (-not $TimeoutMinutes -or $TimeoutMinutes -lt 1) { $TimeoutMinutes = 120 }

    $dataDir = Join-Path (Get-SccTempRoot) ('KVRT_Data_' + ([datetime]::UtcNow.ToString('yyyyMMdd_HHmmss')))
    if (-not (Microsoft.PowerShell.Management\Test-Path -LiteralPath $dataDir)) {
        try { $null = Microsoft.PowerShell.Management\New-Item -ItemType Directory -Path $dataDir -Force -ErrorAction Stop } catch { }
    }
    $argList = @('-accepteula', '-silent', '-dontencrypt', '-details', ('-d "' + $dataDir + '"'))
    if ($ScanPath) {
        $argList += @(('-custom "' + $ScanPath + '"'))
    }
    $commandLine = ('"' + $tool + '" ' + ($argList -join ' '))

    if ($WhatIf) {
        $r = New-SccScanResult -ScannerName $scannerName
        $r.Available = $true
        $r.Status = 'Skipped'
        $r.ScannerVersion = $version
        $r.StartTimeUtc = $start.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
        $r.EndTimeUtc = ([datetime]::UtcNow).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
        $r.CommandLine = $commandLine
        return $r
    }

    # Run the scan
    $run = $null
    try {
        $run = Invoke-ProcessWithTimeout -FilePath $tool -ArgumentList $argList `
            -TimeoutSeconds ($TimeoutMinutes * 60)
    } catch {
        $errors += ('Scan execution failed: ' + $_.Exception.Message)
    }

    $timedOut = $false
    $exitCode = $null
    if ($null -ne $run) {
        $timedOut = $run.TimedOut
        $exitCode = $run.ExitCode
        if ($timedOut) {
            $errors += ('Scanner did not finish within ' + $TimeoutMinutes + ' minute(s); process was terminated.')
        }
        if ($run.StreamDrainTimedOut) {
            $errors += 'Scanner output streams did not close within the drain window after termination; captured output may be incomplete.'
        }
    }

    $end = [datetime]::UtcNow
    $duration = [int]($end - $start).TotalSeconds

    # Exit codes undocumented per Kaspersky doc; completion = Completed
    $status = 'Failed'
    if ($timedOut) {
        $status = 'Timeout'
    } elseif ($null -ne $exitCode) {
        $status = 'Completed'
        if ($exitCode -ne 0) {
            $errors += ('KVRT exited with nonzero code ' + $exitCode + ' (semantics undocumented per doc [1]); check copied reports.')
        }
    } else {
        $errors += 'KVRT process could not be started.'
    }

    # Parse detections from report files
    $detections = @()
    if (-not $timedOut -and $dataDir -and (Microsoft.PowerShell.Management\Test-Path -LiteralPath $dataDir)) {
        try {
            $files = @(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $dataDir -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Extension -in '.txt', '.log', '.htm', '.html' } |
                Sort-Object LastWriteTime -Descending | Select-Object -First 5)
            foreach ($f in $files) {
                $lines = @()
                try { $lines = @(Microsoft.PowerShell.Management\Get-Content -LiteralPath $f.FullName -ErrorAction Stop) } catch { continue }
                foreach ($ln in $lines) {
                    if ($ln -match '(?i)(infected|detected|Trojan|Virus|Malware|Adware)') {
                        $path = ''
                        if ($ln -match '[A-Za-z]:\\[^\t";]+') { $path = $Matches[0].Trim() }
                        $detections += [PSCustomObject]@{
                            Path       = $path
                            ThreatName = $ln.Trim().Substring(0, [Math]::Min(200, $ln.Trim().Length))
                            Severity   = ''
                            Action     = 'Detected'
                        }
                    }
                    if (@($detections).Count -ge 200) { break }
                }
                if (@($detections).Count -ge 200) { break }
            }
        } catch {
            Write-SccScannerLog -ScannerName $scannerName -Message ("Report parse failed: " + $_.Exception.Message)
        }
    }

    if ($null -ne $exitCode -and @($detections).Count -eq 0 -and -not $timedOut) {
        $reportFiles = @()
        try { $reportFiles = @(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $dataDir -Recurse -File -ErrorAction SilentlyContinue) } catch { }
        if ($reportFiles.Count -eq 0) {
            $errors += 'KVRT wrote no report files to the data directory; scan output missing.'
        }
    }

    $logNote = ''
    if ($LogDir) {
        $logNote = Copy-SccKVRTScanLogs -DestinationDir $LogDir -DataDir $dataDir `
            -SinceMinutes ([Math]::Max($duration / 60, 5))
    }

    $r = New-SccScanResult -ScannerName $scannerName
    $r.Available = $true
    $r.ScannerVersion = $version
    $r.StartTimeUtc = $start.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
    $r.EndTimeUtc = $end.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
    $r.DurationSeconds = $duration
    $r.Status = $status
    $r.ExitCode = $exitCode
    $r.Detections = @($detections)
    $r.DetectionCount = @($detections).Count
    $r.LogPath = $logNote
    $r.RebootRequired = $false
    $r.Errors = @($errors)
    $r.CommandLine = $commandLine
    return $r
}

# ---------------------------------------------------------------------------
# Private: Invoke-SccMSERTAdapter
#   Microsoft Safety Scanner (MSERT). Detect-only via /Q (quiet mode).
#   DocUrl: https://learn.microsoft.com/en-us/defender-endpoint/safety-scanner-download
#   Verified switches: /Q (quiet), /F (full scan), /F:Y (full + auto-clean).
#   Log: %SystemRoot%\debug\msert.log
#   Note: /N (detect-only) and /F:Y are from MRT.exe, NOT documented for MSERT.
#   We use /Q only (quick scan, no cleanup) to stay within verified switches.
# ---------------------------------------------------------------------------
function Invoke-SccMSERTAdapter {
    [CmdletBinding()]
    param(
        [string]$ScanPath,
        [int]$TimeoutMinutes = 120,
        [string]$LogDir,
        [switch]$WhatIf
    )

    $scannerName = 'MSERT'
    $start = [datetime]::UtcNow
    $errors = @()

    # Locate msert.exe via centralized resolver
    $candidates = @()
    try {
        $toolDir = Join-Path $PSScriptRoot '..\tools\AV'
        if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $toolDir) {
            $hits = @(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $toolDir -Filter 'msert.exe' -File -ErrorAction SilentlyContinue)
            foreach ($h in $hits) { $candidates += $h.FullName }
        }
        $homeDir = ''
        if ($env:USERPROFILE) { $homeDir = $env:USERPROFILE }
        elseif ($env:HOME) { $homeDir = $env:HOME }
        if ($homeDir) { $candidates += (Join-Path $homeDir 'Downloads\msert.exe') }
        $candidates += (Join-Path (Get-SccTempRoot) 'msert.exe')
        $candidates += 'C:\msert.exe'
    } catch {
        # Non-Windows: path operations with drive letters fail
    }
    $tool = Resolve-SccScannerToolPath -ToolName 'MSERT' -CandidatePaths $candidates

    if (-not $tool) {
        $r = New-SccScanResult -ScannerName $scannerName
        $r.Status = 'NotInstalled'
        $r.StartTimeUtc = $start.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
        $r.EndTimeUtc = ([datetime]::UtcNow).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
        $r.Errors = @('msert.exe not found (checked tools/AV, Downloads, TEMP; pass -ToolPath explicitly)')
        return $r
    }

    # Version from file resource
    $version = ''
    try {
        $vi = (Microsoft.PowerShell.Management\Get-Item -LiteralPath $tool).VersionInfo
        if ($vi.ProductVersion) { $version = [string]$vi.ProductVersion }
        elseif ($vi.FileVersion) { $version = [string]$vi.FileVersion }
    } catch { }

    # Build command line: /Q = quiet mode (verified switch from vendor docs)
    if (-not $TimeoutMinutes -or $TimeoutMinutes -lt 1) { $TimeoutMinutes = 120 }

    $argList = @('/Q')
    $commandLine = ('"' + $tool + '" ' + ($argList -join ' '))

    if ($WhatIf) {
        $r = New-SccScanResult -ScannerName $scannerName
        $r.Available = $true
        $r.Status = 'Skipped'
        $r.ScannerVersion = $version
        $r.StartTimeUtc = $start.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
        $r.EndTimeUtc = ([datetime]::UtcNow).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
        $r.CommandLine = $commandLine
        $r.ToolSource = 'Verification=DocUrl'
        return $r
    }

    # Run the scan
    $run = $null
    try {
        $run = Invoke-ProcessWithTimeout -FilePath $tool -ArgumentList $argList `
            -TimeoutSeconds ($TimeoutMinutes * 60)
    } catch {
        $errors += ('Scan execution failed: ' + $_.Exception.Message)
    }

    $timedOut = $false
    $exitCode = $null
    if ($null -ne $run) {
        $timedOut = $run.TimedOut
        $exitCode = $run.ExitCode
        if ($timedOut) {
            $errors += ('Scanner did not finish within ' + $TimeoutMinutes + ' minute(s); process was terminated.')
        }
        if ($run.StreamDrainTimedOut) {
            $errors += 'Scanner output streams did not close within the drain window after termination; captured output may be incomplete.'
        }
    }

    $end = [datetime]::UtcNow
    $duration = [int]($end - $start).TotalSeconds

    # Exit code mapping from vendor docs and community verification:
    #   0 = no threats found
    #   1 = threats found and cleaned (should not happen without /F:Y)
    #   2 = threats found, not cleaned
    #   3 = scan errors / some files not scanned
    #   >3 = more severe infection levels
    $status = 'Failed'
    if ($timedOut) {
        $status = 'Timeout'
    } elseif ($null -ne $exitCode) {
        if ($exitCode -eq 0) {
            $status = 'Completed'
        } elseif ($exitCode -ge 1) {
            # Non-zero: threats found or errors; still Completed (scan ran)
            $status = 'Completed'
            if ($exitCode -eq 1) {
                $errors += 'Exit code 1: threats found and possibly cleaned (unexpected without /F:Y).'
            } elseif ($exitCode -eq 2) {
                $errors += 'Exit code 2: threats found but not cleaned (detect-only mode).'
            } elseif ($exitCode -eq 3) {
                $errors += 'Exit code 3: scan errors or some files could not be scanned.'
            } else {
                $errors += ('Exit code ' + $exitCode + ': infection detected (severity level ' + $exitCode + ').')
            }
        }
    }

    # Parse detections from log file
    $detections = @()
    $msertLog = ''
    try {
        if ($env:SystemRoot) {
            $msertLog = Join-Path $env:SystemRoot 'debug\msert.log'
        } else {
            $msertLog = 'C:\Windows\debug\msert.log'
        }
    } catch {
        $msertLog = 'C:\Windows\debug\msert.log'
    }

    if ((Microsoft.PowerShell.Management\Test-Path -LiteralPath $msertLog) -and -not $timedOut) {
        try {
            $logLines = @(Microsoft.PowerShell.Management\Get-Content -LiteralPath $msertLog -ErrorAction Stop)
            $inResults = $false
            foreach ($ln in $logLines) {
                if ($ln -match '(?i)Results Summary') { $inResults = $true; continue }
                if ($inResults -and $ln -match '(?i)(threat|found|virus|trojan|malware|worm|adware)') {
                    $path = ''
                    if ($ln -match '[A-Za-z]:\\[^\t";]+') { $path = $Matches[0].Trim() }
                    $detections += [PSCustomObject]@{
                        Path       = $path
                        ThreatName = $ln.Trim().Substring(0, [Math]::Min(200, $ln.Trim().Length))
                        Severity   = ''
                        Action     = 'Detected'
                    }
                }
                if (@($detections).Count -ge 200) { break }
            }
        } catch {
            Write-SccScannerLog -ScannerName $scannerName -Message ("Log parse failed: " + $_.Exception.Message)
        }
    }

    # Copy the MSERT log
    $logNote = ''
    if ($LogDir) {
        $logNote = Copy-SccMSERTScanLogs -DestinationDir $LogDir -LogFile $msertLog
        if (-not $logNote -and (Microsoft.PowerShell.Management\Test-Path -LiteralPath $msertLog)) {
            $errors += 'MSERT log file exists but could not be copied to scanner-results directory.'
        }
    }

    $r = New-SccScanResult -ScannerName $scannerName
    $r.Available = $true
    $r.ScannerVersion = $version
    $r.StartTimeUtc = $start.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
    $r.EndTimeUtc = $end.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
    $r.DurationSeconds = $duration
    $r.Status = $status
    $r.ExitCode = $exitCode
    $r.Detections = @($detections)
    $r.DetectionCount = @($detections).Count
    $r.LogPath = $logNote
    $r.RebootRequired = $false
    $r.Errors = @($errors)
    $r.CommandLine = $commandLine
    $r.ToolSource = 'Verification=DocUrl'
    return $r
}

# ---------------------------------------------------------------------------
# Module exports
# ---------------------------------------------------------------------------
Export-ModuleMember -Function @(
    'Get-SccScannerList',
    'Invoke-SccScanner',
    'Invoke-SccGuiScanner'
)

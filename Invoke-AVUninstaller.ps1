<#
  Invoke-AVUninstaller.ps1  -  discover installed third-party AV and open
  each one's uninstaller for the TECHNICIAN to drive.

  WHY THIS EXISTS
    The cleanup tool removes ScreenConnect (the intrusion vector). But a machine
    that was owned often also has a leftover / unwanted third-party antivirus.
    The owner wants an explicit, attended option to uninstall it. Every product
    opens its uninstaller as a normal visible window for the technician to
    drive - EXCEPT Malwarebytes, which since v1.7.3 is uninstalled via winget
    (`winget uninstall -e --id Malwarebytes.Malwarebytes`, owner directive
    2026-08-27); if winget is not installed the Malwarebytes vendor uninstaller
    GUI is opened instead. The pipeline NEVER invents silent /quiet uninstall
    flags for vendor uninstallers - that would be unsafe and can leave the
    machine without working AV mid-engagement.

    LEFTOVER SWEEP (v1.7.5, owner directive 2026-08-27): some vendor
    uninstallers "don't seem to work" (observed live with ESET) and leave the
    product's Start Menu shortcuts and install folder behind. After each
    uninstall attempt the script sweeps whatever still matches the product
    (Start Menu entries + install folder + temp folder) and MOVES it to a
    quarantine folder under <LogDir>\av-uninstall-quarantine - never deleted,
    every move logged in the results JSON. Disable with -NoLeftoverSweep.

    What it does:
      1. enumerate 64-bit + 32-bit HKLM (and HKCU) Uninstall keys,
      2. keep entries that look like a security/AV product (DisplayName match
         against a known-vendor heuristic, but exclude Windows Defender / MSRT
         / Windows components - those are OS, not "installed AV"),
      3. for each, uninstall it and WAIT until the process exits (or a
         240-minute safety cap; on cap the process is left running),
      4. sweep remaining shortcuts/folders into quarantine (v1.7.5),
      5. emit a JSON result per product recording what was opened + when,
         so it lands in the investigation report.

  Self-contained: run directly, or call from sc-cleanup.ps1 Stage 6.

  PS 5.1 compatible. Pure ASCII, no BOM.
#>

[CmdletBinding()]
param(
    [string]$ToolPath,              # explicit uninstaller EXE/MSI to open (bypasses discovery)
    [string]$DisplayName,           # explicit product name when -ToolPath is given
    [int]$TimeoutMinutes = 240,     # cap for an abandoned uninstall window
    [string]$LogDir,                # where to drop av-uninstall-results.json
    [switch]$ListOnly,              # discover + report, do not launch
    [switch]$NoLeftoverSweep        # skip the post-uninstall leftover sweep
)

$ErrorActionPreference = 'Stop'

function Say { param([string]$Message, [string]$Color='White') Write-Host $Message -ForegroundColor $Color }

# --- product classification ---------------------------------------------
# Vendors considered "installed third-party AV / security suite". This is a
# heuristics list, not exhaustive; it is intentionally CONSERVATIVE so we never
# try to open a Windows OS component's uninstaller.
$avKeywords = @(
    'McAfee', 'Norton', 'Symantec', 'Avast', 'AVG', 'Bitdefender', 'Kaspersky',
    'ESET', 'Sophos', 'Trend Micro', 'Webroot', 'Malwarebytes', 'Avira',
    'Panda', 'F-Secure', 'BullGuard', 'Comodo', 'ZoneAlarm', 'Cylance',
    'CrowdStrike', 'SentinelOne', 'Carbon Black', 'Traps', 'Cortex XDR',
    'Windows Defender'   # matched but EXCLUDED below (OS component)
)
# Strings that mean "do not touch - this is the OS, not installed AV".
$osExclude = @('Windows Defender', 'Microsoft Security Client', 'Microsoft Defender', 'MSRT', 'Windows Malicious Software Removal')

# Products uninstalled via winget instead of their vendor uninstaller GUI
# (owner directive 2026-08-27: Malwarebytes install/uninstall via winget).
# Keys match against DisplayName (substring); values are winget package ids.
$wingetUninstallIds = @{
    'Malwarebytes' = 'Malwarebytes.Malwarebytes'
}

function Test-IsInstalledAv {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    foreach ($x in $osExclude) { if ($Name -like "*$x*") { return $false } }
    foreach ($k in $avKeywords) { if ($Name -like "*$k*") { return $true } }
    return $false
}

# --- discovery ------------------------------------------------------------
function Get-InstalledAv {
    $keys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    $found = @()
    foreach ($key in $keys) {
        if (-not (Test-Path $key)) { continue }
        foreach ($p in (Get-ItemProperty -Path "$key\*" -ErrorAction SilentlyContinue)) {
            $disp = $p.DisplayName
            $unin = $p.UninstallString
            if ([string]::IsNullOrWhiteSpace($disp)) { continue }
            if (-not (Test-IsInstalledAv $disp)) { continue }
            if ([string]::IsNullOrWhiteSpace($unin)) { continue }
            $found += [pscustomobject]@{
                DisplayName         = $disp
                UninstallString     = $unin
                QuietUninstallString = if ($p.PSObject.Properties['QuietUninstallString']) { $p.QuietUninstallString } else { $null }
                InstallLocation     = if ($p.PSObject.Properties['InstallLocation']) { $p.InstallLocation } else { $null }
                Publisher           = if ($p.PSObject.Properties['Publisher']) { $p.Publisher } else { $null }
                Version             = if ($p.PSObject.Properties['DisplayVersion']) { $p.DisplayVersion } else { $null }
                RegistryKey         = $key
            }
        }
    }
    # de-dup by DisplayName+UninstallString
    $seen = @{}
    $out = @()
    foreach ($f in $found) {
        $k = "$($f.DisplayName)|$($f.UninstallString)"
        if ($seen.ContainsKey($k)) { continue }
        $seen[$k] = $true
        $out += $f
    }
    return $out
}

function Test-PathContained {
    param([string]$Root, [string]$Candidate)
    try {
        $rootFull = [System.IO.Path]::GetFullPath($Root).TrimEnd([char[]]@([char]92, [char]47)) + [System.IO.Path]::DirectorySeparatorChar
        $candidateFull = [System.IO.Path]::GetFullPath($Candidate)
        return $candidateFull.StartsWith($rootFull, [System.StringComparison]::OrdinalIgnoreCase)
    } catch { return $false }
}

function Test-AllowedAvPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $candidate = [System.Environment]::ExpandEnvironmentVariables($Path).Trim().Trim('"')
    $roots = @()
    if ($env:ProgramFiles) { $roots += $env:ProgramFiles }
    if (${env:ProgramFiles(x86)}) { $roots += ${env:ProgramFiles(x86)} }
    if ($env:ProgramData) { $roots += $env:ProgramData }
    foreach ($root in $roots) {
        if (Test-PathContained -Root $root -Candidate $candidate) { return $true }
    }
    return $false
}

function Resolve-UninstallCommand {
    param([string]$CommandLine)
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $null }
    $s = $CommandLine.Trim()
    # Shell metacharacters are never accepted. The command is started directly
    # with ProcessStartInfo, so a registry value cannot chain another command.
    if ($s -match '[&|<>^`\r\n]') { return $null }
    $m = [regex]::Match($s, '^\s*"([^"]+)"\s*(.*)$')
    if ($m.Success) {
        $exe = $m.Groups[1].Value
        $args = $m.Groups[2].Value
    } else {
        $m = [regex]::Match($s, '^\s*(.+?\.exe)(?:\s+(.*))?$', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        if (-not $m.Success) { return $null }
        $exe = $m.Groups[1].Value
        $args = if ($m.Groups[2].Success) { $m.Groups[2].Value } else { '' }
    }
    $resolved = $null
    if ([System.IO.Path]::IsPathRooted($exe)) {
        if (Test-Path -LiteralPath $exe -PathType Leaf) { $resolved = (Resolve-Path -LiteralPath $exe).Path }
    } else {
        $cmd = Get-Command $exe -ErrorAction SilentlyContinue
        if ($cmd) { $resolved = $cmd.Source }
    }
    if (-not $resolved) { return $null }
    $resolvedLeaf = [System.IO.Path]::GetFileName($resolved)
    $isSystemMsi = $false
    if ($resolvedLeaf -ieq 'msiexec.exe' -and $env:windir) {
        $systemRoot = Join-Path $env:windir 'System32'
        $isSystemMsi = Test-PathContained -Root $systemRoot -Candidate $resolved
    }
    if (-not (Test-AllowedAvPath -Path $resolved) -and -not $isSystemMsi) {
        # A registry value may resolve to a real executable outside the product
        # roots. It is still untrusted and must not run during AV cleanup.
        return $null
    }
    return [pscustomobject]@{ FileName = $resolved; Arguments = $args }
}

# --- launch + wait --------------------------------------------------------
function Open-Uninstaller {
    param($Product)
    $start = Get-Date

    # Malwarebytes is uninstalled via winget (owner directive 2026-08-27).
    # Everything else opens its vendor uninstaller GUI for the technician.
    $wingetId = $null
    foreach ($k in $wingetUninstallIds.Keys) {
        if ($Product.DisplayName -like ("*" + $k + "*")) { $wingetId = $wingetUninstallIds[$k]; break }
    }

    if ($wingetId) {
        $winget = Get-Command winget -ErrorAction SilentlyContinue
        if (-not $winget) {
            Say ("  winget not found - falling back to the vendor uninstaller GUI for " + $Product.DisplayName) 'Yellow'
        } else {
            $us = 'winget uninstall -e --id ' + $wingetId + ' --accept-package-agreements --accept-source-agreements'
            Say ("  Uninstalling via winget: " + $us) 'Cyan'
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.UseShellExecute = $true
            $psi.FileName = $winget.Source
            $psi.Arguments = 'uninstall -e --id ' + $wingetId + ' --accept-package-agreements --accept-source-agreements'
            $proc = $null
            try {
                $proc = [System.Diagnostics.Process]::Start($psi)
            } catch {
                return [pscustomobject]@{
                    DisplayName = $Product.DisplayName
                    UninstallString = $us
                    OpenedAt = $start.ToString('o')
                    ClosedAt = $null
                    Status = 'LaunchFailed'
                    Error = $_.Exception.Message
                    Method = 'winget'
                }
            }
            $closed = $null
            $exitCode = $null
            if ($proc) {
                # Block until winget finishes (or the safety cap is hit).
                $exited = $proc.WaitForExit([int]($TimeoutMinutes * 60 * 1000))
                if ($exited) {
                    $closed = (Get-Date).ToString('o')
                    $status = 'ClosedByUser'
                    try { $exitCode = $proc.ExitCode } catch { }
                } else {
                    # Timed out: leave the process running (do not kill mid-uninstall).
                    $status = 'TimeoutLeftRunning'
                }
            } else {
                $status = 'LaunchFailed'
            }
            return [pscustomobject]@{
                DisplayName = $Product.DisplayName
                UninstallString = $us
                OpenedAt = $start.ToString('o')
                ClosedAt = $closed
                Status = $status
                Error = $null
                Method = 'winget'
                ExitCode = $exitCode
            }
        }
    }

    $us = $Product.UninstallString
    Say ("  Opening uninstaller for: " + $Product.DisplayName) 'Cyan'
    Say ("    command: " + $us) 'DarkGray'
    $parsed = Resolve-UninstallCommand -CommandLine $us
    if (-not $parsed) {
        return [pscustomobject]@{
            DisplayName = $Product.DisplayName
            UninstallString = $us
            OpenedAt = $start.ToString('o')
            ClosedAt = $null
            Status = 'LaunchRejected'
            Error = 'UninstallString was not a safe, resolvable executable command'
            Method = 'direct-process'
        }
    }
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.UseShellExecute = $true
    $psi.FileName = $parsed.FileName
    $psi.Arguments = $parsed.Arguments
    $psi.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Normal
    $proc = $null
    try {
        $proc = [System.Diagnostics.Process]::Start($psi)
    } catch {
        return [pscustomobject]@{
            DisplayName = $Product.DisplayName
            UninstallString = $us
            OpenedAt = $start.ToString('o')
            ClosedAt = $null
            Status = 'LaunchFailed'
            Error = $_.Exception.Message
        }
    }
    $closed = $null
    if ($proc) {
        # Block until the technician finishes (or the safety cap is hit).
        $exited = $proc.WaitForExit([int]($TimeoutMinutes * 60 * 1000))
        if ($exited) {
            $closed = (Get-Date).ToString('o')
            $status = 'ClosedByUser'
        } else {
            # Timed out: leave the process running (do not kill mid-uninstall).
            $status = 'TimeoutLeftRunning'
        }
    } else {
        $status = 'LaunchFailed'
    }
    return [pscustomobject]@{
        DisplayName = $Product.DisplayName
        UninstallString = $us
        OpenedAt = $start.ToString('o')
        ClosedAt = $closed
        Status = $status
        Error = $null
    }
}

# --- leftover sweep --------------------------------------------------------
# Vendor uninstallers sometimes "don't seem to work" (observed live with ESET)
# and leave Start Menu shortcuts + the install folder behind. Sweep whatever
# still matches the product keyword and MOVE it to quarantine (never delete -
# quarantine-never-delete stays the tool's invariant). Every move is logged.
function Clear-ProductLeftovers {
    param($Product, [string]$QuarantineRoot)

    $moves = @()
    $kw = $null
    foreach ($k in $avKeywords) {
        if ($Product.DisplayName -like ("*" + $k + "*")) { $kw = $k; break }
    }
    if (-not $kw) { return $moves }

    $targets = New-Object System.Collections.ArrayList

    # 1) Start Menu entries (all-users + current user) matching the keyword.
    $smRoots = @()
    if ($env:ProgramData) { $smRoots += (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs') }
    if ($env:APPDATA) { $smRoots += (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs') }
    foreach ($sm in $smRoots) {
        if (-not (Test-Path -LiteralPath $sm)) { continue }
        foreach ($item in (Get-ChildItem -LiteralPath $sm -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -like ("*" + $kw + "*") })) {
            if (-not $targets.Contains($item.FullName)) { [void]$targets.Add($item.FullName) }
        }
    }

    # 2) Install folder: trust a registry InstallLocation only when it is
    #    below a standard product root. Never move an arbitrary registry path.
    $registryInstall = if ($Product.InstallLocation) { [System.Environment]::ExpandEnvironmentVariables([string]$Product.InstallLocation).Trim().Trim('"') } else { $null }
    if ($registryInstall -and (Test-Path -LiteralPath $registryInstall) -and (Test-AllowedAvPath -Path $registryInstall)) {
        [void]$targets.Add($registryInstall)
    } elseif ($registryInstall -and (Test-Path -LiteralPath $registryInstall)) {
        Say ("  Refusing registry InstallLocation outside Program Files/ProgramData: " + $registryInstall) 'Yellow'
    } else {
        $pfRoots = @()
        if ($env:ProgramFiles) { $pfRoots += $env:ProgramFiles }
        if (${env:ProgramFiles(x86)}) { $pfRoots += ${env:ProgramFiles(x86)} }
        foreach ($pf in $pfRoots) {
            if (-not (Test-Path -LiteralPath $pf)) { continue }
            foreach ($d in (Get-ChildItem -LiteralPath $pf -Directory -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -like ("*" + $kw + "*") })) {
                if (-not $targets.Contains($d.FullName)) { [void]$targets.Add($d.FullName) }
            }
        }
    }

    # 3) Temp folder matching the keyword (e.g. "ESET Online Scanner" runtime dir).
    if ($env:TEMP -and (Test-Path -LiteralPath $env:TEMP)) {
        foreach ($d in (Get-ChildItem -LiteralPath $env:TEMP -Directory -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -like ("*" + $kw + "*") })) {
            if (-not $targets.Contains($d.FullName)) { [void]$targets.Add($d.FullName) }
        }
    }

    if ($targets.Count -eq 0) { return $moves }

    $safeName = ($Product.DisplayName -replace '[^A-Za-z0-9 ._-]', '_').Trim()
    $destRoot = Join-Path $QuarantineRoot ($safeName + '-' + (Get-Date).ToString('yyyyMMdd_HHmmss'))
    if (-not (Test-PathContained -Root $QuarantineRoot -Candidate $destRoot)) { throw "Refusing AV quarantine path outside root: $destRoot" }
    $null = New-Item -ItemType Directory -Path $destRoot -Force

    foreach ($t in $targets) {
        if (-not (Test-Path -LiteralPath $t)) { continue }
        $separatorChars = [char[]]@([char]92, [char]47)
        if ($t.TrimEnd($separatorChars) -eq $QuarantineRoot.TrimEnd($separatorChars)) { continue }   # never move the quarantine root
        $leaf = Split-Path -Leaf $t
        $dest = Join-Path $destRoot $leaf
        if (Test-Path -LiteralPath $dest) {
            $dest = Join-Path $destRoot ($leaf + '-' + [System.Guid]::NewGuid().ToString('N').Substring(0, 8))
        }
        if (-not (Test-PathContained -Root $QuarantineRoot -Candidate $dest)) {
            throw "Refusing AV destination outside quarantine root: $dest"
        }
        try {
            Move-Item -LiteralPath $t -Destination $dest -Force -ErrorAction Stop
            $moves += [pscustomobject]@{ Source = $t; Destination = $dest; Status = 'MovedToQuarantine'; Error = $null }
        } catch {
            $moves += [pscustomobject]@{ Source = $t; Destination = $dest; Status = 'MoveFailed'; Error = $_.Exception.Message }
        }
    }
    return $moves
}

# ===========================================================================
# Main
# ===========================================================================
Say '=== Installed-AV uninstaller (attended) ===' 'Yellow'

$results = @()

$quarantineRoot = ''
if ($LogDir) { $quarantineRoot = Join-Path $LogDir 'av-uninstall-quarantine' }
else { $quarantineRoot = Join-Path 'C:\RIT-SCC' 'av-uninstall-quarantine' }

function Invoke-WithSweep {
    param($Product)
    $r = Open-Uninstaller $Product
    if (-not $NoLeftoverSweep) {
        $moves = @(Clear-ProductLeftovers -Product $Product -QuarantineRoot $quarantineRoot)
        if ($moves.Count -gt 0) {
            $r | Add-Member -NotePropertyName 'LeftoversMoved' -NotePropertyValue $moves.Count -Force
            $r | Add-Member -NotePropertyName 'Leftovers' -NotePropertyValue $moves -Force
            Say ("  Leftover sweep: " + $moves.Count + " item(s) moved to quarantine under:") 'Yellow'
            Say ("    " + $quarantineRoot) 'DarkGray'
            foreach ($m in $moves) {
                Say ("    - " + $m.Source + "  [" + $m.Status + "]") 'DarkGray'
            }
        }
    }
    return $r
}

if ($ToolPath) {
    # Explicit mode: open one specific uninstaller.
    if (-not (Test-Path -LiteralPath $ToolPath)) {
        Say ("ERROR: -ToolPath not found: " + $ToolPath) 'Red'
        exit 3
    }
    $prod = [pscustomobject]@{
        DisplayName = if ($DisplayName) { $DisplayName } else { (Split-Path -Leaf $ToolPath) }
        UninstallString = $ToolPath
        QuietUninstallString = $null; Publisher = $null; Version = $null; RegistryKey = $null
    }
    if ($ListOnly) {
        Say ("Would open: " + $prod.DisplayName) 'Cyan'
        $results += $prod
    } else {
        $results += (Invoke-WithSweep $prod)
    }
} else {
    $av = Get-InstalledAv
    if ($av.Count -eq 0) {
        Say 'No third-party antivirus/uninstallable security product detected (excluding Windows Defender / MSRT).' 'Green'
        $results += [pscustomobject]@{ DisplayName = $null; UninstallString = $null; Status = 'NoneFound' }
    } else {
        Say ("Detected $($av.Count) installed AV product(s):") 'Green'
        foreach ($a in $av) { Say ("  - " + $a.DisplayName + "  (" + $a.Publisher + ")") 'White' }
        if ($ListOnly) {
            $results = $av
        } else {
            foreach ($a in $av) { $results += (Invoke-WithSweep $a) }
        }
    }
}

# Emit JSON for the report / caller.
$out = [pscustomobject]@{
    Tool = 'Invoke-AVUninstaller'
    GeneratedUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
    QuarantineRoot = $quarantineRoot
    Count = $results.Count
    Results = $results
}
$json = $out | ConvertTo-Json -Depth 5 -Compress
if ($LogDir) {
    $null = New-Item -ItemType Directory -Path $LogDir -Force
    $json | Set-Content -Path (Join-Path $LogDir 'av-uninstall-results.json') -Encoding UTF8 -NoNewline
    Say ("Wrote: " + (Join-Path $LogDir 'av-uninstall-results.json')) 'DarkGray'
}
# Also print to stdout so sc-cleanup.ps1 can capture it.
$json
exit 0

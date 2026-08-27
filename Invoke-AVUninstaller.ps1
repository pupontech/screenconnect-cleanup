<#
  Invoke-AVUninstaller.ps1  -  discover installed third-party AV and open
  each one's uninstaller for the TECHNICIAN to drive.

  WHY THIS EXISTS
    The cleanup tool removes ScreenConnect (the intrusion vector). But a machine
    that was owned often also has a leftover / unwanted third-party antivirus.
    The owner wants an explicit, attended option to uninstall it. Just like the
    Malwarebytes scanner, this is GUI-ATTENDED: the script finds the installed
    product's uninstall entry and launches its uninstaller as a normal visible
    window, then blocks until the technician closes it. The pipeline NEVER
    invents silent /quiet uninstall flags - that would be unsafe and can leave
    the machine without working AV mid-engagement.

    What it does:
      1. enumerate 64-bit + 32-bit HKLM (and HKCU) Uninstall keys,
      2. keep entries that look like a security/AV product (DisplayName match
         against a known-vendor heuristic, but exclude Windows Defender / MSRT
         / Windows components - those are OS, not "installed AV"),
      3. for each, launch the uninstaller GUI and WAIT until the process exits
         (or a 240-minute safety cap; on cap the process is left running),
      4. emit a JSON result per product recording what was opened + when,
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
    [switch]$ListOnly               # discover + report, do not launch
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
                QuietUninstallString = if ($p.QuietUninstallString) { $p.QuietUninstallString } else { $null }
                Publisher           = if ($p.Publisher) { $p.Publisher } else { $null }
                Version             = if ($p.DisplayVersion) { $p.DisplayVersion } else { $null }
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

# --- launch + wait --------------------------------------------------------
function Open-Uninstaller {
    param($Product)
    $start = Get-Date
    $us = $Product.UninstallString
    Say ("  Opening uninstaller for: " + $Product.DisplayName) 'Cyan'
    Say ("    command: " + $us) 'DarkGray'
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.UseShellExecute = $true
    $psi.FileName = 'cmd.exe'
    $psi.Arguments = "/c $us"
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

# ===========================================================================
# Main
# ===========================================================================
Say '=== Installed-AV uninstaller (attended) ===' 'Yellow'

$results = @()

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
        $results += (Open-Uninstaller $prod)
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
            foreach ($a in $av) { $results += (Open-Uninstaller $a) }
        }
    }
}

# Emit JSON for the report / caller.
$out = [pscustomobject]@{
    Tool = 'Invoke-AVUninstaller'
    GeneratedUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
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

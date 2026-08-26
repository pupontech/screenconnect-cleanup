
# Ensure Microsoft.PowerShell.Utility cmdlets ([datetime]::UtcNow, New-Object, ConvertTo-Json,
# Out-Null, Add-Member, etc.) are visible inside this module's session state on every
# host. Without this, module functions fail with CommandNotFoundException on Windows
# when the module is loaded through Pester or a nested session state.
$null = Import-Module -Name 'Microsoft.PowerShell.Utility' -ErrorAction SilentlyContinue

<#
.SYNOPSIS
  Scc.Tools - the central ToolManager for ScreenConnect Cleaner.

  NAS-first tool acquisition with validation (size, SHA256, authenticode
  signature, file version) and provenance recording. Acquisition order is
  configurable (config nas.priorityOrder); the default is:
      local cache -> NAS -> official vendor.

  Ported from legacy tools/Get-AVTools.ps1 and tools/Get-ToolPack.ps1.
  Keeps the exact official vendor URLs (verified live 2026-08-26) and the
  FileVersion + size reporting trick for downloaded binaries.

  PS 5.1 compatible. Pure ASCII source, no BOM.
#>

# =====================================================================
# Public API (exported): Get-SccToolCatalog, Resolve-SccTool,
#   Test-SccToolIntegrity, Get-SccToolStatus, Save-SccToolToCache,
#   Write-SccToolProvenance.
# Every other function here is private (not exported).
# =====================================================================

<#
.SYNOPSIS
  Built-in tool catalog.
.DESCRIPTION
  KVRT, MSERT, AdwCleaner, ESETOnline, Malwarebytes plus the Sysinternals
  diagnostic utilities (autorunsc64, sigcheck64, procmon, tcpview).
  Each entry: Name, FileName, OfficialUrl, Publisher, MinVersion,
  ExpectedArchitecture, AttendedOnly, Licensing, Redistributable, plus an
  optional ExpectedSha256 (only where a pinned upstream baseline exists).
#>
function Get-SccToolCatalog {
    [CmdletBinding()]
    param()

    $catalog = @()

    # --- KVRT (Kaspersky Virus Removal Tool) ------------------------
    # URL copied exactly from tools/Get-AVTools.ps1 (verified live 2026-08-26).
    # KVRT has no pinned version upstream; fetched fresh each run. Always fetch
    # current, so no ExpectedSha256 baseline.
    $catalog += [PSCustomObject]@{
        Name                  = 'KVRT'
        FileName              = 'KVRT.exe'
        OfficialUrl           = 'https://devbuilds.s.kaspersky-labs.com/kvrt/latest/full/KVRT.exe'
        Publisher             = 'Kaspersky Lab'
        MinVersion            = $null
        ExpectedArchitecture  = 'x64'
        AttendedOnly          = $false
        Licensing             = 'Free; owner-approved (D2); fresh download every run'
        Redistributable       = $true
        ExpectedSha256        = $null
    }

    # --- MSERT (Microsoft Safety Scanner, a.k.a. Microsoft Support
    #       Emergency Response Tool) ---------------------------------
    # Not present in legacy Get-AVTools.ps1; MSERT official 64-bit download is
    # the Microsoft Learn Safety Scanner link (fetched 2026-08-26 from
    # learn.microsoft.com/defender-endpoint/safety-scanner-download, LinkId
    # 212732). Self-expiring tool - always download the latest before a scan.
    $catalog += [PSCustomObject]@{
        Name                  = 'MSERT'
        FileName              = 'msert.exe'
        OfficialUrl           = 'https://go.microsoft.com/fwlink/?LinkId=212732'
        Publisher             = 'Microsoft Corporation'
        MinVersion            = $null                    # MSERT has no pinned version; record actual
        ExpectedArchitecture  = 'x64'
        AttendedOnly          = $false                   # documented MSERT.log + manual trigger only - not attended-GUI
        Licensing             = 'Microsoft Safety Scanner - free, self-expiring 10 days'
        Redistributable       = $true
        ExpectedSha256        = $null                    # self-expiring build; record actual hash, no baseline
    }

    # --- AdwCleaner (Malwarebytes) ----------------------------------
    # URL copied exactly from tools/Get-AVTools.ps1; downloads.malwarebytes.com
    # /file/adwcleaner/ 302-redirects to adwcleaner.malwarebytes.com.
    # GUI-only, no invented silent flags (owner decision 2026-08-26).
    $catalog += [PSCustomObject]@{
        Name                  = 'AdwCleaner'
        FileName              = 'adwcleaner.exe'
        OfficialUrl           = 'https://downloads.malwarebytes.com/file/adwcleaner/'
        Publisher             = 'Malwarebytes'
        MinVersion            = $null
        ExpectedArchitecture  = 'x64'
        AttendedOnly          = $true
        Licensing             = 'Free (AdwCleaner)'
        Redistributable       = $true
        ExpectedSha256        = $null
    }

    # --- ESET Online Scanner ----------------------------------------
    # URL copied exactly from tools/Get-AVTools.ps1 (behind the online-scanner
    # buttons on eset.com; verified live 2026-08-26). GUI-only, attended.
    $catalog += [PSCustomObject]@{
        Name                  = 'ESETOnline'
        FileName              = 'esetonlinescanner.exe'
        OfficialUrl           = 'https://download.eset.com/com/eset/tools/online_scanner/latest/esetonlinescanner.exe'
        Publisher             = 'ESET, spol. s r.o.'
        MinVersion            = $null
        ExpectedArchitecture  = 'x64'
        AttendedOnly          = $true
        Licensing             = 'ESET Online Scanner - free (consumer)'
        Redistributable       = $true
        ExpectedSha256        = $null
    }

    # --- Malwarebytes (MB5 consumer installer) ----------------------
    # URL copied exactly from tools/Get-AVTools.ps1; downloads.malwarebytes.com
    # /file/mb-windows/ 302-redirects to data-cdn.mbamupdates.com/.../MBSetup.exe.
    # Live FileVersion observed 5.6.x (2026-08-26) -> MB5, set MinVersion 5.0.
    $catalog += [PSCustomObject]@{
        Name                  = 'Malwarebytes'
        FileName              = 'MBSetup.exe'
        OfficialUrl           = 'https://downloads.malwarebytes.com/file/mb-windows/'
        Publisher             = 'Malwarebytes'
        MinVersion            = '5.0.0.0'
        ExpectedArchitecture  = 'x64'
        AttendedOnly          = $true
        Licensing             = 'Malwarebytes 5 consumer installer (GUI, attended)'
        Redistributable       = $true
        ExpectedSha256        = $null
    }

    # --- Sysinternals diagnostic utilities --------------------------
    # URLs follow download.sysinternals.com/files/<Zip>.zip exactly as in
    # tools/Get-ToolPack.ps1. ExpectedSha256 baselines are the checked-in Seed
    # values from tools/manifest.json for the same binary (Sigcheck/Autoruns/
    # ProcessMonitor/TCPView entries). Each catalog row maps to the specific
    # x64 executable inside its zip.
    $catalog += [PSCustomObject]@{
        Name                  = 'autorunsc64'
        FileName              = 'autorunsc64.exe'
        OfficialUrl           = 'https://download.sysinternals.com/files/Autoruns.zip'
        Publisher             = 'Microsoft Corporation'
        MinVersion            = $null
        ExpectedArchitecture  = 'x64'
        AttendedOnly          = $false
        Licensing             = 'Microsoft Sysinternals - freeware (EULA)'
        Redistributable       = $true
        ExpectedSha256        = '093D1C6B91D280C9644635C667753E0AA0E78C656EB4082147BF30364787D96F'
    }
    $catalog += [PSCustomObject]@{
        Name                  = 'sigcheck64'
        FileName              = 'sigcheck64.exe'
        OfficialUrl           = 'https://download.sysinternals.com/files/Sigcheck.zip'
        Publisher             = 'Microsoft Corporation'
        MinVersion            = $null
        ExpectedArchitecture  = 'x64'
        AttendedOnly          = $false
        Licensing             = 'Microsoft Sysinternals - freeware (EULA)'
        Redistributable       = $true
        ExpectedSha256        = 'A2EFFF8D5BCE9DB4B899D38AFAA706BDFD822711F929616A51B0DBC9F76C6281'
    }
    $catalog += [PSCustomObject]@{
        Name                  = 'procmon'
        FileName              = 'Procmon64.exe'
        OfficialUrl           = 'https://download.sysinternals.com/files/ProcessMonitor.zip'
        Publisher             = 'Microsoft Corporation'
        MinVersion            = $null
        ExpectedArchitecture  = 'x64'
        AttendedOnly          = $false
        Licensing             = 'Microsoft Sysinternals - freeware (EULA)'
        Redistributable       = $true
        ExpectedSha256        = '78D7148EF5E1472BBCEC02CFD655F5AA789006B65D9990862DD8546ECF6C9AF1'
    }
    $catalog += [PSCustomObject]@{
        Name                  = 'tcpview'
        FileName              = 'tcpview64.exe'
        OfficialUrl           = 'https://download.sysinternals.com/files/TCPView.zip'
        Publisher             = 'Microsoft Corporation'
        MinVersion            = $null
        ExpectedArchitecture  = 'x64'
        AttendedOnly          = $false
        Licensing             = 'Microsoft Sysinternals - freeware (EULA)'
        Redistributable       = $true
        ExpectedSha256        = '0CBCB7EC4A042622B0D9D91B18F908E4208E4725EE1FA74A3555C4DCB622CFC1'
    }

    return @($catalog)
}

# =====================================================================
# Private helpers
# =====================================================================

<#
.SYNOPSIS
  Look up one catalog entry by tool name (case-insensitive). Programmer error
  (unknown tool) throws.
#>
function Get-SccCatalogEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Tool
    )
    $hit = @(Get-SccToolCatalog | Where-Object { $_.Name -ieq $Tool })
    if ($hit.Count -eq 0) {
        throw ("Unknown Scc.Tools catalog tool: " + $Tool)
    }
    return $hit[0]
}

<#
.SYNOPSIS
  True on a Windows host; used to decide whether real Authenticode checks run.
#>
function Test-SccWindowsHost {
    [CmdletBinding()]
    param()
    return ($env:OS -eq 'Windows_NT')
}

<#
.SYNOPSIS
  Portable boolean coercion that does not treat 'false' as true.
#>
function ConvertTo-SccBool {
    [CmdletBinding()]
    param($Value, [bool]$Default = $false)
    if ($null -eq $Value) { return $Default }
    if ($Value -is [bool]) { return [bool]$Value }
    $s = ([string]$Value).Trim()
    if ($s -ieq 'true' -or $s -eq '1') { return $true }
    if ($s -ieq 'false' -or $s -eq '0' -or $s -eq '') { return $false }
    try { return [bool]$Value } catch { return $Default }
}

<#
.SYNOPSIS
  Sweep a textual priorityOrder into a guaranteed array, applying the default
  local -> nas -> official when absent.
#>
function Get-SccNormalizedPriorityOrder {
    [CmdletBinding()]
    param($Raw)
    $valid = @('local', 'nas', 'official')
    $order = @()
    if ($null -ne $Raw) {
        foreach ($item in @($Raw)) {
            $normalized = ([string]$item).Trim().ToLowerInvariant()
            if ($valid -contains $normalized) { $order += $normalized }
        }
    }
    if ($order.Count -eq 0) { $order = @('local', 'nas', 'official') }
    return @($order)
}

<#
.SYNOPSIS
  Resolve the runtime configuration the ToolManager operates under.
.DESCRIPTION
  Precedence: (1) a script-scope override set by tests via
  Set-SccToolRuntimeConfig (InModuleScope); (2) Scc.Core (Get-SccConfig +
  Get-SccPaths) when the sibling module is importable; (3) embedded defaults.
  Returns a hashtable:
    ToolCacheDir, NasEnabled, NasPath, PriorityOrder, DownloadAllowed
#>
function Get-SccToolRuntimeConfig {
    [CmdletBinding()]
    param()

    if ($script:SccToolRuntimeConfig) { return $script:SccToolRuntimeConfig }

    $cfg = $null

    try {
        $corePath = Join-Path $PSScriptRoot '..\Scc.Core\Scc.Core.psd1'
        if (Test-Path -LiteralPath $corePath) {
            Import-Module -Name $corePath -Force -ErrorAction Stop
            $paths = Get-SccPaths -ErrorAction Stop
            $config = Get-SccConfig -ErrorAction SilentlyContinue
            if ($paths -and $paths.ToolCacheDir) {
                $cfg = @{
                    ToolCacheDir    = $paths.ToolCacheDir
                    NasEnabled      = $true
                    NasPath         = ''
                    PriorityOrder   = @('local', 'nas', 'official')
                    DownloadAllowed = $true
                }
                if ($config -and $config.ContainsKey('nas')) {
                    $nas = $config['nas']
                    if ($nas -and $nas.ContainsKey('enabled')) { $cfg.NasEnabled = ConvertTo-SccBool -Value $nas['enabled'] -Default $true }
                    if ($nas -and $nas.ContainsKey('path'))     { $cfg.NasPath = [string]$nas['path'] }
                    if ($nas -and $nas.ContainsKey('priorityOrder')) { $cfg.PriorityOrder = Get-SccNormalizedPriorityOrder $nas['priorityOrder'] }
                }
                if ($config -and $config.ContainsKey('download')) {
                    $dl = $config['download']
                    if ($dl -and $dl.ContainsKey('allowed')) { $cfg.DownloadAllowed = ConvertTo-SccBool -Value $dl['allowed'] -Default $true }
                }
            }
        }
    } catch {
        $cfg = $null
    }

    if ($null -eq $cfg) {
        $base = $env:LocalAppData
        if (-not $base) {
            try { $base = Join-Path $HOME 'AppData/Local' } catch { $base = $env:TEMP }
        }
        $cfg = @{
            ToolCacheDir    = Join-Path $base 'ScreenConnectCleaner\tools'
            NasEnabled      = $true
            NasPath         = ''
            PriorityOrder   = @('local', 'nas', 'official')
            DownloadAllowed = $true
        }
    }

    return $cfg
}

<#
.SYNOPSIS
  Set the script-scope runtime-config override. Used by tests so that
  ToolManager operations point at throwaway temp directories. Not exported.
#>
function Set-SccToolRuntimeConfig {
    [CmdletBinding()]
    param($Config)
    $script:SccToolRuntimeConfig = $Config
}

<#
.SYNOPSIS
  Full file facts without the Scc.Core per-run cache (a cache would serve stale
  SHA256 values to the tamper-detection tests). Pure local filesystem reads.
#>
function Get-SccToolFacts {
    [CmdletBinding()]
    param([string]$Path)

    $facts = [PSCustomObject]@{
        Path            = $Path
        Exists          = $false
        SizeBytes       = $null
        SHA256          = $null
        FileVersion     = ''
        Publisher       = ''
        SignatureStatus = 'NotChecked'
        LastWriteUtc    = $null
    }

    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return $facts }

    $facts.Exists = $true
    try {
        $item = Get-Item -LiteralPath $Path -ErrorAction Stop
        $facts.SizeBytes = $item.Length
        $facts.LastWriteUtc = $item.LastWriteTimeUtc
        try {
            if ($item.VersionInfo.FileVersion) { $facts.FileVersion = $item.VersionInfo.FileVersion }
        } catch { }
    } catch { }

    try {
        $facts.SHA256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash
    } catch { }

    try {
        if (Test-SccWindowsHost) {
            $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
            $facts.SignatureStatus = $sig.Status.ToString()
            if ($sig.SignerCertificate) {
                $facts.Publisher = $sig.SignerCertificate.Subject
            }
        } else {
            # Authenticode is a Windows API; on this platform we record
            # NotChecked and accept with a note (see Test-SccToolIntegrity).
            $facts.SignatureStatus = 'NotChecked'
        }
    } catch {
        $facts.SignatureStatus = 'Error'
    }

    return $facts
}

<#
.SYNOPSIS
  Read the current cache manifest (userData/tools/tool-cache-manifest.json).
  Returns a guaranteed array (empty when missing/empty/malformed).
#>
function Get-SccCacheManifest {
    [CmdletBinding()]
    param()
    $cfg = Get-SccToolRuntimeConfig
    $path = Join-Path $cfg.ToolCacheDir 'tool-cache-manifest.json'
    if (-not (Test-Path -LiteralPath $path)) { return @() }
    $raw = Get-Content -LiteralPath $path -Raw -ErrorAction Stop
    if ($null -eq $raw -or $raw.Trim() -eq '') { return @() }
    $obj = ConvertFrom-Json -InputObject $raw -ErrorAction Stop
    if ($null -eq $obj) { return @() }
    if ($obj -is [System.Array]) { return @($obj) }
    return @($obj)   # single-element JSON unwraps to a scalar in 5.1
}

<#
.SYNOPSIS
  Find the manifest entry for a tool by name (case-insensitive), or $null.
#>
function Get-SccCacheManifestEntry {
    [CmdletBinding()]
    param([string]$Tool)
    $entries = @(Get-SccCacheManifest)
    foreach ($e in $entries) {
        if ($e.Name -ieq $Tool) { return $e }
    }
    return $null
}

<#
.SYNOPSIS
  Persist the cache manifest as a JSON array (userData/tools/
  tool-cache-manifest.json).
#>
function Write-SccCacheManifest {
    [CmdletBinding()]
    param($Entries)
    $cfg = Get-SccToolRuntimeConfig
    $dir = $cfg.ToolCacheDir
    if (-not (Test-Path -LiteralPath $dir)) {
        $null = New-Item -ItemType Directory -Path $dir -Force
    }
    $path = Join-Path $dir 'tool-cache-manifest.json'
    $json = ConvertTo-Json -InputObject @($Entries) -Depth 8
    Set-Content -LiteralPath $path -Value $json -Encoding UTF8
}

<#
.SYNOPSIS
  Look for a tool on the NAS: <NasRoot>\<Tool>\<FileName> and flat
  <NasRoot>\<FileName>. Case-insensitive (a bounded name scan when the exact
  case fails, so it also works on case-sensitive Linux). Returns the full path
  or $null.
#>
function Find-SccNasFile {
    [CmdletBinding()]
    param(
        [string]$NasRoot,
        [string]$Tool,
        [string]$FileName
    )
    $pTool = Join-Path $NasRoot (Join-Path $Tool $FileName)
    $pFlat = Join-Path $NasRoot $FileName
    if (Test-Path -LiteralPath $pTool) { return $pTool }
    if (Test-Path -LiteralPath $pFlat) { return $pFlat }

    foreach ($container in @((Join-Path $NasRoot $Tool), $NasRoot)) {
        if (-not (Test-Path -LiteralPath $container)) { continue }
        try {
            $hit = @(Get-ChildItem -LiteralPath $container -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -ieq $FileName } |
                Select-Object -First 1)
            if ($hit.Count -gt 0) { return $hit[0].FullName }
        } catch { }
    }
    return $null
}

<#
.SYNOPSIS
  Extract a Sysinternals zip and locate the requested binary inside it.
  Returns the extracted file's full path or $null.
#>
function Expand-SccZipAndFind {
    [CmdletBinding()]
    param(
        [string]$ZipPath,
        [string]$FileName
    )
    $dir = Split-Path -Parent $ZipPath
    $extract = Join-Path $dir ((Split-Path -Leaf $ZipPath) + '.d')
    if (Test-Path -LiteralPath $extract) {
        Remove-Item -LiteralPath $extract -Recurse -Force -ErrorAction SilentlyContinue
    }
    $null = New-Item -ItemType Directory -Path $extract -Force
    try {
        Expand-Archive -LiteralPath $ZipPath -DestinationPath $extract -Force -ErrorAction Stop
    } catch {
        return $null
    }
    $hit = @(Get-ChildItem -LiteralPath $extract -File -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -ieq $FileName } |
        Select-Object -First 1)
    if ($hit.Count -gt 0) { return $hit[0].FullName }
    return $null
}

<#
.SYNOPSIS
  Wrapper around Invoke-WebRequest so tests can Mock it. HTTPS, TLS 1.2,
  records the final URL and observed redirect target, reports success/failure.
  Never throws; returns a hashtable { Success, LocalPath, FinalUrl, Redirects,
  Error }.
#>
function Get-SccWebDownload {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Url,
        [Parameter(Mandatory = $true)][string]$Dest
    )
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $ProgressPreference = 'SilentlyContinue'
        $resp = Invoke-WebRequest -Uri $Url -OutFile $Dest -UseBasicParsing ``
            -MaximumRedirection 20 -ErrorAction Stop
        $final = $Url
        try { $final = $resp.BaseResponse.RequestMessage.RequestUri.AbsoluteUri } catch {
            try { $final = $resp.BaseResponse.ResponseUri.AbsoluteUri } catch { }
        }
        $redirects = @()
        if ($final -ne $Url) { $redirects = @($final) }
        return @{
            Success   = $true
            LocalPath = $Dest
            FinalUrl  = $final
            Redirects = $redirects
            Error     = ''
        }
    } catch {
        return @{
            Success   = $false
            LocalPath = $Dest
            FinalUrl  = $Url
            Redirects = @()
            Error     = $_.Exception.Message
        }
    }
}

<#
.SYNOPSIS
  Build the resolved-tool result object.
#>
function New-SccResolvedTool {
    [CmdletBinding()]
    param(
        [string]$Name,
        [string]$Path,
        [string]$Source,
        $Facts,
        $Provenance
    )
    $ageDays = -1
    if ($Facts.LastWriteUtc) {
        try { $ageDays = [math]::Round((([datetime]::UtcNow) - $Facts.LastWriteUtc).TotalDays, 1) } catch { }
    }
    return [PSCustomObject]@{
        Name           = $Name
        ResolvedPath   = $Path
        Source         = $Source
        Version        = $Facts.FileVersion
        Publisher      = $Facts.Publisher
        SHA256         = $Facts.SHA256
        SignatureStatus= $Facts.SignatureStatus
        SizeBytes      = $Facts.SizeBytes
        AgeDays        = $ageDays
        VerifiedAtUtc  = ([datetime]::UtcNow).ToUniversalTime()
        Provenance     = $Provenance
    }
}

# =====================================================================
# Test-SccToolIntegrity
# =====================================================================
<#
.SYNOPSIS
  Full integrity validation of a tool binary.
.DESCRIPTION
  Checks: existence, SizeBytes > 0, SHA256 against the catalog baseline (when
  known) and against the previous cache-manifest hash (when present), the
  Authenticode signature (publisher matching the catalog when we can check it;
  NotChecked accepted with a note on non-Windows platforms), and FileVersion >=
  MinVersion when a minimum is set. Returns { Passed, Reasons[], Facts }.
.PARAMETER Path
  The file to validate. When omitted, the currently cached copy is validated.
.PARAMETER Tool
  The tool name from Get-SccToolCatalog whose baseline is applied.
#>
function Test-SccToolIntegrity {
    [CmdletBinding()]
    param(
        [string]$Path,
        [Parameter(Mandatory = $true)][string]$Tool
    )
    $cat = Get-SccCatalogEntry -Tool $Tool
    if (-not $Path) {
        $cfg = Get-SccToolRuntimeConfig
        $Path = Join-Path $cfg.ToolCacheDir (Join-Path $Tool $cat.FileName)
    }

    $facts = Get-SccToolFacts -Path $Path
    $reasons = @()
    $passed = $true

    if (-not $facts.Exists) {
        $passed = $false
        $reasons += 'not present: ' + $Path
    }

    if ($facts.Exists -and (-not $facts.SizeBytes)) {
        $passed = $false
        $reasons += 'size is zero or missing'
    }

    if ($facts.SHA256) {
        if ($cat.ExpectedSha256 -and $facts.SHA256 -ne $cat.ExpectedSha256) {
            $passed = $false
            $reasons += 'SHA256 mismatch vs catalog baseline (got ' + $facts.SHA256 + ')'
        }
        $manifestEntry = Get-SccCacheManifestEntry -Tool $Tool
        if ($manifestEntry -and $manifestEntry.SHA256 -and $facts.SHA256 -ne $manifestEntry.SHA256) {
            $passed = $false
            $reasons += 'SHA256 mismatch vs cache manifest (got ' + $facts.SHA256 + ')'
        }
    } elseif ($facts.Exists) {
        $reasons += 'SHA256 could not be computed'
    }

    switch ($facts.SignatureStatus) {
        'Valid' {
            if ($cat.Publisher -and $facts.Publisher) {
                $escaped = [regex]::Escape($cat.Publisher)
                if ($facts.Publisher -notmatch $escaped) {
                    $passed = $false
                    $reasons += 'publisher mismatch (signed by ' + $facts.Publisher + ')'
                }
            }
            $reasons += 'signature valid'
        }
        'NotChecked' {
            # Authenticode is a Windows API; on this (non-Windows) platform we
            # record NotChecked and accept with a note (documented platform
            # limitation, recorded in Provenance). This is NOT a Windows trust
            # decision and must never be treated as a trusted signature.
            $reasons += 'signature not checked on this platform, accepted'
        }
        'Invalid' { $passed = $false; $reasons += 'signature invalid' }
        'HashMismatch' { $passed = $false; $reasons += 'signature hash mismatch' }
        'NotSigned' { $passed = $false; $reasons += 'binary is not signed' }
        'NotTrusted' { $passed = $false; $reasons += 'signature not trusted (chain does not reach a trusted root)' }
        'UnknownError' { $passed = $false; $reasons += 'signature verification returned UnknownError' }
        'NotSupported' { $passed = $false; $reasons += 'signature verification not supported on this host' }
        'Error' {
            # A genuine Authenticode failure (incl. the catch -> Error path):
            # never mark Verified; treat as failed verification with a reason.
            $passed = $false
            $reasons += 'signature check errored, verification failed'
        }
        default {
            # Any unhandled status is a trust gap: never silently accept, never
            # mark Verified. Fail verification and record the raw status.
            $passed = $false
            $reasons += 'signature status unhandled (' + $facts.SignatureStatus + '), verification failed'
        }
    }

    if ($cat.MinVersion) {
        if ($facts.FileVersion) {
            try {
                if ([version]$facts.FileVersion -lt [version]$cat.MinVersion) {
                    $passed = $false
                    $reasons += 'version ' + $facts.FileVersion + ' below minimum ' + $cat.MinVersion
                }
            } catch {
                $passed = $false
                $reasons += 'version unparsable, rejected (MinVersion enforced)'
            }
        } else {
            # FileVersion empty but a MinVersion is required. Enforce the
            # minimum unless a catalog SHA256 baseline already provides
            # equivalent assurance (a pinned, hash-verified binary is trusted
            # regardless of the embedded version resource).
            if ($cat.ExpectedSha256) {
                $reasons += 'version unknown for ' + $Tool + '; accepted because a catalog SHA256 baseline exists'
            } else {
                $passed = $false
                $reasons += 'version unknown for ' + $Tool + ' but MinVersion ' + $cat.MinVersion + ' is enforced'
            }
        }
    }

    return [PSCustomObject]@{
        Passed  = [bool]$passed
        Reasons = @($reasons)
        Facts   = $facts
    }
}

# =====================================================================
# Save-SccToolToCache
# =====================================================================
<#
.SYNOPSIS
  Validate then copy a tool into the local cache and record it in the cache
  manifest.
.DESCRIPTION
  Refuses (returns $false, warns) when the source does not pass
  Test-SccToolIntegrity. On success copies to <ToolCacheDir>\<Tool>\<FileName>
  and writes a tool-cache-manifest.json entry, replacing any prior entry for the
  same tool.
.PARAMETER Source
  Optional provenance tag recorded in the manifest entry (LocalCache/Nas/
  Official, etc.) - defaults to 'Cached'.
.PARAMETER DownloadUrl
  Optional source URL recorded in the manifest entry.
#>
function Save-SccToolToCache {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Tool,
        [string]$Source = 'Cached',
        [string]$DownloadUrl = '',
        $Integrity = $null
    )
    # Prefer a caller-supplied integrity result (e.g. from Resolve-SccTool) so
    # we never re-hash a file that was already validated in this pass (B3).
    if ($null -eq $Integrity) {
        $check = Test-SccToolIntegrity -Path $Path -Tool $Tool
    } else {
        $check = $Integrity
    }
    if (-not $check.Passed) {
        Write-Warning ('Refusing to cache ' + $Tool + ' from ' + $Path + ': ' + ($check.Reasons -join '; '))
        return $false
    }

    $cat = Get-SccCatalogEntry -Tool $Tool
    $cfg = Get-SccToolRuntimeConfig
    $destDir = Join-Path $cfg.ToolCacheDir $Tool
    if (-not (Test-Path -LiteralPath $destDir)) {
        $null = New-Item -ItemType Directory -Path $destDir -Force
    }
    $dest = Join-Path $destDir $cat.FileName
    Copy-Item -LiteralPath $Path -Destination $dest -Force

    $entry = [PSCustomObject]@{
        Name            = $Tool
        Version         = $check.Facts.FileVersion
        SHA256          = $check.Facts.SHA256
        Size            = $check.Facts.SizeBytes
        Publisher       = $check.Facts.Publisher
        SignatureStatus = $check.Facts.SignatureStatus
        CachedUtc       = ([datetime]::UtcNow).ToUniversalTime().ToString('o')
        Source          = $Source
        DownloadUrl     = $DownloadUrl
    }

    $entries = @(Get-SccCacheManifest | Where-Object { $_.Name -ine $Tool })
    $entries = @($entries) + $entry
    Write-SccCacheManifest -Entries $entries
    return $true
}

# =====================================================================
# Resolve-SccTool
# =====================================================================
<#
.SYNOPSIS
  Acquire a tool following the configured source order (default: local cache ->
  NAS -> official vendor), validating every candidate before use.
.DESCRIPTION
  Returns a tool object { Name, ResolvedPath, Source (LocalCache|Nas|Official|
  None), Version, Publisher, SHA256, SignatureStatus, SizeBytes, AgeDays,
  VerifiedAtUtc, Provenance { CandidatesTried[], DownloadUrl, FinalUrl,
  Redirects[], Warnings[] } }.
  - Local cache: userData/tools/<Tool>/<FileName> -> Test-SccToolIntegrity ->
    Source=LocalCache.
  - NAS: <nas.path>\<Tool>\<FileName> and flat <nas.path>\<FileName>, same
    validation as a download (never trusted blindly). NAS unreachable is a
    WARNING, never fatal - proceeds to the next source.
  - Official: HTTPS download (only when config download.allowed), final URL +
    redirects recorded, validated before caching. Allocation failure is
    non-fatal; Source=None with a recorded reason when every source fails.
.PARAMETER ForceRefresh
  Bypass the local cache and re-acquire from NAS / official.
#>
function Resolve-SccTool {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Tool,
        [psobject]$Run,
        [switch]$ForceRefresh
    )
    $cat = Get-SccCatalogEntry -Tool $Tool
    $cfg = Get-SccToolRuntimeConfig

    $prov = [PSCustomObject]@{
        CandidatesTried = @()
        DownloadUrl     = $null
        FinalUrl        = $null
        Redirects       = @()
        Warnings        = @()
    }

    $resolved = $null

    foreach ($source in @($cfg.PriorityOrder)) {
        if ($null -ne $resolved) { break }

        switch ($source) {
            'local' {
                $cacheFile = Join-Path $cfg.ToolCacheDir (Join-Path $Tool $cat.FileName)
                $prov.CandidatesTried += 'local cache: ' + $cacheFile
                if ((Test-Path -LiteralPath $cacheFile) -and (-not $ForceRefresh)) {
                    $check = Test-SccToolIntegrity -Path $cacheFile -Tool $Tool
                    $prov.Warnings += $check.Reasons
                    if ($check.Passed) {
                        $resolved = New-SccResolvedTool -Name $Tool -Path $cacheFile `
                            -Source 'LocalCache' -Facts $check.Facts -Provenance $prov
                    }
                } elseif ($ForceRefresh) {
                    $prov.CandidatesTried += 'local cache: bypassed (-ForceRefresh)'
                }
            }

            'nas' {
                if ($cfg.NasEnabled -and $cfg.NasPath) {
                    $prov.CandidatesTried += 'nas: ' + $cfg.NasPath
                    if (-not (Test-Path -LiteralPath $cfg.NasPath)) {
                        $prov.Warnings += 'NAS unreachable (nas.path not found); proceeding to next source'
                    } else {
                        $nasFile = Find-SccNasFile -NasRoot $cfg.NasPath -Tool $Tool -FileName $cat.FileName
                        if (-not $nasFile) {
                            $prov.CandidatesTried += 'nas: <Tool>/<FileName> and flat <FileName> not found'
                        } else {
                            $prov.CandidatesTried += 'nas file: ' + $nasFile
                            $check = Test-SccToolIntegrity -Path $nasFile -Tool $Tool
                            $prov.Warnings += $check.Reasons
                            if ($check.Passed) {
                                $null = Save-SccToolToCache -Path $nasFile -Tool $Tool -Source 'Nas' -Integrity $check
                                $cached = Join-Path $cfg.ToolCacheDir (Join-Path $Tool $cat.FileName)
                                $prov.Warnings += 'copied from NAS to local cache'
                                $resolved = New-SccResolvedTool -Name $Tool -Path $cached `
                                    -Source 'Nas' -Facts $check.Facts -Provenance $prov
                            } else {
                                $prov.CandidatesTried += 'nas file rejected: ' + ($check.Reasons -join '; ')
                            }
                        }
                    }
                } elseif ($cfg.NasEnabled) {
                    $prov.Warnings += 'NAS enabled but nas.path not configured; skipping NAS source'
                }
            }

            'official' {
                if (-not $cfg.DownloadAllowed) {
                    $prov.Warnings += 'download not allowed (config download.allowed=false); official source skipped'
                    $prov.CandidatesTried += 'official: skipped (download disabled)'
                    break
                }

                $prov.DownloadUrl = $cat.OfficialUrl
                $prov.CandidatesTried += 'official: ' + $cat.OfficialUrl
                $tempRoot = $env:TEMP
                if (-not $tempRoot) { $tempRoot = '/tmp' }
                $tempDir = Join-Path $tempRoot 'ScreenConnectCleaner'
                if (-not (Test-Path -LiteralPath $tempDir)) {
                    $null = New-Item -ItemType Directory -Path $tempDir -Force
                }
                $tempFile = Join-Path $tempDir ((Split-Path -Leaf $cat.OfficialUrl) -replace '[\?&=]', '_')

                $down = Get-SccWebDownload -Url $cat.OfficialUrl -Dest $tempFile
                $prov.FinalUrl = $down.FinalUrl
                $prov.Redirects = $down.Redirects

                if (-not $down.Success) {
                    $prov.Warnings += 'official download failed: ' + $down.Error
                    $prov.CandidatesTried += 'official: FAILED (' + $down.Error + ')'
                    if (Test-Path -LiteralPath $down.LocalPath) {
                        Remove-Item -LiteralPath $down.LocalPath -Force -ErrorAction SilentlyContinue
                    }
                    break
                }

                $validationPath = $down.LocalPath
                $extracted = $false
                if ($cat.OfficialUrl -like '*.zip') {
                    $exe = Expand-SccZipAndFind -ZipPath $down.LocalPath -FileName $cat.FileName
                    if ($exe) {
                        $validationPath = $exe
                        $extracted = $true
                    } else {
                        $prov.Warnings += 'official zip did not contain expected binary ' + $cat.FileName
                    }
                }

                $check = Test-SccToolIntegrity -Path $validationPath -Tool $Tool
                $prov.Warnings += $check.Reasons

                if ($check.Passed) {
                    $null = Save-SccToolToCache -Path $validationPath -Tool $Tool `
                        -Source 'Official' -DownloadUrl $cat.OfficialUrl -Integrity $check
                    $cached = Join-Path $cfg.ToolCacheDir (Join-Path $Tool $cat.FileName)
                    $resolved = New-SccResolvedTool -Name $Tool -Path $cached `
                        -Source 'Official' -Facts $check.Facts -Provenance $prov
                } else {
                    $prov.Warnings += 'official download failed validation: ' + ($check.Reasons -join '; ')
                    $prov.CandidatesTried += 'official: validation failed'
                }

                # Clean up the temp download (and any extraction dir).
                if (Test-Path -LiteralPath $down.LocalPath) {
                    Remove-Item -LiteralPath $down.LocalPath -Force -ErrorAction SilentlyContinue
                }
                $extractDir = $down.LocalPath + '.d'
                if (Test-Path -LiteralPath $extractDir) {
                    Remove-Item -LiteralPath $extractDir -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }

    if ($null -eq $resolved) {
        $prov.Warnings += 'no source yielded a validated copy of ' + $Tool
        $emptyFacts = [PSCustomObject]@{
            FileVersion = ''; Publisher = ''; SHA256 = $null
            SignatureStatus = 'NotChecked'; SizeBytes = $null; LastWriteUtc = $null
        }
        return New-SccResolvedTool -Name $Tool -Path '' -Source 'None' `
            -Facts $emptyFacts -Provenance $prov
    }

    return $resolved
}

# =====================================================================
# Get-SccToolStatus
# =====================================================================
<#
.SYNOPSIS
  Dashboard status for every catalog tool. No network calls: the NAS check is a
  Test-Path only (fast).
#>
function Get-SccToolStatus {
    [CmdletBinding()]
    param([psobject]$Run)
    $cfg = Get-SccToolRuntimeConfig
    $catalog = @(Get-SccToolCatalog)
    $out = @()

    foreach ($cat in $catalog) {
        $cacheFile = Join-Path $cfg.ToolCacheDir (Join-Path $cat.Name $cat.FileName)
        $cached = (Test-Path -LiteralPath $cacheFile)
        $cacheVerified = $false
        $cachedVersion = $null
        if ($cached) {
            try {
                $chk = Test-SccToolIntegrity -Path $cacheFile -Tool $cat.Name
                $cacheVerified = $chk.Passed
                if ($chk.Facts.FileVersion) { $cachedVersion = $chk.Facts.FileVersion }
            } catch { }
            if (-not $cachedVersion) {
                $manEntry = Get-SccCacheManifestEntry -Tool $cat.Name
                if ($manEntry -and $manEntry.Version) { $cachedVersion = $manEntry.Version }
            }
        }

        $nasReachable = $false
        $nasPathFound = $false
        if ($cfg.NasEnabled -and $cfg.NasPath) {
            $nasReachable = (Test-Path -LiteralPath $cfg.NasPath)
            if ($nasReachable) {
                $nasPathFound = [bool](Find-SccNasFile -NasRoot $cfg.NasPath -Tool $cat.Name -FileName $cat.FileName)
            }
        }

        $officialAvailable = $cfg.DownloadAllowed

        $source = 'None'
        foreach ($p in @($cfg.PriorityOrder)) {
            switch ($p) {
                'local'    { if ($cached -and $cacheVerified) { $source = 'LocalCache' } }
                'nas'      { if ($nasPathFound) { $source = 'Nas' } }
                'official' { if ($officialAvailable) { $source = 'Official' } }
            }
            if ($source -ne 'None') { break }
        }

        $out += [PSCustomObject]@{
            Name             = $cat.Name
            Cached           = $cached
            CacheVerified    = $cacheVerified
            NasPathFound     = $nasPathFound
            NasReachable     = $nasReachable
            OfficialAvailable= $officialAvailable
            CachedVersion    = $cachedVersion
            Source           = $source
        }
    }

    return @($out)
}

# =====================================================================
# Write-SccToolProvenance
# =====================================================================
<#
.SYNOPSIS
  Export provenance for resolved tools into a run's tool-provenance.json.
.DESCRIPTION
  Writes to <runDir>\tool-provenance.json when a -Run with a RunDir is given,
  or to the explicitly supplied -OutputPath. Uses Scc.Core (when importable)
  only to derive the run directory from a run object; accepts -OutputPath
  directly when Scc.Core is unavailable ('if not importable, accept -OutputPath').
#>
function Write-SccToolProvenance {
    [CmdletBinding()]
    param(
        [psobject]$Run,
        [Parameter(Mandatory = $true)]$Tools,
        [string]$OutputPath
    )
    $target = $OutputPath
    if (-not $target -and $Run) {
        $runDir = $null
        try {
            if ($Run -is [System.Collections.IDictionary]) {
                if ($Run.ContainsKey('RunDir')) { $runDir = $Run['RunDir'] }
            } elseif ($Run.PSObject.Properties['RunDir']) {
                $runDir = $Run.RunDir
            }
        } catch { }
        if (-not $runDir) {
            try {
                $corePath = Join-Path $PSScriptRoot '..\Scc.Core\Scc.Core.psd1'
                if (Test-Path -LiteralPath $corePath) {
                    Import-Module -Name $corePath -Force -ErrorAction Stop
                    $paths = Get-SccPaths -Run $Run -ErrorAction SilentlyContinue
                    if ($paths -and $paths.ToolCacheDir) { $runDir = $paths.ToolCacheDir }
                }
            } catch { }
        }
        if (-not $runDir) {
            throw 'Write-SccToolProvenance: no run dir available (pass -OutputPath or a -Run carrying a RunDir)'
        }
        $target = Join-Path $runDir 'tool-provenance.json'
    }
    if (-not $target) {
        throw 'Write-SccToolProvenance: no output path resolved; pass -OutputPath or a -Run with a RunDir'
    }

    $dir = Split-Path -Parent $target
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        $null = New-Item -ItemType Directory -Path $dir -Force
    }

    $json = ConvertTo-Json -InputObject @($Tools) -Depth 8
    Set-Content -LiteralPath $target -Value $json -Encoding UTF8
    return $target
}

# The exports are declared in Scc.Tools.psd1's FunctionsToExport; no explicit
# Export-ModuleMember call is required for these module-level functions.
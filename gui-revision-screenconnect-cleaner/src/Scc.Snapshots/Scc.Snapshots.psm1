
# Ensure Microsoft.PowerShell.Utility cmdlets (Get-Date, New-Object, ConvertTo-Json,
# Out-Null, Add-Member, etc.) are visible inside this module's session state on every
# host. Without this, module functions fail with CommandNotFoundException on Windows
# when the module is loaded through Pester or a nested session state.
$null = Import-Module -Name 'Microsoft.PowerShell.Utility' -ErrorAction SilentlyContinue

<#
  Scc.Snapshots.psm1 - Before/after diff and resurrection detection

  Compares two snapshot objects (or JSON files) by stable Key and reports
  Removed/StillPresent/New/Changed per section. Detects resurrection of
  remote-access software across runs.
#>

# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

function Get-ItemKey {
    param($Item)
    if ($null -eq $Item) { return '<null>' }
    $k = $Item.Key
    if ($null -eq $k -or "$k" -eq '') { return '<missing-key>' }
    return [string]$k
}

function Get-ChangedFields {
    param($BeforeItem, $AfterItem)
    $diffs = @()
    $bp = $BeforeItem.PSObject.Properties
    $ap = $AfterItem.PSObject.Properties
    foreach ($p in $ap) {
        if (-not $bp[$p.Name]) {
            $diffs += "+$($p.Name)"
            continue
        }
        $b = $bp[$p.Name].Value
        $a = $p.Value
        if ("$b" -ne "$a") { $diffs += $p.Name }
    }
    foreach ($p in $bp) {
        if (-not $ap[$p.Name]) { $diffs += "-$($p.Name)" }
    }
    return , @($diffs)
}

function Compare-SccSectionArray {
    param(
        [string]$SectionName,
        $BeforeItems,
        $AfterItems
    )

    $beforeMap = @{}
    foreach ($it in @($BeforeItems)) {
        $beforeMap[(Get-ItemKey $it)] = $it
    }
    $afterMap = @{}
    foreach ($it in @($AfterItems)) {
        $afterMap[(Get-ItemKey $it)] = $it
    }

    $removed = @()
    $stillPresent = @()
    $new = @()
    $changed = @()

    foreach ($k in $beforeMap.Keys) {
        if (-not $afterMap.ContainsKey($k)) {
            $removed += $k
        }
        else {
            $stillPresent += $k
            $fields = Get-ChangedFields -BeforeItem $beforeMap[$k] -AfterItem $afterMap[$k]
            $nonKeyFields = @($fields | Where-Object { $_ -ne 'Key' })
            if ($nonKeyFields.Count -gt 0) {
                $changed += [PSCustomObject]@{
                    Key    = $k
                    Fields = $nonKeyFields
                }
            }
        }
    }

    foreach ($k in $afterMap.Keys) {
        if (-not $beforeMap.ContainsKey($k)) {
            $new += $k
        }
    }

    return [PSCustomObject]@{
        Section      = $SectionName
        Removed      = @($removed | Sort-Object)
        StillPresent = @($stillPresent | Sort-Object)
        New          = @($new | Sort-Object)
        Changed      = @($changed)
    }
}

function Compare-SccObjectSection {
    param(
        [string]$SectionName,
        $BeforeValue,
        $AfterValue
    )

    $changed = @()
    $bJson = ''
    $aJson = ''
    try { $bJson = $BeforeValue | ConvertTo-Json -Depth 12 -Compress } catch { $bJson = '<unserializable>' }
    try { $aJson = $AfterValue | ConvertTo-Json -Depth 12 -Compress } catch { $aJson = '<unserializable>' }

    if ($bJson -ne $aJson) {
        if ($BeforeValue -is [pscustomobject] -and $AfterValue -is [pscustomobject]) {
            $bp = $BeforeValue.PSObject.Properties
            $ap = $AfterValue.PSObject.Properties
            foreach ($p in $ap) {
                if (-not $bp[$p.Name]) { $changed += "+$($p.Name)"; continue }
                try {
                    $bv = $bp[$p.Name].Value | ConvertTo-Json -Depth 12 -Compress
                }
                catch { $bv = '<unserializable>' }
                try {
                    $av = $p.Value | ConvertTo-Json -Depth 12 -Compress
                }
                catch { $av = '<unserializable>' }
                if ("$bv" -ne "$av") { $changed += $p.Name }
            }
            foreach ($p in $bp) {
                if (-not $ap[$p.Name]) { $changed += "-$($p.Name)" }
            }
        }
        if ($changed.Count -eq 0) { $changed = @('value') }
    }

    $resultChanged = @()
    if ($changed.Count -gt 0) {
        $resultChanged = @([PSCustomObject]@{ Key = '<object>'; Fields = $changed })
    }

    return [PSCustomObject]@{
        Section  = $SectionName
        Removed  = @()
        StillPresent = @()
        New      = @()
        Changed  = $resultChanged
    }
}

function Read-SnapshotFile {
    param([string]$Path, [string]$Role)
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "$Role file not found: $Path"
    }
    try {
        $obj = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    }
    catch {
        throw "$Role file is not valid JSON ($Path): $($_.Exception.Message)"
    }
    return $obj
}

# ---------------------------------------------------------------------------
# Public functions
# ---------------------------------------------------------------------------

function Compare-SccSnapshots {
    <#
    .SYNOPSIS
        Compares two snapshots and produces a structured diff.
    .DESCRIPTION
        Matches items by stable Key within each section. Reports Removed,
        StillPresent, New, and Changed per section. Writes diff.json when
        -Run is provided.
    .PARAMETER Before
        Before snapshot object or path to JSON file.
    .PARAMETER After
        After snapshot object or path to JSON file.
    .PARAMETER Run
        Optional run object (RunDir property). When provided, writes diff.json
        to the snapshots directory.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Before,
        [Parameter(Mandatory = $true)]
        $After,
        $Run
    )

    # Resolve snapshots
    $beforeSnap = $null
    if ($Before -is [string]) {
        $beforeSnap = Read-SnapshotFile -Path $Before -Role 'Before'
    }
    else {
        $beforeSnap = $Before
    }

    $afterSnap = $null
    if ($After -is [string]) {
        $afterSnap = Read-SnapshotFile -Path $After -Role 'After'
    }
    else {
        $afterSnap = $After
    }

    # All known section names (array sections)
    $arraySections = @(
        'Services', 'ScheduledTasks', 'RegistryAutoruns', 'StartupFolders',
        'Processes', 'Connections', 'InstalledPrograms', 'LocalAccounts',
        'FirewallRules', 'WmiPersistence', 'RecentFiles', 'ScInstallations'
    )

    # Object sections
    $objectSections = @('SystemSettings')

    $sectionDiffs = @()
    $totalRemoved = 0
    $totalStillPresent = 0
    $totalNew = 0
    $totalChanged = 0

    foreach ($name in $arraySections) {
        $b = @($beforeSnap.Sections.$name)
        $a = @($afterSnap.Sections.$name)
        $diff = Compare-SccSectionArray -SectionName $name -BeforeItems $b -AfterItems $a
        $sectionDiffs += $diff
        $totalRemoved += $diff.Removed.Count
        $totalStillPresent += $diff.StillPresent.Count
        $totalNew += $diff.New.Count
        $totalChanged += @($diff.Changed).Count
    }

    foreach ($name in $objectSections) {
        $bv = $beforeSnap.Sections.$name
        $av = $afterSnap.Sections.$name
        $diff = Compare-SccObjectSection -SectionName $name -BeforeValue $bv -AfterValue $av
        $sectionDiffs += $diff
        $totalChanged += @($diff.Changed).Count
    }

    $result = [ordered]@{
        SchemaVersion = 1
        DiffUtc       = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
        BeforeLabel   = $beforeSnap.Label
        AfterLabel    = $afterSnap.Label
        BeforeCollectedUtc = $beforeSnap.CollectedUtc
        AfterCollectedUtc  = $afterSnap.CollectedUtc
        SameComputerName   = ("$($beforeSnap.ComputerName)" -eq "$($afterSnap.ComputerName)")
        Summary = [ordered]@{
            RemovedCount    = $totalRemoved
            StillPresentCount = $totalStillPresent
            NewCount        = $totalNew
            ChangedCount    = $totalChanged
        }
        Sections = $sectionDiffs
    }

    # Write diff.json if Run provided
    if ($Run) {
        $runDir = $null
        if ($Run -is [string]) {
            $runDir = $Run
        }
        elseif ($Run.PSObject.Properties['RunDir']) {
            $runDir = $Run.RunDir
        }
        if ($runDir) {
            $snapshotsDir = Join-Path $runDir 'snapshots'
            if (-not (Test-Path -LiteralPath $snapshotsDir)) {
                New-Item -ItemType Directory -Path $snapshotsDir -Force | Out-Null
            }
            $diffFile = Join-Path $snapshotsDir 'diff.json'
            $json = $result | ConvertTo-Json -Depth 8
            $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
            [System.IO.File]::WriteAllText($diffFile, $json, $utf8NoBom)
        }
    }

    return $result
}

function Test-SccResurrection {
    <#
    .SYNOPSIS
        Detects resurrection of remote-access software across snapshots.
    .DESCRIPTION
        Scans ScInstallations New/Changed and Services New/Changed matching
        remote-access patterns (ScreenConnect, AnyDesk, TeamViewer, etc.)
        and returns a list of flagged items.
    .PARAMETER Diff
        Diff object from Compare-SccSnapshots.
    .OUTPUTS
        Array of {Section, Key, Note} objects for flagged items.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Diff
    )

    $remoteAccessPatterns = @(
        'ScreenConnect', 'ConnectWise', 'AnyDesk', 'TeamViewer',
        'UltraViewer', 'Supremo', 'RustDesk', 'Splashtop',
        'LogMeIn', 'GoTo', 'Zoho', 'Atera', 'DWAgent',
        'MeshCentral', 'NetSupport', 'Remote Utilities',
        'VNC', 'TightVNC', 'RealVNC', 'UltraVNC'
    )

    $flagged = @()

    # Check ScInstallations section
    $scSection = $null
    foreach ($sd in $Diff.Sections) {
        if ($sd.Section -eq 'ScInstallations') {
            $scSection = $sd
            break
        }
    }
    if ($scSection) {
        foreach ($item in @($scSection.New)) {
            $flagged += [PSCustomObject]@{
                Section = 'ScInstallations'
                Key     = $item
                Note    = 'New ScreenConnect installation detected'
            }
        }
        foreach ($item in @($scSection.Changed)) {
            $flagged += [PSCustomObject]@{
                Section = 'ScInstallations'
                Key     = $item.Key
                Note    = "Changed: $($item.Fields -join ', ')"
            }
        }
    }

    # Check Services section for remote-access patterns
    $svcSection = $null
    foreach ($sd in $Diff.Sections) {
        if ($sd.Section -eq 'Services') {
            $svcSection = $sd
            break
        }
    }
    if ($svcSection) {
        foreach ($item in @($svcSection.New)) {
            $matched = $false
            foreach ($pat in $remoteAccessPatterns) {
                if ($item -match "(?i)$([regex]::Escape($pat))") {
                    $matched = $true
                    break
                }
            }
            if ($matched) {
                $flagged += [PSCustomObject]@{
                    Section = 'Services'
                    Key     = $item
                    Note    = "New remote-access service: $item"
                }
            }
        }
        foreach ($item in @($svcSection.Changed)) {
            $matched = $false
            foreach ($pat in $remoteAccessPatterns) {
                if ($item.Key -match "(?i)$([regex]::Escape($pat))") {
                    $matched = $true
                    break
                }
            }
            if ($matched) {
                $flagged += [PSCustomObject]@{
                    Section = 'Services'
                    Key     = $item.Key
                    Note    = "Changed remote-access service: $($item.Fields -join ', ')"
                }
            }
        }
    }

    return @($flagged)
}

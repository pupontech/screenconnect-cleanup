<#
.SYNOPSIS
    Stage 7 helper: diff two collect-snapshot.ps1 output files (before vs after).

.DESCRIPTION
    Matches items by their stable 'Key' field within each section and reports:
      - Removed : present in Before, absent in After  (proof of removal)
      - Added   : absent in Before, present in After  (catches resurrections)
      - Changed : same Key in both, but compared fields differ (volatile state)
    Sections that are plain objects (SystemSettings, Srum) are compared by value.
    Exit code: 0 = CLEAN (complete collections, no stable additions), 1 =
    RESURRECTION or INCOMPLETE, 2 = usage/input error. Removed/changed items
    remain visible in the report for operator review.

    PowerShell 5.1 compatible. Pure ASCII.

.PARAMETER BeforeFile
    Path to the 'before' snapshot JSON (Stage 1).

.PARAMETER AfterFile
    Path to the 'after' snapshot JSON (Stage 7).

.PARAMETER OutFile
    Optional path for a JSON diff report. Default: alongside AfterFile,
    named <after-stem>.diff.json.

.EXAMPLE
    .\diff-snapshots.ps1 -BeforeFile snap-before.json -AfterFile snap-after.json
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$BeforeFile,
    [Parameter(Mandatory = $true)][string]$AfterFile,
    [string]$OutFile
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Sections that are arrays of keyed items.
# VolatileState sections: identity keys are stable but values churn every run
# (PIDs, timestamps, connection tuples) - changes there are EXPECTED and do not
# fail the run; only Added/Removed matter as signals.
# StableState sections: any Added/Removed item is a real signal (possible
# resurrection); Changed is also reported.
# ObjectSections are compared wholesale by serialized value.
# ---------------------------------------------------------------------------
$VolatileSections = @('Processes', 'Connections', 'RecentFiles')
$StableSections   = @('Services', 'ScheduledTasks', 'RegistryAutoruns',
                      'StartupFolders', 'InstalledPrograms', 'LocalAccounts',
                      'FirewallRules', 'WmiPersistence')
$InformationalSections = @('Prefetch', 'ShimCache', 'BamDam', 'UserAssist', 'Amcache')
$ObjectSections   = @('Srum', 'SystemSettings')

function Read-Snapshot {
    param([string]$Path, [string]$Role)
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "$Role file not found: $Path"
    }
    try {
        $obj = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    } catch {
        throw "$Role file is not valid JSON ($Path): $($_.Exception.Message)"
    }
    return $obj
}

function Get-JsonItems {
    param($Value)
    if ($null -eq $Value) { return , @() }
    if ($Value -is [pscustomobject] -and @($Value.PSObject.Properties).Count -eq 0) { return , @() }
    if ($Value -is [System.Array]) { return , @($Value) }
    return , @($Value)
}

function Get-SnapshotSection {
    param($Snapshot, [string]$Name)
    if ($null -eq $Snapshot) { return $null }
    $sectionsProp = $Snapshot.PSObject.Properties['Sections']
    if (-not $sectionsProp -or $null -eq $sectionsProp.Value) { return $null }
    $sectionProp = $sectionsProp.Value.PSObject.Properties[$Name]
    if (-not $sectionProp) { return $null }
    return $sectionProp.Value
}

function Get-SnapshotCollectionComplete {
    param($Snapshot)
    if ($null -eq $Snapshot) { return $false }
    $completeProp = $Snapshot.PSObject.Properties['CollectionComplete']
    if ($completeProp) { return [bool]$completeProp.Value }
    $errorsProp = $Snapshot.PSObject.Properties['CollectionErrors']
    if (-not $errorsProp) { return $true }
    return (@(Get-JsonItems $errorsProp.Value).Count -eq 0)
}

function Get-SnapshotCollectionErrors {
    param($Snapshot)
    if ($null -eq $Snapshot) { return @('Snapshot object is null') }
    $errorsProp = $Snapshot.PSObject.Properties['CollectionErrors']
    if (-not $errorsProp) { return @() }
    return @(Get-JsonItems $errorsProp.Value)
}

function Get-SnapshotCollectionWarnings {
    param($Snapshot)
    if ($null -eq $Snapshot) { return @() }
    $warningsProp = $Snapshot.PSObject.Properties['CollectionWarnings']
    if (-not $warningsProp) { return @() }
    return @(Get-JsonItems $warningsProp.Value)
}

function Get-ObjectCompareValue {
    # SRUM's offline copy path is intentionally timestamped and therefore
    # cannot be used as an activity signal. Compare only the database identity
    # fields promised by the snapshot schema.
    param([string]$SectionName, $Value)
    if ($SectionName -eq 'Srum') {
        if ($null -eq $Value) { return $null }
        return [pscustomobject]@{
            DatabasePresent = $Value.DatabasePresent
            DatabaseSha256  = $Value.DatabaseSha256
        }
    }
    return $Value
}

# Normalize an item to its Key string. Missing Key -> synthesized marker so it
# still shows up in the report instead of being silently dropped.
function Get-ItemKey {
    param($Item)
    if ($null -eq $Item) { return '<null>' }
    $k = $Item.Key
    if ($null -eq $k -or "$k" -eq '') { return '<missing-key>' }
    return [string]$k
}

# Compare two items with the same Key; returns list of differing field names.
function Get-ComparableJson {
    param($Value)
    try {
        # InputObject is deliberate: piping a singleton array enumerates it and
        # changes the JSON shape under Windows PowerShell 5.1.
        return ConvertTo-Json -InputObject $Value -Depth 12 -Compress
    } catch {
        return '<unserializable>'
    }
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
        if ((Get-ComparableJson $b) -ne (Get-ComparableJson $a)) { $diffs += $p.Name }
    }
    foreach ($p in $bp) {
        if (-not $ap[$p.Name]) { $diffs += "-$($p.Name)" }
    }
    return , @($diffs)
}

function Get-SectionDiff {
    param([string]$SectionName, $BeforeItems, $AfterItems, [string]$Kind = 'stable')

    $beforeMap = @{}
    $beforeDuplicates = @()
    foreach ($it in @($BeforeItems)) {
        $baseKey = Get-ItemKey $it
        $mapKey = $baseKey
        $suffix = 2
        while ($beforeMap.ContainsKey($mapKey)) {
            $mapKey = "$baseKey#$suffix"
            $suffix++
        }
        if ($mapKey -ne $baseKey) { $beforeDuplicates += $baseKey }
        $beforeMap[$mapKey] = $it
    }
    $afterMap = @{}
    $afterDuplicates = @()
    foreach ($it in @($AfterItems)) {
        $baseKey = Get-ItemKey $it
        $mapKey = $baseKey
        $suffix = 2
        while ($afterMap.ContainsKey($mapKey)) {
            $mapKey = "$baseKey#$suffix"
            $suffix++
        }
        if ($mapKey -ne $baseKey) { $afterDuplicates += $baseKey }
        $afterMap[$mapKey] = $it
    }

    $removed = @()
    $added = @()
    $changed = @()

    foreach ($k in $beforeMap.Keys) {
        if (-not $afterMap.ContainsKey($k)) { $removed += $k }
    }
    foreach ($k in $afterMap.Keys) {
        if (-not $beforeMap.ContainsKey($k)) { $added += $k }
    }
    foreach ($k in $beforeMap.Keys) {
        if ($afterMap.ContainsKey($k)) {
            $fields = Get-ChangedFields -BeforeItem $beforeMap[$k] -AfterItem $afterMap[$k]
            if ($fields.Count -gt 0) {
                $changed += [pscustomobject]@{ Key = $k; Fields = $fields }
            }
        }
    }

    # Sorted output so the report itself has zero ordering noise.
    return [pscustomobject]@{
        Section     = $SectionName
        Kind        = $Kind
        BeforeCount = @($BeforeItems).Count
        AfterCount  = @($AfterItems).Count
        Removed     = @($removed | Sort-Object)
        Added       = @($added   | Sort-Object)
        Changed     = $changed
        DuplicateKeys = @($beforeDuplicates + $afterDuplicates | Sort-Object -Unique)
    }
}

function Compare-ObjectSection {
    param([string]$SectionName, $BeforeValue, $AfterValue)
    $beforeComparable = Get-ObjectCompareValue -SectionName $SectionName -Value $BeforeValue
    $afterComparable = Get-ObjectCompareValue -SectionName $SectionName -Value $AfterValue
    $bJson = Get-ComparableJson $beforeComparable
    $aJson = Get-ComparableJson $afterComparable
    $changed = @()
    if ($bJson -ne $aJson) {
        # Field-level comparison where both sides are PSCustomObjects.
        if ($beforeComparable -is [pscustomobject] -and $afterComparable -is [pscustomobject]) {
            $bp = $beforeComparable.PSObject.Properties
            $ap = $afterComparable.PSObject.Properties
            foreach ($p in $ap) {
                if (-not $bp[$p.Name]) { $changed += "+$($p.Name)"; continue }
                $bv = Get-ComparableJson $bp[$p.Name].Value
                $av = Get-ComparableJson $p.Value
                if ($bv -ne $av) { $changed += $p.Name }
            }
            foreach ($p in $bp) {
                if (-not $ap[$p.Name]) { $changed += "-$($p.Name)" }
            }
        }
        if ($changed.Count -eq 0) { $changed = @('value') }
    }
    return [pscustomobject]@{
        Section     = $SectionName
        Kind        = 'object'
        BeforeCount = -1
        AfterCount  = -1
        Removed     = @()
        Added       = @()
        Changed     = $changed
    }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
try {
    $before = Read-Snapshot -Path $BeforeFile -Role 'Before'
    $after  = Read-Snapshot -Path $AfterFile  -Role 'After'
} catch {
    Write-Error $_.Exception.Message
    exit 2
}

if (-not $OutFile) {
    $dir = Split-Path -Parent $AfterFile
    if (-not $dir) { $dir = '.' }
    $stem = [System.IO.Path]::GetFileNameWithoutExtension($AfterFile)
    $OutFile = Join-Path $dir ($stem + '.diff.json')
}

$beforeComplete = Get-SnapshotCollectionComplete -Snapshot $before
$afterComplete = Get-SnapshotCollectionComplete -Snapshot $after
$beforeErrors = Get-SnapshotCollectionErrors -Snapshot $before
$afterErrors = Get-SnapshotCollectionErrors -Snapshot $after
$beforeWarnings = Get-SnapshotCollectionWarnings -Snapshot $before
$afterWarnings = Get-SnapshotCollectionWarnings -Snapshot $after

$sectionDiffs = @()

foreach ($name in $StableSections) {
    $b = Get-JsonItems (Get-SnapshotSection -Snapshot $before -Name $name)
    $a = Get-JsonItems (Get-SnapshotSection -Snapshot $after -Name $name)
    $sectionDiffs += Get-SectionDiff -SectionName $name -BeforeItems $b -AfterItems $a -Kind 'stable'
}
foreach ($name in $VolatileSections) {
    $b = Get-JsonItems (Get-SnapshotSection -Snapshot $before -Name $name)
    $a = Get-JsonItems (Get-SnapshotSection -Snapshot $after -Name $name)
    $sectionDiffs += Get-SectionDiff -SectionName $name -BeforeItems $b -AfterItems $a -Kind 'volatile'
}
foreach ($name in $InformationalSections) {
    $b = Get-JsonItems (Get-SnapshotSection -Snapshot $before -Name $name)
    $a = Get-JsonItems (Get-SnapshotSection -Name $name -Snapshot $after)
    $sectionDiffs += Get-SectionDiff -SectionName $name -BeforeItems $b -AfterItems $a -Kind 'informational'
}
foreach ($name in $ObjectSections) {
    $sectionDiffs += Compare-ObjectSection -SectionName $name `
        -BeforeValue (Get-SnapshotSection -Snapshot $before -Name $name) -AfterValue (Get-SnapshotSection -Snapshot $after -Name $name)
}

# Signals that matter: removal proof + resurrection catch on STABLE sections.
$resurrectionCount = 0
foreach ($d in $sectionDiffs) {
    if ($d.Kind -eq 'stable') {
        $resurrectionCount += $d.Added.Count
    }
}

$collectionComplete = ($beforeComplete -and $afterComplete)
$verdict = if (-not $collectionComplete) { 'INCOMPLETE' } elseif ($resurrectionCount -gt 0) { 'RESURRECTION' } else { 'CLEAN' }
$report = [ordered]@{
    SchemaVersion          = 1
    DiffUtc                = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
    BeforeFile             = (Split-Path -Leaf $BeforeFile)
    BeforeLabel            = $before.Label
    BeforeCollectedUtc     = $before.CollectedUtc
    BeforeCollectionComplete = $beforeComplete
    BeforeCollectionErrors = $beforeErrors
    BeforeCollectionWarnings = $beforeWarnings
    AfterFile              = (Split-Path -Leaf $AfterFile)
    AfterLabel             = $after.Label
    AfterCollectedUtc      = $after.CollectedUtc
    AfterCollectionComplete = $afterComplete
    AfterCollectionErrors  = $afterErrors
    AfterCollectionWarnings = $afterWarnings
    SameComputerName       = ("$($before.ComputerName)" -eq "$($after.ComputerName)")
    ResurrectionsAdded     = $resurrectionCount
    Verdict                = $verdict
    Sections               = $sectionDiffs
}

$json = $report | ConvertTo-Json -Depth 8
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($OutFile, $json, $utf8NoBom)

# Console summary
Write-Host "Snapshot diff: $($report.BeforeFile) -> $($report.AfterFile)"
if (-not $report.SameComputerName) {
    Write-Warning "ComputerName differs between snapshots ('$($before.ComputerName)' vs '$($after.ComputerName)') - diff may be meaningless."
}
foreach ($d in $sectionDiffs) {
    $line = "{0,-18} {1,-8} before={2,-5} after={3,-5} removed={4,-3} added={5,-3} changed={6}" -f `
        $d.Section, $d.Kind, `
        $(if ($d.BeforeCount -ge 0) { $d.BeforeCount } else { '-' }), `
        $(if ($d.AfterCount -ge 0) { $d.AfterCount } else { '-' }), `
        $d.Removed.Count, $d.Added.Count, @($d.Changed).Count
    Write-Host $line
    foreach ($r in $d.Removed) { Write-Host "    REMOVED  $r" }
    foreach ($a in $d.Added)   { Write-Host "    ADDED    $a" }
    foreach ($c in @($d.Changed)) {
        if ($c -is [string]) { Write-Host "    CHANGED  $c" }
        else { Write-Host ("    CHANGED  {0} ({1})" -f $c.Key, ($c.Fields -join ', ')) }
    }
}
Write-Host ""
Write-Host "Verdict: $($report.Verdict)  (added-in-after stable items: $resurrectionCount; collections complete: $collectionComplete)"
Write-Host "Report written to: $OutFile"

exit $(if ($report.Verdict -eq 'CLEAN') { 0 } else { 1 })

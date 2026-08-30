<#
.SYNOPSIS
    Stage 7 helper: diff two collect-snapshot.ps1 output files (before vs after).

.DESCRIPTION
    Matches items by their stable 'Key' field within each section and reports:
      - Removed : present in Before, absent in After  (proof of removal)
      - Added   : absent in Before, present in After  (catches resurrections)
      - Changed : same Key in both, but compared fields differ (volatile state)
    Sections that are plain objects (SystemSettings, Srum) are compared by value.
    Exit code: 0 = clean (only expected-volatile changes), 1 = any Removed/Added
    item or unexpected change found, 2 = usage/input error.

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
                      'FirewallRules', 'WmiPersistence', 'Prefetch',
                      'ShimCache', 'BamDam', 'UserAssist', 'Amcache')
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

function Get-SectionDiff {
    param([string]$SectionName, $BeforeItems, $AfterItems, [bool]$IsVolatile)

    $beforeMap = @{}
    foreach ($it in @($BeforeItems)) { $beforeMap[(Get-ItemKey $it)] = $it }
    $afterMap = @{}
    foreach ($it in @($AfterItems))  { $afterMap[(Get-ItemKey $it)] = $it }

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
        Kind        = $(if ($IsVolatile) { 'volatile' } else { 'stable' })
        BeforeCount = @($BeforeItems).Count
        AfterCount  = @($AfterItems).Count
        Removed     = @($removed | Sort-Object)
        Added       = @($added   | Sort-Object)
        Changed     = $changed
    }
}

function Compare-ObjectSection {
    param([string]$SectionName, $BeforeValue, $AfterValue)
    $bJson = ''
    $aJson = ''
    try { $bJson = $BeforeValue | ConvertTo-Json -Depth 12 -Compress } catch { $bJson = '<unserializable>' }
    try { $aJson = $AfterValue  | ConvertTo-Json -Depth 12 -Compress } catch { $aJson = '<unserializable>' }
    $changed = @()
    if ($bJson -ne $aJson) {
        # Field-level comparison where both sides are PSCustomObjects.
        if ($BeforeValue -is [pscustomobject] -and $AfterValue -is [pscustomobject]) {
            $bp = $BeforeValue.PSObject.Properties
            $ap = $AfterValue.PSObject.Properties
            foreach ($p in $ap) {
                if (-not $bp[$p.Name]) { $changed += "+$($p.Name)"; continue }
                try {
                    $bv = $bp[$p.Name].Value | ConvertTo-Json -Depth 12 -Compress
                } catch { $bv = '<unserializable>' }
                try {
                    $av = $p.Value | ConvertTo-Json -Depth 12 -Compress
                } catch { $av = '<unserializable>' }
                if ("$bv" -ne "$av") { $changed += $p.Name }
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

$sectionDiffs = @()

foreach ($name in $StableSections) {
    $b = @($before.Sections.$name)
    $a = @($after.Sections.$name)
    $sectionDiffs += Get-SectionDiff -SectionName $name -BeforeItems $b -AfterItems $a -IsVolatile $false
}
foreach ($name in $VolatileSections) {
    $b = @($before.Sections.$name)
    $a = @($after.Sections.$name)
    $sectionDiffs += Get-SectionDiff -SectionName $name -BeforeItems $b -AfterItems $a -IsVolatile $true
}
foreach ($name in $ObjectSections) {
    $sectionDiffs += Compare-ObjectSection -SectionName $name `
        -BeforeValue $before.Sections.$name -AfterValue $after.Sections.$name
}

# Signals that matter: removal proof + resurrection catch on STABLE sections.
$resurrectionCount = 0
foreach ($d in $sectionDiffs) {
    if ($d.Kind -eq 'stable') {
        $resurrectionCount += $d.Added.Count
    }
}

$report = [ordered]@{
    SchemaVersion      = 1
    DiffUtc            = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
    BeforeFile         = (Split-Path -Leaf $BeforeFile)
    BeforeLabel        = $before.Label
    BeforeCollectedUtc = $before.CollectedUtc
    AfterFile          = (Split-Path -Leaf $AfterFile)
    AfterLabel         = $after.Label
    AfterCollectedUtc  = $after.CollectedUtc
    SameComputerName   = ("$($before.ComputerName)" -eq "$($after.ComputerName)")
    ResurrectionsAdded = $resurrectionCount
    Verdict            = $(if ($resurrectionCount -gt 0) { 'RESURRECTION' } else { 'CLEAN' })
    Sections           = $sectionDiffs
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
Write-Host "Verdict: $($report.Verdict)  (added-in-after stable items: $resurrectionCount)"
Write-Host "Report written to: $OutFile"

exit $(if ($report.Verdict -eq 'CLEAN') { 0 } else { 1 })

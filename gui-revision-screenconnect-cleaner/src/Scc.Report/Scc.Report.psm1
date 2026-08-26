
# Ensure Microsoft.PowerShell.Utility cmdlets ([datetime]::UtcNow, New-Object, ConvertTo-Json,
# Out-Null, Add-Member, etc.) are visible inside this module's session state on every
# host. Without this, module functions fail with CommandNotFoundException on Windows
# when the module is loaded through Pester or a nested session state.
$null = Import-Module -Name 'Microsoft.PowerShell.Utility' -ErrorAction SilentlyContinue
$null = Import-Module -Name 'Microsoft.PowerShell.Management' -ErrorAction SilentlyContinue

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function ConvertTo-SccHtml {
    param(
        [Parameter(ValueFromPipeline = $true)]
        [object]$Text
    )
    process {
        if ($null -eq $Text) { return '' }
        $s = [string]$Text
        $s = $s.Replace('&', '&amp;')
        $s = $s.Replace('<', '&lt;')
        $s = $s.Replace('>', '&gt;')
        $s = $s.Replace('"', '&quot;')
        $s = $s.Replace("'", '&#39;')
        return $s
    }
}

function Get-SccSafeProp {
    param($Obj, [string]$Name, $Default = $null)
    if ($null -eq $Obj) { return $Default }
    $names = @($Obj.PSObject.Properties.Name)
    if ($names -contains $Name) {
        $v = $Obj.$Name
        if ($null -eq $v) { return $Default }
        return $v
    }
    return $Default
}

function Get-SccSafeItems {
    param($Value)
    if ($null -eq $Value) { return @() }
    if ($Value -is [string]) { return @($Value) }
    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        $props = @($Value.PSObject.Properties)
        if (@($props).Count -eq 0) { return @() }
        return @($Value)
    }
    if ($Value -is [System.Array]) { return $Value }
    if ($Value -is [System.Collections.IEnumerable]) { return @($Value) }
    return @($Value)
}

function Read-SccJsonFile {
    param([string]$Path)
    $result = [ordered]@{
        Exists = $false
        Path = $Path
        Data = $null
        Error = $null
        Reason = ''
    }
    if (-not (Test-Path -LiteralPath $Path)) {
        $result.Reason = 'Not collected / not applicable - file not found: ' + $Path
        return $result
    }
    $result.Exists = $true
    try {
        $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($raw)) {
            $result.Data = $null
            $result.Reason = 'Not collected / not applicable - file empty: ' + $Path
            return $result
        }
        $obj = $raw | ConvertFrom-Json -ErrorAction Stop
        $result.Data = $obj
        return $result
    } catch {
        $result.Error = $_.Exception.Message
        $result.Reason = 'Not collected / not applicable - could not parse JSON: ' + $_.Exception.Message
        return $result
    }
}

function Resolve-SccRunDir {
    param($Run, [string]$OutputDir)
    $dir = $null
    if ($Run -is [string]) {
        $dir = $Run
    } elseif ($null -ne $Run) {
        if ($Run -is [hashtable]) {
            if ($Run.ContainsKey('RunDir')) { $dir = $Run['RunDir'] }
            elseif ($Run.ContainsKey('Path')) { $dir = $Run['Path'] }
            elseif ($Run.ContainsKey('RunPath')) { $dir = $Run['RunPath'] }
        } else {
            $propNames = @($Run.PSObject.Properties.Name)
            if ($propNames -contains 'RunDir') { $dir = $Run.RunDir }
            elseif ($propNames -contains 'Path') { $dir = $Run.Path }
            elseif ($propNames -contains 'RunPath') { $dir = $Run.RunPath }
            elseif ($propNames -contains 'Directory') { $dir = $Run.Directory }
        }
        if (-not $dir -and $Run -is [object]) {
            $s = [string]$Run
            if ($s -and (Test-Path -LiteralPath $s)) { $dir = $s }
        }
    }
    if (-not $dir -and $OutputDir) { $dir = $OutputDir }
    if (-not $dir) { $dir = (Get-Location).Path }
    return $dir
}

function Get-SccFileSize {
    param([string]$Path)
    try {
        if (Test-Path -LiteralPath $Path) {
            $it = Get-Item -LiteralPath $Path -ErrorAction Stop
            if (-not $it.PSIsContainer) { return $it.Length }
        }
    } catch { }
    return $null
}

function Format-SccNotCollected {
    param([string]$Reason)
    $esc = ConvertTo-SccHtml $Reason
    if (-not $esc) { $esc = 'Not collected / not applicable' }
    return "<p class='muted'>$esc</p>"
}

function Get-SccScInstances {
    param($FindingsData)
    if ($null -eq $FindingsData) { return @() }
    $candidates = @()
    # New shape: { ScreenConnect: [...] }
    $sc = Get-SccSafeProp $FindingsData 'ScreenConnect' $null
    if ($null -ne $sc) {
        if ($sc -is [System.Array]) {
            $candidates = @($sc)
        } elseif ($sc -is [System.Management.Automation.PSCustomObject]) {
            $inner = Get-SccSafeProp $sc 'Instances' $null
            if ($null -ne $inner) {
                $candidates = Get-SccSafeItems $inner
            } else {
                $props = @($sc.PSObject.Properties)
                if (@($props).Count -gt 0) {
                    # Could be the instance itself
                    $hasRelay = $false
                    foreach ($p in $props) { if ($p.Name -eq 'RelayHost') { $hasRelay = $true } }
                    if ($hasRelay) { $candidates = @($sc) }
                }
            }
        }
    }
    if (@($candidates).Count -eq 0) {
        # Try legacy alternate: findings may have Detection with ScreenConnect array
        $alt = Get-SccSafeProp $FindingsData 'Detections' $null
        if ($null -ne $alt) { $candidates = Get-SccSafeItems $alt }
    }
    # Also handle if findings file is already an array shape under 'ScreenConnect' directly as objects
    if (@($candidates).Count -eq 0) {
        # Check for ComputerName wrapper but Instances nested elsewhere
        $names = @($FindingsData.PSObject.Properties.Name)
        if ($names -contains 'Instances') {
            $candidates = Get-SccSafeItems (Get-SccSafeProp $FindingsData 'Instances' $null)
        }
    }
    # Filter to only objects that look like SC instance (have RelayHost or InstanceId or InstallPath)
    $filtered = @()
    foreach ($c in $candidates) {
        if ($null -eq $c) { continue }
        if ($c -is [string]) { continue }
        $filtered += $c
    }
    return @($filtered)
}

function Get-SccRemoteAccessFindings {
    param($FindingsData)
    if ($null -eq $FindingsData) { return @() }
    $ra = Get-SccSafeProp $FindingsData 'RemoteAccess' $null
    if ($null -ne $ra) { return Get-SccSafeItems $ra }
    $ra = Get-SccSafeProp $FindingsData 'OtherTargets' $null
    if ($null -ne $ra) {
        $out = [System.Collections.ArrayList]::new()
        foreach ($g in (Get-SccSafeItems $ra)) {
            $hits = Get-SccSafeProp $g 'Hits' $null
            if ($null -eq $hits) { $hits = Get-SccSafeProp $g 'Findings' $null }
            $items = Get-SccSafeItems $hits
            foreach ($h in $items) { [void]$out.Add($h) }
            if (@($items).Count -eq 0) {
                # If hits missing, treat group itself as finding if it has DisplayName
                $dn = Get-SccSafeProp $g 'Name' $null
                if ($dn) { [void]$out.Add($g) }
            }
        }
        return @($out.ToArray())
    }
    $ra = Get-SccSafeProp $FindingsData 'OtherRemoteAccess' $null
    if ($null -ne $ra) { return Get-SccSafeItems $ra }
    return @()
}

function Get-SccTimelineEvents {
    param(
        $RunStateData,
        $FindingsData,
        $PlanData,
        $RemediationData,
        $BeforeData,
        $AfterData,
        $DiffData,
        $ScannerResults,
        $ToolProvData,
        [string]$ReportGeneratedUtc
    )
    $events = [System.Collections.ArrayList]::new()
    function Add-EventLocal {
        param([string]$TimeRaw, [string]$Label)
        if ([string]::IsNullOrWhiteSpace($TimeRaw)) { return }
        $t = $TimeRaw.Trim()
        # Try to normalize to yyyy-MM-dd HH:mm:ss for sorting; keep original for display but sort key is normalized string if ISO
        # Ensure we produce ISO-lexicographically sortable form: yyyy-MM-dd HH:mm:ss
        [void]$events.Add([PSCustomObject]@{ TimeUtc = $t; Event = $Label })
    }
    # Snapshot A
    if ($null -ne $BeforeData) {
        $ct = Get-SccSafeProp $BeforeData 'CollectedUtc' $null
        if (-not $ct) { $ct = Get-SccSafeProp $BeforeData 'CollectedAt' $null }
        Add-EventLocal $ct 'Snapshot A (before) collected'
        $label = Get-SccSafeProp $BeforeData 'Label' $null
        if (-not $ct -and $label) { Add-EventLocal '2026-01-01 00:00:00' 'Snapshot A label: before' }
    }
    # Detection
    if ($null -ne $FindingsData) {
        $dt = Get-SccSafeProp $FindingsData 'DetectedUtc' $null
        if (-not $dt) { $dt = Get-SccSafeProp $FindingsData 'GeneratedUtc' $null }
        if (-not $dt) { $dt = Get-SccSafeProp $FindingsData 'CollectedUtc' $null }
        Add-EventLocal $dt 'Detection completed'
    }
    # Plan / Review
    if ($null -ne $PlanData) {
        $pt = Get-SccSafeProp $PlanData 'CreatedUtc' $null
        if (-not $pt) { $pt = Get-SccSafeProp $PlanData 'GeneratedUtc' $null }
        Add-EventLocal $pt 'Review / plan created'
    }
    # Remediation actions
    if ($null -ne $RemediationData) {
        $items = @()
        if ($RemediationData -is [System.Array]) { $items = $RemediationData }
        else {
            $act = Get-SccSafeProp $RemediationData 'Actions' $null
            if ($null -ne $act) { $items = Get-SccSafeItems $act }
            else {
                $entries = Get-SccSafeProp $RemediationData 'Entries' $null
                if ($null -ne $entries) { $items = Get-SccSafeItems $entries }
                else { $items = @($RemediationData) }
            }
        }
        foreach ($a in $items) {
            if ($null -eq $a) { continue }
            $at = Get-SccSafeProp $a 'TimestampUtc' $null
            if (-not $at) { $at = Get-SccSafeProp $a 'TimeUtc' $null }
            if (-not $at) { $at = Get-SccSafeProp $a 'CompletedUtc' $null }
            if (-not $at) { $at = Get-SccSafeProp $a 'ExecutedUtc' $null }
            if ($at) { Add-EventLocal $at ('Remediation: ' + (ConvertTo-SccHtml (Get-SccSafeProp $a 'Action' 'action')) ) }
        }
        if (@($items).Count -gt 0 -and @($events).Count -eq 0) {
            # placeholder if no timestamps
        }
    }
    # Scanners
    foreach ($sr in $ScannerResults) {
        if ($null -eq $sr) { continue }
        $st = Get-SccSafeProp $sr.Data 'StartTimeUtc' $null
        if (-not $st) { $st = Get-SccSafeProp $sr.Data 'StartedUtc' $null }
        $et = Get-SccSafeProp $sr.Data 'EndTimeUtc' $null
        if (-not $et) { $et = Get-SccSafeProp $sr.Data 'CompletedUtc' $null }
        $nm = Get-SccSafeProp $sr.Data 'ScannerName' $null
        if (-not $nm) { $nm = Get-SccSafeProp $sr.Data 'Name' $null }
        if (-not $nm) { $nm = $sr.FileName }
        if ($st) { Add-EventLocal $st ('Scanner ' + $nm + ' started') }
        if ($et) { Add-EventLocal $et ('Scanner ' + $nm + ' ended') }
        if (-not $st -and -not $et) {
            $ts = Get-SccSafeProp $sr.Data 'TimestampUtc' $null
            if ($ts) { Add-EventLocal $ts ('Scanner ' + $nm) }
        }
    }
    # Snapshot B
    if ($null -ne $AfterData) {
        $ct = Get-SccSafeProp $AfterData 'CollectedUtc' $null
        if (-not $ct) { $ct = Get-SccSafeProp $AfterData 'CollectedAt' $null }
        Add-EventLocal $ct 'Snapshot B (after) collected'
    }
    # Diff
    if ($null -ne $DiffData) {
        $dt = Get-SccSafeProp $DiffData 'DiffUtc' $null
        if (-not $dt) { $dt = Get-SccSafeProp $DiffData 'GeneratedUtc' $null }
        Add-EventLocal $dt 'Diff (before/after) generated'
    }
    # Report
    Add-EventLocal $ReportGeneratedUtc 'Report generated'
    # Sort ascending by TimeUtc string (ISO lexical sort works for yyyy-MM-dd HH:mm:ss)
    $sorted = @($events | Sort-Object -Property TimeUtc)
    return @($sorted)
}

function Get-SccDeterministicReportTime {
    param(
        $FindingsData,
        $BeforeData,
        $AfterData,
        $DiffData,
        $PlanData,
        $RemediationData,
        $ScannerResults
    )
    $candidates = [System.Collections.ArrayList]::new()
    function Add-Candidate { param($v) if (-not [string]::IsNullOrWhiteSpace([string]$v)) { [void]$candidates.Add([string]$v) } }
    if ($null -ne $FindingsData) {
        Add-Candidate (Get-SccSafeProp $FindingsData 'DetectedUtc' $null)
        Add-Candidate (Get-SccSafeProp $FindingsData 'GeneratedUtc' $null)
    }
    if ($null -ne $BeforeData) { Add-Candidate (Get-SccSafeProp $BeforeData 'CollectedUtc' $null) }
    if ($null -ne $AfterData) { Add-Candidate (Get-SccSafeProp $AfterData 'CollectedUtc' $null) }
    if ($null -ne $DiffData) { Add-Candidate (Get-SccSafeProp $DiffData 'DiffUtc' $null) }
    if ($null -ne $PlanData) { Add-Candidate (Get-SccSafeProp $PlanData 'CreatedUtc' $null) }
    foreach ($sr in $ScannerResults) {
        if ($null -ne $sr.Data) {
            Add-Candidate (Get-SccSafeProp $sr.Data 'EndTimeUtc' $null)
            Add-Candidate (Get-SccSafeProp $sr.Data 'StartTimeUtc' $null)
        }
    }
    $max = $null
    foreach ($c in $candidates) {
        if ($null -eq $max -or $c -gt $max) { $max = $c }
    }
    if ($max) {
        # Append 1 minute deterministic offset by string manipulation: increment minutes if parsable
        try {
            $dt = [DateTime]::Parse($max, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal)
            $dt = $dt.AddMinutes(1)
            return $dt.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture)
        } catch {
            return $max
        }
    }
    return '2026-08-26 00:00:00'
}

function New-SccReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Run,
        [string]$OutputDir
    )

    $runDir = Resolve-SccRunDir -Run $Run -OutputDir $OutputDir
    if (-not (Test-Path -LiteralPath $runDir)) {
        try { New-Item -ItemType Directory -Path $runDir -Force | Out-Null } catch { }
    }
    $outDir = $OutputDir
    if ([string]::IsNullOrWhiteSpace($outDir)) { $outDir = $runDir }
    if (-not (Test-Path -LiteralPath $outDir)) {
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    }

    # Load inputs
    $runStateFile = Read-SccJsonFile ([System.IO.Path]::Combine($runDir, 'runstate.json'))
    $findingsFile = Read-SccJsonFile ([System.IO.Path]::Combine($runDir, 'findings.json'))
    $planFile = Read-SccJsonFile ([System.IO.Path]::Combine($runDir, 'plan.json'))
    $remediationFile = Read-SccJsonFile ([System.IO.Path]::Combine($runDir, 'remediation.json'))
    $toolProvFile = Read-SccJsonFile ([System.IO.Path]::Combine($runDir, 'tool-provenance.json'))
    $beforeFile = Read-SccJsonFile ([System.IO.Path]::Combine($runDir, 'snapshots/before.json'))
    $afterFile = Read-SccJsonFile ([System.IO.Path]::Combine($runDir, 'snapshots/after.json'))
    $diffFile = Read-SccJsonFile ([System.IO.Path]::Combine($runDir, 'snapshots/diff.json'))
    # Also try alternate diff path snapshots/diff.json is canonical; also check root diff
    if (-not $diffFile.Exists) {
        $alt = Read-SccJsonFile ([System.IO.Path]::Combine($runDir, 'diff.json'))
        if ($alt.Exists) { $diffFile = $alt }
    }

    $scannerDir = [System.IO.Path]::Combine($runDir, 'scanner-results')
    $scannerResults = [System.Collections.ArrayList]::new()
    if (Test-Path -LiteralPath $scannerDir) {
        $files = @(Get-ChildItem -LiteralPath $scannerDir -File -Filter '*.json' -ErrorAction SilentlyContinue | Sort-Object -Property Name)
        foreach ($f in $files) {
            $r = Read-SccJsonFile $f.FullName
            [void]$scannerResults.Add([PSCustomObject]@{ FileName = $f.Name; Path = $f.FullName; Data = $r.Data; Exists = $r.Exists; Reason = $r.Reason })
        }
    }

    $masterLogPath = [System.IO.Path]::Combine($runDir, 'logs/master.log')
    $masterLogExists = Test-Path -LiteralPath $masterLogPath
    $masterLogContent = $null
    if ($masterLogExists) {
        try { $masterLogContent = Get-Content -LiteralPath $masterLogPath -Raw -ErrorAction Stop } catch { $masterLogContent = '' }
    }

    # Derived values
    $runStateData = $runStateFile.Data
    $findingsData = $findingsFile.Data
    $planData = $planFile.Data
    $remediationData = $remediationFile.Data
    $toolProvData = $toolProvFile.Data
    $beforeData = $beforeFile.Data
    $afterData = $afterFile.Data
    $diffData = $diffFile.Data

    $reportGeneratedUtc = Get-SccDeterministicReportTime -FindingsData $findingsData -BeforeData $beforeData -AfterData $afterData -DiffData $diffData -PlanData $planData -RemediationData $remediationData -ScannerResults $scannerResults

    # SC instances
    $scInstances = Get-SccScInstances $findingsData
    $scCount = @($scInstances).Count
    $knownCount = 0
    $unknownCount = 0
    foreach ($inst in $scInstances) {
        $tm = Get-SccSafeProp $inst 'TrustMatch' $null
        if (-not $tm) { $tm = Get-SccSafeProp $inst 'Trust' $null }
        if ($tm -and $tm.ToString() -ieq 'Known') { $knownCount++ } else { $unknownCount++ }
        # Default: if no TrustMatch field, treat as Unknown when instances exist
    }
    # If scCount>0 but both zero (no TrustMatch field), set unknown = scCount
    if ($scCount -gt 0 -and $knownCount -eq 0 -and $unknownCount -eq 0) { $unknownCount = $scCount }

    # Other remote access
    $otherFindings = Get-SccRemoteAccessFindings $findingsData
    $otherCount = @($otherFindings).Count

    # Scanner stats
    $scanTotal = @($scannerResults).Count
    $scanCompleted = 0
    $scanFailed = 0
    $scanSkipped = 0
    $scanNotInstalled = 0
    foreach ($sr in $scannerResults) {
        $st = $null
        if ($null -ne $sr.Data) { $st = Get-SccSafeProp $sr.Data 'Status' $null }
        if (-not $st) { $st = Get-SccSafeProp $sr.Data 'Result' $null }
        if ($st) {
            $s = [string]$st
            if ($s -ieq 'Completed') { $scanCompleted++ }
            elseif ($s -ieq 'Failed') { $scanFailed++ }
            elseif ($s -ieq 'Skipped') { $scanSkipped++ }
            elseif ($s -ieq 'NotInstalled') { $scanNotInstalled++ }
            elseif ($s -ieq 'Timeout') { $scanFailed++ }
            elseif ($s -ieq 'NotVerified') { $scanFailed++ }
        }
    }

    # Remediation stats
    $planRemoveCount = 0
    if ($null -ne $planData) {
        $items = Get-SccSafeProp $planData 'Items' $null
        if ($null -eq $items) { $items = Get-SccSafeProp $planData 'Entries' $null }
        $itemsArr = Get-SccSafeItems $items
        foreach ($it in $itemsArr) {
            $act = Get-SccSafeProp $it 'Action' $null
            if ($act -and $act.ToString() -ieq 'REMOVE') { $planRemoveCount++ }
        }
    }
    $remediationActions = 0
    $quarantinedCount = 0
    if ($null -ne $remediationData) {
        if ($remediationData -is [System.Array]) { $remediationActions = @($remediationData).Count }
        else {
            $acts = Get-SccSafeProp $remediationData 'Actions' $null
            if ($null -ne $acts) { $remediationActions = @(Get-SccSafeItems $acts).Count }
            else {
                $ents = Get-SccSafeProp $remediationData 'Entries' $null
                if ($null -ne $ents) { $remediationActions = @(Get-SccSafeItems $ents).Count }
                else { $remediationActions = 1 }
            }
            $qm = Get-SccSafeProp $remediationData 'Quarantined' $null
            if ($null -ne $qm) { $quarantinedCount = @(Get-SccSafeItems $qm).Count }
        }
        # also check quarantine-manifest.json
        $qManifestPath = [System.IO.Path]::Combine($runDir, 'quarantine-manifest.json')
        $qMetaPath = [System.IO.Path]::Combine($runDir, 'quarantine-meta/quarantine-manifest.json')
        $qm2 = Read-SccJsonFile $qManifestPath
        if ($qm2.Exists -and $null -ne $qm2.Data) {
            if ($qm2.Data -is [System.Array]) { $quarantinedCount = @($qm2.Data).Count }
            else { $quarantinedCount = 1 }
        } else {
            $qm3 = Read-SccJsonFile $qMetaPath
            if ($qm3.Exists -and $null -ne $qm3.Data) {
                if ($qm3.Data -is [System.Array]) { $quarantinedCount = @($qm3.Data).Count }
                else { $quarantinedCount = 1 }
            }
        }
    }

    # Diff stats
    $diffRemoved = 0
    $diffNew = 0
    $diffChanged = 0
    $diffStillPresent = 0
    $diffReappeared = 0
    if ($null -ne $diffData) {
        $summary = Get-SccSafeProp $diffData 'Summary' $null
        if ($null -ne $summary) {
            $diffRemoved = [int](Get-SccSafeProp $summary 'RemovedCount' 0)
            $diffNew = [int](Get-SccSafeProp $summary 'NewCount' 0)
            $diffChanged = [int](Get-SccSafeProp $summary 'ChangedCount' 0)
            $still = Get-SccSafeProp $summary 'StillPresentCount' $null
            if ($null -ne $still) { $diffStillPresent = [int]$still }
        } else {
            $secs = Get-SccSafeProp $diffData 'Sections' $null
            if ($null -ne $secs) {
                # Could be array or object
                $secArr = @()
                if ($secs -is [System.Array]) { $secArr = $secs }
                elseif ($secs -is [System.Management.Automation.PSCustomObject]) {
                    foreach ($p in $secs.PSObject.Properties) { $secArr += $p.Value }
                }
                foreach ($s in $secArr) {
                    $r = Get-SccSafeProp $s 'Removed' $null
                    $a = Get-SccSafeProp $s 'Added' $null
                    $n = Get-SccSafeProp $s 'New' $null
                    $c = Get-SccSafeProp $s 'Changed' $null
                    if ($null -ne $r) { $diffRemoved += @(Get-SccSafeItems $r).Count }
                    if ($null -ne $a) { $diffNew += @(Get-SccSafeItems $a).Count }
                    if ($null -ne $n) { $diffNew += @(Get-SccSafeItems $n).Count }
                    if ($null -ne $c) { $diffChanged += @(Get-SccSafeItems $c).Count }
                    $sp = Get-SccSafeProp $s 'StillPresent' $null
                    if ($null -ne $sp) { $diffStillPresent += @(Get-SccSafeItems $sp).Count }
                }
            }
        }
        # Also handle direct fields
        if ($diffRemoved -eq 0 -and $diffNew -eq 0) {
            $r2 = Get-SccSafeProp $diffData 'Removed' $null
            if ($null -ne $r2) { $diffRemoved = @(Get-SccSafeItems $r2).Count }
            $n2 = Get-SccSafeProp $diffData 'New' $null
            if ($null -ne $n2) { $diffNew = @(Get-SccSafeItems $n2).Count }
        }
    }

    # Outstanding concerns: heuristic
    $outstanding = 0
    if ($unknownCount -gt 0) { $outstanding++ }
    if ($scanFailed -gt 0) { $outstanding++ }
    if ($diffNew -gt 0 -or $diffChanged -gt 0) { $outstanding++ }
    # Parser warnings
    $parserWarningsCount = 0
    foreach ($inst in $scInstances) {
        $pw = Get-SccSafeProp $inst 'ParserWarnings' $null
        if ($null -ne $pw) { $parserWarningsCount += @(Get-SccSafeItems $pw).Count }
        $unk = Get-SccSafeProp $inst 'UnknownParameters' $null
        if ($null -ne $unk) { $parserWarningsCount += @(Get-SccSafeItems $unk).Count }
    }
    if ($parserWarningsCount -gt 0) { $outstanding++ }

    # System information
    $computerName = 'Unknown'
    $osCaption = $null
    $arch = $null
    if ($null -ne $findingsData) {
        $cn = Get-SccSafeProp $findingsData 'ComputerName' $null
        if ($cn) { $computerName = [string]$cn }
        $osCaption = Get-SccSafeProp $findingsData 'OSCaption' $null
        if (-not $osCaption) { $osCaption = Get-SccSafeProp $findingsData 'OsCaption' $null }
    }
    if ($null -ne $beforeData) {
        $cn2 = Get-SccSafeProp $beforeData 'ComputerName' $null
        if ($cn2 -and $computerName -eq 'Unknown') { $computerName = [string]$cn2 }
        $os2 = Get-SccSafeProp $beforeData 'OsCaption' $null
        if ($os2 -and -not $osCaption) { $osCaption = [string]$os2 }
    }
    if ($null -ne $runStateData) {
        $cn3 = Get-SccSafeProp $runStateData 'ComputerName' $null
        if ($cn3 -and $computerName -eq 'Unknown') { $computerName = [string]$cn3 }
    }

    # RunId
    $runId = ''
    if ($null -ne $runStateData) { $runId = [string](Get-SccSafeProp $runStateData 'RunId' '') }
    if (-not $runId) { $runId = Split-Path -Leaf $runDir }

    # Incident Timeline events
    $timelineEvents = Get-SccTimelineEvents -RunStateData $runStateData -FindingsData $findingsData -PlanData $planData -RemediationData $remediationData -BeforeData $beforeData -AfterData $afterData -DiffData $diffData -ScannerResults $scannerResults -ToolProvData $toolProvData -ReportGeneratedUtc $reportGeneratedUtc

    # --- Build HTML sections ---
    $css = @'
:root {
  --ink: #1b2430;
  --muted: #5c6773;
  --border: #d7dde3;
  --bg: #ffffff;
  --bg-alt: #f5f7f9;
  --danger-bg: #fdecea;
  --danger-border: #e0554a;
  --danger-text: #8a2b23;
  --warn-bg: #fff6e5;
  --warn-border: #d99a1b;
  --warn-text: #7a5a06;
  --ok-bg: #eaf6ec;
  --ok-border: #3f9450;
  --ok-text: #275c31;
}
* { box-sizing: border-box; }
body { font-family: Segoe UI, Arial, Helvetica, sans-serif; color: var(--ink); background: var(--bg); margin: 0; padding: 24px; line-height: 1.45; font-size: 14px; }
h1 { font-size: 22px; margin: 0 0 12px 0; }
h2 { font-size: 18px; margin: 28px 0 10px 0; padding-bottom: 6px; border-bottom: 2px solid var(--border); }
h3 { font-size: 15px; margin: 18px 0 8px 0; }
h4 { font-size: 13px; margin: 14px 0 6px 0; color: var(--muted); text-transform: uppercase; letter-spacing: 0.03em; }
p { margin: 6px 0; }
.muted { color: var(--muted); font-size: 13px; }
.ok-line { color: var(--ok-text); background: var(--ok-bg); border: 1px solid var(--ok-border); padding: 8px 12px; border-radius: 4px; }
.warn-line { color: var(--warn-text); background: var(--warn-bg); border: 1px solid var(--warn-border); padding: 8px 12px; border-radius: 4px; }
.danger-line { color: var(--danger-text); background: var(--danger-bg); border: 1px solid var(--danger-border); padding: 8px 12px; border-radius: 4px; }
.badge { display: inline-block; padding: 2px 9px; border-radius: 10px; font-size: 12px; font-weight: 700; border: 1px solid transparent; }
.badge-known { background: var(--ok-bg); color: var(--ok-text); border-color: var(--ok-border); }
.badge-unknown { background: var(--warn-bg); color: var(--warn-text); border-color: var(--warn-border); }
.badge-high { background: var(--danger-bg); color: var(--danger-text); border-color: var(--danger-border); }
.badge-medium { background: var(--warn-bg); color: var(--warn-text); border-color: var(--warn-border); }
.badge-low { background: var(--ok-bg); color: var(--ok-text); border-color: var(--ok-border); }
.stat-row { display: flex; flex-wrap: wrap; gap: 12px; margin: 10px 0; }
.stat-card { flex: 1 1 180px; border: 1px solid var(--border); border-left: 6px solid var(--border); border-radius: 4px; padding: 12px 14px; background: var(--bg-alt); }
.stat-card.stat-ok { border-left-color: var(--ok-border); }
.stat-card.stat-warn { border-left-color: var(--warn-border); }
.stat-card.stat-danger { border-left-color: var(--danger-border); }
.stat-number { font-size: 26px; font-weight: 700; }
.stat-label { font-size: 12.5px; color: var(--muted); }
.fact-table { width: 100%; border-collapse: collapse; margin-bottom: 6px; }
.fact-table th { text-align: left; width: 220px; vertical-align: top; color: var(--muted); font-weight: 600; padding: 4px 10px 4px 0; border-bottom: 1px solid var(--border); font-size: 13px; }
.fact-table td { padding: 4px 0; vertical-align: top; border-bottom: 1px solid var(--border); word-break: break-word; font-size: 13px; }
.data-table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
.data-table th { text-align: left; background: var(--bg-alt); border: 1px solid var(--border); padding: 5px 8px; }
.data-table td { border: 1px solid var(--border); padding: 5px 8px; vertical-align: top; word-break: break-word; }
.table-scroll { overflow-x: auto; max-width: 100%; }
.instance-card { border: 1px solid var(--border); border-radius: 6px; padding: 14px 16px; margin: 14px 0; background: var(--bg); }
.header-table { width: 100%; border-collapse: collapse; }
.header-table th { text-align: left; color: var(--muted); font-weight: 600; padding: 3px 8px 3px 0; white-space: nowrap; font-size: 13px; }
.header-table td { padding: 3px 20px 3px 0; font-size: 13px; }
footer { margin-top: 30px; padding-top: 10px; border-top: 1px solid var(--border); color: var(--muted); font-size: 12px; }
'@

    $titleText = 'ScreenConnect Cleaner - Investigation Report - ' + $computerName

    # Executive Summary HTML
    $execSummaryHtml = @"
<section id="executive-summary">
<h2>Executive Summary</h2>
<div class="stat-row">
  <div class="stat-card $(if($scCount -gt 0){'stat-danger'}else{'stat-ok'})"><div class="stat-number">$scCount</div><div class="stat-label">ScreenConnect instances (Known $knownCount / Unknown $unknownCount)</div></div>
  <div class="stat-card $(if($otherCount -gt 0){'stat-warn'}else{'stat-ok'})"><div class="stat-number">$otherCount</div><div class="stat-label">Other remote-access findings</div></div>
  <div class="stat-card $(if($scanFailed -gt 0){'stat-warn'}else{'stat-ok'})"><div class="stat-number">$scanTotal</div><div class="stat-label">Scans run (Completed $scanCompleted / Failed $scanFailed / Skipped $scanSkipped)</div></div>
  <div class="stat-card stat-ok"><div class="stat-number">$remediationActions</div><div class="stat-label">Remediation actions (Plan REMOVE $planRemoveCount)</div></div>
  <div class="stat-card stat-ok"><div class="stat-number">$quarantinedCount</div><div class="stat-label">Quarantined items</div></div>
  <div class="stat-card $(if($diffNew -gt 0 -or $diffChanged -gt 0){'stat-warn'}else{'stat-ok'})"><div class="stat-number">$diffRemoved / $diffNew / $diffChanged</div><div class="stat-label">Diff Removed / New / Changed (StillPresent $diffStillPresent)</div></div>
  <div class="stat-card $(if($outstanding -gt 0){'stat-warn'}else{'stat-ok'})"><div class="stat-number">$outstanding</div><div class="stat-label">Outstanding concerns</div></div>
</div>
<p class="muted">Trust verdict: Known $knownCount, Unknown $unknownCount. Unknown relays require manual review; never auto-classified malicious.</p>
</section>
"@

    # System Information
    $sysInfoRows = ''
    $sysInfoRows += "<tr><th>Computer</th><td>$(ConvertTo-SccHtml $computerName)</td></tr>`n"
    $sysInfoRows += "<tr><th>Operating system</th><td>$(ConvertTo-SccHtml $(if($osCaption){$osCaption}else{'Not collected / not applicable - OS info not found'}))</td></tr>`n"
    $sysInfoRows += "<tr><th>Run ID</th><td>$(ConvertTo-SccHtml $runId)</td></tr>`n"
    $sysInfoRows += "<tr><th>Report generated (UTC)</th><td>$(ConvertTo-SccHtml $reportGeneratedUtc)</td></tr>`n"
    if ($null -ne $runStateData) {
        $stages = Get-SccSafeProp $runStateData 'Stages' $null
        if (-not $stages) { $stages = Get-SccSafeProp $runStateData 'stages' $null }
        if ($null -ne $stages) {
            foreach ($p in $stages.PSObject.Properties) {
                $sysInfoRows += "<tr><th>Stage $(ConvertTo-SccHtml $p.Name)</th><td>$(ConvertTo-SccHtml ([string]$p.Value))</td></tr>`n"
            }
        }
    } else {
        $sysInfoRows += "<tr><th>Run state</th><td>Not collected / not applicable - runstate.json not found</td></tr>`n"
    }
    $systemInfoHtml = @"
<section id="system-information">
<h2>System Information</h2>
<table class="fact-table">
$sysInfoRows
</table>
</section>
"@

    # Incident Timeline
    $timelineRows = ''
    if (@($timelineEvents).Count -gt 0) {
        foreach ($ev in $timelineEvents) {
            $timelineRows += "<tr><td>$(ConvertTo-SccHtml $ev.TimeUtc)</td><td>$(ConvertTo-SccHtml $ev.Event)</td></tr>`n"
        }
    } else {
        $timelineRows = "<tr><td colspan='2'>Not collected / not applicable - no timestamped events found</td></tr>"
    }
    $timelineHtml = @"
<section id="incident-timeline">
<h2>Incident Timeline</h2>
<div class="table-scroll"><table class="data-table"><thead><tr><th>Time (UTC)</th><th>Event</th></tr></thead><tbody>
$timelineRows
</tbody></table></div>
</section>
"@

    # ScreenConnect Findings
    $scFindingsHtml = ''
    if (-not $findingsFile.Exists) {
        $scFindingsHtml = @"
<section id="screenconnect-findings">
<h2>ScreenConnect Findings</h2>
$(Format-SccNotCollected $findingsFile.Reason)
<p class="muted">ScreenConnect section not collected - findings.json missing.</p>
</section>
"@
    } elseif ($scCount -eq 0) {
        $scFindingsHtml = @"
<section id="screenconnect-findings">
<h2>ScreenConnect Findings</h2>
<p class="ok-line">None found. No ScreenConnect instances detected.</p>
</section>
"@
    } else {
        $cards = ''
        $idx = 0
        foreach ($inst in $scInstances) {
            $idx++
            $relay = Get-SccSafeProp $inst 'RelayHost' $null
            if (-not $relay) { $relay = Get-SccSafeProp $inst 'Relay' $null }
            $instanceId = Get-SccSafeProp $inst 'InstanceId' $null
            if (-not $instanceId) { $instanceId = Get-SccSafeProp $inst 'Identifier' $null }
            if (-not $instanceId) { $instanceId = Get-SccSafeProp $inst 'Key' $null }
            $fp = Get-SccSafeProp $inst 'ServerKeyFingerprint' $null
            if (-not $fp) { $fp = Get-SccSafeProp $inst 'ServerFingerprint' $null }
            if (-not $fp) { $fp = Get-SccSafeProp $inst 'Fingerprint' $null }
            $sessionType = Get-SccSafeProp $inst 'SessionType' $null
            if (-not $sessionType) { $sessionType = Get-SccSafeProp $inst 'Session' $null }
            $installPath = Get-SccSafeProp $inst 'InstallPath' $null
            if (-not $installPath) { $installPath = Get-SccSafeProp $inst 'InstallDir' $null }
            if (-not $installPath) { $installPath = Get-SccSafeProp $inst 'ExecutablePath' $null }
            $service = Get-SccSafeProp $inst 'Service' $null
            if (-not $service) { $service = Get-SccSafeProp $inst 'ServiceName' $null }
            $installTs = Get-SccSafeProp $inst 'InstallTimestamp' $null
            if (-not $installTs) { $installTs = Get-SccSafeProp $inst 'InstallTimestampUtc' $null }
            if (-not $installTs) { $installTs = Get-SccSafeProp $inst 'InstallDirCreatedUtc' $null }
            $publisher = Get-SccSafeProp $inst 'Publisher' $null
            $sig = Get-SccSafeProp $inst 'Signature' $null
            if (-not $sig) { $sig = Get-SccSafeProp $inst 'SignatureStatus' $null }
            $version = Get-SccSafeProp $inst 'Version' $null
            if (-not $version) { $version = Get-SccSafeProp $inst 'DisplayVersion' $null }
            if (-not $version) { $version = Get-SccSafeProp $inst 'FileVersion' $null }
            $confidence = Get-SccSafeProp $inst 'Confidence' $null
            $trust = Get-SccSafeProp $inst 'TrustMatch' $null
            if (-not $trust) { $trust = Get-SccSafeProp $inst 'Trust' $null }
            if (-not $trust) { $trust = 'Unknown' }
            $trustBadgeClass = 'badge-unknown'
            if ($trust -ieq 'Known') { $trustBadgeClass = 'badge-known' }
            $persistence = Get-SccSafeProp $inst 'Persistence' $null
            $processes = Get-SccSafeProp $inst 'Processes' $null
            if (-not $processes) { $processes = Get-SccSafeProp $inst 'AssociatedProcesses' $null }
            $connections = Get-SccSafeProp $inst 'Connections' $null
            if (-not $connections) { $connections = Get-SccSafeProp $inst 'NetworkConnections' $null }
            $rawParams = Get-SccSafeProp $inst 'RawLaunchParameters' $null
            if (-not $rawParams) { $rawParams = Get-SccSafeProp $inst 'ParamBlob' $null }
            if (-not $rawParams) { $rawParams = Get-SccSafeProp $inst 'RawParameters' $null }
            $parserWarnings = Get-SccSafeProp $inst 'ParserWarnings' $null
            $unknownParams = Get-SccSafeProp $inst 'UnknownParameters' $null
            if (-not $unknownParams) { $unknownParams = Get-SccSafeProp $inst 'UnknownParams' $null }

            $detailRows = ''
            $detailRows += "<tr><th>InstanceId</th><td>$(ConvertTo-SccHtml $(if($instanceId){$instanceId}else{'-'}))</td></tr>`n"
            $detailRows += "<tr><th>RelayHost</th><td>$(ConvertTo-SccHtml $(if($relay){$relay}else{'-'}))</td></tr>`n"
            $detailRows += "<tr><th>ServerKeyFingerprint</th><td>$(ConvertTo-SccHtml $(if($fp){$fp}else{'-'}))</td></tr>`n"
            $detailRows += "<tr><th>SessionType</th><td>$(ConvertTo-SccHtml $(if($sessionType){$sessionType}else{'-'}))</td></tr>`n"
            $detailRows += "<tr><th>InstallPath</th><td>$(ConvertTo-SccHtml $(if($installPath){$installPath}else{'-'}))</td></tr>`n"
            $detailRows += "<tr><th>Service</th><td>$(ConvertTo-SccHtml $(if($service){$service}else{'-'}))</td></tr>`n"
            $detailRows += "<tr><th>InstallTimestamp</th><td>$(ConvertTo-SccHtml $(if($installTs){$installTs}else{'-'}))</td></tr>`n"
            $detailRows += "<tr><th>Publisher</th><td>$(ConvertTo-SccHtml $(if($publisher){$publisher}else{'-'}))</td></tr>`n"
            $detailRows += "<tr><th>Signature</th><td>$(ConvertTo-SccHtml $(if($sig){$sig}else{'-'}))</td></tr>`n"
            $detailRows += "<tr><th>Version</th><td>$(ConvertTo-SccHtml $(if($version){$version}else{'-'}))</td></tr>`n"
            $detailRows += "<tr><th>Confidence</th><td>$(ConvertTo-SccHtml $(if($confidence){$confidence}else{'-'}))</td></tr>`n"
            $detailRows += "<tr><th>TrustMatch</th><td><span class='badge $trustBadgeClass'>$(ConvertTo-SccHtml $trust)</span></td></tr>`n"

            # Persistence sub-section
            $persHtml = ''
            if ($null -ne $persistence) {
                $persItems = Get-SccSafeItems $persistence
                if (@($persItems).Count -gt 0) {
                    $pr = ''
                    foreach ($pe in $persItems) {
                        if ($pe -is [string]) { $pr += "<tr><td colspan='2'>$(ConvertTo-SccHtml $pe)</td></tr>`n" }
                        else {
                            $pt = Get-SccSafeProp $pe 'Type' '-'
                            $pl = Get-SccSafeProp $pe 'Location' '-'
                            $pd = Get-SccSafeProp $pe 'Details' '-'
                            $pr += "<tr><td>$(ConvertTo-SccHtml $pt)</td><td>$(ConvertTo-SccHtml $pl) : $(ConvertTo-SccHtml $pd)</td></tr>`n"
                        }
                    }
                    $persHtml = "<h4>Persistence</h4><div class='table-scroll'><table class='data-table'><thead><tr><th>Type</th><th>Location</th></tr></thead><tbody>$pr</tbody></table></div>"
                }
            }
            # Processes
            $procHtml = ''
            if ($null -ne $processes) {
                $procItems = Get-SccSafeItems $processes
                if (@($procItems).Count -gt 0) {
                    $pr = ''
                    foreach ($pe in $procItems) {
                        if ($pe -is [string]) { $pr += "<tr><td colspan='3'>$(ConvertTo-SccHtml $pe)</td></tr>`n" }
                        else {
                            $pn = Get-SccSafeProp $pe 'Name' (Get-SccSafeProp $pe 'ProcessName' '-')
                            $pp = Get-SccSafeProp $pe 'ExecutablePath' (Get-SccSafeProp $pe 'Path' '-')
                            $pidv = Get-SccSafeProp $pe 'ProcessId' (Get-SccSafeProp $pe 'PID' '-')
                            $pr += "<tr><td>$(ConvertTo-SccHtml $pidv)</td><td>$(ConvertTo-SccHtml $pn)</td><td>$(ConvertTo-SccHtml $pp)</td></tr>`n"
                        }
                    }
                    $procHtml = "<h4>Processes</h4><div class='table-scroll'><table class='data-table'><thead><tr><th>PID</th><th>Name</th><th>Path</th></tr></thead><tbody>$pr</tbody></table></div>"
                }
            }
            # Connections
            $connHtml = ''
            if ($null -ne $connections) {
                $connItems = Get-SccSafeItems $connections
                if (@($connItems).Count -gt 0) {
                    $cr = ''
                    foreach ($ce in $connItems) {
                        if ($ce -is [string]) { $cr += "<tr><td colspan='3'>$(ConvertTo-SccHtml $ce)</td></tr>`n" }
                        else {
                            $la = Get-SccSafeProp $ce 'LocalAddress' '-'
                            $lp = Get-SccSafeProp $ce 'LocalPort' '-'
                            $ra = Get-SccSafeProp $ce 'RemoteAddress' '-'
                            $rp = Get-SccSafeProp $ce 'RemotePort' '-'
                            $st = Get-SccSafeProp $ce 'State' '-'
                            $cr += "<tr><td>$(ConvertTo-SccHtml "$la`:$lp")</td><td>$(ConvertTo-SccHtml "$ra`:$rp")</td><td>$(ConvertTo-SccHtml $st)</td></tr>`n"
                        }
                    }
                    $connHtml = "<h4>Connections</h4><div class='table-scroll'><table class='data-table'><thead><tr><th>Local</th><th>Remote</th><th>State</th></tr></thead><tbody>$cr</tbody></table></div>"
                }
            }
            # RawLaunchParameters
            $rawHtml = ''
            if ($rawParams) { $rawHtml = "<h4>RawLaunchParameters</h4><p class='muted'>$(ConvertTo-SccHtml $rawParams)</p>" }
            # ParserWarnings
            $pwHtml = ''
            if ($null -ne $parserWarnings) {
                $pwItems = Get-SccSafeItems $parserWarnings
                if (@($pwItems).Count -gt 0) {
                    $pr = ''
                    foreach ($w in $pwItems) { $pr += "<li>$(ConvertTo-SccHtml $w)</li>`n" }
                    $pwHtml = "<h4>ParserWarnings</h4><ul>$pr</ul>"
                }
            }
            # UnknownParameters
            $upHtml = ''
            if ($null -ne $unknownParams) {
                $upItems = Get-SccSafeItems $unknownParams
                if (@($upItems).Count -gt 0) {
                    $pr = ''
                    foreach ($u in $upItems) {
                        if ($u -is [string]) { $pr += "<tr><td>$(ConvertTo-SccHtml $u)</td><td>-</td></tr>`n" }
                        else {
                            $un = Get-SccSafeProp $u 'Name' (Get-SccSafeProp $u 'Key' '-')
                            $uv = Get-SccSafeProp $u 'Value' (Get-SccSafeProp $u 'Val' '-')
                            $pr += "<tr><td>$(ConvertTo-SccHtml $un)</td><td>$(ConvertTo-SccHtml $uv)</td></tr>`n"
                        }
                    }
                    $upHtml = "<h4>UnknownParameters</h4><div class='table-scroll'><table class='data-table'><thead><tr><th>Name</th><th>Value</th></tr></thead><tbody>$pr</tbody></table></div>"
                }
            }

            $cards += @"
<div class="instance-card">
<h3>Instance $idx - $(ConvertTo-SccHtml $(if($instanceId){$instanceId}else{"instance-$idx"}))</h3>
<table class="fact-table">
$detailRows
</table>
$persHtml
$procHtml
$connHtml
$rawHtml
$pwHtml
$upHtml
</div>
"@
        }
        $scFindingsHtml = @"
<section id="screenconnect-findings">
<h2>ScreenConnect Findings</h2>
$cards
</section>
"@
    }

    # Other Remote Access Findings
    $otherHtml = ''
    if (-not $findingsFile.Exists) {
        $otherHtml = @"
<section id="other-remote-access-findings">
<h2>Other Remote Access Findings</h2>
$(Format-SccNotCollected $findingsFile.Reason)
</section>
"@
    } elseif ($otherCount -eq 0) {
        $otherHtml = @"
<section id="other-remote-access-findings">
<h2>Other Remote Access Findings</h2>
<p class="ok-line">None found among scanned remote-access products.</p>
</section>
"@
    } else {
        $rows = ''
        foreach ($f in $otherFindings) {
            $prod = Get-SccSafeProp $f 'Product' (Get-SccSafeProp $f 'Name' (Get-SccSafeProp $f 'DisplayName' '-'))
            $detType = Get-SccSafeProp $f 'DetectionType' (Get-SccSafeProp $f 'Kind' (Get-SccSafeProp $f 'Type' '-'))
            $ev = Get-SccSafeProp $f 'Evidence' (Get-SccSafeProp $f 'Path' '-')
            if ($ev -is [object] -and $ev.PSObject.Properties.Name -contains 'Path') { $ev = $ev.Path }
            $ver = Get-SccSafeProp $f 'Version' '-'
            $pub = Get-SccSafeProp $f 'Publisher' '-'
            $conf = Get-SccSafeProp $f 'Confidence' '-'
            $rows += "<tr><td>$(ConvertTo-SccHtml $prod)</td><td>$(ConvertTo-SccHtml $detType)</td><td>$(ConvertTo-SccHtml $ev)</td><td>$(ConvertTo-SccHtml $ver)</td><td>$(ConvertTo-SccHtml $pub)</td><td>$(ConvertTo-SccHtml $conf)</td></tr>`n"
        }
        $otherHtml = @"
<section id="other-remote-access-findings">
<h2>Other Remote Access Findings</h2>
<div class="table-scroll"><table class="data-table"><thead><tr><th>Product</th><th>DetectionType</th><th>Evidence</th><th>Version</th><th>Publisher</th><th>Confidence</th></tr></thead><tbody>
$rows
</tbody></table></div>
</section>
"@
    }

    # Persistence
    $persistenceHtml = ''
    if ($null -ne $beforeData -or $null -ne $afterData) {
        $secNames = @('Services','ScheduledTasks','RegistryAutoruns','StartupFolders','WmiPersistence')
        $content = ''
        $foundAny = $false
        foreach ($sec in $secNames) {
            $items = $null
            if ($null -ne $beforeData) { $items = Get-SccSafeProp $beforeData.Sections $sec $null }
            if ($null -eq $items -and $null -ne $afterData) { $items = Get-SccSafeProp $afterData.Sections $sec $null }
            # Also check top-level Sections object
            if ($null -eq $items -and $null -ne $beforeData) {
                $secObj = Get-SccSafeProp $beforeData 'Sections' $null
                if ($null -ne $secObj) { $items = Get-SccSafeProp $secObj $sec $null }
            }
            $arr = Get-SccSafeItems $items
            # Sort by Key for determinism
            $arr = @($arr | Sort-Object -Property Key)
            if (@($arr).Count -gt 0) {
                $foundAny = $true
                $rows = ''
                $sample = $arr | Select-Object -First 5
                foreach ($it in $sample) {
                    $k = Get-SccSafeProp $it 'Key' '-'
                    $rows += "<tr><td>$(ConvertTo-SccHtml $k)</td><td>$(ConvertTo-SccHtml ([string]$it))</td></tr>`n"
                }
                if (@($arr).Count -gt 5) { $rows += "<tr><td colspan='2' class='muted'>... and $(@($arr).Count - 5) more</td></tr>`n" }
                $content += "<h4>$sec ($(@($arr).Count))</h4><div class='table-scroll'><table class='data-table'><thead><tr><th>Key</th><th>Details</th></tr></thead><tbody>$rows</tbody></table></div>`n"
            }
        }
        if (-not $foundAny) { $content = "<p class='muted'>No persistence items in snapshots or not collected.</p>" }
        $persistenceHtml = @"
<section id="persistence">
<h2>Persistence</h2>
$content
</section>
"@
    } else {
        $persistenceHtml = @"
<section id="persistence">
<h2>Persistence</h2>
$(Format-SccNotCollected 'Not collected / not applicable - snapshots not found')
</section>
"@
    }

    # Network Findings
    $networkHtml = ''
    if ($null -ne $beforeData -or $null -ne $afterData) {
        $connItems = @()
        if ($null -ne $beforeData) {
            $sec = Get-SccSafeProp $beforeData 'Sections' $null
            if ($null -ne $sec) { $connItems = Get-SccSafeItems (Get-SccSafeProp $sec 'Connections' $null) }
            if (@($connItems).Count -eq 0) { $connItems = Get-SccSafeItems (Get-SccSafeProp $beforeData 'Connections' $null) }
        }
        $fwItems = @()
        if ($null -ne $beforeData) {
            $sec = Get-SccSafeProp $beforeData 'Sections' $null
            if ($null -ne $sec) { $fwItems = Get-SccSafeItems (Get-SccSafeProp $sec 'FirewallRules' $null) }
        }
        $content = ''
        if (@($connItems).Count -gt 0) {
            $connItems = @($connItems | Sort-Object -Property Key)
            $rows = ''
            foreach ($c in ($connItems | Select-Object -First 10)) {
                $k = Get-SccSafeProp $c 'Key' '-'
                $rows += "<tr><td>$(ConvertTo-SccHtml $k)</td></tr>`n"
            }
            $content += "<h4>Connections ($(@($connItems).Count))</h4><div class='table-scroll'><table class='data-table'><tbody>$rows</tbody></table></div>`n"
        } else { $content += "<p class='muted'>Connections: Not collected / not applicable - no connection data</p>`n" }
        if (@($fwItems).Count -gt 0) {
            $fwItems = @($fwItems | Sort-Object -Property Key)
            $rows = ''
            foreach ($f in ($fwItems | Select-Object -First 10)) {
                $k = Get-SccSafeProp $f 'Key' '-'
                $rows += "<tr><td>$(ConvertTo-SccHtml $k)</td></tr>`n"
            }
            $content += "<h4>FirewallRules ($(@($fwItems).Count))</h4><div class='table-scroll'><table class='data-table'><tbody>$rows</tbody></table></div>`n"
        } else { $content += "<p class='muted'>FirewallRules: Not collected / not applicable</p>`n" }
        $networkHtml = @"
<section id="network-findings">
<h2>Network Findings</h2>
$content
</section>
"@
    } else {
        $networkHtml = @"
<section id="network-findings">
<h2>Network Findings</h2>
$(Format-SccNotCollected 'Not collected / not applicable - snapshots not found')
</section>
"@
    }

    # Scanner Results
    $scannerHtml = ''
    if (@($scannerResults).Count -eq 0) {
        $scannerHtml = @"
<section id="scanner-results">
<h2>Scanner Results</h2>
$(Format-SccNotCollected 'Not collected / not applicable - no scanner results found (scanner-results/*.json missing)')
</section>
"@
    } else {
        $rows = ''
        foreach ($sr in ($scannerResults | Sort-Object -Property FileName)) {
            $d = $sr.Data
            $name = ConvertTo-SccHtml (Get-SccSafeProp $d 'ScannerName' (Get-SccSafeProp $d 'Name' $sr.FileName))
            $status = ConvertTo-SccHtml (Get-SccSafeProp $d 'Status' (Get-SccSafeProp $d 'Result' 'Unknown'))
            $exit = ConvertTo-SccHtml (Get-SccSafeProp $d 'ExitCode' '-')
            $detCount = ConvertTo-SccHtml (Get-SccSafeProp $d 'DetectionCount' (Get-SccSafeProp $d 'Detections' '-'))
            if ($detCount -is [object] -and $detCount -ne '-') { $detCount = ConvertTo-SccHtml $detCount }
            $start = ConvertTo-SccHtml (Get-SccSafeProp $d 'StartTimeUtc' (Get-SccSafeProp $d 'StartedUtc' '-'))
            $end = ConvertTo-SccHtml (Get-SccSafeProp $d 'EndTimeUtc' (Get-SccSafeProp $d 'CompletedUtc' '-'))
            $rows += "<tr><td>$name</td><td>$status</td><td>$exit</td><td>$detCount</td><td>$start</td><td>$end</td></tr>`n"
        }
        $scannerHtml = @"
<section id="scanner-results">
<h2>Scanner Results</h2>
<div class="table-scroll"><table class="data-table"><thead><tr><th>Scanner</th><th>Status</th><th>ExitCode</th><th>Detections</th><th>Start (UTC)</th><th>End (UTC)</th></tr></thead><tbody>
$rows
</tbody></table></div>
</section>
"@
    }

    # Remediation Actions
    $remediationHtml = ''
    if (-not $planFile.Exists -and -not $remediationFile.Exists) {
        $remediationHtml = @"
<section id="remediation-actions">
<h2>Remediation Actions</h2>
$(Format-SccNotCollected 'Not collected / not applicable - plan.json and remediation.json not found')
</section>
"@
    } elseif (-not $remediationFile.Exists) {
        $remediationHtml = @"
<section id="remediation-actions">
<h2>Remediation Actions</h2>
$(Format-SccNotCollected $remediationFile.Reason)
<p class='muted'>Plan exists with $planRemoveCount REMOVE items but remediation not yet executed.</p>
</section>
"@
    } else {
        $rows = ''
        $entries = @()
        if ($remediationData -is [System.Array]) { $entries = $remediationData }
        else {
            $acts = Get-SccSafeProp $remediationData 'Actions' $null
            if ($null -ne $acts) { $entries = Get-SccSafeItems $acts }
            else {
                $ents = Get-SccSafeProp $remediationData 'Entries' $null
                if ($null -ne $ents) { $entries = Get-SccSafeItems $ents }
                else { $entries = @($remediationData) }
            }
        }
        $entries = @($entries | Sort-Object -Property { [string]$_.Action } )
        foreach ($e in $entries) {
            $fid = ConvertTo-SccHtml (Get-SccSafeProp $e 'FindingId' (Get-SccSafeProp $e 'Id' '-'))
            $act = ConvertTo-SccHtml (Get-SccSafeProp $e 'Action' '-')
            $target = ConvertTo-SccHtml (Get-SccSafeProp $e 'Target' (Get-SccSafeProp $e 'Detail' (Get-SccSafeProp $e 'Path' '-')))
            $result = ConvertTo-SccHtml (Get-SccSafeProp $e 'Result' (Get-SccSafeProp $e 'Status' '-'))
            $rows += "<tr><td>$fid</td><td>$act</td><td>$target</td><td>$result</td></tr>`n"
        }
        $remediationHtml = @"
<section id="remediation-actions">
<h2>Remediation Actions</h2>
<div class="table-scroll"><table class="data-table"><thead><tr><th>FindingId</th><th>Action</th><th>Target</th><th>Result</th></tr></thead><tbody>
$rows
</tbody></table></div>
</section>
"@
    }

    # Quarantine
    $quarantineHtml = ''
    $qManifestData = $null
    $qManifestReason = 'Not collected / not applicable - quarantine-manifest.json not found'
    $qPathsToTry = @(
        ([System.IO.Path]::Combine($runDir, 'quarantine-manifest.json')),
        ([System.IO.Path]::Combine($runDir, 'quarantine-meta/quarantine-manifest.json')),
        ([System.IO.Path]::Combine($outDir, 'quarantine-manifest.json'))
    )
    foreach ($qp in $qPathsToTry) {
        $qr = Read-SccJsonFile $qp
        if ($qr.Exists -and $null -ne $qr.Data) { $qManifestData = $qr.Data; $qManifestReason = ''; break }
        if ($qr.Exists) { $qManifestReason = $qr.Reason }
    }
    if ($null -eq $qManifestData) {
        # Also check if remediation file had quarantine info
        if ($quarantinedCount -gt 0) {
            $quarantineHtml = @"
<section id="quarantine">
<h2>Quarantine</h2>
<p class='muted'>$quarantinedCount item(s) quarantined per remediation record. Manifest file not separately found.</p>
</section>
"@
        } else {
            $quarantineHtml = @"
<section id="quarantine">
<h2>Quarantine</h2>
$(Format-SccNotCollected $qManifestReason)
</section>
"@
        }
    } else {
        $items = Get-SccSafeItems $qManifestData
        if (@($items).Count -eq 0 -and $qManifestData -is [System.Management.Automation.PSCustomObject]) { $items = @($qManifestData) }
        $rows = ''
        foreach ($qi in ($items | Sort-Object -Property { [string](Get-SccSafeProp $_ 'OriginalPath' '') })) {
            $op = ConvertTo-SccHtml (Get-SccSafeProp $qi 'OriginalPath' '-')
            $qp = ConvertTo-SccHtml (Get-SccSafeProp $qi 'QuarantinePath' '-')
            $sz = ConvertTo-SccHtml (Get-SccSafeProp $qi 'SizeBytes' (Get-SccSafeProp $qi 'Size' '-'))
            $sha = ConvertTo-SccHtml (Get-SccSafeProp $qi 'SHA256' (Get-SccSafeProp $qi 'Sha256' '-'))
            $rows += "<tr><td>$op</td><td>$qp</td><td>$sz</td><td>$sha</td></tr>`n"
        }
        $quarantineHtml = @"
<section id="quarantine">
<h2>Quarantine</h2>
<div class="table-scroll"><table class="data-table"><thead><tr><th>OriginalPath</th><th>QuarantinePath</th><th>Size</th><th>SHA256</th></tr></thead><tbody>
$rows
</tbody></table></div>
</section>
"@
    }

    # Before/After Comparison
    $compareHtml = ''
    if (-not $diffFile.Exists) {
        $compareHtml = @"
<section id="before-after-comparison">
<h2>Before/After Comparison</h2>
$(Format-SccNotCollected $diffFile.Reason)
</section>
"@
    } else {
        $sections = Get-SccSafeProp $diffData 'Sections' $null
        $rowsRemoved = ''
        $rowsStill = ''
        $rowsNew = ''
        $rowsReappeared = ''
        $rowsChanged = ''
        if ($null -ne $sections) {
            $secArr = @()
            if ($sections -is [System.Array]) { $secArr = $sections }
            elseif ($sections -is [System.Management.Automation.PSCustomObject]) {
                foreach ($p in $sections.PSObject.Properties) {
                    $secArr += [PSCustomObject]@{ Section = $p.Name; Data = $p.Value }
                }
            }
            foreach ($sec in $secArr) {
                $secName = Get-SccSafeProp $sec 'Section' $null
                if (-not $secName) { $secName = Get-SccSafeProp $sec 'Name' $null }
                if (-not $secName) {
                    $tmpSec = Get-SccSafeProp $sec 'Section' $null
                    if ($tmpSec) { $secName = $tmpSec }
                }
                if (-not $secName) { $secName = 'Unknown' }
                $secDataTmp = Get-SccSafeProp $sec 'Data' $null
                $dataObj = $sec
                if ($null -ne $secDataTmp) { $dataObj = $secDataTmp }
                $removed = Get-SccSafeProp $dataObj 'Removed' $null
                $still = Get-SccSafeProp $dataObj 'StillPresent' $null
                $added = Get-SccSafeProp $dataObj 'Added' $null
                $newItems = Get-SccSafeProp $dataObj 'New' $null
                if ($null -eq $newItems) { $newItems = $added }
                $changed = Get-SccSafeProp $dataObj 'Changed' $null
                foreach ($r in (Get-SccSafeItems $removed)) { $rowsRemoved += "<tr><td>$(ConvertTo-SccHtml $secName)</td><td>$(ConvertTo-SccHtml $r)</td></tr>`n" }
                foreach ($s in (Get-SccSafeItems $still)) { $rowsStill += "<tr><td>$(ConvertTo-SccHtml $secName)</td><td>$(ConvertTo-SccHtml $s)</td></tr>`n" }
                foreach ($n in (Get-SccSafeItems $newItems)) { $rowsNew += "<tr><td>$(ConvertTo-SccHtml $secName)</td><td>$(ConvertTo-SccHtml $n)</td></tr>`n" }
                foreach ($c in (Get-SccSafeItems $changed)) {
                    $key = $c
                    $fields = ''
                    if ($c -is [System.Management.Automation.PSCustomObject]) {
                        $key = Get-SccSafeProp $c 'Key' ([string]$c)
                        $fields = Get-SccSafeProp $c 'Fields' $null
                        if ($fields) { $fields = (Get-SccSafeItems $fields) -join ', ' }
                    }
                    $rowsChanged += "<tr><td>$(ConvertTo-SccHtml $secName)</td><td>$(ConvertTo-SccHtml $key)</td><td>$(ConvertTo-SccHtml $fields)</td></tr>`n"
                }
                # Reappeared = items that were Removed then New? approximate as New in diff with warning
                # Use DiffData Reappeared if present
                $reapp = Get-SccSafeProp $dataObj 'Reappeared' $null
                foreach ($rp in (Get-SccSafeItems $reapp)) { $rowsReappeared += "<tr><td>$(ConvertTo-SccHtml $secName)</td><td>$(ConvertTo-SccHtml $rp)</td></tr>`n" }
            }
        } else {
            # Diff is flat structure
            foreach ($p in $diffData.PSObject.Properties) {
                if ($p.Name -eq 'Removed') {
                    foreach ($r in (Get-SccSafeItems $p.Value)) { $rowsRemoved += "<tr><td>-</td><td>$(ConvertTo-SccHtml $r)</td></tr>`n" }
                }
                if ($p.Name -eq 'New' -or $p.Name -eq 'Added') {
                    foreach ($n in (Get-SccSafeItems $p.Value)) { $rowsNew += "<tr><td>-</td><td>$(ConvertTo-SccHtml $n)</td></tr>`n" }
                }
            }
        }
        if (-not $rowsRemoved) { $rowsRemoved = "<tr><td colspan='2' class='muted'>None</td></tr>" }
        if (-not $rowsStill) { $rowsStill = "<tr><td colspan='2' class='muted'>None</td></tr>" }
        if (-not $rowsNew) { $rowsNew = "<tr><td colspan='2' class='muted'>None</td></tr>" }
        if (-not $rowsReappeared) { $rowsReappeared = "<tr><td colspan='2' class='muted'>None</td></tr>" }
        if (-not $rowsChanged) { $rowsChanged = "<tr><td colspan='3' class='muted'>None</td></tr>" }

        $compareHtml = @"
<section id="before-after-comparison">
<h2>Before/After Comparison</h2>
<h3>Removed</h3><div class="table-scroll"><table class="data-table"><thead><tr><th>Section</th><th>Key</th></tr></thead><tbody>
$rowsRemoved
</tbody></table></div>
<h3>Still Present</h3><div class="table-scroll"><table class="data-table"><thead><tr><th>Section</th><th>Key</th></tr></thead><tbody>
$rowsStill
</tbody></table></div>
<h3>New</h3><div class="table-scroll"><table class="data-table"><thead><tr><th>Section</th><th>Key</th></tr></thead><tbody>
$rowsNew
</tbody></table></div>
<h3>Reappeared</h3><div class="table-scroll"><table class="data-table"><thead><tr><th>Section</th><th>Key</th></tr></thead><tbody>
$rowsReappeared
</tbody></table></div>
<h3>Changed</h3><div class="table-scroll"><table class="data-table"><thead><tr><th>Section</th><th>Key</th><th>Fields</th></tr></thead><tbody>
$rowsChanged
</tbody></table></div>
</section>
"@
    }

    # Outstanding Concerns
    $concerns = [System.Collections.ArrayList]::new()
    if ($unknownCount -gt 0) { [void]$concerns.Add("Unknown ScreenConnect relay(s) detected ($unknownCount) - manual review required") }
    if ($scanFailed -gt 0) { [void]$concerns.Add("Scanner failures: $scanFailed scan(s) failed or not verified") }
    if ($diffNew -gt 0) { [void]$concerns.Add("New items appeared after remediation ($diffNew) - possible resurrection") }
    if ($diffChanged -gt 0) { [void]$concerns.Add("Changed items after remediation ($diffChanged)") }
    if ($parserWarningsCount -gt 0) { [void]$concerns.Add("Parser warnings / unknown parameters present ($parserWarningsCount)") }
    if (@($concerns).Count -eq 0) { [void]$concerns.Add("No outstanding concerns detected - verify manually") }
    $concernRows = ''
    foreach ($c in $concerns) { $concernRows += "<li>$(ConvertTo-SccHtml $c)</li>`n" }
    $outstandingHtml = @"
<section id="outstanding-concerns">
<h2>Outstanding Concerns</h2>
<ul>
$concernRows
</ul>
</section>
"@

    # Errors / Warnings
    $errorsHtml = ''
    $errorLines = [System.Collections.ArrayList]::new()
    if ($masterLogExists -and $masterLogContent) {
        $lines = $masterLogContent -split "`n"
        foreach ($l in $lines) {
            if ($l -match '(ERROR|WARNING|WARN|Failed)') { [void]$errorLines.Add($l.Trim()) }
        }
        $errorLines = @($errorLines | Select-Object -First 20)
    }
    if ($null -ne $beforeData) {
        $ce = Get-SccSafeProp $beforeData 'CollectionErrors' $null
        foreach ($e in (Get-SccSafeItems $ce)) {
            $sec = Get-SccSafeProp $e 'Section' '-'
            $msg = Get-SccSafeProp $e 'Error' '-'
            [void]$errorLines.Add("CollectionError $sec : $msg")
        }
    }
    if (@($errorLines).Count -eq 0) {
        $errorsHtml = @"
<section id="errors-warnings">
<h2>Errors / Warnings</h2>
<p class="ok-line">No errors or warnings recorded.</p>
</section>
"@
    } else {
        $rows = ''
        foreach ($el in $errorLines) { $rows += "<tr><td>$(ConvertTo-SccHtml $el)</td></tr>`n" }
        $errorsHtml = @"
<section id="errors-warnings">
<h2>Errors / Warnings</h2>
<div class="table-scroll"><table class="data-table"><tbody>
$rows
</tbody></table></div>
</section>
"@
    }

    # Tool Provenance
    $toolProvHtml = ''
    if (-not $toolProvFile.Exists) {
        $toolProvHtml = @"
<section id="tool-provenance">
<h2>Tool Provenance</h2>
$(Format-SccNotCollected $toolProvFile.Reason)
</section>
"@
    } else {
        $rows = ''
        if ($toolProvData -is [System.Array]) {
            foreach ($tp in $toolProvData) {
                $name = ConvertTo-SccHtml (Get-SccSafeProp $tp 'Name' (Get-SccSafeProp $tp 'Tool' '-'))
                $ver = ConvertTo-SccHtml (Get-SccSafeProp $tp 'Version' '-')
                $sha = ConvertTo-SccHtml (Get-SccSafeProp $tp 'SHA256' (Get-SccSafeProp $tp 'Sha256' '-'))
                $src = ConvertTo-SccHtml (Get-SccSafeProp $tp 'Source' (Get-SccSafeProp $tp 'Provenance' '-'))
                $rows += "<tr><td>$name</td><td>$ver</td><td>$sha</td><td>$src</td></tr>`n"
            }
        } elseif ($toolProvData -is [System.Management.Automation.PSCustomObject]) {
            foreach ($p in $toolProvData.PSObject.Properties) {
                $tp = $p.Value
                if ($tp -is [string]) {
                    $rows += "<tr><td>$(ConvertTo-SccHtml $p.Name)</td><td>$(ConvertTo-SccHtml $tp)</td><td>-</td><td>-</td></tr>`n"
                } else {
                    $name = ConvertTo-SccHtml $p.Name
                    $ver = ConvertTo-SccHtml (Get-SccSafeProp $tp 'Version' '-')
                    $sha = ConvertTo-SccHtml (Get-SccSafeProp $tp 'SHA256' '-')
                    $rows += "<tr><td>$name</td><td>$ver</td><td>$sha</td><td>-</td></tr>`n"
                }
            }
        }
        if (-not $rows) { $rows = "<tr><td colspan='4'>$(ConvertTo-SccHtml ([string]$toolProvData))</td></tr>" }
        $toolProvHtml = @"
<section id="tool-provenance">
<h2>Tool Provenance</h2>
<div class="table-scroll"><table class="data-table"><thead><tr><th>Tool</th><th>Version</th><th>SHA256</th><th>Source</th></tr></thead><tbody>
$rows
</tbody></table></div>
</section>
"@
    }

    # Credential / Incident Follow-up Checklist
    $checklistHtml = @"
<section id="credential-checklist">
<h2>Credential / Incident Follow-up Checklist</h2>
<ul>
<li>Reset ScreenConnect / ConnectWise Control credentials and revoke active sessions/tokens</li>
<li>Rotate local administrator and service-account passwords on affected host</li>
<li>Verify multi-factor authentication (MFA) enabled on all remote-access services</li>
<li>Review authorized relay hosts - confirm only known relays remain</li>
<li>Rotate API keys and integration tokens that may have been exposed</li>
<li>Check for additional persistence (scheduled tasks, Run keys, WMI) - see Persistence section</li>
<li>Review network connections and firewall rules for unauthorized access</li>
<li>Re-run investigation scan to confirm remediation and no resurrection</li>
<li>Document incident timeline and retain report for compliance</li>
<li>Consider credential reset for domain accounts if lateral movement suspected</li>
</ul>
</section>
"@

    # Raw Evidence Index
    $evidenceIndexHtml = ''
    $allFilesRaw = @(Get-ChildItem -LiteralPath $runDir -File -Recurse -ErrorAction SilentlyContinue | Sort-Object -Property FullName)
    # Exclude outputs themselves for determinism (second run would otherwise include previous report)
    $allFiles = @($allFilesRaw | Where-Object { $_.Name -notin @('report.html','report.json','technician-summary.txt') })
    if (@($allFiles).Count -eq 0) {
        $evidenceIndexHtml = @"
<section id="raw-evidence-index">
<h2>Raw Evidence Index</h2>
$(Format-SccNotCollected 'Not collected / not applicable - no files found in run directory')
</section>
"@
    } else {
        $rows = ''
        foreach ($f in $allFiles) {
            $rel = $f.FullName.Substring($runDir.Length).TrimStart('\','/')
            $rel = $rel -replace '\\','/'
            $size = $f.Length
            $rows += "<tr><td>$(ConvertTo-SccHtml $rel)</td><td>$size</td></tr>`n"
        }
        $evidenceIndexHtml = @"
<section id="raw-evidence-index">
<h2>Raw Evidence Index</h2>
<div class="table-scroll"><table class="data-table"><thead><tr><th>Path</th><th>Size (bytes)</th></tr></thead><tbody>
$rows
</tbody></table></div>
</section>
"@
    }

    # Assemble HTML document
    $headerHtml = @"
<header>
<h1>ScreenConnect Cleaner - Investigation Report</h1>
<table class="header-table">
<tr><th>Computer</th><td>$(ConvertTo-SccHtml $computerName)</td><th>Run ID</th><td>$(ConvertTo-SccHtml $runId)</td></tr>
<tr><th>Generated (UTC)</th><td>$(ConvertTo-SccHtml $reportGeneratedUtc)</td><th>SC instances</th><td>$scCount (Known $knownCount / Unknown $unknownCount)</td></tr>
</table>
<p class="muted">Self-contained report - inline CSS only. Re-run investigation to confirm any changes.</p>
</header>
"@

    $bodyHtml = @"
$headerHtml
<main>
$execSummaryHtml
$systemInfoHtml
$timelineHtml
$scFindingsHtml
$otherHtml
$persistenceHtml
$networkHtml
$scannerHtml
$remediationHtml
$quarantineHtml
$compareHtml
$outstandingHtml
$errorsHtml
$toolProvHtml
$checklistHtml
$evidenceIndexHtml
</main>
<footer>
Generated by Scc.Report $reportGeneratedUtc from run $runId. Read-only report - no changes to system.
</footer>
"@

    $fullHtml = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>$(ConvertTo-SccHtml $titleText)</title>
<style>
$css
</style>
</head>
<body>
$bodyHtml
</body>
</html>
"@

    # Ensure no raw on* javascript patterns slip through - we already escaped all dynamic values
    # but verify we did not include event handlers in static HTML
    # Write outputs deterministically: sort json keys? Use ordered hashtables

    $htmlPath = [System.IO.Path]::Combine($outDir, 'report.html')
    $jsonPath = [System.IO.Path]::Combine($outDir, 'report.json')
    $txtPath = [System.IO.Path]::Combine($outDir, 'technician-summary.txt')

    # report.json
    $summaryObj = [ordered]@{
        RunId = $runId
        ComputerName = $computerName
        GeneratedUtc = $reportGeneratedUtc
        Counts = [ordered]@{
            ScreenConnectInstances = $scCount
            Known = $knownCount
            Unknown = $unknownCount
            OtherRemoteAccessFindings = $otherCount
            ScansTotal = $scanTotal
            ScansCompleted = $scanCompleted
            ScansFailed = $scanFailed
            ScansSkipped = $scanSkipped
            PlanRemove = $planRemoveCount
            RemediationActions = $remediationActions
            Quarantined = $quarantinedCount
            DiffRemoved = $diffRemoved
            DiffNew = $diffNew
            DiffChanged = $diffChanged
            DiffStillPresent = $diffStillPresent
            OutstandingConcerns = @($concerns).Count
        }
        Timeline = @($timelineEvents)
    }

    $reportJsonObj = [ordered]@{
        SchemaVersion = 1
        GeneratedUtc = $reportGeneratedUtc
        RunId = $runId
        RunDir = $runDir
        Summary = $summaryObj
        Inputs = [ordered]@{
            RunState = $runStateData
            Findings = $findingsData
            Plan = $planData
            Remediation = $remediationData
            ToolProvenance = $toolProvData
            BeforeSnapshot = $beforeData
            AfterSnapshot = $afterData
            Diff = $diffData
            ScannerResults = @($scannerResults | ForEach-Object { $_.Data })
            MasterLog = $masterLogContent
        }
        Files = [ordered]@{
            RunStateFile = $runStateFile.Path
            FindingsFile = $findingsFile.Path
            PlanFile = $planFile.Path
            RemediationFile = $remediationFile.Path
            ToolProvenanceFile = $toolProvFile.Path
            BeforeSnapshotFile = $beforeFile.Path
            AfterSnapshotFile = $afterFile.Path
            DiffFile = $diffFile.Path
            ScannerDir = $scannerDir
            MasterLog = $masterLogPath
        }
        Verification = [ordered]@{
            NotCollected = @(
                if (-not $runStateFile.Exists) { 'runstate.json' }
                if (-not $findingsFile.Exists) { 'findings.json' }
                if (-not $planFile.Exists) { 'plan.json' }
                if (-not $remediationFile.Exists) { 'remediation.json' }
                if (-not $toolProvFile.Exists) { 'tool-provenance.json' }
                if (-not $beforeFile.Exists) { 'snapshots/before.json' }
                if (-not $afterFile.Exists) { 'snapshots/after.json' }
                if (-not $diffFile.Exists) { 'snapshots/diff.json' }
                if (@($scannerResults).Count -eq 0) { 'scanner-results/*.json' }
                if (-not $masterLogExists) { 'logs/master.log' }
            )
        }
    }

    # Write files UTF8 NoBOM deterministically
    $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText($htmlPath, $fullHtml, $utf8NoBom)

    # For determinism, ensure report.json ordering stable: ConvertTo-Json with depth 12
    # PowerShell 5.1 ConvertTo-Json may emit properties in hash order; we used ordered hashtables so order is preserved
    $jsonText = $reportJsonObj | ConvertTo-Json -Depth 12
    [System.IO.File]::WriteAllText($jsonPath, $jsonText, $utf8NoBom)

    # technician-summary.txt <=60 lines
    $txtLines = [System.Collections.ArrayList]::new()
    [void]$txtLines.Add('ScreenConnect Cleaner - Technician Summary')
    [void]$txtLines.Add(('Run: ' + $runId + '  Computer: ' + $computerName + '  Generated: ' + $reportGeneratedUtc + ' UTC'))
    [void]$txtLines.Add('----------------------------------------------------------------')
    [void]$txtLines.Add(('Verdict: SC instances ' + $scCount + ' (Known ' + $knownCount + ' / Unknown ' + $unknownCount + ')'))
    if ($unknownCount -gt 0) { [void]$txtLines.Add('  -> Unknown relay(s) require manual review') }
    [void]$txtLines.Add(('Other RAT findings: ' + $otherCount))
    [void]$txtLines.Add(('Scans: ' + $scanTotal + ' total (Completed ' + $scanCompleted + ' / Failed ' + $scanFailed + ' / Skipped ' + $scanSkipped + ')'))
    [void]$txtLines.Add(('Remediation: ' + $remediationActions + ' action(s) (Plan REMOVE ' + $planRemoveCount + ')  Quarantined: ' + $quarantinedCount))
    [void]$txtLines.Add(('Diff: Removed ' + $diffRemoved + '  New ' + $diffNew + '  Changed ' + $diffChanged + '  StillPresent ' + $diffStillPresent))
    [void]$txtLines.Add(('Outstanding concerns: ' + @($concerns).Count))
    foreach ($c in $concerns) { [void]$txtLines.Add(('  - ' + $c)) }
    [void]$txtLines.Add('----------------------------------------------------------------')
    [void]$txtLines.Add('What was done:')
    if ($findingsFile.Exists) { [void]$txtLines.Add('  - Detection collected') } else { [void]$txtLines.Add('  - Detection NOT collected') }
    if ($beforeFile.Exists) { [void]$txtLines.Add('  - Snapshot before collected') } else { [void]$txtLines.Add('  - Snapshot before NOT collected') }
    if ($remediationActions -gt 0) { [void]$txtLines.Add('  - Remediation executed') } else { [void]$txtLines.Add('  - Remediation not executed / dry-run') }
    if ($scanTotal -gt 0) { [void]$txtLines.Add('  - Scanners executed') } else { [void]$txtLines.Add('  - Scanners NOT run') }
    if ($afterFile.Exists) { [void]$txtLines.Add('  - Snapshot after collected') } else { [void]$txtLines.Add('  - Snapshot after NOT collected') }
    if ($diffFile.Exists) { [void]$txtLines.Add('  - Before/after diff generated') } else { [void]$txtLines.Add('  - Diff NOT generated') }
    [void]$txtLines.Add('What was NOT checked (missing inputs):')
    $notChecked = @($reportJsonObj.Verification.NotCollected)
    if (@($notChecked).Count -eq 0) { [void]$txtLines.Add('  - None - all inputs present') }
    else {
        foreach ($nc in $notChecked) { [void]$txtLines.Add(('  - ' + $nc)) }
    }
    [void]$txtLines.Add('Next steps:')
    [void]$txtLines.Add('  1. Review ScreenConnect Findings and trust badges')
    [void]$txtLines.Add('  2. Inspect Other Remote Access Findings')
    [void]$txtLines.Add('  3. Check Before/After Comparison for resurrection')
    [void]$txtLines.Add('  4. Review Errors / Warnings and Outstanding Concerns')
    [void]$txtLines.Add('  5. Follow Credential / Incident Follow-up Checklist')
    [void]$txtLines.Add('  6. Retain report.html and report.json for handoff')
    [void]$txtLines.Add('----------------------------------------------------------------')
    [void]$txtLines.Add('Credential checklist: see report.html -> Credential / Incident Follow-up Checklist')
    [void]$txtLines.Add('Full details: report.html  Machine data: report.json')
    [void]$txtLines.Add('Generated: ' + $reportGeneratedUtc + ' UTC')

    # Enforce <=60 lines
    if (@($txtLines).Count -gt 60) {
        $trimmed = [System.Collections.ArrayList]::new()
        for ($i = 0; $i -lt 59; $i++) { [void]$trimmed.Add($txtLines[$i]) }
        [void]$trimmed.Add('... truncated (max 60 lines)')
        $txtLines = $trimmed
    }
    $txtContent = ($txtLines -join "`r`n") + "`r`n"
    [System.IO.File]::WriteAllText($txtPath, $txtContent, $utf8NoBom)

    return [PSCustomObject]@{
        RunDir = $runDir
        OutputDir = $outDir
        HtmlPath = $htmlPath
        JsonPath = $jsonPath
        TxtPath = $txtPath
        Summary = $summaryObj
    }
}

Export-ModuleMember -Function New-SccReport, ConvertTo-SccHtml

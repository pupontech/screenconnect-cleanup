<#
  Invoke-ReviewAndRemove.ps1  -  Review detected ScreenConnect instances and
  remove the approved ones.

  This is the removal entry point for the GUIDED runner (START-HERE.bat).
  sc-cleanup.ps1 has its own equivalent review gate as Stage 3; this script
  exists so the guided, step-by-step flow can remove too without re-running
  the whole 10-stage pipeline (which would redo both snapshots).

  The actual removal is NOT reimplemented here - it delegates to
  remove-screenconnect.ps1, which stays the single removal engine
  (quarantine-never-delete, manifest, reboot resume).

  OWNER POLICY: ScreenConnect instances ONLY. Every other remote-access
  product in targets.json is detect/report-only and is never touched.

  Dry-run by default. Nothing is removed unless the technician completes the
  typed review and confirmation prompts. The former -Yes compatibility switch is
  rejected because automatic destructive approval is not safe.

  Review model (owner directive): ONE typed confirmation removes ALL detected
  ScreenConnect instances. There is no per-instance selection and no second
  confirmation prompt - the single y/N answer below is the only removal prompt.

  OPT-IN EXCEPTION (-SelectKeep / -KeepIdentifier, or -AskKeep from the offline
  launcher, which first asks "Keep any?" and only when instances were found): the
  technician first marks the instances that are LEGITIMATE and must stay installed
  (for example the customer's own ScreenConnect support agent). Kept instances are
  never put in the plan, so the removal engine never sees them; the rest still go
  through the same single y/N prompt. The kept ones are recorded in the plan
  (KeptScreenConnectInstances) and in kept-instances.json for the report. Without
  those switches this script behaves exactly as before.

  PS 5.1 compatible. Pure ASCII, no BOM.
  Exit codes: 0 = ok (including "nothing to do"), 1 = removal reported failure.
#>

param(
    # findings.json to review. Default: newest under the detector's output root.
    [string]$FindingsJson,

    # Where plan.json / quarantine / manifest go. Default: C:\RIT-SCC\<host>-<stamp>
    [string]$WorkDir,

    # Recommended free-space threshold; below it, explicit Y/Yes is required.
    [int]$MinFreeGB = 10,

    # Where to look for findings when -FindingsJson is not given.
    [string]$ScanRoot = "$env:USERPROFILE\Desktop\RemoteAccessScan",

    # Deprecated compatibility switch. It is rejected; destructive approval must
    # always be performed through the typed review and confirmation prompts.
    [switch]$Yes,

    # Review and write plan.json, but never call the remover.
    [switch]$WhatIfOnly,

    # Select mode: ask which instances to KEEP as legitimate before the remove prompt.
    [switch]$SelectKeep,

    # Non-interactive form of the same choice: Identifier values to keep. An
    # identifier that matches no detected instance stops the run (a typo must
    # never turn into "remove it").
    [string[]]$KeepIdentifier,

    # Offline launcher: when instances WERE found, first ask "Keep any?" (y = select
    # mode, anything else = remove all as before). Never asked when nothing was found.
    [switch]$AskKeep
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

function Write-Line {
    param([string]$Message, [string]$Color = 'Gray')
    Write-Host $Message -ForegroundColor $Color
}

if ($Yes) {
    Write-Line 'ERROR: -Yes automatic approval is disabled. Use the typed review and confirmation prompts.' 'Red'
    exit 2
}

function Get-AvailableDiskSpace {
    param([string]$Path)
    try {
        $fullPath = [System.IO.Path]::GetFullPath($Path)
        $root = [System.IO.Path]::GetPathRoot($fullPath)
        if ([string]::IsNullOrWhiteSpace($root)) { return -1 }
        $drive = New-Object System.IO.DriveInfo($root)
        return [math]::Floor($drive.AvailableFreeSpace / 1GB)
    } catch {
        return -1
    }
}

function Confirm-LowDiskSpace {
    param(
        [int]$FreeGB,
        [string]$Path,
        [int]$MinFreeGB
    )
    Write-Line ("WARNING: Only {0} GB free on {1}; the recommended minimum is {2} GB." -f $FreeGB, $Path, $MinFreeGB) 'Yellow'
    # Emit the prompt text explicitly: with redirected stdin (CI, piped runs),
    # Read-Host does not echo the prompt on Windows PowerShell 5.1.
    Write-Host 'Continue anyway? [y/N]' -NoNewline
    try {
        $answer = Read-Host
    } catch {
        Write-Line ("Could not read the low-disk confirmation: " + $_.Exception.Message) 'Red'
        return $false
    }
    if ($null -ne $answer -and $answer.Trim() -match '^(?i:y|yes)$') {
        Write-Line 'Continuing despite the low-disk warning because the operator confirmed.' 'Yellow'
        return $true
    }
    Write-Line 'Low disk space was not approved; removal is stopping before the plan is written.' 'Red'
    return $false
}

function Get-Prop {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function Get-JsonItems {
    param($Value)
    if ($null -eq $Value) { return , @() }
    if ($Value -is [pscustomobject] -and @($Value.PSObject.Properties).Count -eq 0) { return , @() }
    if ($Value -is [System.Array]) { return , @($Value) }
    return , @($Value)
}

function ConvertTo-KeepIndexes {
    # Parses the "which to keep" answer. Blank = keep none, A/ALL = keep all,
    # otherwise a list of 1-based numbers. Anything else is rejected (never guessed).
    param([string]$Text, [int]$Count)
    $t = ([string]$Text).Trim()
    if ($t -eq '') { return [pscustomobject]@{ Ok = $true; Indexes = @(); Message = '' } }
    if ($t -match '^(?i:a|all)$') { return [pscustomobject]@{ Ok = $true; Indexes = @(1..$Count); Message = '' } }
    $picked = New-Object System.Collections.Generic.List[int]
    foreach ($tok in @($t -split '[,\s;]+' | Where-Object { $_ -ne '' })) {
        if ($tok -notmatch '^\d{1,4}$') {
            return [pscustomobject]@{ Ok = $false; Indexes = @(); Message = ("'" + $tok + "' is not a number from the list.") }
        }
        $v = [int]$tok
        if ($v -lt 1 -or $v -gt $Count) {
            return [pscustomobject]@{ Ok = $false; Indexes = @(); Message = ($v.ToString() + ' is not in the list (1-' + $Count + ').') }
        }
        if (-not $picked.Contains($v)) { [void]$picked.Add($v) }
    }
    $sorted = @($picked.ToArray() | Sort-Object)
    return [pscustomobject]@{ Ok = $true; Indexes = $sorted; Message = '' }
}

function Get-InstanceIdentifier {
    param($Instance, [int]$Number)
    $id = Get-Prop $Instance 'Identifier'
    if (-not $id) { $id = Get-Prop $Instance 'Key' }
    if (-not $id) { $id = '(unidentified)' }
    return [string]$id
}

# --- Locate findings.json ---------------------------------------------------
if (-not $FindingsJson) {
    if (-not (Test-Path -LiteralPath $ScanRoot)) {
        Write-Line "No scan results found under $ScanRoot - run the detection step first." 'Yellow'
        exit 0
    }
    $newest = Get-ChildItem -LiteralPath $ScanRoot -Filter 'findings.json' -Recurse -ErrorAction SilentlyContinue |
              Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $newest) {
        Write-Line "No findings.json under $ScanRoot - run the detection step first." 'Yellow'
        exit 0
    }
    $FindingsJson = $newest.FullName
}

if (-not (Test-Path -LiteralPath $FindingsJson)) {
    Write-Line "findings.json not found: $FindingsJson" 'Red'
    exit 1
}

Write-Line "Reviewing: $FindingsJson" 'Cyan'
$findings = Get-Content -LiteralPath $FindingsJson -Raw | ConvertFrom-Json
$sc = Get-Prop $findings 'ScreenConnect'
$instances = @()
if ($sc) {
    $raw = Get-Prop $sc 'Instances'
    $instances = Get-JsonItems $raw
}

if ($instances.Count -eq 0) {
    Write-Line "No live ScreenConnect instances in these findings - nothing to remove." 'Green'
    exit 0
}

$selectMode = ([bool]$SelectKeep) -or (@($KeepIdentifier | Where-Object { $_ }).Count -gt 0)
# -AskKeep shows the numbered, detailed list up front so the answer is an informed one.
$detailedList = $selectMode -or [bool]$AskKeep

Write-Line ""
Write-Line ("Found " + $instances.Count + " ScreenConnect instance(s).") 'White'
$listNumber = 0
foreach ($inst in $instances) {
    $listNumber++
    $id = Get-InstanceIdentifier $inst $listNumber
    if ($detailedList) { Write-Line ("    [" + $listNumber + "] " + $id) 'White' } else { Write-Line ("    - " + $id) 'Gray' }
    $installDir = Get-Prop $inst 'InstallDir'
    if ($installDir) { Write-Line ("        Install directory: " + $installDir) 'Gray' }
    $relayHost = Get-Prop $inst 'RelayHost'
    if ($relayHost) {
        $relayPort = Get-Prop $inst 'RelayPort'
        if ($detailedList -and $relayPort) { $relayHost = ([string]$relayHost + ':' + [string]$relayPort) }
        Write-Line ("        Relay host: " + $relayHost) 'Gray'
    }
    if ($detailedList) {
        $svcName = Get-Prop $inst 'ServiceName'
        if ($svcName) {
            $svcState = Get-Prop $inst 'ServiceState'
            Write-Line ("        Service: " + $svcName + $(if ($svcState) { ' (' + $svcState + ')' } else { '' })) 'Gray'
        }
        $sessionType = Get-Prop $inst 'SessionType'
        if ($sessionType) { Write-Line ("        Session type: " + $sessionType) 'Gray' }
        $fileInfo = Get-Prop $inst 'File'
        if ($fileInfo) {
            $sigStatus = Get-Prop $fileInfo 'SignatureStatus'
            $sigSubject = Get-Prop $fileInfo 'SignerSubject'
            if ($sigStatus -or $sigSubject) { Write-Line ("        Signature: " + $sigStatus + $(if ($sigSubject) { ' - ' + $sigSubject } else { '' })) 'Gray' }
        }
        $created = Get-Prop $inst 'InstallDirCreatedUtc'
        if ($created) { Write-Line ("        Installed (folder created, UTC): " + $created) 'Gray' }
    }
}

# --- Offline launcher: is any of them supposed to be there? -----------------------
# Only reached when instances were found. y/yes = select mode; anything else (Enter,
# n, end of input) = remove all, exactly as without -AskKeep.
if ($AskKeep -and -not $selectMode) {
    Write-Line ""
    Write-Line "Is any of these SUPPOSED to be there, for example the customer's own support agent?" 'Cyan'
    Write-Host 'Keep any ScreenConnect? y = choose which ones to keep, Enter = remove all [y/N]' -NoNewline
    $askKeepAnswer = Read-Host
    if (([string]$askKeepAnswer).Trim() -match '^(?i:y|yes)$') { $selectMode = $true }
}

# --- Select mode: which instances are legitimate and stay -----------------------
$removeInstances = @($instances)
$keptInstances = @()
if ($selectMode) {
    $keepIdx = @()
    $explicit = @($KeepIdentifier | Where-Object { $_ })
    # powershell -File passes "-KeepIdentifier a,b" as the ONE string "a,b" (it does not build
    # an array), and a second space-separated value is lost. So a value that matches no
    # identifier as a whole is split on commas. An exact whole match always wins, so an
    # identifier that itself contains a comma still works. Each part must still match.
    $wanted = @()
    foreach ($w in $explicit) {
        $wholeHit = $false
        for ($i = 0; $i -lt $instances.Count; $i++) {
            if ((Get-InstanceIdentifier $instances[$i] ($i + 1)) -ieq [string]$w) { $wholeHit = $true }
        }
        if ($wholeHit -or ([string]$w).IndexOf(',') -lt 0) { $wanted += [string]$w }
        else { foreach ($part in ([string]$w -split ',')) { $t = $part.Trim(); if ($t) { $wanted += $t } } }
    }
    $explicit = @($wanted)
    if ($explicit.Count -gt 0) {
        $unmatched = @()
        foreach ($want in $explicit) {
            $hit = $false
            for ($i = 0; $i -lt $instances.Count; $i++) {
                if ((Get-InstanceIdentifier $instances[$i] ($i + 1)) -ieq [string]$want) { $hit = $true; if ($keepIdx -notcontains ($i + 1)) { $keepIdx += ($i + 1) } }
            }
            if (-not $hit) { $unmatched += [string]$want }
        }
        if ($unmatched.Count -gt 0) {
            Write-Line ("ERROR: -KeepIdentifier value(s) match no detected instance: " + ($unmatched -join ', ')) 'Red'
            Write-Line "Nothing was removed. Check the identifiers above and run again." 'Red'
            exit 2
        }
    } else {
        Write-Line ""
        Write-Line "SELECT MODE: mark the instances that are LEGITIMATE and should stay installed." 'Cyan'
        Write-Line "Check the relay host and the signature first. A relay host you do not recognize is a reason to remove it." 'Yellow'
        do {
            Write-Host 'Numbers to KEEP (e.g. 1,3), A = keep all, Enter = keep none:' -NoNewline
            $answer = Read-Host
            $parsed = ConvertTo-KeepIndexes -Text ([string]$answer) -Count $instances.Count
            if (-not $parsed.Ok) { Write-Line ("  " + $parsed.Message) 'Red' }
        } while (-not $parsed.Ok)
        $keepIdx = @($parsed.Indexes)
    }
    $keptInstances = @(for ($i = 0; $i -lt $instances.Count; $i++) { if ($keepIdx -contains ($i + 1)) { $instances[$i] } })
    $removeInstances = @(for ($i = 0; $i -lt $instances.Count; $i++) { if ($keepIdx -notcontains ($i + 1)) { $instances[$i] } })
    Write-Line ""
    Write-Line ("KEEP   (stays installed, not touched): " + $keptInstances.Count) 'Green'
    foreach ($k in $keptInstances) { Write-Line ("    = " + (Get-InstanceIdentifier $k 0)) 'Green' }
    Write-Line ("REMOVE (quarantined, never deleted):   " + $removeInstances.Count) 'Yellow'
    foreach ($r in $removeInstances) { Write-Line ("    - " + (Get-InstanceIdentifier $r 0)) 'Yellow' }
}

function Save-KeptInstances {
    param([string]$Dir)
    if ($keptInstances.Count -eq 0) { return }
    if (-not (Test-Path -LiteralPath $Dir)) { $null = New-Item -ItemType Directory -Path $Dir -Force }
    $keptDoc = [ordered]@{
        SchemaVersion = 1
        ComputerName  = $env:COMPUTERNAME
        GeneratedUtc  = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
        Note          = 'ScreenConnect instances the technician marked as legitimate and left installed. Not removed, not modified.'
        Kept          = $keptInstances
    }
    $keptDoc | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $Dir 'kept-instances.json') -Encoding UTF8 -NoNewline
}

# The work folder is needed early in select mode (everything kept = no removal, but a record is still written).
if (-not $WorkDir) {
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd_HHmmss')
    $WorkDir = Join-Path 'C:\RIT-SCC' ($env:COMPUTERNAME + '-' + $stamp)
}
if ($selectMode -and $removeInstances.Count -eq 0) {
    Save-KeptInstances -Dir $WorkDir
    Write-Line ""
    Write-Line "Every detected instance was kept - nothing to remove. Recorded in kept-instances.json." 'Green'
    exit 0
}

# --- Confirmation -----------------------------------------------------------
# ONE typed confirmation covers every detected instance (owner directive).
# Every ScreenConnect instance in the current findings is a removal candidate;
# a single y answers for all of them. Files are quarantined, never deleted.
Write-Line ""
if ($selectMode) {
    Write-Line ($removeInstances.Count.ToString() + " ScreenConnect instance(s) will be removed on 'y' (" + $keptInstances.Count + " kept).") 'Yellow'
    Write-Line "Files are quarantined, never deleted. Type y to remove the instances that are NOT kept."
} else {
    Write-Line ($instances.Count.ToString() + " ScreenConnect instance(s) will be removed on 'y'.") 'Yellow'
    Write-Line "Files are quarantined, never deleted. Type y to remove all detected instances."
}
# Emit the prompt text explicitly: with redirected stdin (CI, piped runs),
# Read-Host does not echo the prompt on Windows PowerShell 5.1.
if ($selectMode) { Write-Host 'Remove the instances that are NOT kept? [y/N]' -NoNewline } else { Write-Host 'Remove all detected ScreenConnect instances? [y/N]' -NoNewline }
$confirmed = $false
do {
    $c = Read-Host
    if ([string]::IsNullOrWhiteSpace($c)) { $c = 'N' }
    $c = $c.Trim().Substring(0,1).ToUpperInvariant()
} while ($c -ne 'Y' -and $c -ne 'N')
if ($c -eq 'Y') { $confirmed = $true }

if (-not $confirmed) {
    Write-Line "Confirmation not given - nothing was removed." 'Yellow'
    exit 0
}

# --- Write the plan ---------------------------------------------------------
$freeGb = Get-AvailableDiskSpace -Path $WorkDir
if ($freeGb -lt 0) {
    Write-Line ("Could not determine free disk space for {0}; continuing with a warning." -f $WorkDir) 'Yellow'
} elseif ($freeGb -lt $MinFreeGB) {
    if (-not (Confirm-LowDiskSpace -FreeGB $freeGb -Path $WorkDir -MinFreeGB $MinFreeGB)) {
        exit 1
    }
}
if (-not (Test-Path -LiteralPath $WorkDir)) {
    $null = New-Item -ItemType Directory -Path $WorkDir -Force
}

$decision = 'ALL_REMOVE'
if ($instances.Count -eq 0) { $decision = 'KEEP_ALL' }
elseif ($keptInstances.Count -gt 0) { $decision = 'PARTIAL_REMOVE' }

$planPath = Join-Path $WorkDir 'plan.json'
$sourceFindingsHash = (Get-FileHash -LiteralPath $FindingsJson -Algorithm SHA256 -ErrorAction Stop).Hash
$sourceRunId = Split-Path -Leaf (Split-Path -Parent $FindingsJson)
$plan = [ordered]@{
    PlanSchemaVersion       = 2
    RunId                   = $sourceRunId
    GeneratedUtc            = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
    ComputerName            = $env:COMPUTERNAME
    Decision                = $decision
    SourceFindings          = $FindingsJson
    SourceFindingsSha256    = $sourceFindingsHash
    RemovalConfirmed        = $true
    ScreenConnectInstances  = $removeInstances
}
if ($selectMode) { $plan['KeptScreenConnectInstances'] = $keptInstances }
Save-KeptInstances -Dir $WorkDir
$plan | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $planPath -Encoding UTF8 -NoNewline
Write-Line ""
Write-Line ("Plan written: " + $planPath) 'Cyan'

if ($WhatIfOnly) {
    Write-Line "-WhatIfOnly: stopping before removal." 'Yellow'
    exit 0
}

# --- Delegate to the removal engine ----------------------------------------
$remover = Join-Path $ScriptRoot 'remove-screenconnect.ps1'
if (-not (Test-Path -LiteralPath $remover)) {
    Write-Line "remove-screenconnect.ps1 not found next to this script." 'Red'
    exit 1
}

Write-Line "Running removal..." 'Cyan'
# remove-screenconnect.ps1 uses top-level exit codes. Run it in a child host so
# those codes cannot terminate this review wrapper before it reports status.
$childPowerShell = 'powershell.exe'
if ($PSVersionTable.PSEdition -eq 'Core') {
    $pwshCommand = Get-Command pwsh -ErrorAction SilentlyContinue
    if ($pwshCommand) { $childPowerShell = $pwshCommand.Source }
}
& $childPowerShell -NoProfile -ExecutionPolicy Bypass -File $remover -PlanJson $planPath -WorkDir $WorkDir -Execute
$rc = $LASTEXITCODE
if ($null -eq $rc) { $rc = 1 }

Write-Line ""
if ($rc -eq 0) {
    Write-Line "Removal completed. Manifest + quarantine are under:" 'Green'
    Write-Line ("  " + $WorkDir) 'Green'
} else {
    Write-Line ("Removal reported problems (exit " + $rc + "). Check removal-manifest.json under:") 'Yellow'
    Write-Line ("  " + $WorkDir) 'Yellow'
}
exit $rc

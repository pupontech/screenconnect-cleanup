<#
  Invoke-ReviewAndRemove.ps1  -  Review detected ScreenConnect instances and
  remove the approved ones.

  This is the removal entry point for the GUIDED runner (START-HERE.bat).
  sc-cleanup.ps1 has its own equivalent review gate as Stage 3; this script
  exists so the guided, step-by-step flow can remove too without re-running
  the whole 9-stage pipeline (which would redo both snapshots).

  The actual removal is NOT reimplemented here - it delegates to
  remove-screenconnect.ps1, which stays the single removal engine
  (quarantine-never-delete, manifest, reboot resume).

  OWNER POLICY: ScreenConnect instances ONLY. Every other remote-access
  product in targets.json is detect/report-only and is never touched.

  Dry-run by default. Nothing is removed unless the technician types the
  confirmation phrase, or -Yes is passed. START-HERE.bat Step 5 passes -Yes:
  the guided runner detects, removes and logs automatically with NO prompts
  (owner directive 2026-08-27).

  PS 5.1 compatible. Pure ASCII, no BOM.
  Exit codes: 0 = ok (including "nothing to do"), 1 = removal reported failure.
#>

param(
    # findings.json to review. Default: newest under the detector's output root.
    [string]$FindingsJson,

    # Where plan.json / quarantine / manifest go. Default: C:\RIT-SCC\<host>-<stamp>
    [string]$WorkDir,

    # Where to look for findings when -FindingsJson is not given.
    [string]$ScanRoot = "$env:USERPROFILE\Desktop\RemoteAccessScan",

    # Automatic: mark every ScreenConnect instance REMOVE and skip the typed
    # confirmation. Used by START-HERE.bat Step 5 (owner directive 2026-08-27:
    # "just run and remove and log").
    [switch]$Yes,

    # Review and write plan.json, but never call the remover.
    [switch]$WhatIfOnly
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

function Write-Line {
    param([string]$Message, [string]$Color = 'Gray')
    Write-Host $Message -ForegroundColor $Color
}

function Get-Prop {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
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
    if ($raw) { $instances = @($raw) }
}

if ($instances.Count -eq 0) {
    Write-Line "No live ScreenConnect instances in these findings - nothing to remove." 'Green'
    exit 0
}

Write-Line ""
Write-Line ("Found " + $instances.Count + " ScreenConnect instance(s).") 'White'

if ($Yes) {
    Write-Line ""
    Write-Line "  *** -Yes: AUTOMATIC REMOVAL (owner directive 2026-08-27). Every" 'Red'
    Write-Line "  *** ScreenConnect instance is marked REMOVE and -Execute applied" 'Red'
    Write-Line "  *** with NO typed confirmation. ScreenConnect-only; quarantine," 'Red'
    Write-Line "  *** never delete; every action is logged to the manifest + report." 'Red'
    Write-Line ""
}

# --- Review gate ------------------------------------------------------------
$approved = New-Object System.Collections.ArrayList
$n = 0
foreach ($inst in $instances) {
    $n++
    $id = Get-Prop $inst 'Identifier'
    if (-not $id) { $id = Get-Prop $inst 'Key' }
    if (-not $id) { $id = "(unidentified $n)" }

    Write-Line ""
    Write-Line ("Instance " + $n + "/" + $instances.Count + ": " + $id) 'White'
    foreach ($f in @('InstallDir','ServiceName','RelayHost','SessionType','DisplayVersion','Publisher')) {
        $v = Get-Prop $inst $f
        if ($v) { Write-Line ("    {0,-15} {1}" -f ($f + ':'), $v) }
    }

    if ($Yes) {
        Write-Line "  -Yes: automatically marked REMOVE." 'Yellow'
        [void]$approved.Add($inst)
    } else {
        # KEEP is the default. ScreenConnect is legitimate software a client's
        # own IT may have installed deliberately, so a careless Enter must not
        # remove anything. Explicit 'y' is required to mark an instance.
        do {
            $d = Read-Host 'Remove this instance? [y/N]'
            if ([string]::IsNullOrWhiteSpace($d)) { $d = 'N' }
            $d = $d.Trim().Substring(0,1).ToUpperInvariant()
        } while ($d -ne 'Y' -and $d -ne 'N')
        if ($d -eq 'Y') { [void]$approved.Add($inst) } else { Write-Line "  Keeping $id." }
    }
}

if ($approved.Count -eq 0) {
    Write-Line ""
    Write-Line "Nothing marked for removal - done." 'Green'
    exit 0
}

# --- Confirmation -----------------------------------------------------------
$confirmed = $false
if ($Yes) {
    $confirmed = $true
} else {
    Write-Line ""
    Write-Line ($approved.Count.ToString() + " instance(s) marked REMOVE.") 'Yellow'
    Write-Line "Files are quarantined, never deleted. Type y to proceed." 'Yellow'
    do {
        $c = Read-Host 'Proceed with removal? [y/N]'
        if ([string]::IsNullOrWhiteSpace($c)) { $c = 'N' }
        $c = $c.Trim().Substring(0,1).ToUpperInvariant()
    } while ($c -ne 'Y' -and $c -ne 'N')
    if ($c -eq 'Y') { $confirmed = $true }
}

if (-not $confirmed) {
    Write-Line "Confirmation not given - nothing was removed." 'Yellow'
    exit 0
}

# --- Write the plan ---------------------------------------------------------
if (-not $WorkDir) {
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd_HHmmss')
    $WorkDir = Join-Path 'C:\RIT-SCC' ($env:COMPUTERNAME + '-' + $stamp)
}
if (-not (Test-Path -LiteralPath $WorkDir)) {
    $null = New-Item -ItemType Directory -Path $WorkDir -Force
}

$decision = 'PARTIAL_REMOVE'
if ($approved.Count -eq $instances.Count) { $decision = 'ALL_REMOVE' }

$planPath = Join-Path $WorkDir 'plan.json'
$plan = [ordered]@{
    GeneratedUtc           = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
    ComputerName           = $env:COMPUTERNAME
    Decision               = $decision
    SourceFindings         = $FindingsJson
    RemovalConfirmed       = $true
    ScreenConnectInstances = $approved.ToArray()
}
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
& $remover -PlanJson $planPath -WorkDir $WorkDir -Execute
$rc = $LASTEXITCODE

Write-Line ""
if ($rc -eq 0) {
    Write-Line "Removal completed. Manifest + quarantine are under:" 'Green'
    Write-Line ("  " + $WorkDir) 'Green'
} else {
    Write-Line ("Removal reported problems (exit " + $rc + "). Check removal-manifest.json under:") 'Yellow'
    Write-Line ("  " + $WorkDir) 'Yellow'
}
exit $rc

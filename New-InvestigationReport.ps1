<#
  New-InvestigationReport.ps1

  Turns findings.json (produced by detect-remote-access.ps1) into a single
  self-contained HTML report that a technician can hand to a client, or
  print/PDF for a file. Read-only: never touches the input JSON or anything
  else on disk except the report file it writes.

  Windows PowerShell 5.1 compatible. Pure ASCII source, no BOM.
#>

param(
    [Parameter(Mandatory=$true)][string]$FindingsJson,
    [string]$OutputPath,
    [string]$RemovalManifest,
    [string]$AVUninstall,
    [switch]$PassThru
)

$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

function Encode-Html {
    # Escapes text so it can never be interpreted as markup. Applied to every
    # value that came from the scanned machine's JSON before it is written
    # into the report.
    param([object]$Value)
    if ($null -eq $Value) { return '' }
    $s = [string]$Value
    $s = $s.Replace('&', '&amp;')
    $s = $s.Replace('<', '&lt;')
    $s = $s.Replace('>', '&gt;')
    $s = $s.Replace('"', '&quot;')
    $s = $s.Replace("'", '&#39;')
    return $s
}

function Get-Prop {
    # Safe property getter for PSCustomObject coming out of ConvertFrom-Json.
    # Returns $Default when the property is absent OR its value is null.
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

function Get-Items {
    # Normalizes a JSON-derived value into a PowerShell array, undoing two
    # well-known PowerShell 5.1 ConvertTo-Json quirks that show up throughout
    # findings.json:
    #   - a zero-element array is written as "{}" (an empty object), and
    #   - a one-element array is written as a bare object/scalar (no []).
    # Without this, a single hit/instance/process silently disappears from
    # loops written with "foreach ($x in $value)".
    param($Value)
    if ($null -eq $Value) { return @() }
    if ($Value -is [string]) { return @($Value) }
    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        $props = @($Value.PSObject.Properties)
        if ($props.Count -eq 0) { return @() }
        return @($Value)
    }
    if ($Value -is [System.Array]) { return $Value }
    if ($Value -is [System.Collections.IEnumerable]) { return @($Value) }
    return @($Value)
}

function Fmt {
    # Escaped scalar text for display, with a placeholder for null/blank.
    param($Value, [string]$Empty = '-')
    if ($null -eq $Value) { return (Encode-Html $Empty) }
    $s = [string]$Value
    if ($s.Trim() -eq '') { return (Encode-Html $Empty) }
    return (Encode-Html $s)
}

function FmtBool {
    param($Value, [string]$Empty = '-')
    if ($null -eq $Value) { return (Encode-Html $Empty) }
    if ($Value -is [bool]) { if ($Value) { return 'Yes' } else { return 'No' } }
    $s = [string]$Value
    if ($s -eq 'True') { return 'Yes' }
    if ($s -eq 'False') { return 'No' }
    return (Encode-Html $s)
}

function FmtList {
    # Escaped, joined text for an array-ish value.
    param($Value, [string]$Sep = ', ', [string]$Empty = '-')
    $items = Get-Items $Value
    if ($items.Count -eq 0) { return (Encode-Html $Empty) }
    $strs = New-Object System.Collections.ArrayList
    foreach ($it in $items) {
        if ($null -eq $it) { continue }
        [void]$strs.Add([string]$it)
    }
    if ($strs.Count -eq 0) { return (Encode-Html $Empty) }
    return (Encode-Html ($strs -join $Sep))
}

function Get-KvPairs {
    # Enumerates a JSON "dictionary" (an ordered hashtable serialized as an
    # object) into Name/Value pairs, skipping blank values. Safe against an
    # empty {} object.
    param($Obj)
    $out = New-Object System.Collections.ArrayList
    if ($null -eq $Obj) { return $out }
    if ($Obj -is [System.Management.Automation.PSCustomObject]) {
        foreach ($p in $Obj.PSObject.Properties) {
            if ($null -eq $p.Value) { continue }
            $s = [string]$p.Value
            if ($s.Trim() -eq '') { continue }
            [void]$out.Add([PSCustomObject]@{ Name = $p.Name; Value = $p.Value })
        }
    }
    return $out
}

function Row {
    # One <tr> for a definition-style table. Omits the row entirely when the
    # value is empty, unless -AlwaysShow is passed.
    param([string]$Label, $Value, [switch]$AlwaysShow, [string]$Empty = '-')
    $isBlank = ($null -eq $Value) -or ([string]::IsNullOrWhiteSpace([string]$Value))
    if ($isBlank -and -not $AlwaysShow) { return '' }
    $v = if ($isBlank) { Encode-Html $Empty } else { Fmt $Value }
    return "<tr><th>$(Encode-Html $Label)</th><td>$v</td></tr>`n"
}

function SessionBadgeInfo {
    param($SessionType)
    if ($null -eq $SessionType -or [string]::IsNullOrWhiteSpace([string]$SessionType)) {
        return @{ Text = 'Unknown'; Class = 'badge-unknown'; Note = 'Session type could not be determined from the launch parameters.' }
    }
    $st = ([string]$SessionType).Trim()
    if ($st -ieq 'Access') {
        return @{ Text = 'Access'; Class = 'badge-high'; Note = 'Persistent unattended access - the connection does not require someone at the keyboard to approve it. Highest-risk session type.' }
    }
    if ($st -ieq 'Support') {
        return @{ Text = 'Support'; Class = 'badge-low'; Note = 'One-time support session - normally requires the user to accept the connection.' }
    }
    if ($st -ieq 'Meeting') {
        return @{ Text = 'Meeting'; Class = 'badge-medium'; Note = 'Meeting session type.' }
    }
    return @{ Text = $st; Class = 'badge-medium'; Note = 'Non-standard session type value - review manually.' }
}

function SignatureBadgeClass {
    param($Status)
    if ($null -eq $Status -or [string]::IsNullOrWhiteSpace([string]$Status)) { return 'badge-unknown' }
    if (([string]$Status) -ieq 'Valid') { return 'badge-low' }
    return 'badge-high'
}

# ---------------------------------------------------------------------------
# Load input
# ---------------------------------------------------------------------------

if (-not (Test-Path -LiteralPath $FindingsJson)) {
    throw "Findings file not found: $FindingsJson"
}

$rawText = Get-Content -LiteralPath $FindingsJson -Raw
try {
    $findings = $rawText | ConvertFrom-Json
} catch {
    throw "Could not parse '$FindingsJson' as JSON: $($_.Exception.Message)"
}

if (-not $OutputPath) {
    $parent = Split-Path -Path $FindingsJson -Parent
    if (-not $parent) { $parent = "." }
    $OutputPath = Join-Path $parent "report.html"
}

# ---------------------------------------------------------------------------
# Top-level fields
# ---------------------------------------------------------------------------

$computerName    = Get-Prop $findings 'ComputerName'
$osCaption       = Get-Prop $findings 'OSCaption'
$generatedUtc    = Get-Prop $findings 'GeneratedUtc'
$runAsUser       = Get-Prop $findings 'RunAsUser'
$isAdmin         = Get-Prop $findings 'IsAdmin'
$toolName        = Get-Prop $findings 'Tool'
$toolVersion     = Get-Prop $findings 'Version'
$psVersion       = Get-Prop $findings 'PSVersion'
$targetsSource   = Get-Prop $findings 'TargetsSource'
$targetsSelected = Get-Items (Get-Prop $findings 'TargetsSelected')
$eventLogError   = Get-Prop $findings 'EventLogError'
$scResult        = Get-Prop $findings 'ScreenConnect'
$otherTargets    = Get-Items (Get-Prop $findings 'OtherTargets')

$removalEntries = @()
$removalManifestError = $null
if ($RemovalManifest) {
    if (Test-Path -LiteralPath $RemovalManifest) {
        try {
            $manifestObject = (Get-Content -LiteralPath $RemovalManifest -Raw) | ConvertFrom-Json
            $removalEntries = Get-Items (Get-Prop $manifestObject 'Entries')
        }
        catch { $removalManifestError = $_.Exception.Message }
    } else { $removalManifestError = 'Manifest file not found.' }
}

$scInstances    = @()
$scParseIssues  = @()
$scHistorical   = @()
$scRawFiles     = @()
if ($null -ne $scResult) {
    $scInstances   = Get-Items (Get-Prop $scResult 'Instances')
    $scParseIssues = Get-Items (Get-Prop $scResult 'ParseIssues')
    $scHistorical  = Get-Items (Get-Prop $scResult 'Historical')
    $scRawFiles    = Get-Items (Get-Prop $scResult 'RawFilesSaved')
}

$otherHitTotal = 0
$otherProductsWithHits = 0
$otherAgentGroups = New-Object System.Collections.ArrayList
foreach ($t in $otherTargets) {
    $hits = Get-Items (Get-Prop $t 'Hits')
    if ($hits.Count -gt 0) {
        $otherHitTotal += $hits.Count
        $otherProductsWithHits++
    }
    [void]$otherAgentGroups.Add([PSCustomObject]@{
        Id   = Get-Prop $t 'Id'
        Name = Get-Prop $t 'Name'
        Hits = $hits
    })
}

$reportGeneratedLocal = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")

# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------

$elevatedText = FmtBool $isAdmin
$elevatedClass = 'badge-low'
if ($isAdmin -is [bool] -and -not $isAdmin) { $elevatedClass = 'badge-medium' }

$headerHtml = @"
<header>
  <h1>Remote Access Investigation Report</h1>
  <table class="header-table">
    <tr><th>Computer</th><td>$(Fmt $computerName)</td><th>Operating system</th><td>$(Fmt $osCaption)</td></tr>
    <tr><th>Scan performed (UTC)</th><td>$(Fmt $generatedUtc)</td><th>Run as</th><td>$(Fmt $runAsUser)</td></tr>
    <tr><th>Elevated (admin)</th><td><span class="badge $elevatedClass">$elevatedText</span></td><th>Scan tool</th><td>$(Fmt $toolName) $(Fmt $toolVersion)</td></tr>
  </table>
  <p class="muted">Report generated $(Fmt $reportGeneratedLocal) from a point-in-time scan. Re-run the scan to confirm anything has changed.</p>
</header>
"@

# ---------------------------------------------------------------------------
# Summary banner
# ---------------------------------------------------------------------------

$scCount = $scInstances.Count
$scCardClass = 'stat-ok'
if ($scCount -gt 0) { $scCardClass = 'stat-danger' }

$otherCardClass = 'stat-ok'
if ($otherHitTotal -gt 0) { $otherCardClass = 'stat-warn' }

$parseCardClass = 'stat-ok'
if ($scParseIssues.Count -gt 0) { $parseCardClass = 'stat-danger' }

$histCardClass = 'stat-ok'
if ($scHistorical.Count -gt 0) { $histCardClass = 'stat-warn' }

$eventLogNoteHtml = ''
if ($eventLogError) {
    $eventLogNoteHtml = "<p class='warn-line'>Service-install history (Windows Event ID 7045) was not available during this scan: $(Fmt $eventLogError) Historical entries below may be incomplete.</p>"
}

$summaryHtml = @"
<section id="summary">
  <h2>Summary</h2>
  <div class="stat-row">
    <div class="stat-card $scCardClass">
      <div class="stat-number">$scCount</div>
      <div class="stat-label">ScreenConnect instance(s) found</div>
    </div>
    <div class="stat-card $otherCardClass">
      <div class="stat-number">$otherHitTotal</div>
      <div class="stat-label">Other remote-access artifact(s) across $otherProductsWithHits product(s)</div>
    </div>
    <div class="stat-card $parseCardClass">
      <div class="stat-number">$($scParseIssues.Count)</div>
      <div class="stat-label">Parse problem(s)</div>
    </div>
    <div class="stat-card $histCardClass">
      <div class="stat-number">$($scHistorical.Count)</div>
      <div class="stat-label">Historical install event(s), agent no longer present</div>
    </div>
  </div>
  $eventLogNoteHtml
</section>
"@

# ---------------------------------------------------------------------------
# ScreenConnect instances
# ---------------------------------------------------------------------------

function Build-InstanceHtml {
    param($inst)

    $identifier = Get-Prop $inst 'Identifier'
    $key        = Get-Prop $inst 'Key'
    $title      = $identifier
    if ([string]::IsNullOrWhiteSpace([string]$title)) { $title = $key }
    if ([string]::IsNullOrWhiteSpace([string]$title)) { $title = '(unidentified instance)' }

    $relayHost = Get-Prop $inst 'RelayHost'
    $relayPort = Get-Prop $inst 'RelayPort'
    $sessionType = Get-Prop $inst 'SessionType'
    $sb = SessionBadgeInfo $sessionType

    $file = Get-Prop $inst 'File'
    $sigStatus = $null
    $signerSubject = $null
    if ($null -ne $file) {
        $sigStatus = Get-Prop $file 'SignatureStatus'
        $signerSubject = Get-Prop $file 'SignerSubject'
    }
    $sigClass = SignatureBadgeClass $sigStatus
    $sigText = Fmt $sigStatus 'Not captured'

    $installDirCreated = Get-Prop $inst 'InstallDirCreatedUtc'

    $relayHtml = ''
    if ([string]::IsNullOrWhiteSpace([string]$relayHost)) {
        $relayHtml = "<div class='relay-box relay-missing'><div class='relay-label'>RELAY HOST</div><div class='relay-value'>NOT DETERMINED</div><div class='relay-sub'>The tool could not extract a relay host for this instance (see Parse problems below, or the raw evidence files). Treat this instance as unverified until the relay host is confirmed manually - this is the field that separates an authorized install from an attacker's.</div></div>"
    } else {
        $portSuffix = ''
        if (-not [string]::IsNullOrWhiteSpace([string]$relayPort)) { $portSuffix = ":$(Fmt $relayPort)" }
        $relayHtml = "<div class='relay-box relay-present'><div class='relay-label'>RELAY HOST</div><div class='relay-value'>$(Fmt $relayHost)$portSuffix</div><div class='relay-sub'>Confirm this host is the client's own authorized ScreenConnect/ConnectWise server. If it is not one your organization or the client's IT provider controls, this instance is unauthorized.</div></div>"
    }

    $sessionRow = "<div class='key-fact'><span class='key-fact-label'>Session type</span><span class='badge $($sb.Class)'>$(Encode-Html $sb.Text)</span><span class='key-fact-note'>$(Encode-Html $sb.Note)</span></div>"
    $installRow = "<div class='key-fact'><span class='key-fact-label'>Install directory created (UTC)</span><span>$(Fmt $installDirCreated)</span></div>"
    $sigRow = "<div class='key-fact'><span class='key-fact-label'>File signature</span><span class='badge $sigClass'>$sigText</span><span class='key-fact-note'>$(Fmt $signerSubject '')</span></div>"

    # --- identity / install details table ---
    $detailRows = ''
    $detailRows += Row 'Identifier' $identifier
    $detailRows += Row 'Relay port' $relayPort
    $detailRows += Row 'Role' (Get-Prop $inst 'Role')
    $detailRows += Row 'Session id' (Get-Prop $inst 'SessionId')
    $detailRows += Row 'Server key fingerprint' (Get-Prop $inst 'ServerKeyFingerprint')
    $detailRows += Row 'Launch-parameter source' (Get-Prop $inst 'ParamBlobSource')
    $detailRows += Row 'Install directory' (Get-Prop $inst 'InstallDir')
    $detailRows += Row 'Found via' (FmtList (Get-Prop $inst 'Sources'))
    $detailRows += Row 'Uninstall entry name' (Get-Prop $inst 'UninstallDisplayName')
    $detailRows += Row 'Publisher' (Get-Prop $inst 'Publisher')
    $detailRows += Row 'Version' (Get-Prop $inst 'DisplayVersion')
    $detailRows += Row 'Install date (registry)' (Get-Prop $inst 'InstallDate')
    $detailRows += Row 'Uninstall command' (Get-Prop $inst 'UninstallString')

    $detailHtml = ''
    if ($detailRows -ne '') {
        $detailHtml = "<h4>Install details</h4><table class='fact-table'>$detailRows</table>"
    }

    # --- service details ---
    $svcRows = ''
    $svcRows += Row 'Service name' (Get-Prop $inst 'ServiceName')
    $svcRows += Row 'Display name' (Get-Prop $inst 'ServiceDisplayName')
    $svcRows += Row 'State' (Get-Prop $inst 'ServiceState')
    $svcRows += Row 'Start mode' (Get-Prop $inst 'ServiceStartMode')
    $svcRows += Row 'Log on as' (Get-Prop $inst 'ServiceAccount')
    $svcRows += Row 'Image path' (Get-Prop $inst 'ServiceImagePath')
    $svcHtml = ''
    if ($svcRows -ne '') {
        $svcHtml = "<h4>Service</h4><table class='fact-table'>$svcRows</table>"
    }

    # --- file details ---
    $fileHtml = ''
    if ($null -ne $file) {
        $fileRows = ''
        $fileRows += Row 'Main executable' (Get-Prop $file 'Path')
        $fileRows += Row 'File version' (Get-Prop $file 'FileVersion')
        $fileRows += Row 'Product name' (Get-Prop $file 'ProductName')
        $fileRows += Row 'Company name' (Get-Prop $file 'CompanyName')
        $fileRows += Row 'Signer' (Get-Prop $file 'SignerSubject')
        $fileRows += Row 'SHA-256' (Get-Prop $file 'Sha256')
        $fileRows += Row 'Created (UTC)' (Get-Prop $file 'CreatedUtc')
        $fileRows += Row 'Modified (UTC)' (Get-Prop $file 'ModifiedUtc')
        if ($fileRows -ne '') {
            $fileHtml = "<h4>File details</h4><table class='fact-table'>$fileRows</table>"
        }
    }

    # --- custom properties ---
    $customHtml = ''
    $customPairs = Get-KvPairs (Get-Prop $inst 'CustomProperties')
    if ($customPairs.Count -gt 0) {
        $rows = ''
        foreach ($p in $customPairs) { $rows += "<tr><th>$(Fmt $p.Name)</th><td>$(Fmt $p.Value)</td></tr>`n" }
        $customHtml = "<h4>Custom properties (set by whoever deployed this install)</h4><table class='fact-table'>$rows</table>"
    }

    # --- unknown / unmapped parameters ---
    $unknownHtml = ''
    $unknownPairs = Get-KvPairs (Get-Prop $inst 'UnknownParams')
    if ($unknownPairs.Count -gt 0) {
        $rows = ''
        foreach ($p in $unknownPairs) { $rows += "<tr><th>$(Fmt $p.Name)</th><td>$(Fmt $p.Value)</td></tr>`n" }
        $unknownHtml = "<h4>Unrecognized launch parameters</h4><p class='muted'>These keys were found in the launch string but are not understood by this version of the tool. They do not affect the fields above, but review the raw evidence files if anything here looks unusual.</p><table class='fact-table'>$rows</table>"
    }

    # --- processes ---
    $procHtml = ''
    $procs = Get-Items (Get-Prop $inst 'Processes')
    if ($procs.Count -gt 0) {
        $rows = ''
        foreach ($p in $procs) {
            $rows += "<tr><td>$(Fmt (Get-Prop $p 'ProcessId'))</td><td>$(Fmt (Get-Prop $p 'ParentProcessId'))</td><td>$(Fmt (Get-Prop $p 'Name'))</td><td>$(Fmt (Get-Prop $p 'ExecutablePath'))</td><td>$(Fmt (Get-Prop $p 'StartedUtc'))</td></tr>`n"
        }
        $procHtml = "<h4>Running processes at scan time</h4><div class='table-scroll'><table class='data-table'><thead><tr><th>PID</th><th>PPID</th><th>Name</th><th>Path</th><th>Started (UTC)</th></tr></thead><tbody>$rows</tbody></table></div>"
    }

    # --- connections ---
    $connHtml = ''
    $conns = Get-Items (Get-Prop $inst 'Connections')
    if ($conns.Count -gt 0) {
        $rows = ''
        foreach ($c in $conns) {
            $local = "$(Fmt (Get-Prop $c 'LocalAddress'))`:$(Fmt (Get-Prop $c 'LocalPort'))"
            $remote = "$(Fmt (Get-Prop $c 'RemoteAddress'))`:$(Fmt (Get-Prop $c 'RemotePort'))"
            $rows += "<tr><td>$local</td><td>$remote</td><td>$(Fmt (Get-Prop $c 'State'))</td></tr>`n"
        }
        $connHtml = "<h4>Network connections at scan time</h4><div class='table-scroll'><table class='data-table'><thead><tr><th>Local</th><th>Remote</th><th>State</th></tr></thead><tbody>$rows</tbody></table></div>"
    }

    # --- related service-install events ---
    $evtHtml = ''
    $evts = Get-Items (Get-Prop $inst 'ServiceInstallEvents')
    if ($evts.Count -gt 0) {
        $rows = ''
        foreach ($e in $evts) {
            $rows += "<tr><td>$(Fmt (Get-Prop $e 'TimeUtc'))</td><td>$(Fmt (Get-Prop $e 'Message'))</td></tr>`n"
        }
        $evtHtml = "<h4>Related service-install events</h4><div class='table-scroll'><table class='data-table'><thead><tr><th>Time (UTC)</th><th>Message</th></tr></thead><tbody>$rows</tbody></table></div>"
    }

    # --- config files captured ---
    $cfgHtml = ''
    $cfgs = Get-Items (Get-Prop $inst 'ConfigFiles')
    if ($cfgs.Count -gt 0) {
        $rows = ''
        foreach ($c in $cfgs) {
            $rows += "<tr><td>$(Fmt (Get-Prop $c 'Name'))</td><td>$(Fmt (Get-Prop $c 'Path'))</td><td>$(Fmt (Get-Prop $c 'ModifiedUtc'))</td></tr>`n"
        }
        $cfgHtml = "<h4>Config files captured (verbatim copies saved to the raw evidence folder)</h4><div class='table-scroll'><table class='data-table'><thead><tr><th>Name</th><th>Path</th><th>Modified (UTC)</th></tr></thead><tbody>$rows</tbody></table></div>"
    }

    $cardHtml = @"
<div class="instance-card">
  <h3>Instance: $(Fmt $title)</h3>
  $relayHtml
  <div class="key-facts">
    $sessionRow
    $installRow
    $sigRow
  </div>
  $detailHtml
  $svcHtml
  $fileHtml
  $customHtml
  $unknownHtml
  $procHtml
  $connHtml
  $evtHtml
  $cfgHtml
</div>
"@
    return $cardHtml
}

$scSectionHtml = ''
if ($null -eq $scResult) {
    $scSectionHtml = "<section id='screenconnect'><h2>ScreenConnect instances</h2><p class='muted'>ScreenConnect was not included as a scan target in this run (see Targets scanned in the Environment section).</p></section>"
} elseif ($scInstances.Count -eq 0) {
    $scSectionHtml = "<section id='screenconnect'><h2>ScreenConnect instances</h2><p class='ok-line'>None found. No ScreenConnect / ConnectWise Control service, process, install directory, or uninstall entry was detected on this machine.</p></section>"
} else {
    $cards = ''
    foreach ($inst in $scInstances) { $cards += (Build-InstanceHtml $inst) }
    $scSectionHtml = "<section id='screenconnect'><h2>ScreenConnect instances ($($scInstances.Count))</h2>$cards</section>"
}

# ---------------------------------------------------------------------------
# Other remote-access agents
# ---------------------------------------------------------------------------

$otherSectionHtml = ''
$groupsWithHits = @($otherAgentGroups | Where-Object { $_.Hits.Count -gt 0 })
if ($groupsWithHits.Count -eq 0) {
    $otherSectionHtml = "<section id='other-agents'><h2>Other remote-access agents</h2><p class='ok-line'>None found among the products this scan checked for.</p></section>"
} else {
    $groupsHtml = ''
    foreach ($g in $groupsWithHits) {
        $rows = ''
        foreach ($h in $g.Hits) {
            $rows += "<tr><td>$(Fmt (Get-Prop $h 'Kind'))</td><td>$(Fmt (Get-Prop $h 'Name'))</td><td>$(Fmt (Get-Prop $h 'Detail'))</td><td>$(Fmt (Get-Prop $h 'Path'))</td><td>$(Fmt (Get-Prop $h 'State'))</td><td>$(Fmt (Get-Prop $h 'StartMode'))</td></tr>`n"
        }
        $groupsHtml += @"
<div class="agent-card">
  <h3>$(Fmt $g.Name) <span class="count-badge">$($g.Hits.Count) artifact(s)</span></h3>
  <div class="table-scroll">
  <table class="data-table">
    <thead><tr><th>Kind</th><th>Name</th><th>Detail</th><th>Path</th><th>State</th><th>Start mode</th></tr></thead>
    <tbody>$rows</tbody>
  </table>
  </div>
</div>
"@
    }
    $otherSectionHtml = "<section id='other-agents'><h2>Other remote-access agents</h2>$groupsHtml</section>"
}

# ---------------------------------------------------------------------------
# Installed-AV uninstall (Stage 6) - attended results
# ---------------------------------------------------------------------------
$avUninstallSectionHtml = ''
if ($AVUninstall) {
    $avData = $null
    $avError = $null
    if (Test-Path -LiteralPath $AVUninstall) {
        try { $avData = (Get-Content -LiteralPath $AVUninstall -Raw) | ConvertFrom-Json }
        catch { $avError = $_.Exception.Message }
    } else { $avError = "results file not found: $AVUninstall" }

    $rows = ''
    if ($avData -and $avData.Results) {
        foreach ($r in $avData.Results) {
            $name  = Get-Prop $r 'DisplayName'
            $status = Get-Prop $r 'Status'
            $opened = Get-Prop $r 'OpenedAt'
            $closed = Get-Prop $r 'ClosedAt'
            $cmd = Get-Prop $r 'UninstallString'
            $left = Get-Prop $r 'LeftoversMoved'
            $leftCell = ''
            if ($left) { $leftCell = "$left item(s) quarantined" }
            $rows += "<tr><td>$(Fmt $name)</td><td>$(Fmt $status)</td><td>$(Fmt $opened)</td><td>$(Fmt $closed)</td><td class='mono'>$(Fmt $cmd)</td><td>$(Fmt $leftCell)</td></tr>`n"
        }
    }
    if (-not $rows) {
        if ($avError) {
            $rows = "<tr><td colspan='6'>Could not load AV-uninstall results: $(Fmt $avError)</td></tr>"
        } else {
            $rows = '<tr><td colspan="6">No installed third-party AV was detected (or the step was skipped).</td></tr>'
        }
    }
    $qRoot = Get-Prop $avData 'QuarantineRoot'
    $qNote = ''
    if ($qRoot) { $qNote = " <span class='muted'>Leftover shortcuts/folders were moved (not deleted) to <code>$(Fmt $qRoot)</code>.</span>" }
    $avNote = if ($avError) { "<p class='warn-line'>$avError</p>" } else { "<p class='muted'>Uninstallers were opened for the technician to drive (attended). Source: $(Fmt $AVUninstall)</p>$qNote" }
    $avUninstallSectionHtml = @"
<section id="av-uninstall">
  <h2>Installed antivirus / security products uninstalled</h2>
  $avNote
  <div class="table-scroll"><table class="data-table"><thead><tr><th>Product</th><th>Status</th><th>Opened (UTC)</th><th>Closed (UTC)</th><th>Uninstall command</th><th>Leftovers</th></tr></thead><tbody>$rows</tbody></table></div>
  <p class="muted">These products were opened for attended removal. Confirm each was fully uninstalled before leaving the site; a machine should not be left without working AV unless a replacement is being deployed.</p>
</section>
"@
}

# ---------------------------------------------------------------------------
# Removal manifest and credential-reset reminder
# ---------------------------------------------------------------------------
$removalSectionHtml = ''
if ($RemovalManifest -or $removalManifestError) {
    $rows = ''
    foreach ($entry in $removalEntries) {
        $rows += "<tr><td>$(Fmt (Get-Prop $entry 'InstanceId'))</td><td>$(Fmt (Get-Prop $entry 'Action'))</td><td>$(Fmt (Get-Prop $entry 'Target'))</td><td>$(Fmt (Get-Prop $entry 'Result'))</td><td>$(Fmt (Get-Prop $entry 'Details'))</td></tr>`n"
    }
    if (-not $rows) { $rows = '<tr><td colspan="5">No removal actions were recorded.</td></tr>' }
    $manifestNote = if ($removalManifestError) { "<p class='warn-line'>Removal manifest could not be loaded: $(Fmt $removalManifestError)</p>" } else { "<p class='muted'>Machine-readable manifest: $(Fmt $RemovalManifest). A plain-English copy is in <code>removal-report.txt</code> alongside it.</p>" }
    $removalSectionHtml = @"
<section id="removal">
  <h2>Removed and quarantined items</h2>
  $manifestNote
  <div class="table-scroll"><table class="data-table"><thead><tr><th>Instance</th><th>Action</th><th>Target</th><th>Result</th><th>Details</th></tr></thead><tbody>$rows</tbody></table></div>
  <h3>Credential-reset checklist reminder</h3>
  <p class="warn-line">After containment, reset ScreenConnect/ConnectWise credentials and any local or service-account credentials that may have been exposed. Revoke active sessions/tokens, rotate API keys, and verify MFA and authorized relay hosts.</p>
</section>
"@
}

# ---------------------------------------------------------------------------
# Historical service-install events
# ---------------------------------------------------------------------------

$histSectionHtml = ''
if ($scHistorical.Count -eq 0) {
    if ($null -ne $scResult) {
        $histSectionHtml = "<section id='historical'><h2>Historical service installs</h2><p class='ok-line'>No ScreenConnect service-install events were found with no matching live install.</p></section>"
    }
} else {
    $rows = ''
    foreach ($h in $scHistorical) {
        $ident = Get-Prop $h 'Identifier'
        if ([string]::IsNullOrWhiteSpace([string]$ident)) { $ident = '(no identifier parsed)' }
        $rows += "<tr><td>$(Fmt (Get-Prop $h 'TimeUtc'))</td><td>$(Fmt $ident)</td><td>$(Fmt (Get-Prop $h 'Message'))</td><td>$(Fmt (Get-Prop $h 'Note'))</td></tr>`n"
    }
    $histSectionHtml = @"
<section id="historical">
  <h2>Historical service installs (agent installed at some point, not currently present)</h2>
  <p class="muted">Taken from Windows Event ID 7045 (service installed). This can reveal an agent that was installed and later removed or reinstalled under a different identifier.</p>
  <div class="table-scroll">
  <table class="data-table">
    <thead><tr><th>Time (UTC)</th><th>Identifier</th><th>Event message</th><th>Note</th></tr></thead>
    <tbody>$rows</tbody>
  </table>
  </div>
</section>
"@
}

# ---------------------------------------------------------------------------
# Parse problems
# ---------------------------------------------------------------------------

$parseSectionHtml = ''
if ($scParseIssues.Count -gt 0) {
    $rows = ''
    foreach ($p in $scParseIssues) {
        $ident = Get-Prop $p 'Identifier'
        $key = Get-Prop $p 'Key'
        if ([string]::IsNullOrWhiteSpace([string]$ident)) { $ident = $key }
        $extra = ''
        $svcImg = Get-Prop $p 'ServiceImagePath'
        if (-not [string]::IsNullOrWhiteSpace([string]$svcImg)) {
            $extra += "<div class='muted'>Service image path: $(Fmt $svcImg)</div>"
        }
        $cfgSeen = Get-Items (Get-Prop $p 'ConfigFilesSeen')
        if ($cfgSeen.Count -gt 0) {
            $extra += "<div class='muted'>Config files seen: $(FmtList $cfgSeen)</div>"
        }
        $blob = Get-Prop $p 'ParamBlob'
        if (-not [string]::IsNullOrWhiteSpace([string]$blob)) {
            $extra += "<div class='muted'>Launch-parameter blob: $(Fmt $blob)</div>"
        }
        $keysSeen = Get-Items (Get-Prop $p 'KeysSeen')
        if ($keysSeen.Count -gt 0) {
            $extra += "<div class='muted'>Keys seen in blob: $(FmtList $keysSeen)</div>"
        }
        $rows += @"
<div class="parse-issue">
  <div class="parse-issue-head">$(Fmt $ident) - $(Fmt (Get-Prop $p 'InstallDir') '')</div>
  <div class="parse-issue-body">$(Fmt (Get-Prop $p 'Issue'))</div>
  $extra
</div>
"@
    }
    $parseSectionHtml = @"
<section id="parse-problems">
  <h2 class="danger-heading">Parse problems ($($scParseIssues.Count)) - the tool could not fully read one or more instances</h2>
  <p class="warn-line">These instances could not be fully identified. Do not assume they are safe. The raw evidence folder from the scan (service ImagePath, .config files) has the verbatim data needed to investigate further or fix the parser.</p>
  $($rows -join "`n")
</section>
"@
}

# ---------------------------------------------------------------------------
# Environment / raw evidence
# ---------------------------------------------------------------------------

$rawFilesHtml = "<p class='muted'>No raw evidence files were saved by this scan.</p>"
if ($scRawFiles.Count -gt 0) {
    $items = ''
    foreach ($f in $scRawFiles) { $items += "<li>$(Fmt $f)</li>`n" }
    $rawFilesHtml = "<ul class='file-list'>$items</ul>"
}

$eventLogEnvHtml = ''
if ($eventLogError) {
    $eventLogEnvHtml = Row 'Event log status' "Unavailable - $eventLogError" -AlwaysShow
} else {
    $eventLogEnvHtml = Row 'Event log status' 'Available' -AlwaysShow
}

$envSectionHtml = @"
<section id="environment">
  <h2>Environment</h2>
  <table class="fact-table">
    $(Row 'Scan tool' "$(Fmt $toolName) (version $(Fmt $toolVersion))" -AlwaysShow)
    $(Row 'PowerShell version' $psVersion -AlwaysShow)
    $(Row 'Targets configuration source' $targetsSource -AlwaysShow)
    $(Row 'Targets scanned' (FmtList $targetsSelected) -AlwaysShow)
    $eventLogEnvHtml
  </table>
  <h3>Raw evidence files saved during the scan</h3>
  $rawFilesHtml
</section>
"@

# ---------------------------------------------------------------------------
# CSS
# ---------------------------------------------------------------------------

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
body {
  font-family: Segoe UI, Arial, Helvetica, sans-serif;
  color: var(--ink);
  background: var(--bg);
  margin: 0;
  padding: 24px;
  line-height: 1.45;
  font-size: 14px;
}
h1 { font-size: 22px; margin: 0 0 12px 0; }
h2 { font-size: 18px; margin: 28px 0 10px 0; padding-bottom: 6px; border-bottom: 2px solid var(--border); }
h3 { font-size: 15px; margin: 18px 0 8px 0; }
h4 { font-size: 13px; margin: 14px 0 6px 0; color: var(--muted); text-transform: uppercase; letter-spacing: 0.03em; }
p { margin: 6px 0; }
.muted { color: var(--muted); font-size: 13px; }
.ok-line { color: var(--ok-text); background: var(--ok-bg); border: 1px solid var(--ok-border); padding: 8px 12px; border-radius: 4px; }
.warn-line { color: var(--warn-text); background: var(--warn-bg); border: 1px solid var(--warn-border); padding: 8px 12px; border-radius: 4px; }
.danger-heading { color: var(--danger-text); }

header { border-bottom: 3px solid var(--ink); padding-bottom: 12px; margin-bottom: 8px; }
.header-table { width: 100%; border-collapse: collapse; }
.header-table th { text-align: left; color: var(--muted); font-weight: 600; padding: 3px 8px 3px 0; white-space: nowrap; font-size: 13px; }
.header-table td { padding: 3px 20px 3px 0; font-size: 13px; }

.stat-row { display: flex; flex-wrap: wrap; gap: 12px; margin: 10px 0; }
.stat-card { flex: 1 1 200px; border: 1px solid var(--border); border-left: 6px solid var(--border); border-radius: 4px; padding: 12px 14px; background: var(--bg-alt); }
.stat-card.stat-ok { border-left-color: var(--ok-border); }
.stat-card.stat-warn { border-left-color: var(--warn-border); }
.stat-card.stat-danger { border-left-color: var(--danger-border); }
.stat-number { font-size: 28px; font-weight: 700; }
.stat-label { font-size: 12.5px; color: var(--muted); }

.instance-card, .agent-card {
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 14px 16px;
  margin: 14px 0;
  background: var(--bg);
  page-break-inside: avoid;
}

.relay-box { border-radius: 6px; padding: 12px 16px; margin: 8px 0 14px 0; border: 2px solid; }
.relay-box.relay-present { border-color: var(--warn-border); background: var(--warn-bg); }
.relay-box.relay-missing { border-color: var(--danger-border); background: var(--danger-bg); }
.relay-label { font-size: 11px; letter-spacing: 0.08em; font-weight: 700; color: var(--muted); }
.relay-value { font-size: 26px; font-weight: 800; word-break: break-all; }
.relay-box.relay-missing .relay-value { color: var(--danger-text); }
.relay-sub { font-size: 12.5px; color: var(--muted); margin-top: 4px; }

.key-facts { display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 6px; }
.key-fact { flex: 1 1 260px; border: 1px solid var(--border); border-radius: 4px; padding: 8px 10px; background: var(--bg-alt); }
.key-fact-label { display: block; font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.03em; margin-bottom: 4px; }
.key-fact-note { display: block; font-size: 11.5px; color: var(--muted); margin-top: 4px; }

.badge { display: inline-block; padding: 2px 9px; border-radius: 10px; font-size: 12px; font-weight: 700; border: 1px solid transparent; }
.badge-high { background: var(--danger-bg); color: var(--danger-text); border-color: var(--danger-border); }
.badge-medium { background: var(--warn-bg); color: var(--warn-text); border-color: var(--warn-border); }
.badge-low { background: var(--ok-bg); color: var(--ok-text); border-color: var(--ok-border); }
.badge-unknown { background: var(--bg-alt); color: var(--muted); border-color: var(--border); }
.count-badge { display: inline-block; font-size: 12px; font-weight: 600; color: var(--muted); background: var(--bg-alt); border: 1px solid var(--border); border-radius: 10px; padding: 1px 8px; margin-left: 8px; }

.fact-table { width: 100%; border-collapse: collapse; margin-bottom: 6px; }
.fact-table th { text-align: left; width: 240px; vertical-align: top; color: var(--muted); font-weight: 600; padding: 4px 10px 4px 0; border-bottom: 1px solid var(--border); font-size: 13px; }
.fact-table td { padding: 4px 0; vertical-align: top; border-bottom: 1px solid var(--border); word-break: break-word; font-size: 13px; }

.table-scroll { overflow-x: auto; max-width: 100%; }
.data-table { width: 100%; border-collapse: collapse; font-size: 12.5px; min-width: 480px; }
.data-table th { text-align: left; background: var(--bg-alt); border: 1px solid var(--border); padding: 5px 8px; }
.data-table td { border: 1px solid var(--border); padding: 5px 8px; vertical-align: top; word-break: break-word; }

.parse-issue { border: 1px solid var(--danger-border); background: var(--danger-bg); border-radius: 4px; padding: 10px 12px; margin: 10px 0; }
.parse-issue-head { font-weight: 700; color: var(--danger-text); margin-bottom: 4px; }
.parse-issue-body { margin-bottom: 4px; }

.file-list { font-size: 12.5px; word-break: break-all; }
footer { margin-top: 30px; padding-top: 10px; border-top: 1px solid var(--border); color: var(--muted); font-size: 12px; }

@media print {
  body { padding: 0; font-size: 12px; }
  .stat-card, .instance-card, .agent-card, .relay-box, .key-fact, .parse-issue {
    background: #ffffff !important;
  }
  a { color: inherit; text-decoration: none; }
  section { page-break-inside: avoid; }
  h2 { break-before: auto; }
}
'@

# ---------------------------------------------------------------------------
# Assemble document
# ---------------------------------------------------------------------------

$titleText = "Remote Access Investigation Report"
if (-not [string]::IsNullOrWhiteSpace([string]$computerName)) {
    $titleText = "Remote Access Investigation Report - $computerName"
}

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>$(Encode-Html $titleText)</title>
<style>
$css
</style>
</head>
<body>
$headerHtml
<main>
$summaryHtml
$scSectionHtml
$otherSectionHtml
$avUninstallSectionHtml
$removalSectionHtml
$histSectionHtml
$parseSectionHtml
$envSectionHtml
</main>
<footer>
  Generated by $(Fmt $toolName) $(Fmt $toolVersion) findings, rendered by New-InvestigationReport.ps1. Read-only report - no changes were made to the scanned machine while producing it.
</footer>
</body>
</html>
"@

# ---------------------------------------------------------------------------
# Write output (UTF-8, no BOM)
# ---------------------------------------------------------------------------

$resolvedOutputDir = Split-Path -Path $OutputPath -Parent
if ($resolvedOutputDir -and -not (Test-Path -LiteralPath $resolvedOutputDir)) {
    New-Item -ItemType Directory -Path $resolvedOutputDir -Force | Out-Null
}

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($OutputPath, $html, $utf8NoBom)

Write-Host "Report written to: $OutputPath"

if ($PassThru) {
    return $OutputPath
}

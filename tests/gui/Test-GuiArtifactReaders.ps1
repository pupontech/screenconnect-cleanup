<#
  Test-GuiArtifactReaders.ps1 - the readers behind the GUI panels (Gui.Core.psm1) against
  fixture run folders: a complete findings.json, one instance (the single-element array trap),
  none, truncated JSON, an empty file, a missing file, duplicate or unidentified identifiers.
  Every reader must report "not available" instead of throwing, and the findings view must
  carry NO verdict about a relay host (design decision D4: the technician decides).

  No admin, no network. Windows PowerShell 5.1, pure ASCII, no BOM.
#>
param(
    [string]$ToolRoot = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$script:Failures = New-Object System.Collections.ArrayList
$script:Passes = 0
function Check {
    param([bool]$Condition, [string]$Message)
    if ($Condition) { $script:Passes++; Write-Host ('  [pass] ' + $Message) -ForegroundColor Green }
    else { [void]$script:Failures.Add($Message); Write-Host ('  [FAIL] ' + $Message) -ForegroundColor Red }
}

Import-Module (Join-Path $ToolRoot 'gui\Gui.Core.psm1') -Force
$work = Join-Path $env:TEMP ('scc-gui-readers-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $work -Force

function New-Instance {
    param([string]$Id, [string]$Relay, [int]$Port = 8041)
    return [ordered]@{
        Key = 'svc:' + $Id; Identifier = $Id; InstallDir = 'C:\Program Files (x86)\ScreenConnect Client (' + $Id + ')'
        ServiceName = 'ScreenConnect Client (' + $Id + ')'; ServiceState = 'Running'
        RelayHost = $Relay; RelayPort = $Port; SessionType = 'Support'
        File = [ordered]@{ SignatureStatus = 'Valid'; SignerSubject = 'CN=Elsinore Technologies' }
        InstallDirCreatedUtc = '2026-01-02 03:04:05'
    }
}
function Write-Findings {
    param([string]$Name, $Instances, [switch]$Raw, [string]$RawText)
    $p = Join-Path $work ($Name + '.json')
    if ($Raw) { Set-Content -LiteralPath $p -Value $RawText -Encoding UTF8; return $p }
    $doc = [ordered]@{
        Tool = 'detect-remote-access.ps1'; RunId = 'T'; ComputerName = 'TESTPC'; GeneratedUtc = '2026-11-10 10:00:00'
        ScreenConnect = [ordered]@{ Instances = $Instances; ParseIssues = @(); Historical = @(); RawFilesSaved = @() }
        OtherTargets = @([pscustomobject]@{ Id = 'anydesk'; Name = 'AnyDesk'; Hits = @([pscustomobject]@{ Kind = 'directory'; Name = 'AnyDesk'; Path = 'C:\x' }); Count = 1 },
            [pscustomobject]@{ Id = 'vnc'; Name = 'VNC'; Hits = @(); Count = 0 })
    }
    ($doc | ConvertTo-Json -Depth 8) | Set-Content -LiteralPath $p -Encoding UTF8
    return $p
}

try {
    Write-Host 'Findings view' -ForegroundColor Cyan
    $three = Write-Findings 'three' @((New-Instance 'aaaa1111aaaa1111' 'evil.example.net'), (New-Instance 'bbbb2222bbbb2222' 'support.customer.example'), (New-Instance 'cccc3333cccc3333' 'other.example.org' 443))
    $v = Get-GuiFindingsView $three
    Check ($v.Available -and @($v.Instances).Count -eq 3) 'three instances read'
    Check ($v.Instances[0].Relay -eq 'evil.example.net:8041' -and $v.Instances[2].Relay -eq 'other.example.org:443') 'relay host and port are shown together'
    Check ($v.Instances[1].ServiceState -eq 'Running' -and $v.Instances[1].SignatureStatus -eq 'Valid' -and $v.Instances[1].InstalledUtc -eq '2026-01-02 03:04:05') 'service, signature and install date are read'
    Check (@($v.Instances | Where-Object { -not $_.KeepSelectable }).Count -eq 0) 'distinct identifiers can all be kept one at a time'
    Check (@($v.OtherTargets).Count -eq 1 -and $v.OtherTargets[0].Name -eq 'AnyDesk') 'other remote-access products with hits are listed; empty ones are not'

    $one = Write-Findings 'one' @((New-Instance 'aaaa1111aaaa1111' 'only.example.net'))
    $v = Get-GuiFindingsView $one
    Check ($v.Available -and @($v.Instances).Count -eq 1) 'a single-element array is one instance (not zero, not a broken scalar)'
    $bare = Write-Findings 'bare' $null -Raw -RawText '{"ComputerName":"T","ScreenConnect":{"Instances":{"Identifier":"dddd4444dddd4444","RelayHost":"h.example","RelayPort":1},"ParseIssues":[],"Historical":[]},"OtherTargets":[]}'
    $v = Get-GuiFindingsView $bare
    Check (@($v.Instances).Count -eq 1 -and $v.Instances[0].Identifier -eq 'dddd4444dddd4444') 'a bare object where an array was expected still reads as one instance'

    $none = Write-Findings 'none' @()
    $v = Get-GuiFindingsView $none
    Check ($v.Available -and @($v.Instances).Count -eq 0) 'zero instances: available, empty list'
    $emptyObj = Write-Findings 'emptyobj' $null -Raw -RawText '{"ScreenConnect":{"Instances":{},"ParseIssues":[]},"OtherTargets":[]}'
    $v = Get-GuiFindingsView $emptyObj
    Check ($v.Available -and @($v.Instances).Count -eq 0) 'an empty object where an array was expected means none'
    $noSc = Write-Findings 'nosc' $null -Raw -RawText '{"ComputerName":"T"}'
    $v = Get-GuiFindingsView $noSc
    Check ($v.Available -and @($v.Instances).Count -eq 0) 'no ScreenConnect section at all: available, empty'

    $trunc = Write-Findings 'trunc' $null -Raw -RawText '{"ScreenConnect":{"Instances":[{"Identifier":"aaaa'
    $v = Get-GuiFindingsView $trunc
    Check ((-not $v.Available) -and $v.Error -match 'could not be read') 'truncated JSON: not available, with a reason, no exception'
    $emptyFile = Join-Path $work 'empty.json'; Set-Content -LiteralPath $emptyFile -Value '' -Encoding UTF8
    $v = Get-GuiFindingsView $emptyFile
    Check ((-not $v.Available) -and $v.Error -match 'empty') 'an empty file: not available'
    $v = Get-GuiFindingsView (Join-Path $work 'missing.json')
    Check ((-not $v.Available) -and $v.Error -match 'not available yet') 'a missing file: not available yet'
    $v = Get-GuiFindingsView ''
    Check (-not $v.Available) 'an empty path: not available'

    Write-Host 'Keep selection guard' -ForegroundColor Cyan
    $dup = Write-Findings 'dup' @((New-Instance 'aaaa1111aaaa1111' 'a.example'), (New-Instance 'AAAA1111AAAA1111' 'b.example'), (New-Instance 'bbbb2222bbbb2222' 'c.example'))
    $v = Get-GuiFindingsView $dup
    Check ((-not $v.Instances[0].KeepSelectable) -and (-not $v.Instances[1].KeepSelectable) -and $v.Instances[2].KeepSelectable) 'two instances sharing an identifier (any case) cannot be kept one at a time'
    $unid = Write-Findings 'unid' $null -Raw -RawText '{"ScreenConnect":{"Instances":[{"RelayHost":"x.example","RelayPort":1}]},"OtherTargets":[]}'
    $v = Get-GuiFindingsView $unid
    Check ($v.Instances[0].Identifier -eq '(unidentified)' -and -not $v.Instances[0].KeepSelectable) 'an instance with no identifier cannot be selected to keep'
    $comma = Write-Findings 'comma' @((New-Instance 'a,b' 'a.example'))
    $v = Get-GuiFindingsView $comma
    Check (-not $v.Instances[0].KeepSelectable) 'an identifier containing a comma cannot be passed in a comma list'

    Write-Host 'No verdicts (decision D4)' -ForegroundColor Cyan
    $v = Get-GuiFindingsView $three
    $names = @($v.Instances[0].PSObject.Properties.Name) + @($v.PSObject.Properties.Name)
    Check (@($names | Where-Object { $_ -match '(?i)safe|trust|suspic|known|allow|reputation|verdict|legit' }).Count -eq 0) 'the findings view has no safe/known/suspicious/allowlist property'
    $src = [IO.File]::ReadAllText((Join-Path $ToolRoot 'gui\Gui.Core.psm1'))
    Check ($src -notmatch '(?i)allowlist|known-good|trusted relay') 'the core contains no relay allowlist'

    Write-Host 'Other readers never throw' -ForegroundColor Cyan
    $run = Join-Path $work 'run'; $null = New-Item -ItemType Directory -Path $run -Force
    $mb = Get-GuiScannerResult $run 'Malwarebytes'
    Check (-not $mb.Available) 'scanner result: not available when the file is missing'
    $null = New-Item -ItemType Directory -Path (Join-Path $run 'logs') -Force
    Set-Content -LiteralPath (Join-Path $run 'logs\scanner-Malwarebytes-result.json') -Value '{"Status":"Completed"' -Encoding UTF8
    $mb = Get-GuiScannerResult $run 'Malwarebytes'
    Check (-not $mb.Available -and $mb.Error -match 'could not be read') 'scanner result: truncated JSON is reported, not thrown'
    Set-Content -LiteralPath (Join-Path $run 'logs\scanner-Malwarebytes-result.json') -Value '{"Status":"Completed"}' -Encoding UTF8
    $mb = Get-GuiScannerResult $run 'Malwarebytes'
    Check ($mb.Available -and $mb.Data.Status -eq 'Completed') 'scanner result: complete file is read'
    $pv = Get-GuiPersistenceView $run
    Check (-not $pv.Available) 'persistence view: not available before the scan'
    $null = New-Item -ItemType Directory -Path (Join-Path $run 'persistence') -Force
    Set-Content -LiteralPath (Join-Path $run 'persistence\inventory.json') -Value '{"Status":"Incomplete","Findings":{"Kind":"Run key"}}' -Encoding UTF8
    $pv = Get-GuiPersistenceView $run
    Check ($pv.Available -and $pv.Status -eq 'Incomplete' -and @($pv.Findings).Count -eq 1) 'persistence view: status and a single finding (bare object) are read'
    $dv = Get-GuiDiffView $run
    Check (-not $dv.Available) 'diff view: not available when the diff was not written'
    $ri = Get-GuiReportInfo $run
    Check ((-not $ri.ReportExists) -and (-not $ri.OfflineMarker)) 'report info: nothing yet'
    Set-Content -LiteralPath (Join-Path $run 'report.html') -Value '<html></html>' -Encoding ASCII
    Set-Content -LiteralPath (Join-Path $run 'phase-offline.json') -Value '{}' -Encoding ASCII
    $ri = Get-GuiReportInfo $run
    Check ($ri.ReportExists -and $ri.OfflineMarker -and -not $ri.OnlineMarker) 'report info: report and offline marker seen'

    Write-Host 'Display-only session file' -ForegroundColor Cyan
    $s = New-GuiSession -Mode Detect -ToolRoot $ToolRoot -RitRoot $work
    $s.RunRoot = $run
    Save-GuiSession $s
    $sf = Join-Path $run 'gui-session.json'
    Check (Test-Path -LiteralPath $sf) 'gui-session.json is written to the run folder'
    $doc = ([IO.File]::ReadAllText($sf) | ConvertFrom-Json)
    Check ($doc.Note -match 'Nothing reads this file') 'the file says it is display data'
    $core = [IO.File]::ReadAllText((Join-Path $ToolRoot 'gui\Gui.Core.psm1'))
    Check (([regex]::Matches($core, 'gui-session\.json')).Count -eq 1) 'gui-session.json is only ever written (named once, in Save-GuiSession)'
} finally {
    if ($work -and $work.StartsWith($env:TEMP, [StringComparison]::OrdinalIgnoreCase) -and $work -match 'scc-gui-readers-[0-9a-f]{32}$') {
        Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Host ''
Write-Host ('Result: ' + $script:Passes + ' passed, ' + $script:Failures.Count + ' failed') -ForegroundColor $(if ($script:Failures.Count -eq 0) { 'Green' } else { 'Red' })
if ($script:Failures.Count -gt 0) { $script:Failures | ForEach-Object { Write-Host ('  FAILED: ' + $_) -ForegroundColor Red }; exit 1 }
exit 0

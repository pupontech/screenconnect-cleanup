# =====================================================================
# Test-WindowsIntegration.ps1 -- SAFE Windows integration tests.
#
# Runs ONLY non-destructive paths on a GitHub Windows runner:
#   1. removal dry-run (no -Execute): loads a synthetic plan and proves
#      the whole Stage 4 pipeline is inert (no service stop, no file move,
#      no registry change) AND that a smuggled foreign entry is rejected.
#   2. report XSS escape: hostile findings.json -> 0 raw <script> in HTML.
#   3. sc-cleanup.ps1 -WhatIf parses and gates every stage.
#
# Exit codes: 0 = all pass, 1 = any failure. PS 5.1 compatible, ASCII, no BOM.
# =====================================================================
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('scc-ci-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp -Force | Out-Null

$failures = 0

function Check {
    param([string]$Name, [bool]$Ok, [string]$Detail = '')
    if ($Ok) { Write-Host ("PASS  {0}" -f $Name) }
    else {
        Write-Host ("FAIL  {0}  {1}" -f $Name, $Detail)
        $script:failures++
    }
}

# ---------------------------------------------------------------------
# 1. Removal dry-run is inert + rejects a smuggled non-ScreenConnect entry
# ---------------------------------------------------------------------
$planJson = Join-Path $tmp 'plan.json'
$plan = @{
    GeneratedUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
    TechName = 'CI'
    ClientName = 'CI'
    IncidentDate = (Get-Date).ToString('yyyy-MM-dd')
    Decision = 'ALL_REMOVE'
    SourceFindings = ''
    ScreenConnectInstances = @(
        @{
            InstanceId = 'a1b2c3d4e5f6'
            Identifier = 'a1b2c3d4e5f6'
            ServiceName = 'ScreenConnect Client (a1b2c3d4e5f6)'
            ServiceImagePath = "C:\Program Files (x86)\ScreenConnect Client (a1b2c3d4e5f6)\ScreenConnect.ClientService.exe"
            InstallDir = "C:\Program Files (x86)\ScreenConnect Client (a1b2c3d4e5f6)"
        },
        @{
            # SMUGGLED: AnyDesk entry placed inside ScreenConnectInstances.
            # Per owner policy nothing but ScreenConnect may be removed; the
            # removal engine must reject this and never act on it.
            InstanceId = 'evil-anydesk'
            Identifier = 'evil-anydesk'
            ServiceName = 'AnyDesk Service'
            ServiceImagePath = "C:\Program Files (x86)\AnyDesk\AnyDesk.exe"
            InstallDir = "C:\Program Files (x86)\AnyDesk"
        }
    )
}
$plan | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $planJson -Encoding UTF8 -NoNewline

$workDir = Join-Path $tmp 'workdir'
New-Item -ItemType Directory -Path $workDir -Force | Out-Null

$remover = Join-Path $repoRoot 'remove-screenconnect.ps1'
# DRY-RUN (no -Execute). Process exit must be 0 or 1 (1 = dry-run records
# 'Failed' for absent services on a bare runner, still inert). It must NEVER
# be any crash, and crucially must write a manifest proving verification gated
# the smuggled AnyDesk entry.
& $remover -PlanJson $planJson -WorkDir $workDir -NoRestorePoint
$rc = $LASTEXITCODE
Check 'removal dry-run exit code sane (0 or 1)' ($rc -eq 0 -or $rc -eq 1) "rc=$rc"

$manifestPath = Join-Path $workDir 'removal-manifest.json'
Check 'removal-manifest.json written by dry-run' (Test-Path -LiteralPath $manifestPath)

if (Test-Path -LiteralPath $manifestPath) {
    $mf = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $entries = @($mf.Entries)
    $verifEntries = @($entries | Where-Object { $_.Action -eq 'ProductVerification' })
    $verifFailed = @($verifEntries | Where-Object { $_.Result -eq 'PRODUCT_VERIFICATION_FAILED' })
    # Wrapped in @() - PS 5.1 unwraps a single-element Where-Object result to a
    # bare object whose .Count is $null, so .Count -ge 1 would silently fail
    # (the exact trap documented in docs/06-safety-model.md).
    $smuggledRejected = @($verifFailed | Where-Object { $_.InstanceId -eq 'evil-anydesk' })
    Check 'smuggled AnyDesk entry rejected by product verification' ($smuggledRejected.Count -ge 1)

    # No destructive action may have been recorded with a real Success result
    # for the smuggled entry (it must be PRODUCT_VERIFICATION_FAILED, never
    # StopService/Kill/Uninstall/Quarantine Success).
    $smuggledActions = @($entries | Where-Object {
        $_.InstanceId -eq 'evil-anydesk' -and
        $_.Result -eq 'Success' -and
        $_.Action -in @('StopService','KillProcess','KillProcesses','Uninstall','Quarantine','DeleteService','DeleteScheduledTask','DeleteRunKey','DeleteWmiSubscription')
    })
    Check 'no destructive Success action for smuggled entry' ($smuggledActions.Count -eq 0)
} else {
    Check 'smuggled AnyDesk entry rejected (manifest missing)' $false
}

# No quarantine dir should contain the AnyDesk tree (nothing was moved).
$anydeskQ = Join-Path (Join-Path $workDir 'quarantine') 'evil-anydesk'
Check 'no quarantine of smuggled entry on disk' (-not (Test-Path -LiteralPath $anydeskQ))

# ---------------------------------------------------------------------
# 2. Report XSS escape
# ---------------------------------------------------------------------
$hostileFindings = Join-Path $tmp 'hostile-findings.json'
$hostile = @{
    Tool = 'detect-remote-access.ps1'
    Version = '0.1'
    GeneratedUtc = '2026-08-25 00:00:00'
    ComputerName = '<script>alert(1)</script>'
    RunAsUser = 'u'
    IsAdmin = $false
    OSCaption = '<img src=x onerror=alert(2)>'
    PSVersion = '5.1'
    TargetsSource = 't'
    TargetsSelected = @('screenconnect')
    EventLogError = $null
    ScreenConnect = @{
        Instances = @(@{
            Identifier = 'a1b2c3'; Key = 'a1b2c3'; InstallDir = 'C:\x'
            RelayHost = '<script>bad</script>'; RelayPort = '8041'
            SessionType = 'Access'; Role = 'Guest'; SessionId = 's'
            ServerKeyFingerprint = 'fp'; ParamBlobSource = 'service'
            CustomProperties = @{ c1 = '<b>hi</b>' }
            UnknownParams = @{ zz = '<i>u</i>' }
            Sources = @('service')
            File = @{ Path = 'C:\x.exe'; Sha256 = 'h'; SignatureStatus = 'Valid'; SignerSubject = '<script>x</script>' }
            Processes = @(@{ ProcessId = 1; ParentProcessId = 0; Name = 'p'; ExecutablePath = 'C:\p.exe'; StartedUtc = '' })
            Connections = @(@{ LocalAddress = '1.1.1.1'; LocalPort = '1'; RemoteAddress = '2.2.2.2'; RemotePort = '2'; State = 'Established' })
            ServiceInstallEvents = @(@{ TimeUtc = 't'; Message = '<script>m</script>' })
            UninstallString = 'MsiExec.exe /X{00000000-0000-0000-0000-000000000000}'
        })
        ParseIssues = @(@{ Key = 'k'; Issue = '<script>pi</script>'; ParamBlob = '?h=x&y=z'; KeysSeen = @('h') })
        Historical = @(@{ TimeUtc = 't'; Identifier = 'i'; Message = '<script>h</script>' })
        RawFilesSaved = @('C:\raw\x.config')
    }
    OtherTargets = @(@{ Id = 'anydesk'; Name = ''; Hits = @(@{ Kind = 'service'; Name = '<script>h</script>'; Detail = ''; Path = ''; State = ''; StartMode = '' }) })
}
$hostile | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $hostileFindings -Encoding UTF8 -NoNewline

$reportHtml = Join-Path $tmp 'report.html'
$reportScript = Join-Path $repoRoot 'New-InvestigationReport.ps1'
# NOTE: New-InvestigationReport.ps1 does not call `exit`, and a .ps1 invoked
# with `&` never sets $LASTEXITCODE (that only tracks native commands). So it
# is meaningless to assert `$LASTEXITCODE -eq 0` here - on the Windows runner
# the value leaks the PRIOR child's code. The meaningful success signal is:
# no terminating error AND the report file was actually written.
$repOk = $true
try {
    & $reportScript -FindingsJson $hostileFindings -OutputPath $reportHtml *> $null
} catch {
    $repOk = $false
    Write-Host ("report generator threw: {0}" -f $_.Exception.Message)
}
Check 'report generator ran without error' $repOk

if (Test-Path -LiteralPath $reportHtml) {
    $html = Get-Content -LiteralPath $reportHtml -Raw
    Check 'report has 0 raw <script>' (-not $html.Contains('<script>'))
    # Encode-Html escapes < and > to &lt; &gt;, so an attacker's
    # `onerror=` survives only as inert text inside escaped markup: the
    # literal substring `onerror=` WILL appear, but no live `<img ... onerror`
    # or `<... onerror=` element can. Assert THERE IS NO ACTIVE HANDLER
    # (i.e. no `<` immediately preceding an `onerror=` inside a tag), and
    # that the hostile OSCaption was escaped, rather than a naive substring
    # absence that falsely fails on correctly-neutralized text.
    Check 'no live onerror= handler in report' (-not $html.Contains('<img src=x onerror='))
    Check 'onerror payload is bracket-escaped' ($html.Contains('&lt;img src=x onerror=alert(2)&gt;'))
} else {
    Check 'report HTML written' $false
}

# ---------------------------------------------------------------------
# 3. sc-cleanup.ps1 -WhatIf parses and gating works (no stage executed)
# ---------------------------------------------------------------------
$scCleanup = Join-Path $repoRoot 'sc-cleanup.ps1'
# Run in a CHILD process so its exit code is real: `& .ps1` does not set
# $LASTEXITCODE. Also pass -force because GitHub runners are Windows SERVER
# (2022/2025 Datacenter) and the server-OS refusal is a deliberate product
# guard (docs/06 rule 8) that a CI host legitimately overrides. -WhatIf still
# executes NOTHING, so this stays safe.
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = (Get-Command powershell.exe -ErrorAction SilentlyContinue).Source
if (-not $psi.FileName) { $psi.FileName = (Get-Command pwsh -ErrorAction SilentlyContinue).Source }
if (-not $psi.FileName) { $psi.FileName = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName }
$psi.Arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $scCleanup + '" -WhatIf -force -np -offline -OutRoot "' + $tmp + '" -TechName CI -ClientName CI'
$psi.UseShellExecute = $false
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$proc = [System.Diagnostics.Process]::Start($psi)
$proc.WaitForExit()
$whatIfRc = $proc.ExitCode
Check 'sc-cleanup -WhatIf exits 0' ($whatIfRc -eq 0) "rc=$whatIfRc"

# ---------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------
Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host ("Windows integration tests: {0} failure(s)." -f $failures)
if ($failures -gt 0) { exit 1 }
exit 0

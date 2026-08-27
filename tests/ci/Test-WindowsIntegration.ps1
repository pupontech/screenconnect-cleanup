# =====================================================================
# Test-WindowsIntegration.ps1 -- SAFE Windows integration tests.
#
# Runs ONLY non-destructive paths on a GitHub Windows runner:
#   1. removal dry-run (no -Execute): loads a synthetic plan and proves
#      the whole Stage 4 pipeline is inert (no service stop, no file move,
#      no registry change) AND that a smuggled foreign entry is rejected.
#   2. report XSS escape: hostile findings.json -> 0 raw <script> in HTML.
#   3. sc-cleanup.ps1 -WhatIf parses and gates every stage.
#   4. registry entries missing UninstallString dry-run cleanly (d71d40a).
#   5. Run-VendorUninstaller execution shape: async pipe drain (no
#      deadlock), honored 5-minute bound, kill-on-timeout, Failed entry.
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
$hostExe = (Get-Command powershell.exe -ErrorAction SilentlyContinue).Source
if (-not $hostExe) { $hostExe = (Get-Command pwsh -ErrorAction SilentlyContinue).Source }
if (-not $hostExe) { $hostExe = 'pwsh' }
$whatIfArgs = @(
    '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
    '-File', $scCleanup,
    '-WhatIf', '-force', '-np', '-offline',
    '-OutRoot', $tmp, '-TechName', 'CI', '-ClientName', 'CI'
)
# Start-Process -Wait -PassThru drains inheritable streams itself (unlike a
# manual ProcessStartInfo with RedirectStandardOutput/Error=true that deadlocks
# if you never read the pipes), and its ExitCode is the script's real one.
$whatIfP = Start-Process -FilePath $hostExe -ArgumentList $whatIfArgs -Wait -PassThru -NoNewWindow
$whatIfRc = $whatIfP.ExitCode
Check 'sc-cleanup -WhatIf exits 0' ($whatIfRc -eq 0) "rc=$whatIfRc"

# ---------------------------------------------------------------------
# 4. Registry entries missing UninstallString are clean dry-runs with NO
#    StrictMode crash.
#
#    d71d40a crashes processing such an instance. The main loop
#    dereferenced $uninstallEntry.UninstallString directly
#    (remove-screenconnect.ps1 line 1337/1340) under Set-StrictMode
#    -Version 2.0, so any registration without that value threw
#    ("The property 'UninstallString' cannot be found on this object"),
#    which was caught as a 'ProcessInstance' Failed and failed the run.
#
#    Two non-destructive synthetic registrations are exercised:
#      a. quiet-only: carries ONLY QuietUninstallString -> the original
#         regression. Run-VendorUninstaller dry-run "succeeds" and the
#         success-recording line must not crash.
#      b. nostrings sibling: ScreenConnect-labelled key with NEITHER
#         UninstallString NOR QuietUninstallString, only a verified
#         InstallLocation -> Run-VendorUninstaller takes its clean
#         null-return branch ("no uninstall string, manual surgery")
#         and the main loop's fallback-decision recording must not
#         crash and must not lie about a failure.
#    Non-destructive: dry-run (no -Execute) never starts a process and
#    never executes a registry command string; the fabricated uninstall
#    paths point at files that do not exist on the runner.
# ---------------------------------------------------------------------
$quietRoot = 'HKCU:\Software\RIT-SCC-CI'
$quietKey = Join-Path $quietRoot ('quiet-' + [Guid]::NewGuid().ToString('N'))
$bareKey = Join-Path $quietRoot ('bare-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $quietKey -Force | Out-Null
New-Item -ItemType Directory -Path $bareKey -Force | Out-Null
try {
    $quietInstallDir = 'C:\Program Files (x86)\ScreenConnect Client (quietonly)'
    New-ItemProperty -LiteralPath $quietKey -Name 'DisplayName' -PropertyType String -Value 'ScreenConnect Client (quietonly)' -Force | Out-Null
    # Deliberately NO 'UninstallString' value - only QuietUninstallString. The
    # value references the verified install dir so Get-VerifiedUninstallEntry
    # accepts the key; Run-VendorUninstaller (dry-run) never executes it.
    New-ItemProperty -LiteralPath $quietKey -Name 'QuietUninstallString' -PropertyType String -Value ('"C:\Program Files (x86)\ScreenConnect Client (quietonly)\ScreenConnect.ClientService.exe" /s') -Force | Out-Null

    # Sibling of the quiet-only leaf: ScreenConnect-labelled, but with NO
    # uninstall command at all - just DisplayName + InstallLocation pointing
    # at the verified install dir. This drives Run-VendorUninstaller into its
    # null-return branch (no command -> record Skipped, return $null), so
    # the main loop's fallback-decision recording runs against an entry that
    # has neither value.
    $bareInstallDir = 'C:\Program Files (x86)\ScreenConnect Client (nostrings)'
    New-ItemProperty -LiteralPath $bareKey -Name 'DisplayName' -PropertyType String -Value 'ScreenConnect Client (nostrings)' -Force | Out-Null
    New-ItemProperty -LiteralPath $bareKey -Name 'InstallLocation' -PropertyType String -Value $bareInstallDir -Force | Out-Null

    $quietPlan = Join-Path $tmp 'plan-quiet.json'
    @{
        GeneratedUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
        TechName = 'CI'
        ClientName = 'CI'
        IncidentDate = (Get-Date).ToString('yyyy-MM-dd')
        Decision = 'ALL_REMOVE'
        SourceFindings = ''
        ScreenConnectInstances = @(
            @{
                InstanceId = 'quietonly'
                Identifier = 'quietonly'
                ServiceName = 'ScreenConnect Client (quietonly)'
                ServiceImagePath = $quietInstallDir + '\ScreenConnect.ClientService.exe'
                InstallDir = $quietInstallDir
                UninstallRegistryKey = $quietKey
            },
            @{
                InstanceId = 'nostrings'
                Identifier = 'nostrings'
                ServiceName = 'ScreenConnect Client (nostrings)'
                ServiceImagePath = $bareInstallDir + '\ScreenConnect.ClientService.exe'
                InstallDir = $bareInstallDir
                UninstallRegistryKey = $bareKey
            }
        )
    } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $quietPlan -Encoding UTF8 -NoNewline

    $quietWork = Join-Path $tmp 'workdir-quiet'
    New-Item -ItemType Directory -Path $quietWork -Force | Out-Null

    # HARDENED: an unexpected throw from the remover must become an explicit
    # failed Check, not kill this harness before the HKCU cleanup below runs.
    $global:LASTEXITCODE = $null
    $removerThrew = $false
    $throwMsg = ''
    try {
        & $remover -PlanJson $quietPlan -WorkDir $quietWork -NoRestorePoint
    } catch {
        $removerThrew = $true
        $throwMsg = $_.Exception.Message
    }
    $removerRc = $LASTEXITCODE
    Check 'remover invocation did not throw' (-not $removerThrew) "unexpected throw: $throwMsg"
    if (-not $removerThrew) {
        Check 'removal dry-run exit code sane (0 or 1)' ($removerRc -eq 0 -or $removerRc -eq 1) "rc=$removerRc"
    }

    $quietManifest = Join-Path $quietWork 'removal-manifest.json'
    if ((-not $removerThrew) -and (Test-Path -LiteralPath $quietManifest)) {
        $qm = Get-Content -LiteralPath $quietManifest -Raw | ConvertFrom-Json
        $qEntries = @($qm.Entries)

        # --- Original quiet-only regression (preserved) ---
        # Processing this instance must be clean. Any 'ProcessInstance' Failed
        # for 'quietonly' means the success path dereferenced a missing
        # .UninstallString and threw under StrictMode.
        $qProcFail = @($qEntries | Where-Object { $_.Action -eq 'ProcessInstance' -and $_.Result -eq 'Failed' -and $_.InstanceId -eq 'quietonly' })
        Check 'quiet-only uninstall: no ProcessInstance crash' ($qProcFail.Count -eq 0)

        # The registration must be recorded as a clean dry-run, never Failed
        # and never silently skipped because of a crash before the decision.
        $qDryRun = @($qEntries | Where-Object { $_.Action -eq 'Uninstall' -and $_.Result -eq 'DryRun' -and $_.InstanceId -eq 'quietonly' })
        Check 'quiet-only uninstall: recorded as clean dry-run' ($qDryRun.Count -ge 1)

        # --- Sibling null-return branch (neither uninstall value) ---
        # No crash on the failure-recording path either.
        $bProcFail = @($qEntries | Where-Object { $_.Action -eq 'ProcessInstance' -and $_.Result -eq 'Failed' -and $_.InstanceId -eq 'nostrings' })
        Check 'nostrings uninstall: no ProcessInstance crash' ($bProcFail.Count -eq 0)

        # Run-VendorUninstaller MUST have taken its designed null-return
        # branch: no command on the key -> recorded Skipped (not Failed),
        # manual-surgery fallback announced.
        $bSkipped = @($qEntries | Where-Object {
            $_.InstanceId -eq 'nostrings' -and
            $_.Action -eq 'Uninstall' -and
            $_.Result -eq 'Skipped' -and
            $_.Details -like '*No uninstall string*manual surgery*'
        })
        Check 'nostrings uninstall: null-return branch recorded Skipped' ($bSkipped.Count -ge 1)

        # The main loop then records its fallback DECISION without crashing
        # and without a misleading failure: Action 'UninstallFallback',
        # Result 'Planned', and a real Target (DisplayName) instead of an
        # empty one. A run whose manual surgery succeeds must never show
        # 'Uninstall: Failed'.
        $bFallback = @($qEntries | Where-Object {
            $_.InstanceId -eq 'nostrings' -and
            $_.Action -eq 'UninstallFallback' -and
            $_.Result -eq 'Planned' -and
            $_.Details -like '*manual surgery + quarantine*'
        })
        Check 'nostrings uninstall: fallback decision recorded as Planned' ($bFallback.Count -eq 1)
        Check 'nostrings uninstall: fallback Target carries DisplayName' ($bFallback.Count -eq 1 -and [string]$bFallback[0].Target -eq 'ScreenConnect Client (nostrings)')

        # Nothing may record the stringless registration as a failed
        # Uninstall - there was nothing to run.
        $bUfail = @($qEntries | Where-Object {
            $_.InstanceId -eq 'nostrings' -and
            $_.Action -eq 'Uninstall' -and
            $_.Result -eq 'Failed'
        })
        Check 'nostrings uninstall: no Failed Uninstall entry' ($bUfail.Count -eq 0)

        # Non-destructive correctness: nothing was executed or claimed done -
        # no Success and no DryRun Uninstall for the stringless entry.
        $bDestructive = @($qEntries | Where-Object {
            $_.InstanceId -eq 'nostrings' -and
            $_.Action -in @('StopService','KillProcess','KillProcesses','Uninstall','Quarantine','DeleteService','DeleteScheduledTask','DeleteRunKey','DeleteWmiSubscription') -and
            $_.Result -eq 'Success'
        })
        Check 'no destructive Success action for stringless entry' ($bDestructive.Count -eq 0)
        $bDryRunU = @($qEntries | Where-Object {
            $_.InstanceId -eq 'nostrings' -and $_.Action -eq 'Uninstall' -and $_.Result -eq 'DryRun'
        })
        Check 'nostrings uninstall: no DryRun uninstall command (nothing to run)' ($bDryRunU.Count -eq 0)
    } else {
        Check 'stringless-entry manifest written and remover silent' $false
    }
} finally {
    # Clean the created GUID leaves...
    Remove-Item -LiteralPath $quietKey -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $bareKey -Recurse -Force -ErrorAction SilentlyContinue
    # ...and remove the RIT-SCC-CI parent ONLY if this run left it empty, so
    # we never delete a pre-existing tree or siblings owned by another run.
    try {
        if (Test-Path -LiteralPath $quietRoot) {
            $leftovers = @(Get-ChildItem -LiteralPath $quietRoot -ErrorAction SilentlyContinue)
            if ($leftovers.Count -eq 0) {
                Remove-Item -LiteralPath $quietRoot -Force -ErrorAction SilentlyContinue
            }
        }
    } catch { }
}

# ---------------------------------------------------------------------
# 5. Run-VendorUninstaller execution shape: no pipe deadlock, honored
#    5-minute bound, kill-on-timeout, clear Failed manifest entry.
#
#    Regression for the old sequential synchronous drain:
#        $stdout = $proc.StandardOutput.ReadToEnd()
#        $stderr = $proc.StandardError.ReadToEnd()
#        $proc.WaitForExit(300000)      # timeout result ignored
#        $exitCode = $proc.ExitCode
#    which deadlocked when the child filled either pipe while we were
#    blocked reading the other, never enforced its own timeout, and read
#    ExitCode off a possibly still-running process.
#
#    Three layers, all inert (no ScreenConnect or vendor binary is ever
#    installed, downloaded, or executed; every child below is a stub this
#    test generates itself; cmd.exe is never invoked):
#
#    5a. STATIC parse pins on the real remove-screenconnect.ps1: both
#        redirected pipes drained via ReadToEndAsync BEFORE the bounded
#        wait, WaitForExit(300000)'s RESULT captured, Kill() on the
#        timeout path, and a Failed manifest entry recorded there.
#
#    5b. DYNAMIC proof of the execution shape: a stub child floods about
#        2 MB to STDERR (far past any pipe buffer) and only then writes
#        stdout and exits 7. Through the fixed async shape this must
#        complete; through the old sequential sync pair it deadlocks by
#        construction (child blocks writing stderr forever, so stdout
#        never closes and the first ReadToEnd() never returns), which is
#        exactly why completion is the regression signal.
#
#    5c. DYNAMIC end-to-end through the REAL function body: the
#        FunctionDefinitionAst for Run-VendorUninstaller is extracted
#        with the language parser, ONLY the timeout literal is patched
#        (300000 -> 3000 ms so CI pays seconds instead of five minutes),
#        minimal shims stand in for Write-Log / Add-ManifestEntry /
#        Get-EntryPropertySafe, and the function runs against two
#        compiled stub executables (one exits cleanly, one floods
#        stderr then hangs holding both pipes open). The literal patch
#        is required because the product hardcodes the 5-minute
#        constant; everything else - the vendor-uninstaller allowlist
#        gate, the verified-install-dir gate, the no-cmd.exe rule,
#        manifest recording - runs unmodified. The stub leaf name
#        unins000.exe rides the EXISTING allowlist branch
#        (^unins[0-9]*\.exe$) inside a ScreenConnect-named install dir,
#        so the verification gates are exercised as-is, not weakened.
#
#    Why the shipped function is not driven live end-to-end with its own
#    constant: that would burn a real 5+ minutes of runner budget per
#    case per edition, and the function hardcodes Arguments='' so any
#    stock runner executable would misbehave unpredictably with zero
#    arguments. Compiling our own inert stubs keeps child behavior
#    deterministic; the 5a static pins guarantee the file on disk still
#    carries the exact fixed shape.
# ---------------------------------------------------------------------
$productScript = Join-Path $repoRoot 'remove-screenconnect.ps1'
$tok5 = $null; $err5 = $null
$prodAst = [System.Management.Automation.Language.Parser]::ParseFile($productScript, [ref]$tok5, [ref]$err5)
Check '5a: remove-screenconnect.ps1 parses' ($err5.Count -eq 0)

$fdefs5 = @($prodAst.FindAll({ param($a) $a -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true))
$ruv5 = $fdefs5 | Where-Object { $_.Name -eq 'Run-VendorUninstaller' } | Select-Object -First 1

if ($ruv5) {
    $src5 = $ruv5.Extent.Text
    $rbp5 = $fdefs5 | Where-Object { $_.Name -eq 'Run-BoundedProcess' } | Select-Object -First 1
    if ($rbp5) {
        $runc5 = $rbp5.Extent.Text
        $iOutA = $runc5.IndexOf('$proc.StandardOutput.ReadToEndAsync()')
        $iErrA = $runc5.IndexOf('$proc.StandardError.ReadToEndAsync()')
        $iWait = $runc5.IndexOf('$proc.WaitForExit($TimeoutMs)')
        $iKill = $runc5.IndexOf('$proc.Kill()')

        Check '5a: both pipes drained via ReadToEndAsync' (($iOutA -ge 0) -and ($iErrA -ge 0))
        Check '5a: no synchronous pipe ReadToEnd left' ((-not $runc5.Contains('$proc.StandardOutput.ReadToEnd()')) -and (-not $runc5.Contains('$proc.StandardError.ReadToEnd()')))
        Check '5a: async drains precede the bounded wait' (($iOutA -ge 0) -and ($iErrA -ge 0) -and ($iWait -gt $iOutA) -and ($iWait -gt $iErrA))
        Check '5a: bounded WaitForExit($TimeoutMs) present' ($iWait -ge 0)
        Check '5a: exactly one bounded wait literal' (@([regex]::Matches($runc5, 'WaitForExit\(\$TimeoutMs\)')).Count -eq 1)
        Check '5a: Kill() sits on the timeout path' (($iKill -gt $iWait))
        Check '5a: uninstaller uses the bounded runner with the 5-minute bound' ((@([regex]::Matches($src5, 'Run-BoundedProcess')).Count -ge 1) -and $src5.Contains('-TimeoutMs 300000'))
        if ($iKill -gt 0) {
            $tail5 = $runc5.Substring($iKill)
            Check '5a: timeout path reaps the process' ($tail5 -match 'WaitForExit\(1000\)')
            Check '5a: timeout records clear Failed manifest entry' (($src5 -match 'timed out after 300s and was killed') -and ($src5 -match "Result 'Failed'"))
        } else {
            Check '5a: timeout records clear Failed manifest entry' $false 'Kill() not found'
        }
    } else {
        Check '5a: Run-BoundedProcess found for static pins' $false
    }
} else {
    Check '5a: Run-VendorUninstaller found for static pins' $false
}

# --- 5b: stub child floods stderr then writes stdout, via the fixed shape ---
$shapeCmd = '$line=(''x'' * 500); for($i=0;$i -lt 4000;$i++){[Console]::Error.WriteLine($line)}; [Console]::Error.Flush(); [Console]::Out.WriteLine(''SC-SHAPE-STDOUT-MARKER''); [Console]::Out.Flush(); exit 7'
$shapeEnc = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($shapeCmd))
$shapeHost = (Get-Command powershell.exe -ErrorAction SilentlyContinue).Source
if (-not $shapeHost) { $shapeHost = (Get-Command pwsh -ErrorAction SilentlyContinue).Source }
if (-not $shapeHost) { $shapeHost = 'pwsh' }

$psi5 = New-Object System.Diagnostics.ProcessStartInfo
$psi5.FileName = $shapeHost
$psi5.Arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ' + $shapeEnc
$psi5.UseShellExecute = $false
$psi5.RedirectStandardOutput = $true
$psi5.RedirectStandardError = $true
$psi5.CreateNoWindow = $true

try {
    $shapeProc = [System.Diagnostics.Process]::Start($psi5)
    # The FIXED shape under test (mirrors remove-screenconnect.ps1): drain
    # both pipes asynchronously, then ONE bounded wait, kill on timeout.
    $shapeOutTask = $shapeProc.StandardOutput.ReadToEndAsync()
    $shapeErrTask = $shapeProc.StandardError.ReadToEndAsync()
    $shapeExited = $shapeProc.WaitForExit(20000)
    if (-not $shapeExited) {
        try { $shapeProc.Kill(); $null = $shapeProc.WaitForExit(5000) } catch { }
        Check '5b: stderr-flood stub completed without deadlock' $false '20s timeout hit'
    } else {
        $shapeStdout = $shapeOutTask.Result
        $shapeStderr = $shapeErrTask.Result
        $shapeRc = $shapeProc.ExitCode
        Check '5b: stderr-flood stub completed without deadlock' $true
        Check '5b: exit code propagated through bounded wait' ($shapeRc -eq 7) "rc=$shapeRc"
        Check '5b: stdout survived after 2MB stderr flood' ($shapeStdout.Contains('SC-SHAPE-STDOUT-MARKER'))
        Check '5b: stderr fully drained (>1MB captured)' ($shapeStderr.Length -gt 1000000) ("got $($shapeStderr.Length) chars")
    }
} catch {
    Check '5b: stderr-flood stub completed without deadlock' $false $_.Exception.Message
}

# --- 5c: real function body (timeout literal patched) vs compiled stubs ---
$csOk = @'
using System;
public static class ScStubOk {
    public static void Main() {
        string line = new string('x', 500);
        for (int i = 0; i < 4000; i++) { Console.Error.WriteLine(line); }
        Console.Error.Flush();
        Console.Out.WriteLine("SC-STUB-STDOUT-MARKER");
        Console.Out.Flush();
    }
}
'@
$csHang = @'
using System;
using System.Threading;
public static class ScStubHang {
    public static void Main() {
        string line = new string('x', 500);
        for (int i = 0; i < 4000; i++) { Console.Error.WriteLine(line); }
        Console.Error.Flush();
        Console.Out.WriteLine("SC-STUB-STDOUT-MARKER");
        Console.Out.Flush();
        Thread.Sleep(Timeout.Infinite);
    }
}
'@

$stubRoot5 = Join-Path $tmp 'pipe-stub'
$okDir5 = Join-Path $stubRoot5 'ScreenConnect Client (pipe-ok)'
$hangDir5 = Join-Path $stubRoot5 'ScreenConnect Client (pipe-hang)'
New-Item -ItemType Directory -Path $okDir5 -Force | Out-Null
New-Item -ItemType Directory -Path $hangDir5 -Force | Out-Null
$okExe5 = Join-Path $okDir5 'unins000.exe'
$hangExe5 = Join-Path $hangDir5 'unins000.exe'

# Compile one stub exe from C# source. Prefer the Windows .NET Framework
# compiler when present: its exes always run on the runner. pwsh 7's
# Add-Type -OutputAssembly has emitted non-runnable output on the
# Windows runners, so it is only a fallback for hosts without csc.exe.
function Compile-PipeStub5 {
    param([string]$CSharpSource, [string]$ExePath)
    $csFile = Join-Path $tmp ('stub-' + [Guid]::NewGuid().ToString('N') + '.cs')
    Set-Content -LiteralPath $csFile -Value $CSharpSource -Encoding Ascii
    try {
        $csc = $null
        if (-not [string]::IsNullOrEmpty($env:windir)) {
            $cscCandidate = Join-Path $env:windir 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
            if (Test-Path -LiteralPath $cscCandidate) { $csc = $cscCandidate }
        }
        if ($csc) {
            # Native tool under $ErrorActionPreference='Stop' (set at the top
            # of this harness): any stderr line from csc.exe would become a
            # terminating NativeCommandError on Windows PowerShell 5.1, so
            # drop EAP locally and restore it afterwards.
            $prevEap5 = $ErrorActionPreference
            try {
                $ErrorActionPreference = 'Continue'
                $cscOut = & $csc /nologo /target:exe "/out:$ExePath" $csFile 2>&1
            } finally {
                $ErrorActionPreference = $prevEap5
            }
            if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $ExePath)) {
                Write-Host ("5c stub csc.exe failed ({0}): rc={1} output: {2}" -f (Split-Path -Leaf $ExePath), $LASTEXITCODE, (($cscOut | Out-String).Trim()))
                return $false
            }
            return $true
        }
        Add-Type -TypeDefinition $CSharpSource -OutputAssembly $ExePath -ErrorAction Stop
        return (Test-Path -LiteralPath $ExePath)
    } catch {
        Write-Host ("5c stub compile failed ({0}): {1}" -f (Split-Path -Leaf $ExePath), $_.Exception.Message)
        return $false
    } finally {
        Remove-Item -LiteralPath $csFile -Force -ErrorAction SilentlyContinue
    }
}

$compiledOk = Compile-PipeStub5 -CSharpSource $csOk -ExePath $okExe5
$compiledHang = Compile-PipeStub5 -CSharpSource $csHang -ExePath $hangExe5
Check '5c: pipe-ok stub compiled' ($compiledOk -and (Test-Path -LiteralPath $okExe5))
Check '5c: pipe-hang stub compiled' ($compiledHang -and (Test-Path -LiteralPath $hangExe5))

# Sanity self-run of the compiled ok stub BEFORE trusting it end-to-end: if
# the compiler produced something the OS cannot execute, the two real-function
# cases below would fail with misleading function-result errors, so prove the
# binary actually runs first.
$sanityOk5 = $false
$sanityDetail5 = ''
if ($compiledOk) {
    try {
        $sanityPsi5 = New-Object System.Diagnostics.ProcessStartInfo
        $sanityPsi5.FileName = $okExe5
        $sanityPsi5.UseShellExecute = $false
        $sanityPsi5.RedirectStandardOutput = $true
        $sanityPsi5.RedirectStandardError = $true
        $sanityPsi5.CreateNoWindow = $true
        $sanityProc5 = [System.Diagnostics.Process]::Start($sanityPsi5)
        # Same async-drain shape as 5b/the product: the stub floods ~2MB of
        # stderr, so synchronous reads here would deadlock the sanity run.
        $sanityOutTask5 = $sanityProc5.StandardOutput.ReadToEndAsync()
        $null = $sanityProc5.StandardError.ReadToEndAsync()
        if (-not $sanityProc5.WaitForExit(10000)) {
            try { $sanityProc5.Kill(); $null = $sanityProc5.WaitForExit(5000) } catch { }
            $sanityDetail5 = 'stub did not exit within 10 seconds (killed)'
        } else {
            $sanityRc5 = $sanityProc5.ExitCode
            $sanityStdout5 = $sanityOutTask5.Result
            $markerSeen5 = $sanityStdout5.Contains('SC-STUB-STDOUT-MARKER')
            if ($sanityRc5 -eq 0 -and $markerSeen5) {
                $sanityOk5 = $true
            } else {
                $sanityDetail5 = ("exit code {0}, stdout marker seen: {1}" -f $sanityRc5, $markerSeen5)
            }
        }
    } catch {
        $sanityDetail5 = $_.Exception.Message
    }
} else {
    $sanityDetail5 = 'ok stub was not compiled'
}
Check '5c: compiled stub is runnable' $sanityOk5 $sanityDetail5

if ($ruv5 -and $rbp5 -and $compiledOk -and $compiledHang -and $sanityOk5) {
    $fnSrc5 = $ruv5.Extent.Text
    if ($fnSrc5.Contains('-TimeoutMs 300000')) {
        # Patch ONLY the timeout constant so CI pays ~3 seconds, not five
        # minutes. Everything else in the function body stays verbatim.
        $fnPatched5 = $fnSrc5.Replace('-TimeoutMs 300000', '-TimeoutMs 3000')

        # Minimal shims for the helpers the functions call. They mirror
        # the product implementations; Write-Log captures so we can prove the
        # drained STDOUT actually flowed through the function.
        $harnessLog5 = New-Object System.Collections.ArrayList
        $harnessManifest5 = New-Object System.Collections.ArrayList
        function Write-Log {
            param([string]$Message, [string]$Level = 'Info', [switch]$NoConsole)
            [void]$script:harnessLog5.Add([pscustomobject]@{ Level = $Level; Message = $Message })
        }
        function Add-ManifestEntry {
            param([string]$InstanceId, [string]$Action, [string]$Target, [string]$Result, [string]$Details = '', [int]$ExitCode = 0)
            [void]$script:harnessManifest5.Add([pscustomobject]@{
                TimestampUtc = (Get-Date).ToUniversalTime().ToString('o')
                InstanceId   = $InstanceId
                Action       = $Action
                Target       = $Target
                Result       = $Result
                Details      = $Details
                ExitCode     = $ExitCode
            })
        }
        function Get-EntryPropertySafe {
            param($Instance, [string]$PropertyName)
            if ($null -eq $Instance) { return $null }
            try {
                $pp = $Instance.PSObject.Properties[$PropertyName]
                if ($pp) { return $pp.Value }
            } catch { }
            return $null
        }

        # The real Run-VendorUninstaller delegates to Run-BoundedProcess, so
        # evaluate the production bounded runner first (pure function: process
        # start/wait/kill plus Write-Log only, no registry/service/removal).
        Invoke-Expression $runc5
        Invoke-Expression $fnPatched5
        $Execute = $true

        # Case 1: well-behaved stub - floods ~2MB stderr, writes stdout, exits 0.
        $entryOk5 = [pscustomobject]@{
            DisplayName          = 'ScreenConnect Client (pipe-ok)'
            QuietUninstallString = ('"' + $okExe5 + '"')
            PSPath               = 'Microsoft.PowerShell.Core\Registry::HKEY_CURRENT_USER\Software\RIT-SCC-CI\pipe-ok-fake'
        }
        $swOk5 = [System.Diagnostics.Stopwatch]::StartNew()
        $okResult5 = Run-VendorUninstaller -UninstallEntry $entryOk5 -InstanceId 'pipe-ok' -InstallDir $okDir5
        $swOk5.Stop()

        Check '5c: well-behaved uninstaller reported Success' ($okResult5 -eq $true) "result=$okResult5"
        $okUninst5 = @($harnessManifest5 | Where-Object { $_.Action -eq 'Uninstall' -and $_.InstanceId -eq 'pipe-ok' })
        Check '5c: Success manifest entry with exit code 0' (@($okUninst5 | Where-Object { $_.Result -eq 'Success' -and $_.ExitCode -eq 0 }).Count -ge 1)
        Check '5c: drained stdout flowed through the function' (@($harnessLog5 | Where-Object { $_.Message -like '*SC-STUB-STDOUT-MARKER*' }).Count -ge 1)
        Check '5c: well-behaved case finished well inside bound' ($swOk5.ElapsedMilliseconds -lt 60000) "took $($swOk5.ElapsedMilliseconds) ms"

        # Case 2: hung stub - floods stderr, writes stdout, sleeps forever
        # holding BOTH pipes open. The old code blocked forever here; the
        # fixed code must enforce its wait, kill the child, record Failed,
        # and return promptly.
        $entryHang5 = [pscustomobject]@{
            DisplayName          = 'ScreenConnect Client (pipe-hang)'
            QuietUninstallString = ('"' + $hangExe5 + '"')
            PSPath               = 'Microsoft.PowerShell.Core\Registry::HKEY_CURRENT_USER\Software\RIT-SCC-CI\pipe-hang-fake'
        }
        $swHang5 = [System.Diagnostics.Stopwatch]::StartNew()
        $hangResult5 = Run-VendorUninstaller -UninstallEntry $entryHang5 -InstanceId 'pipe-hang' -InstallDir $hangDir5
        $swHang5.Stop()

        Check '5c: hung uninstaller reported Failure' ($hangResult5 -eq $false) "result=$hangResult5"
        $hangFail5 = @($harnessManifest5 | Where-Object {
            $_.InstanceId -eq 'pipe-hang' -and
            $_.Action -eq 'Uninstall' -and
            $_.Result -eq 'Failed' -and
            $_.Details -match 'timed out' -and
            $_.Details -match 'killed'
        })
        Check '5c: hung uninstaller recorded clear Failed entry' ($hangFail5.Count -ge 1)
        Check '5c: hung child killed, call returned promptly' ($swHang5.ElapsedMilliseconds -lt 60000) "took $($swHang5.ElapsedMilliseconds) ms"

        Remove-Item -LiteralPath $okExe5, $hangExe5 -Force -ErrorAction SilentlyContinue
    } else {
        Check '5c: real function body exercised end-to-end' $false 'timeout literal missing from extracted function'
    }
} else {
    Check '5c: real function body exercised end-to-end' $false 'function, compiled stubs, or passed stub sanity run unavailable'
}

# Defensive: make sure no stub survived anywhere (they are our own builds,
# never vendor binaries).
Get-Process -Name 'unins000' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

# ---------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------
Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host ("Windows integration tests: {0} failure(s)." -f $failures)
if ($failures -gt 0) { exit 1 }
exit 0

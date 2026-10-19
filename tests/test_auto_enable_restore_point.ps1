# =====================================================================
# test_auto_enable_restore_point.ps1
#
# Regression for the pre-cleanup restore point (SystemRestore.psm1):
#   1. the OS system drive is resolved dynamically (never hardcoded C:)
#   2. Enable-ComputerRestore -ErrorAction Stop runs BEFORE
#      Checkpoint-Computer (System Restore is often off on client machines)
#   3. a restore point is only reported as created when a FRESH point is
#      read back - a non-throwing Checkpoint-Computer (e.g. Windows'
#      restore-point frequency throttle) must never be logged as created
#   4. enable/creation failures are reported truthfully and fail closed
#   5. both callers (guided preflight.ps1 and direct sc-cleanup.ps1) use the
#      shared helper and keep -np / -SkipRestore semantics
#
# All Windows cmdlets are replaced by in-process fakes; nothing here touches
# System Restore, the registry or the service configuration of the host.
# Pure ASCII, no BOM, PS 5.1 compatible.
# =====================================================================
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$modulePath = Join-Path $repoRoot 'SystemRestore.psm1'

$script:Failures = New-Object System.Collections.ArrayList
$script:Checks = 0

function Assert-True {
    param([bool]$Condition, [string]$Name)
    $script:Checks++
    if ($Condition) {
        Write-Host ("PASS: " + $Name)
    } else {
        [void]$script:Failures.Add($Name)
        Write-Host ("FAIL: " + $Name) -ForegroundColor Red
    }
}

function Assert-Equal {
    param($Expected, $Actual, [string]$Name)
    $script:Checks++
    if ("$Expected" -ceq "$Actual") {
        Write-Host ("PASS: " + $Name)
    } else {
        [void]$script:Failures.Add($Name + " (expected '" + $Expected + "', got '" + $Actual + "')")
        Write-Host ("FAIL: " + $Name + " (expected '" + $Expected + "', got '" + $Actual + "')") -ForegroundColor Red
    }
}

# ---------------------------------------------------------------------
# Windows cmdlet fakes. Global functions shadow the real cmdlets, so no
# test path can ever reach the live System Restore APIs (5.1 cmdlet lookup
# prefers a function over a cmdlet of the same name).
# ---------------------------------------------------------------------
$global:Fake = $null

function Reset-Fakes {
    param(
        [bool]$CreateOnCheckpoint = $true,
        [string]$EnableThrows = '',
        [string]$CheckpointThrows = '',
        [string]$CheckpointWarning = ''
    )
    $global:Fake = @{
        EnableCalls        = 0
        EnableDrive        = $null
        EnableParameters   = $null
        CheckpointCalls    = 0
        CheckpointParams   = $null
        Order              = (New-Object System.Collections.ArrayList)
        Points             = (New-Object System.Collections.ArrayList)
        NextSequence       = 100
        CreateOnCheckpoint = $CreateOnCheckpoint
        EnableThrows       = $EnableThrows
        CheckpointThrows   = $CheckpointThrows
        CheckpointWarning  = $CheckpointWarning
        ReadCalls          = 0
        ReadThrowsOnce     = $false
        ConcurrentPoint    = $null
    }
}

function global:Enable-ComputerRestore {
    [CmdletBinding()]
    param([string]$Drive)
    $global:Fake.EnableCalls++
    $global:Fake.EnableDrive = $Drive
    $global:Fake.EnableParameters = $PSBoundParameters
    [void]$global:Fake.Order.Add('Enable')
    if ($global:Fake.EnableThrows) { throw $global:Fake.EnableThrows }
}

function global:Checkpoint-Computer {
    [CmdletBinding()]
    param(
        [string]$Description,
        [string]$RestorePointType
    )
    $global:Fake.CheckpointCalls++
    $global:Fake.CheckpointParams = $PSBoundParameters
    [void]$global:Fake.Order.Add('Checkpoint')
    if ($global:Fake.CheckpointThrows) { throw $global:Fake.CheckpointThrows }
    if ($global:Fake.CheckpointWarning) { Write-Warning $global:Fake.CheckpointWarning }
    if ($global:Fake.CreateOnCheckpoint) {
        $global:Fake.NextSequence++
        [void]$global:Fake.Points.Add([pscustomobject]@{
            SequenceNumber = $global:Fake.NextSequence
            Description    = $Description
            CreationTime   = (Get-Date)
        })
    }
}

# The helper probes real host facts when they are not supplied (elevation and
# SKU are genuinely unavailable on a Linux dev host). Tests state the host
# facts explicitly, except the guard cases which override them.
function Invoke-TestRestorePoint {
    param(
        [string]$Description,
        [string]$Drive,
        [System.Nullable[bool]]$IsElevated,
        [System.Nullable[bool]]$IsServerSku,
        [System.Nullable[bool]]$PolicyDisableSR
    )
    if ($null -eq $IsElevated) { $IsElevated = $true }
    if ($null -eq $IsServerSku) { $IsServerSku = $false }
    if ($null -eq $PolicyDisableSR) { $PolicyDisableSR = $false }
    $arguments = @{
        Description     = $Description
        IsElevated      = $IsElevated
        IsServerSku     = $IsServerSku
        PolicyDisableSR = $PolicyDisableSR
    }
    if ($Drive) { $arguments['Drive'] = $Drive }
    return Invoke-SccRestorePoint @arguments
}

function global:Get-ComputerRestorePoint {
    [CmdletBinding()]
    param()
    $global:Fake.ReadCalls++
    if ($global:Fake.ReadThrowsOnce -and $global:Fake.ReadCalls -eq 1) {
        throw 'The RPC server is unavailable (synthetic snapshot failure).'
    }
    # A point written by something other than this run can appear between the
    # baseline snapshot and the readback.
    if ($global:Fake.ReadCalls -eq 2 -and $null -ne $global:Fake.ConcurrentPoint) {
        [void]$global:Fake.Points.Add($global:Fake.ConcurrentPoint)
    }
    return @($global:Fake.Points)
}

if (-not (Test-Path -LiteralPath $modulePath)) {
    Write-Host ("FAIL: shared restore-point helper is missing: " + $modulePath) -ForegroundColor Red
    Write-Host ''
    Write-Host ("0/{0} checks passed." -f 1) -ForegroundColor Red
    exit 1
}
Import-Module -Name $modulePath -Force

$originalSystemDrive = $env:SystemDrive
$originalSystemRoot = $env:SystemRoot
$originalOs = $env:OS
# The helper refuses to act on a non-Windows host, so the cmdlet-fake cases
# run with Windows semantics (unchanged on the Windows CI runners).
$env:OS = 'Windows_NT'

# ---------------------------------------------------------------------
# Case 1: the helper resolves the system drive dynamically, enables System
# Restore before checkpointing, and reports a verified fresh point.
# ---------------------------------------------------------------------
$env:SystemDrive = 'E:'
$env:SystemRoot = 'E:\Windows'
Reset-Fakes
$result = Invoke-TestRestorePoint -Description 'unit test point'

Assert-Equal 'E:\' $result.Drive 'module resolves the OS system drive instead of assuming C:'
Assert-Equal 'E:\' $global:Fake.EnableDrive 'Enable-ComputerRestore is called for the resolved system drive'
Assert-Equal 1 $global:Fake.EnableCalls 'Enable-ComputerRestore is called once'
Assert-True ($global:Fake.EnableParameters.ContainsKey('ErrorAction') -and "$($global:Fake.EnableParameters['ErrorAction'])" -eq 'Stop') 'Enable-ComputerRestore uses -ErrorAction Stop'
Assert-Equal 'Enable,Checkpoint' ($global:Fake.Order -join ',') 'System Restore is enabled before the checkpoint is attempted'
Assert-True ($result.Success -eq $true) 'a verified restore point reports success'
Assert-Equal 'Created' $result.Status 'a verified restore point reports Created'
Assert-Equal 'Created' $result.Summary 'a verified restore point summarizes as Created'
Assert-True ($result.SequenceNumber -eq 101) 'the new restore point sequence number is reported'

# ---------------------------------------------------------------------
# Case 2: a checkpoint that silently does nothing is NOT a created point.
# ---------------------------------------------------------------------
Reset-Fakes -CreateOnCheckpoint $false
$result = Invoke-TestRestorePoint -Description 'unit test point'
Assert-True ($result.Success -eq $false) 'a checkpoint with no fresh restore point is a failure'
Assert-True ($result.Summary -notmatch 'Created') 'an unverified checkpoint is never summarized as Created'
Assert-True ((($result.LogLines | ForEach-Object { $_.Text }) -join "`n") -notmatch 'Created') 'an unverified checkpoint never logs Created'

# ---------------------------------------------------------------------
# Case 3: a failing Enable-ComputerRestore blocks the checkpoint, so a
# disabled machine cannot report a restore point it never made.
# ---------------------------------------------------------------------
Reset-Fakes -EnableThrows 'Access is denied (synthetic enable failure).'
$result = Invoke-TestRestorePoint -Description 'unit test point'
Assert-Equal 'EnableFailed' $result.Status 'an enable failure is reported as EnableFailed'
Assert-True ($result.Success -eq $false) 'an enable failure is a failure'
Assert-Equal 0 $global:Fake.CheckpointCalls 'the checkpoint is never attempted when enabling fails'
Assert-True ($result.Summary -notmatch 'Created') 'an enable failure is never summarized as Created'
Assert-True ($result.Summary -match 'synthetic enable failure') 'the enable failure message reaches the log output'

# ---------------------------------------------------------------------
# Case 4: Windows throttles checkpoints (default 24h) and Checkpoint-Computer
# then returns WITHOUT throwing, emitting only a warning. That is a skipped
# checkpoint, never "Created".
# ---------------------------------------------------------------------
$existing = [pscustomobject]@{ SequenceNumber = 7; Description = 'Earlier point'; CreationTime = (Get-Date).AddHours(-2) }
Reset-Fakes -CreateOnCheckpoint $false -CheckpointWarning 'A new system restore point cannot be created because one has already been created within the past 24 hours.'
[void]$global:Fake.Points.Add($existing)
$result = Invoke-TestRestorePoint -Description 'unit test point'
Assert-Equal 'Throttled' $result.Status 'a throttled checkpoint is reported as Throttled'
Assert-True ($result.Success -eq $false) 'a throttled checkpoint is not a success'
Assert-True ($result.Summary -match '^SKIPPED') 'a throttled checkpoint summarizes as SKIPPED, not Created'
Assert-True ($result.Summary -notmatch '^Created') 'a throttled checkpoint never claims a restore point was created'
$logText = ($result.LogLines | ForEach-Object { $_.Text }) -join "`n"
Assert-True ($logText -notmatch 'restore point created') 'a throttled checkpoint never logs a created restore point'
Assert-True ($logText -match '24 hours') 'the throttling warning from Windows is preserved for the technician'
Assert-True ($logText -match 'sequence 7') 'the existing recent restore point is reported for the technician'
Assert-True ($result.SequenceNumber -eq $null) 'a throttled checkpoint reports no new sequence number'

# Some Windows builds surface the throttle on the error stream instead of the
# warning stream. It is still a skip, never a created point.
Reset-Fakes -CreateOnCheckpoint $false -CheckpointThrows 'A new system restore point cannot be created because one has already been created within the past 24 hours.'
[void]$global:Fake.Points.Add($existing)
$result = Invoke-TestRestorePoint -Description 'unit test point'
Assert-Equal 'Throttled' $result.Status 'a throttled checkpoint raised as an error is still Throttled'
Assert-True ($result.Success -eq $false) 'a throttled error is not a success'
Assert-True ($result.Summary -notmatch '^Created') 'a throttled error never claims a restore point was created'

# ---------------------------------------------------------------------
# Case 5: the cmdlets can be absent (older SKUs / partially serviced OS).
# Report that truthfully instead of a generic failure.
# ---------------------------------------------------------------------
Reset-Fakes
$global:Fake.EnableThrows = [System.Management.Automation.CommandNotFoundException]::new('Enable-ComputerRestore')
$result = Invoke-TestRestorePoint -Description 'unit test point'
Assert-Equal 'EnableUnavailable' $result.Status 'a missing Enable-ComputerRestore is reported as unavailable'
Assert-Equal 0 $global:Fake.CheckpointCalls 'no checkpoint is attempted when the enable cmdlet is unavailable'

Reset-Fakes
$global:Fake.CheckpointThrows = [System.Management.Automation.CommandNotFoundException]::new('Checkpoint-Computer')
$result = Invoke-TestRestorePoint -Description 'unit test point'
Assert-Equal 'CheckpointUnavailable' $result.Status 'a missing Checkpoint-Computer is reported as unavailable'
Assert-True ($result.Summary -notmatch 'Created') 'a missing checkpoint cmdlet never claims Created'

# ---------------------------------------------------------------------
# Case 6: the helper refuses to guess on a non-Windows host (it must not
# invoke any restore API there).
# ---------------------------------------------------------------------
$env:OS = 'Linux'
Reset-Fakes
$result = Invoke-TestRestorePoint -Description 'unit test point'
Assert-Equal 'UnsupportedOs' $result.Status 'a non-Windows host is reported as unsupported'
Assert-Equal 0 $global:Fake.EnableCalls 'no restore API call is made on a non-Windows host'
Assert-Equal 0 $global:Fake.CheckpointCalls 'no checkpoint is attempted on a non-Windows host'
$env:OS = 'Windows_NT'

# ---------------------------------------------------------------------
# Case 7: drive handling - explicit non-system drive and unreadable drive.
# ---------------------------------------------------------------------
Reset-Fakes
$result = Invoke-TestRestorePoint -Description 'unit test point' -Drive 'd:'
Assert-Equal 'D:\' $result.Drive 'an explicit drive is normalized to X:\'
Assert-Equal 'D:\' $global:Fake.EnableDrive 'System Restore is enabled on the requested drive'

$savedSystemDrive = $env:SystemDrive
$savedSystemRoot = $env:SystemRoot
$savedWindir = $env:windir
$savedProgramData = $env:ProgramData
$env:SystemDrive = ''
$env:SystemRoot = ''
$env:windir = ''
$env:ProgramData = ''
Reset-Fakes
$result = Invoke-TestRestorePoint -Description 'unit test point'
Assert-Equal 'DriveUnresolved' $result.Status 'an unresolvable system drive fails closed'
Assert-Equal 0 $global:Fake.EnableCalls 'no restore API call is made without a resolved system drive'
$env:SystemDrive = $savedSystemDrive
$env:SystemRoot = $savedSystemRoot
$env:windir = $savedWindir
$env:ProgramData = $savedProgramData

# ---------------------------------------------------------------------
# Case 8: guided preflight.ps1 delegates to the shared helper instead of
# calling Checkpoint-Computer itself, and fails closed when the point was
# not verified.
# ---------------------------------------------------------------------
$script:StageLines = New-Object System.Collections.ArrayList
$script:PreflightOk = $true
$script:PreflightRoot = $repoRoot

function Write-Stage {
    param([string]$Message)
    [void]$script:StageLines.Add([pscustomobject]@{ Text = $Message; Kind = 'Stage' })
}
function Write-StageWarn {
    param([string]$Message)
    [void]$script:StageLines.Add([pscustomobject]@{ Text = $Message; Kind = 'Warn' })
}
function Write-StageFail {
    param([string]$Message)
    [void]$script:StageLines.Add([pscustomobject]@{ Text = $Message; Kind = 'Fail' })
    $script:PreflightOk = $false
}

$preflightPath = Join-Path $repoRoot 'preflight.ps1'
$preflightText = [System.IO.File]::ReadAllText($preflightPath)
$preflightTokens = $null
$preflightParseErrors = $null
$preflightAst = [System.Management.Automation.Language.Parser]::ParseFile($preflightPath, [ref]$preflightTokens, [ref]$preflightParseErrors)
Assert-Equal 0 @($preflightParseErrors).Count 'preflight.ps1 parses cleanly'
$restoreFn = @($preflightAst.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Invoke-RestorePoint' }, $true))
Assert-Equal 1 $restoreFn.Count 'preflight.ps1 still defines Invoke-RestorePoint'
Assert-True ($preflightText -notmatch '(?m)^\s*Checkpoint-Computer\b') 'preflight.ps1 no longer calls Checkpoint-Computer directly'
Assert-True ($preflightText -match 'Invoke-SccRestorePoint') 'preflight.ps1 uses the shared restore-point helper'

if ($restoreFn.Count -eq 1) {
    $restoreBlock = [scriptblock]::Create($restoreFn[0].Extent.Text)
    # Dot-source the definition so Invoke-RestorePoint lands in this scope and
    # resolves the Write-Stage* mocks below.
    . $restoreBlock

    Reset-Fakes -CreateOnCheckpoint $false -CheckpointWarning 'A new system restore point cannot be created because one has already been created within the past 24 hours.'
    [void]$global:Fake.Points.Add([pscustomobject]@{ SequenceNumber = 41; Description = 'Earlier point'; CreationTime = (Get-Date).AddHours(-3) })
    $script:StageLines.Clear()
    $script:PreflightOk = $true
    $preflightResult = Invoke-RestorePoint
    $preflightLog = (($script:StageLines | ForEach-Object { $_.Text }) -join "`n")
    Assert-True ($preflightResult -eq $false) 'preflight refuses to continue when the restore point was throttled'
    Assert-True ($preflightLog -notmatch 'restore point created OK') 'preflight never reports a created point for a throttled checkpoint'
    Assert-True ($preflightLog -match '(?i)throttl') 'preflight reports the throttle to the technician'
    Assert-True ($preflightLog -match 'sequence 41') 'preflight reports the existing restore point it found'
    Assert-True (@($script:StageLines | Where-Object { $_.Kind -eq 'Fail' }).Count -ge 1) 'a throttled checkpoint is a preflight failure'

    Reset-Fakes
    $script:StageLines.Clear()
    $script:PreflightOk = $true
    $preflightResult = Invoke-RestorePoint
    $preflightLog = (($script:StageLines | ForEach-Object { $_.Text }) -join "`n")
    Assert-True ($preflightResult -eq $true) 'preflight continues after a verified restore point'
    Assert-True ($preflightLog -match 'created and verified') 'preflight reports the verified restore point'

    Reset-Fakes -EnableThrows 'Access is denied (synthetic enable failure).'
    $script:StageLines.Clear()
    $script:PreflightOk = $true
    $preflightResult = Invoke-RestorePoint
    Assert-True ($preflightResult -eq $false) 'preflight fails closed when System Restore cannot be enabled'
    Assert-Equal 0 $global:Fake.CheckpointCalls 'preflight does not checkpoint after a failed enable'
}

# ---------------------------------------------------------------------
# Case 9: the direct runner (sc-cleanup.ps1 Stage 0) uses the same helper,
# records the truthful outcome in master.log, and keeps the fail-closed
# RestorePointFailed gate and -np semantics.
# ---------------------------------------------------------------------
$cleanupPath = Join-Path $repoRoot 'sc-cleanup.ps1'
$cleanupText = [System.IO.File]::ReadAllText($cleanupPath)
$cleanupTokens = $null
$cleanupParseErrors = $null
$cleanupAst = [System.Management.Automation.Language.Parser]::ParseFile($cleanupPath, [ref]$cleanupTokens, [ref]$cleanupParseErrors)
Assert-Equal 0 @($cleanupParseErrors).Count 'sc-cleanup.ps1 parses cleanly'
Assert-True ($cleanupText -notmatch '(?m)^\s*Checkpoint-Computer\b') 'sc-cleanup.ps1 no longer calls Checkpoint-Computer directly'
Assert-True ($cleanupText -match 'Invoke-SccRestorePoint') 'sc-cleanup.ps1 uses the shared restore-point helper'
Assert-True ($cleanupText -match '(?s)RestorePointFailed') 'the fail-closed RestorePointFailed gate is preserved'

$stage0Assign = $cleanupAst.Find({ param($node) $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and $node.Left.Extent.Text -eq '$stage0Result' }, $true)
Assert-True ($null -ne $stage0Assign) 'sc-cleanup.ps1 Stage 0 assignment is present'

if ($null -ne $stage0Assign) {
    $stage0BlockAst = $stage0Assign.Right.Find({ param($node) $node -is [System.Management.Automation.Language.ScriptBlockExpressionAst] }, $true)
    Assert-True ($null -ne $stage0BlockAst) 'sc-cleanup.ps1 Stage 0 block is present'
    $stage0Block = [scriptblock]::Create($stage0BlockAst.ScriptBlock.EndBlock.Extent.Text)

    $script:StageLog = New-Object System.Collections.ArrayList
    function Write-StageLog {
        param([string]$Message, [string]$Level = 'Info')
        [void]$script:StageLog.Add([pscustomobject]@{ Text = $Message; Level = $Level })
    }
    function Write-Dbg { param([string]$Message) }
    function Write-Section { param([string]$Title) }
    function Invoke-ChildScript { param($ScriptPath, $ArgumentList, $LogTag) return 0 }
    # reg.exe is stubbed: the fixture must never touch the real registry.
    function reg.exe {
        param([Parameter(ValueFromRemainingArguments = $true)]$Args)
        $global:LASTEXITCODE = 0
        return $null
    }

    function Invoke-Stage0Fixture {
        param([bool]$NoRestorePoint = $false)
        $work = Join-Path ([System.IO.Path]::GetTempPath()) ('scc-stage0-' + [guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $work -Force
        $ScriptRoot = $repoRoot
        $WorkDir = $work
        $ToolDir = Join-Path $work 'tools'
        $IncidentDate = '2026-01-01'
        $isServer = $false
        $isAdmin = $true
        $offline = $false
        $MasterLogPath = Join-Path $work 'master.log'
        $VerboseLog = $false
        $np = $NoRestorePoint
        $script:RestorePointFailed = $false
        $script:RegistryExportFailed = $false
        $script:StageLog.Clear()
        $stageResult = & $stage0Block
        $masterLog = ''
        if (Test-Path -LiteralPath $MasterLogPath) { $masterLog = [System.IO.File]::ReadAllText($MasterLogPath) }
        return [pscustomobject]@{
            Result      = $stageResult
            MasterLog   = $masterLog
            ConsoleLog  = (($script:StageLog | ForEach-Object { $_.Text }) -join "`n")
            Failed      = $script:RestorePointFailed
        }
    }

    Reset-Fakes
    $fixture = Invoke-Stage0Fixture
    Assert-Equal 'False' $fixture.Failed 'sc-cleanup records a verified restore point as success'
    Assert-True ($fixture.MasterLog -match 'Restore point: Created') 'sc-cleanup master.log records Restore point: Created after verification'
    Assert-True ($fixture.ConsoleLog -match 'created and verified') 'sc-cleanup log reports the verified restore point'

    Reset-Fakes -CreateOnCheckpoint $false -CheckpointWarning 'A new system restore point cannot be created because one has already been created within the past 24 hours.'
    [void]$global:Fake.Points.Add([pscustomobject]@{ SequenceNumber = 12; Description = 'Earlier point'; CreationTime = (Get-Date).AddHours(-1) })
    $fixture = Invoke-Stage0Fixture
    Assert-Equal 'True' $fixture.Failed 'a throttled checkpoint fails the Stage 4 restore-point gate closed'
    Assert-True ($fixture.MasterLog -notmatch 'Restore point: Created') 'sc-cleanup never records Restore point: Created for a throttled checkpoint'
    Assert-True ($fixture.MasterLog -match 'Restore point: SKIPPED \(throttled\)') 'sc-cleanup records the throttle truthfully in master.log'

    Reset-Fakes -EnableThrows 'Access is denied (synthetic enable failure).'
    $fixture = Invoke-Stage0Fixture
    Assert-Equal 'True' $fixture.Failed 'an enable failure fails the Stage 4 restore-point gate closed'
    Assert-Equal 0 $global:Fake.CheckpointCalls 'sc-cleanup does not checkpoint when System Restore cannot be enabled'
    Assert-True ($fixture.MasterLog -notmatch 'Restore point: Created') 'an enable failure never records Restore point: Created'

    Reset-Fakes
    $fixture = Invoke-Stage0Fixture -NoRestorePoint $true
    Assert-Equal 'False' $fixture.Failed '-np still waives the restore point'
    Assert-Equal 0 $global:Fake.EnableCalls '-np skips System Restore enablement entirely'
    Assert-Equal 0 $global:Fake.CheckpointCalls '-np skips the checkpoint entirely'
    Assert-True ($fixture.MasterLog -match 'Restore point: SKIPPED \(-np\)') '-np is recorded truthfully in master.log'
}

# ---------------------------------------------------------------------
# Case 10: an unreadable baseline snapshot must fail closed. It is NOT an
# empty list: treating it as empty would let a pre-existing point that shows
# up on readback be reported as freshly created by this run.
# ---------------------------------------------------------------------
$env:SystemDrive = 'C:'
$env:SystemRoot = 'C:\Windows'
Reset-Fakes
$global:Fake.ReadThrowsOnce = $true
[void]$global:Fake.Points.Add([pscustomobject]@{ SequenceNumber = 5; Description = 'Old point'; CreationTime = (Get-Date).AddDays(-9) })
$result = Invoke-TestRestorePoint -Description 'unit test point'
Assert-Equal 'SnapshotUnreadable' $result.Status 'an unreadable baseline snapshot fails closed'
Assert-True ($result.Success -eq $false) 'an unreadable baseline is never a success'
Assert-True ($result.Summary -notmatch 'Created') 'an unreadable baseline never claims Created'
Assert-Equal 0 $global:Fake.EnableCalls 'no restore API call is made without a readable baseline'
Assert-Equal 0 $global:Fake.CheckpointCalls 'no checkpoint is attempted without a readable baseline'

# A readable snapshot with ZERO points is different: that is a supported
# machine with System Restore simply never used, and it must still work.
Reset-Fakes
$result = Invoke-TestRestorePoint -Description 'unit test point'
Assert-Equal 'Created' $result.Status 'a readable empty baseline still creates a point'
Assert-Equal 2 $global:Fake.ReadCalls 'the baseline does not abort a readable empty snapshot'

# ---------------------------------------------------------------------
# Case 11: a point that appears between snapshot and readback but was not
# created by this checkpoint must not be attributed to this run.
# ---------------------------------------------------------------------
Reset-Fakes -CreateOnCheckpoint $false
$global:Fake.ConcurrentPoint = [pscustomobject]@{ SequenceNumber = 900; Description = 'Windows Update'; CreationTime = (Get-Date) }
$result = Invoke-TestRestorePoint -Description 'unit test point'
Assert-Equal 'Unverified' $result.Status 'an unrelated concurrent point is not reported as created'
Assert-True ($result.Success -eq $false) 'an unrelated concurrent point is not a success'
Assert-True ($result.Summary -cnotmatch '^Created') 'an unrelated concurrent point never yields Created'
Assert-True ($result.SequenceNumber -eq $null) 'an unrelated concurrent point is not reported as our sequence'

# ---------------------------------------------------------------------
# Case 12: host guards run BEFORE any restore API call.
# ---------------------------------------------------------------------
Reset-Fakes
$result = Invoke-TestRestorePoint -Description 'unit test point' -IsServerSku $true
Assert-Equal 'UnsupportedServer' $result.Status 'Windows Server is reported as unsupported'
Assert-Equal 0 $global:Fake.EnableCalls 'System Restore is not enabled on an unsupported server SKU'
Assert-Equal 0 $global:Fake.CheckpointCalls 'no checkpoint is attempted on an unsupported server SKU'

Reset-Fakes
$result = Invoke-TestRestorePoint -Description 'unit test point' -IsElevated $false
Assert-Equal 'NotElevated' $result.Status 'an unelevated run is refused explicitly'
Assert-Equal 0 $global:Fake.EnableCalls 'System Restore is not enabled without elevation'
Assert-Equal 0 $global:Fake.CheckpointCalls 'no checkpoint is attempted without elevation'

Reset-Fakes
$result = Invoke-TestRestorePoint -Description 'unit test point' -PolicyDisableSR $true
Assert-Equal 'PolicyBlocked' $result.Status 'a System Restore policy block is respected'
Assert-Equal 0 $global:Fake.EnableCalls 'the helper never overrides a System Restore policy'
Assert-Equal 0 $global:Fake.CheckpointCalls 'no checkpoint is attempted when policy disables System Restore'

$env:SystemDrive = $originalSystemDrive
$env:SystemRoot = $originalSystemRoot
$env:OS = $originalOs

Write-Host ''
if ($script:Failures.Count -gt 0) {
    Write-Host ("{0}/{1} checks passed - {2} FAILED" -f ($script:Checks - $script:Failures.Count), $script:Checks, $script:Failures.Count) -ForegroundColor Red
    foreach ($failure in $script:Failures) { Write-Host ("  - " + $failure) -ForegroundColor Red }
    exit 1
}
Write-Host ("All {0} checks passed." -f $script:Checks) -ForegroundColor Green
exit 0

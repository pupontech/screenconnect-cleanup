# =====================================================================
# SystemRestore.psm1 -- shared pre-change System Restore helper
#
# Used by preflight.ps1 (guided stage 0) and sc-cleanup.ps1 (direct stage 0)
# so both entry points behave identically:
#
#   . resolve the OS system drive dynamically (never hardcoded C:)
#   . Enable-ComputerRestore -Drive <system> -ErrorAction Stop  (idempotent)
#   . Checkpoint-Computer -RestorePointType MODIFY_SETTINGS -ErrorAction Stop
#   . read the restore-point list back and require a FRESH point
#
# A non-throwing Checkpoint-Computer is not proof of anything: Windows
# silently skips a checkpoint created within the restore-point frequency
# window and only emits a warning, so the caller must never log "created"
# without a new sequence number. Absence of restore points is likewise not
# proof that System Restore is off, so enablement is ensured unconditionally
# (the cmdlet is idempotent on an already-enabled volume).
#
# Deliberately NOT done here: Group Policy changes, quota / retention
# changes (DiskPercent, MaxSize), service settings, or disabling the
# checkpoint frequency throttle. Those are machine-policy changes the
# operator never asked for.
#
# Pure ASCII, no BOM, PS 5.1 compatible.
# =====================================================================
Set-StrictMode -Version 2.0

function Get-SccSystemRestoreDrive {
    <#
    .SYNOPSIS
      Resolve the OS system drive as 'X:\' without assuming C:.
    .DESCRIPTION
      Uses the Windows-provided environment (SystemDrive, SystemRoot,
      windir, ProgramData) and accepts an explicit override. Returns $null
      when no drive letter can be resolved, so the caller can fail closed
      instead of guessing.
    #>
    [CmdletBinding()]
    param([string]$Drive)

    $candidate = $null
    if ($Drive) {
        $candidate = $Drive
    } else {
        foreach ($value in @($env:SystemDrive, $env:SystemRoot, $env:windir)) {
            if ($value) { $candidate = $value; break }
        }
        if (-not $candidate) {
            # Last trustworthy source: the OS itself. Never guess from a data
            # path such as ProgramData, which can point at another volume.
            try {
                $os = Get-CimInstance -ClassName 'Win32_OperatingSystem' -ErrorAction Stop
                if ($os.SystemDrive) { $candidate = [string]$os.SystemDrive }
            } catch { }
        }
    }
    if ([string]::IsNullOrWhiteSpace($candidate)) { return $null }

    $trimmed = $candidate.Trim()
    if ($trimmed -match '^([A-Za-z]):') {
        return ($matches[1].ToUpperInvariant() + ':\')
    }
    return $null
}

function Get-SccRestorePointSnapshot {
    # Snapshot of the restore-point list.
    #
    # Readable=$false means the list could not be read. That is NOT the same as
    # "this machine has no restore points": an enabled machine that never made
    # one also returns nothing. Callers must fail closed on unreadable, because
    # treating it as empty would let a pre-existing point that shows up on
    # readback be reported as freshly created by this run.
    [CmdletBinding()]
    param()

    $unreadable = [pscustomobject]@{
        Readable = $false
        Points   = [object[]]@()
    }

    if (-not (Get-Command -Name 'Get-ComputerRestorePoint' -ErrorAction SilentlyContinue)) {
        return $unreadable
    }
    try {
        $points = @(Get-ComputerRestorePoint -ErrorAction Stop)
    } catch {
        return $unreadable
    }

    $snapshot = New-Object System.Collections.ArrayList
    foreach ($point in $points) {
        $sequence = $null
        try { $sequence = [int]$point.SequenceNumber } catch { $sequence = $null }
        $created = $null
        try {
            if ($point.CreationTime -is [datetime]) {
                $created = $point.CreationTime
            } elseif ($point.CreationTime) {
                try {
                    $created = [System.Management.ManagementDateTimeConverter]::ToDateTime([string]$point.CreationTime)
                } catch {
                    $created = [datetime]::Parse([string]$point.CreationTime)
                }
            }
        } catch { $created = $null }
        $description = ''
        try { if ($point.Description) { $description = [string]$point.Description } } catch { $description = '' }
        [void]$snapshot.Add([pscustomobject]@{
            SequenceNumber = $sequence
            CreationTime   = $created
            Description    = $description
        })
    }

    # [object[]] keeps a zero-point list a real empty array instead of letting
    # the pipeline unroll it to $null (the empty-vs-unreadable defect).
    return [pscustomobject]@{
        Readable = $true
        Points   = [object[]]$snapshot.ToArray()
    }
}

function New-SccRestorePointLogLine {
    param(
        [System.Collections.ArrayList]$Lines,
        [string]$Text,
        [string]$Level = 'Info'
    )
    [void]$Lines.Add([pscustomobject]@{ Text = $Text; Level = $Level })
}

function New-SccRestorePointResult {
    param(
        [bool]$Success = $false,
        [string]$Status = 'Failed',
        [string]$Drive = $null,
        [bool]$EnableAttempted = $false,
        [string]$StateBefore = 'Unknown',
        [int]$PreviousPointCount = 0,
        [System.Collections.ArrayList]$Lines = $null,
        [string]$Message = '',
        [int]$SequenceNumber = 0,
        [int]$ExistingSequenceNumber = 0,
        [datetime]$ExistingCreationTime = [datetime]::MinValue
    )
    $logLines = @()
    if ($null -ne $Lines) { $logLines = $Lines.ToArray() }
    return [pscustomobject]@{
        Success                = $Success
        Status                 = $Status
        Drive                  = $Drive
        EnableAttempted        = $EnableAttempted
        StateBefore            = $StateBefore
        PreviousPointCount     = $PreviousPointCount
        SequenceNumber         = $(if ($SequenceNumber -gt 0) { $SequenceNumber } else { $null })
        ExistingSequenceNumber = $(if ($ExistingSequenceNumber -gt 0) { $ExistingSequenceNumber } else { $null })
        ExistingCreationTime   = $(if ($ExistingCreationTime -ne [datetime]::MinValue) { $ExistingCreationTime } else { $null })
        Message                = $Message
        Summary                = $Message
        LogLines               = $logLines
    }
}

function Get-SccNewestRestorePoint {
    param($Snapshot)
    if ($null -eq $Snapshot -or -not $Snapshot.Readable) { return $null }
    if (@($Snapshot.Points).Count -eq 0) { return $null }
    $ordered = @($Snapshot.Points)
    $newest = $ordered | Where-Object { $null -ne $_.SequenceNumber } | Sort-Object SequenceNumber | Select-Object -Last 1
    return $newest
}

function Test-SccRestoreThrottleMessage {
    # Windows declines a checkpoint inside its restore-point frequency window
    # (default 24 h). Depending on build it arrives as a warning or as a
    # non-terminating error, so the text is classified instead of the stream.
    param([string]$Text)
    if (-not $Text) { return $false }
    return ($Text -match '(?i)already been created|cannot be created|restore point.*(?:frequency|interval)|within the past')
}

function New-SccThrottledRestorePointResult {
    # Shared "skipped by the frequency throttle" result: records the Windows
    # message and the newest existing point, and never claims a creation.
    param(
        [System.Collections.ArrayList]$Lines,
        [string]$ReasonText,
        [string]$Drive,
        [bool]$EnableAttempted,
        [string]$StateBefore,
        [int]$PreviousPointCount,
        $Snapshot
    )
    $newest = Get-SccNewestRestorePoint -Snapshot $Snapshot
    $newestText = ''
    $existingSequence = 0
    $existingTime = [datetime]::MinValue
    if ($null -ne $newest) {
        $existingSequence = [int]$newest.SequenceNumber
        $whenText = 'unknown time'
        if ($newest.CreationTime) {
            $existingTime = [datetime]$newest.CreationTime
            $whenText = $existingTime.ToString('yyyy-MM-dd HH:mm:ss')
        }
        $newestText = 'Newest existing restore point: sequence ' + $existingSequence + ' (' + $whenText + ').'
        New-SccRestorePointLogLine -Lines $Lines -Text $newestText
    }

    New-SccRestorePointLogLine -Lines $Lines -Text ('Windows declined a new restore point (frequency throttle): ' + $ReasonText) -Level 'Warn'
    $message = 'SKIPPED (throttled) - Windows declined a new restore point: ' + $ReasonText
    if ($newestText) { $message = $message + ' ' + $newestText }
    return New-SccRestorePointResult -Status 'Throttled' -Drive $Drive -EnableAttempted $EnableAttempted -StateBefore $StateBefore -PreviousPointCount $PreviousPointCount -Lines $Lines -Message $message -ExistingSequenceNumber $existingSequence -ExistingCreationTime $existingTime
}

function Test-SccRestorePointElevation {
    # Real administrator token check. Process "admin-ness" is not enough on a
    # UAC-filtered account, and Enable-ComputerRestore needs the elevated token.
    try {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

function Test-SccRestorePointServerSku {
    # Win32_OperatingSystem.ProductType: 1 = workstation, 2/3 = domain/standalone
    # server. System Restore (and its cmdlets) is not supported on Server SKUs,
    # so it is reported instead of attempted.
    try {
        $os = Get-CimInstance -ClassName 'Win32_OperatingSystem' -ErrorAction Stop
        return ([int]$os.ProductType -ne 1)
    } catch {
        return $false
    }
}

function Test-SccRestorePointPolicyBlock {
    # Reads only. A System Restore policy belongs to the operator; this helper
    # never writes or clears it.
    try {
        $key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore'
        $value = Get-ItemProperty -Path $key -Name 'DisableSR' -ErrorAction Stop
        return ([int]$value.DisableSR -eq 1)
    } catch {
        return $false
    }
}

function Invoke-SccRestorePoint {
    <#
    .SYNOPSIS
      Ensure System Restore is enabled, create a restore point, verify it.
    .DESCRIPTION
      Returns a result object; it never throws for an ordinary System Restore
      failure, because callers must record the failure and fail closed rather
      than abort the evidence chain.

      Host guards (unsupported OS/SKU, elevation, policy) and a readable
      baseline snapshot all run BEFORE any restore API call: a point can only
      be reported as created when a point carrying this run's description
      appears that was not present in the baseline.
    #>
    [CmdletBinding()]
    param(
        [string]$Description = 'ScreenConnect cleanup - pre-change restore point',
        [string]$RestorePointType = 'MODIFY_SETTINGS',
        [string]$Drive,
        # Host facts the caller already knows; probed when not supplied.
        [System.Nullable[bool]]$IsElevated,
        [System.Nullable[bool]]$IsServerSku,
        [System.Nullable[bool]]$PolicyDisableSR
    )

    $lines = New-Object System.Collections.ArrayList
    if ($env:OS -ne 'Windows_NT') {
        New-SccRestorePointLogLine -Lines $lines -Text 'System Restore is only available on Windows; no restore point was created.' -Level 'Error'
        return New-SccRestorePointResult -Status 'UnsupportedOs' -Lines $lines -Message 'FAILED - System Restore is only available on Windows'
    }

    $serverSku = $IsServerSku
    if ($null -eq $serverSku) { $serverSku = Test-SccRestorePointServerSku }
    if ($serverSku) {
        New-SccRestorePointLogLine -Lines $lines -Text 'System Restore is not supported on Windows Server; no restore point was created.' -Level 'Error'
        New-SccRestorePointLogLine -Lines $lines -Text 'Re-run with -np to waive the restore point at your own risk.' -Level 'Warn'
        return New-SccRestorePointResult -Status 'UnsupportedServer' -Lines $lines -Message 'FAILED - System Restore is not supported on Windows Server'
    }

    $elevated = $IsElevated
    if ($null -eq $elevated) { $elevated = Test-SccRestorePointElevation }
    if (-not $elevated) {
        New-SccRestorePointLogLine -Lines $lines -Text 'Creating a restore point requires an elevated (administrator) session; no restore point was created.' -Level 'Error'
        return New-SccRestorePointResult -Status 'NotElevated' -Lines $lines -Message 'FAILED - an elevated session is required to create a restore point'
    }

    $policyBlocked = $PolicyDisableSR
    if ($null -eq $policyBlocked) { $policyBlocked = Test-SccRestorePointPolicyBlock }
    if ($policyBlocked) {
        New-SccRestorePointLogLine -Lines $lines -Text 'System Restore is disabled by Group Policy (DisableSR). The tool will not override operator policy.' -Level 'Error'
        New-SccRestorePointLogLine -Lines $lines -Text 'Re-run with -np to waive the restore point, or have policy changed deliberately.' -Level 'Warn'
        return New-SccRestorePointResult -Status 'PolicyBlocked' -Lines $lines -Message 'FAILED - System Restore is disabled by policy'
    }

    $resolvedDrive = Get-SccSystemRestoreDrive -Drive $Drive
    if (-not $resolvedDrive) {
        New-SccRestorePointLogLine -Lines $lines -Text 'Could not resolve the OS system drive; no restore point was created.' -Level 'Error'
        return New-SccRestorePointResult -Status 'DriveUnresolved' -Lines $lines -Message 'FAILED - OS system drive could not be resolved'
    }

    # The baseline must be READABLE. An unreadable list is not "no points":
    # without it, a point that already existed could be counted as new.
    $snapshotBefore = Get-SccRestorePointSnapshot
    if (-not $snapshotBefore.Readable) {
        New-SccRestorePointLogLine -Lines $lines -Text 'Could not read the current restore-point list; refusing to create a point that cannot be verified.' -Level 'Error'
        return New-SccRestorePointResult -Status 'SnapshotUnreadable' -Drive $resolvedDrive -Lines $lines -Message 'FAILED - the existing restore-point list could not be read'
    }

    $previousCount = @($snapshotBefore.Points).Count
    $stateBefore = 'Unknown'
    if ($previousCount -gt 0) { $stateBefore = 'Enabled' }
    New-SccRestorePointLogLine -Lines $lines -Text (("Existing restore points on " + $resolvedDrive + ": " + $previousCount + " (an empty list does not prove System Restore is off)."))

    $enableAttempted = $false
    if (-not (Get-Command -Name 'Enable-ComputerRestore' -ErrorAction SilentlyContinue)) {
        New-SccRestorePointLogLine -Lines $lines -Text 'Enable-ComputerRestore is not available on this OS; System Restore cannot be enabled.' -Level 'Error'
        return New-SccRestorePointResult -Status 'EnableUnavailable' -Drive $resolvedDrive -StateBefore $stateBefore -PreviousPointCount $previousCount -Lines $lines -Message 'FAILED - Enable-ComputerRestore is not available'
    }

    New-SccRestorePointLogLine -Lines $lines -Text (("Ensuring System Restore is enabled on " + $resolvedDrive + " (idempotent)."))
    $enableAttempted = $true
    try {
        Enable-ComputerRestore -Drive $resolvedDrive -ErrorAction Stop
    } catch [System.Management.Automation.CommandNotFoundException] {
        New-SccRestorePointLogLine -Lines $lines -Text 'Enable-ComputerRestore is not available on this OS; System Restore cannot be enabled.' -Level 'Error'
        return New-SccRestorePointResult -Status 'EnableUnavailable' -Drive $resolvedDrive -EnableAttempted $enableAttempted -StateBefore $stateBefore -PreviousPointCount $previousCount -Lines $lines -Message 'FAILED - Enable-ComputerRestore is not available'
    } catch {
        New-SccRestorePointLogLine -Lines $lines -Text (("Could not enable System Restore on " + $resolvedDrive + ": " + $_.Exception.Message)) -Level 'Error'
        return New-SccRestorePointResult -Status 'EnableFailed' -Drive $resolvedDrive -EnableAttempted $enableAttempted -StateBefore $stateBefore -PreviousPointCount $previousCount -Lines $lines -Message ('FAILED - System Restore could not be enabled: ' + $_.Exception.Message)
    }
    # Enable-ComputerRestore returns before monitoring is fully up, so this is
    # not treated as proof of state - the readback below is.
    New-SccRestorePointLogLine -Lines $lines -Text (("System Restore enable was requested on " + $resolvedDrive + "."))

    if (-not (Get-Command -Name 'Checkpoint-Computer' -ErrorAction SilentlyContinue)) {
        New-SccRestorePointLogLine -Lines $lines -Text 'Checkpoint-Computer is not available on this OS; no restore point was created.' -Level 'Error'
        return New-SccRestorePointResult -Status 'CheckpointUnavailable' -Drive $resolvedDrive -EnableAttempted $enableAttempted -StateBefore $stateBefore -PreviousPointCount $previousCount -Lines $lines -Message 'FAILED - Checkpoint-Computer is not available'
    }

    New-SccRestorePointLogLine -Lines $lines -Text (("Creating System Restore point (type " + $RestorePointType + ")."))
    $warnings = @()
    try {
        Checkpoint-Computer -Description $Description -RestorePointType $RestorePointType -ErrorAction Stop -WarningAction Continue -WarningVariable warnings
    } catch [System.Management.Automation.CommandNotFoundException] {
        New-SccRestorePointLogLine -Lines $lines -Text 'Checkpoint-Computer is not available on this OS; no restore point was created.' -Level 'Error'
        return New-SccRestorePointResult -Status 'CheckpointUnavailable' -Drive $resolvedDrive -EnableAttempted $enableAttempted -StateBefore $stateBefore -PreviousPointCount $previousCount -Lines $lines -Message 'FAILED - Checkpoint-Computer is not available'
    } catch {
        $failureText = $_.Exception.Message
        if (Test-SccRestoreThrottleMessage -Text $failureText) {
            return New-SccThrottledRestorePointResult -Lines $lines -ReasonText $failureText -Drive $resolvedDrive -EnableAttempted $enableAttempted -StateBefore $stateBefore -PreviousPointCount $previousCount -Snapshot (Get-SccRestorePointSnapshot)
        }
        New-SccRestorePointLogLine -Lines $lines -Text (("Restore point creation failed: " + $failureText)) -Level 'Error'
        return New-SccRestorePointResult -Status 'CreateFailed' -Drive $resolvedDrive -EnableAttempted $enableAttempted -StateBefore $stateBefore -PreviousPointCount $previousCount -Lines $lines -Message ('FAILED - restore point creation failed: ' + $failureText)
    }

    $snapshotAfter = Get-SccRestorePointSnapshot
    if (-not $snapshotAfter.Readable) {
        New-SccRestorePointLogLine -Lines $lines -Text 'Could not read the restore-point list back; the new point cannot be verified.' -Level 'Error'
        return New-SccRestorePointResult -Status 'Unverified' -Drive $resolvedDrive -EnableAttempted $enableAttempted -StateBefore $stateBefore -PreviousPointCount $previousCount -Lines $lines -Message 'FAILED - the restore-point list could not be read back'
    }

    $knownSequences = @($snapshotBefore.Points | Where-Object { $null -ne $_.SequenceNumber } | ForEach-Object { $_.SequenceNumber })
    $candidates = @($snapshotAfter.Points | Where-Object { $null -ne $_.SequenceNumber -and ($knownSequences -notcontains $_.SequenceNumber) })
    $expectedDescription = ([string]$Description).Trim()
    $attributable = @($candidates | Where-Object { ([string]$_.Description).Trim() -eq $expectedDescription })

    if ($attributable.Count -gt 0) {
        $newest = $attributable | Sort-Object SequenceNumber | Select-Object -Last 1
        New-SccRestorePointLogLine -Lines $lines -Text (("System Restore point created and verified (sequence " + $newest.SequenceNumber + ")."))
        return New-SccRestorePointResult -Success $true -Status 'Created' -Drive $resolvedDrive -EnableAttempted $enableAttempted -StateBefore $stateBefore -PreviousPointCount $previousCount -Lines $lines -Message 'Created' -SequenceNumber $newest.SequenceNumber
    }

    if ($candidates.Count -gt 0) {
        $other = $candidates | Sort-Object SequenceNumber | Select-Object -Last 1
        New-SccRestorePointLogLine -Lines $lines -Text (("A restore point appeared after this checkpoint but it was not created by this run (sequence " + $other.SequenceNumber + ", description '" + $other.Description + "').")) -Level 'Error'
        return New-SccRestorePointResult -Status 'Unverified' -Drive $resolvedDrive -EnableAttempted $enableAttempted -StateBefore $stateBefore -PreviousPointCount $previousCount -Lines $lines -Message 'FAILED - a restore point appeared but was not created by this run'
    }

    $warningText = (@($warnings) | ForEach-Object { [string]$_ }) -join ' '
    $newest = Get-SccNewestRestorePoint -Snapshot $snapshotAfter
    $newestText = ''
    $existingSequence = 0
    $existingTime = [datetime]::MinValue
    if ($null -ne $newest) {
        $existingSequence = [int]$newest.SequenceNumber
        $whenText = 'unknown time'
        if ($newest.CreationTime) {
            $existingTime = [datetime]$newest.CreationTime
            $whenText = $existingTime.ToString('yyyy-MM-dd HH:mm:ss')
        }
        $newestText = 'Newest existing restore point: sequence ' + $existingSequence + ' (' + $whenText + ').'
        New-SccRestorePointLogLine -Lines $lines -Text $newestText
    }

    if ($warningText -match '(?i)already been created|cannot be created|restore point.*(?:frequency|interval)|within the past') {
        New-SccRestorePointLogLine -Lines $lines -Text (('Windows declined a new restore point (frequency throttle): ' + $warningText)) -Level 'Warn'
        $throttleMessage = 'SKIPPED (throttled) - Windows declined a new restore point: ' + $warningText
        if ($newestText) { $throttleMessage = $throttleMessage + ' ' + $newestText }
        return New-SccRestorePointResult -Status 'Throttled' -Drive $resolvedDrive -EnableAttempted $enableAttempted -StateBefore $stateBefore -PreviousPointCount $previousCount -Lines $lines -Message $throttleMessage -ExistingSequenceNumber $existingSequence -ExistingCreationTime $existingTime
    }

    New-SccRestorePointLogLine -Lines $lines -Text 'Checkpoint-Computer returned without error but no new restore point is present.' -Level 'Error'
    return New-SccRestorePointResult -Status 'Unverified' -Drive $resolvedDrive -EnableAttempted $enableAttempted -StateBefore $stateBefore -PreviousPointCount $previousCount -Lines $lines -Message ('FAILED - no new restore point was recorded' + $(if ($warningText) { ': ' + $warningText } else { '' }))
}

Export-ModuleMember -Function Get-SccSystemRestoreDrive, Invoke-SccRestorePoint

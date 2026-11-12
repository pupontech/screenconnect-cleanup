Set-StrictMode -Version 2.0

function Get-PowerOptionsRepairPlan {
    [CmdletBinding()]
    param(
        [string[]]$LoadedUserSids = @(),
        [string]$CurrentUserSid,
        [string]$WindowsDirectory = $env:SystemRoot,
        [switch]$ResetLocalGpo
    )

    $explorerValues = @('NoClose', 'NoLogoff', 'HidePowerOptions', 'NoShutdown', 'NoLock')
    $profileSids = New-Object System.Collections.ArrayList
    foreach ($sid in @($LoadedUserSids) + @($CurrentUserSid)) {
        if ([string]::IsNullOrWhiteSpace([string]$sid)) { continue }
        $candidate = ([string]$sid).Trim()
        if ($candidate -notmatch '^S-1-(?:5-21-\d+-\d+-\d+-\d+|12-1-\d+-\d+-\d+-\d+)$') { continue }
        if (-not $profileSids.Contains($candidate)) { [void]$profileSids.Add($candidate) }
    }

    if ([string]::IsNullOrWhiteSpace($WindowsDirectory)) { $WindowsDirectory = 'C:\Windows' }
    $windowsRoot = $WindowsDirectory.TrimEnd('\\')
    $targets = New-Object System.Collections.ArrayList
    [void]$targets.Add([pscustomobject]@{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
        RemoveValues = $explorerValues
        SetValues = @{}
        ExistingValuesOnly = $false
    })
    [void]$targets.Add([pscustomobject]@{
        Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
        RemoveValues = $explorerValues
        SetValues = @{}
        ExistingValuesOnly = $false
    })
    [void]$targets.Add([pscustomobject]@{
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        RemoveValues = @('DisableLockWorkstation')
        SetValues = @{ ShutdownWithoutLogon = 1 }
        ExistingValuesOnly = $false
    })
    [void]$targets.Add([pscustomobject]@{
        Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
        RemoveValues = @('DisableLockWorkstation')
        SetValues = @{}
        ExistingValuesOnly = $false
    })

    foreach ($sid in $profileSids) {
        $userRoot = 'Registry::HKEY_USERS\' + $sid
        [void]$targets.Add([pscustomobject]@{
            Path = $userRoot + '\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            RemoveValues = $explorerValues
            SetValues = @{}
            ExistingValuesOnly = $false
        })
        [void]$targets.Add([pscustomobject]@{
            Path = $userRoot + '\Software\Microsoft\Windows\CurrentVersion\Policies\System'
            RemoveValues = @('DisableLockWorkstation')
            SetValues = @{}
            ExistingValuesOnly = $false
        })
    }

    [void]$targets.Add([pscustomobject]@{
        Path = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Start'
        RemoveValues = @()
        SetValues = @{}
        ExistingValuesOnly = $true
        ResetValues = @('HideShutDown', 'HideRestart', 'HideSleep', 'HideHibernate', 'HideLock', 'HidePowerButton')
    })
    [void]$targets.Add([pscustomobject]@{
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Power'
        RemoveValues = @()
        SetValues = @{}
        ExistingValuesOnly = $false
        DeleteKey = $true
    })

    return [pscustomobject]@{
        RegistryTargets = @($targets.ToArray())
        ExplorerValuesToRemove = $explorerValues
        PolicyManagerValues = @('HideShutDown', 'HideRestart', 'HideSleep', 'HideHibernate', 'HideLock', 'HidePowerButton')
        PowerPolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Power'
        ShutdownWithoutLogonValue = 1
        RestorePowerSchemes = $true
        EnableHibernate = $true
        ButtonActionValues = @{
            AC = @{ PBUTTONACTION = 1; SBUTTONACTION = 1; LIDACTION = 1 }
            DC = @{ PBUTTONACTION = 1; SBUTTONACTION = 1; LIDACTION = 1 }
        }
        ShutdownRightName = 'SeShutdownPrivilege'
        ShutdownRightGroupSids = @('S-1-5-32-544', 'S-1-5-32-551', 'S-1-5-32-545')
        LocalGpoPaths = @(
            [System.IO.Path]::Combine($windowsRoot, 'System32', 'GroupPolicy'),
            [System.IO.Path]::Combine($windowsRoot, 'System32', 'GroupPolicyUsers')
        )
        ResetLocalGpo = [bool]$ResetLocalGpo
        Refresh = @('gpupdate', 'restart-explorer')
    }
}

function Add-PowerRepairActionResult {
    param(
        [System.Collections.ArrayList]$Results,
        [string]$Action,
        [string]$Status,
        [string]$Detail = ''
    )
    [void]$Results.Add([pscustomobject]@{ Action = $Action; Status = $Status; Detail = $Detail })
}

function Invoke-PowerRepairAdapter {
    param(
        [System.Collections.IDictionary]$Adapter,
        [string]$Name,
        [object[]]$Arguments = @()
    )
    if (-not $Adapter.Contains($Name) -or $Adapter[$Name] -isnot [scriptblock]) {
        throw ('Missing repair adapter: ' + $Name)
    }
    $operation = $Adapter[$Name]
    $outputs = @(& $operation @Arguments)
    if (@($outputs).Count -eq 0) { return $null }
    return $outputs[@($outputs).Count - 1]
}

function Invoke-PowerOptionsRepairPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Plan,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Adapter,
        [Parameter(Mandatory = $true)][string]$BackupRoot
    )

    $results = New-Object System.Collections.ArrayList
    $hadFailure = $false
    $requiredAdapters = @(
        'TestRegistryKey', 'BackupRegistryKey', 'GetRegistryValue', 'RemoveRegistryValue', 'RemoveRegistryTree', 'SetRegistryDword',
        'BackupPowerSchemes', 'RestoreDefaultPowerSchemes', 'EnableHibernate', 'SetDefaultButtonActions',
        'BackupShutdownRights', 'GrantShutdownRight', 'BackupLocalGpo', 'ResetLocalGpo', 'RunGpUpdate', 'RestartExplorer'
    )
    foreach ($adapterName in $requiredAdapters) {
        if (-not $Adapter.Contains($adapterName) -or $Adapter[$adapterName] -isnot [scriptblock]) {
            throw ('Missing repair adapter: ' + $adapterName)
        }
    }

    foreach ($target in @($Plan.RegistryTargets)) {
        $path = [string]$target.Path
        $isPresent = $false
        try {
            $isPresent = [bool](Invoke-PowerRepairAdapter -Adapter $Adapter -Name 'TestRegistryKey' -Arguments @($path))
        } catch {
            Add-PowerRepairActionResult -Results $results -Action ('Registry:' + $path) -Status 'Failed' -Detail $_.Exception.Message
            $hadFailure = $true
            continue
        }

        $deleteTree = $false
        $deleteTreeProperty = $target.PSObject.Properties['DeleteKey']
        if ($deleteTreeProperty) { $deleteTree = [bool]$deleteTreeProperty.Value }
        $hasWrites = $deleteTree -or (@($target.RemoveValues).Count -gt 0) -or (@($target.SetValues.Keys).Count -gt 0) -or (@($target.ResetValues).Count -gt 0)
        if (-not $isPresent -and (@($target.SetValues.Keys).Count -eq 0)) {
            Add-PowerRepairActionResult -Results $results -Action ('Registry:' + $path) -Status 'Skipped' -Detail 'Key is absent.'
            continue
        }
        if (-not $hasWrites) {
            Add-PowerRepairActionResult -Results $results -Action ('Registry:' + $path) -Status 'Skipped' -Detail 'No values are configured for this target.'
            continue
        }

        $backupOk = $false
        try {
            $backupOk = [bool](Invoke-PowerRepairAdapter -Adapter $Adapter -Name 'BackupRegistryKey' -Arguments @($path, $BackupRoot))
        } catch {
            Add-PowerRepairActionResult -Results $results -Action ('RegistryBackup:' + $path) -Status 'Failed' -Detail $_.Exception.Message
            $hadFailure = $true
            continue
        }
        if (-not $backupOk) {
            Add-PowerRepairActionResult -Results $results -Action ('RegistryBackup:' + $path) -Status 'Failed' -Detail 'Backup did not verify; registry edits were skipped.'
            $hadFailure = $true
            continue
        }

        $targetFailed = $false
        if ($deleteTree) {
            try {
                $treeOk = [bool](Invoke-PowerRepairAdapter -Adapter $Adapter -Name 'RemoveRegistryTree' -Arguments @($path))
                if (-not $treeOk) { $targetFailed = $true }
            } catch {
                $targetFailed = $true
                Add-PowerRepairActionResult -Results $results -Action ('RemoveTree:' + $path) -Status 'Failed' -Detail $_.Exception.Message
            }
        }
        foreach ($valueName in @($target.RemoveValues)) {
            try {
                $ok = [bool](Invoke-PowerRepairAdapter -Adapter $Adapter -Name 'RemoveRegistryValue' -Arguments @($path, [string]$valueName))
                if (-not $ok) { $targetFailed = $true }
            } catch {
                $targetFailed = $true
                Add-PowerRepairActionResult -Results $results -Action ('RemoveValue:' + $path + ':' + $valueName) -Status 'Failed' -Detail $_.Exception.Message
            }
        }

        if ($target.SetValues -is [System.Collections.IDictionary]) {
            foreach ($valueName in $target.SetValues.Keys) {
                try {
                    $ok = [bool](Invoke-PowerRepairAdapter -Adapter $Adapter -Name 'SetRegistryDword' -Arguments @($path, [string]$valueName, [int]$target.SetValues[$valueName]))
                    if (-not $ok) { $targetFailed = $true }
                } catch {
                    $targetFailed = $true
                    Add-PowerRepairActionResult -Results $results -Action ('SetValue:' + $path + ':' + $valueName) -Status 'Failed' -Detail $_.Exception.Message
                }
            }
        }

        if ($target.ExistingValuesOnly) {
            foreach ($valueName in @($target.ResetValues)) {
                try {
                    $current = Invoke-PowerRepairAdapter -Adapter $Adapter -Name 'GetRegistryValue' -Arguments @($path, [string]$valueName)
                    if ($null -eq $current -or -not $current.Exists) { continue }
                    if ([string]$current.Type -notin @('DWord', 'DWORD', 'Int32')) {
                        Add-PowerRepairActionResult -Results $results -Action ('PolicyManager:' + $valueName) -Status 'Skipped' -Detail 'Existing value is not a DWORD; it was not changed.'
                        continue
                    }
                    $ok = [bool](Invoke-PowerRepairAdapter -Adapter $Adapter -Name 'SetRegistryDword' -Arguments @($path, [string]$valueName, 0))
                    if (-not $ok) { $targetFailed = $true }
                } catch {
                    $targetFailed = $true
                    Add-PowerRepairActionResult -Results $results -Action ('PolicyManager:' + $valueName) -Status 'Failed' -Detail $_.Exception.Message
                }
            }
        }

        if ($targetFailed) {
            Add-PowerRepairActionResult -Results $results -Action ('Registry:' + $path) -Status 'Partial' -Detail 'One or more values could not be changed.'
            $hadFailure = $true
        } else {
            Add-PowerRepairActionResult -Results $results -Action ('Registry:' + $path) -Status 'Completed' -Detail 'Backup completed before edits.'
        }
    }

    $powerBackupOk = $false
    try {
        $powerBackupOk = [bool](Invoke-PowerRepairAdapter -Adapter $Adapter -Name 'BackupPowerSchemes' -Arguments @($BackupRoot))
    } catch {
        Add-PowerRepairActionResult -Results $results -Action 'PowerSchemesBackup' -Status 'Failed' -Detail $_.Exception.Message
        $hadFailure = $true
    }
    $powerRestoreOk = $false
    if ($powerBackupOk) {
        try {
            $powerRestoreOk = [bool](Invoke-PowerRepairAdapter -Adapter $Adapter -Name 'RestoreDefaultPowerSchemes' -Arguments @())
            if (-not $powerRestoreOk) {
                Add-PowerRepairActionResult -Results $results -Action 'RestoreDefaultPowerSchemes' -Status 'Failed' -Detail 'powercfg did not confirm success.'
                $hadFailure = $true
            } else {
                Add-PowerRepairActionResult -Results $results -Action 'RestoreDefaultPowerSchemes' -Status 'Completed'
            }
        } catch {
            Add-PowerRepairActionResult -Results $results -Action 'RestoreDefaultPowerSchemes' -Status 'Failed' -Detail $_.Exception.Message
            $hadFailure = $true
        }
    } else {
        Add-PowerRepairActionResult -Results $results -Action 'RestoreDefaultPowerSchemes' -Status 'Skipped' -Detail 'Power-plan backup did not verify.'
        $hadFailure = $true
    }

    if ($powerRestoreOk) {
        try {
            $hibernateOk = [bool](Invoke-PowerRepairAdapter -Adapter $Adapter -Name 'EnableHibernate' -Arguments @())
            if ($hibernateOk) { Add-PowerRepairActionResult -Results $results -Action 'EnableHibernate' -Status 'Completed' }
            else { Add-PowerRepairActionResult -Results $results -Action 'EnableHibernate' -Status 'Failed'; $hadFailure = $true }
        } catch {
            Add-PowerRepairActionResult -Results $results -Action 'EnableHibernate' -Status 'Failed' -Detail $_.Exception.Message
            $hadFailure = $true
        }
        try {
            $buttonsOk = [bool](Invoke-PowerRepairAdapter -Adapter $Adapter -Name 'SetDefaultButtonActions' -Arguments @($Plan.ButtonActionValues))
            if ($buttonsOk) { Add-PowerRepairActionResult -Results $results -Action 'SetDefaultButtonActions' -Status 'Completed' }
            else { Add-PowerRepairActionResult -Results $results -Action 'SetDefaultButtonActions' -Status 'Failed'; $hadFailure = $true }
        } catch {
            Add-PowerRepairActionResult -Results $results -Action 'SetDefaultButtonActions' -Status 'Failed' -Detail $_.Exception.Message
            $hadFailure = $true
        }
    } else {
        Add-PowerRepairActionResult -Results $results -Action 'EnableHibernate' -Status 'Skipped' -Detail 'Default power schemes were not restored.'
        Add-PowerRepairActionResult -Results $results -Action 'SetDefaultButtonActions' -Status 'Skipped' -Detail 'Default power schemes were not restored.'
    }

    $rightsBackupOk = $false
    try {
        $rightsBackupOk = [bool](Invoke-PowerRepairAdapter -Adapter $Adapter -Name 'BackupShutdownRights' -Arguments @($BackupRoot))
    } catch {
        Add-PowerRepairActionResult -Results $results -Action 'ShutdownRightBackup' -Status 'Failed' -Detail $_.Exception.Message
        $hadFailure = $true
    }
    if ($rightsBackupOk) {
        foreach ($groupSid in @($Plan.ShutdownRightGroupSids)) {
            try {
                $rightOk = [bool](Invoke-PowerRepairAdapter -Adapter $Adapter -Name 'GrantShutdownRight' -Arguments @([string]$groupSid, [string]$Plan.ShutdownRightName))
                if ($rightOk) { Add-PowerRepairActionResult -Results $results -Action ('GrantShutdownRight:' + $groupSid) -Status 'Completed' }
                else { Add-PowerRepairActionResult -Results $results -Action ('GrantShutdownRight:' + $groupSid) -Status 'Failed'; $hadFailure = $true }
            } catch {
                Add-PowerRepairActionResult -Results $results -Action ('GrantShutdownRight:' + $groupSid) -Status 'Failed' -Detail $_.Exception.Message
                $hadFailure = $true
            }
        }
    } else {
        Add-PowerRepairActionResult -Results $results -Action 'GrantShutdownRight' -Status 'Skipped' -Detail 'User-rights backup did not verify.'
        $hadFailure = $true
    }

    if ($Plan.ResetLocalGpo) {
        $gpoBackupOk = $false
        try {
            $gpoBackupOk = [bool](Invoke-PowerRepairAdapter -Adapter $Adapter -Name 'BackupLocalGpo' -Arguments @($BackupRoot, @($Plan.LocalGpoPaths)))
        } catch {
            Add-PowerRepairActionResult -Results $results -Action 'LocalGpoBackup' -Status 'Failed' -Detail $_.Exception.Message
            $hadFailure = $true
        }
        if ($gpoBackupOk) {
            try {
                $gpoOk = [bool](Invoke-PowerRepairAdapter -Adapter $Adapter -Name 'ResetLocalGpo' -Arguments @(@($Plan.LocalGpoPaths)))
                if ($gpoOk) { Add-PowerRepairActionResult -Results $results -Action 'ResetLocalGpo' -Status 'Completed' }
                else { Add-PowerRepairActionResult -Results $results -Action 'ResetLocalGpo' -Status 'Failed'; $hadFailure = $true }
            } catch {
                Add-PowerRepairActionResult -Results $results -Action 'ResetLocalGpo' -Status 'Failed' -Detail $_.Exception.Message
                $hadFailure = $true
            }
        } else {
            Add-PowerRepairActionResult -Results $results -Action 'ResetLocalGpo' -Status 'Skipped' -Detail 'Local Group Policy backup did not verify; folders were not cleared.'
            $hadFailure = $true
        }
    } else {
        Add-PowerRepairActionResult -Results $results -Action 'ResetLocalGpo' -Status 'Skipped' -Detail 'Not requested.'
    }

    try {
        $gpOk = [bool](Invoke-PowerRepairAdapter -Adapter $Adapter -Name 'RunGpUpdate' -Arguments @())
        if ($gpOk) { Add-PowerRepairActionResult -Results $results -Action 'GpUpdate' -Status 'Completed' }
        else { Add-PowerRepairActionResult -Results $results -Action 'GpUpdate' -Status 'Failed'; $hadFailure = $true }
    } catch {
        Add-PowerRepairActionResult -Results $results -Action 'GpUpdate' -Status 'Failed' -Detail $_.Exception.Message
        $hadFailure = $true
    }
    try {
        $explorerOk = [bool](Invoke-PowerRepairAdapter -Adapter $Adapter -Name 'RestartExplorer' -Arguments @())
        if ($explorerOk) { Add-PowerRepairActionResult -Results $results -Action 'RestartExplorer' -Status 'Completed' }
        else { Add-PowerRepairActionResult -Results $results -Action 'RestartExplorer' -Status 'Failed'; $hadFailure = $true }
    } catch {
        Add-PowerRepairActionResult -Results $results -Action 'RestartExplorer' -Status 'Failed' -Detail $_.Exception.Message
        $hadFailure = $true
    }

    $status = 'Completed'
    if ($hadFailure) { $status = 'Partial' }
    return [pscustomobject]@{
        SchemaVersion = 1
        Status = $status
        BackupRoot = $BackupRoot
        ResetLocalGpoRequested = [bool]$Plan.ResetLocalGpo
        Actions = @($results.ToArray())
        Notes = @(
            'The repair does not reboot automatically.',
            'Domain or MDM policy may reapply restrictions after refresh or the next policy sync.',
            'A forced restart can lose unsaved work; offer it only after the report has opened.'
        )
    }
}

Export-ModuleMember -Function Get-PowerOptionsRepairPlan, Invoke-PowerOptionsRepairPlan

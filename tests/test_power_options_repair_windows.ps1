# Synthetic Windows-adapter regressions. Never call live registry/native tools.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$module = Import-Module (Join-Path $repoRoot 'PowerOptionsRepair.Windows.psm1') -Force -PassThru
$script:failures = 0
function Check {
    param([string]$Name, [bool]$Condition)
    if ($Condition) { Write-Host ('PASS  ' + $Name) }
    else { Write-Host ('FAIL  ' + $Name); $script:failures++ }
}

# Override provider commands inside the imported module, not global OS state.
& $module {
    function script:Get-Item { param($LiteralPath, $ErrorAction) throw 'synthetic access denied' }
}
$denied = $false
try { $null = & $module { Get-PowerRepairRegistryValue -Path 'HKLM:\synthetic' -Name 'HideSleep' } }
catch { $denied = $true }
Check 'unreadable policy value is a failure, not an absent value' $denied

& $module {
    function script:Get-Item {
        param($LiteralPath, $ErrorAction)
        $key = New-Object PSObject
        $key | Add-Member -MemberType ScriptMethod -Name GetValueNames -Value { return @('Present') }
        $key | Add-Member -MemberType ScriptMethod -Name GetValueKind -Value { param($Name) return 'DWord' }
        $key | Add-Member -MemberType ScriptMethod -Name GetValue -Value { param($Name) return 1 }
        return $key
    }
}
$absent = & $module { Get-PowerRepairRegistryValue -Path 'HKLM:\synthetic' -Name 'Missing' }
Check 'genuinely absent policy value remains absent' (-not $absent.Exists)
$present = & $module { Get-PowerRepairRegistryValue -Path 'HKLM:\synthetic' -Name 'Present' }
Check 'existing DWORD policy value retains its value and kind' ($present.Exists -and $present.Type -eq 'DWord' -and $present.Value -eq 1)

& $module {
    function script:Test-PowerRepairRegistryKey { param($Path) return $true }
    function script:Remove-ItemProperty {
        [CmdletBinding()]
        param($LiteralPath, $Name)
        Write-Error 'synthetic remove denied'
    }
}
$removed = & $module { Remove-PowerRepairRegistryValue -Path 'HKLM:\synthetic' -Name 'Present' }
Check 'denied registry removal cannot report success' (-not $removed)

# Exercise the production Explorer refresh with process doubles only.
& $module {
    $script:stoppedIds = New-Object System.Collections.ArrayList
    $script:currentSession = [Diagnostics.Process]::GetCurrentProcess().SessionId
    function script:Get-Process {
        param($Name, $ErrorAction)
        return @(
            [pscustomobject]@{ Id = 1001; SessionId = $script:currentSession },
            [pscustomobject]@{ Id = 2002; SessionId = ($script:currentSession + 1) }
        )
    }
    function script:Stop-Process { param($Id, [switch]$Force, $ErrorAction) [void]$script:stoppedIds.Add($Id) }
    function script:Start-Process { param($FilePath, $ErrorAction) }
    function script:Start-Sleep { param($Seconds) }
}
$oldSystemRoot = $env:SystemRoot
try {
    # Join-Path needs a real root on Linux; no file at this path is executed.
    $env:SystemRoot = $repoRoot
    $refreshed = & $module { Restart-PowerRepairExplorer }
    $stopped = @(& $module { $script:stoppedIds.ToArray() })
    Check 'Explorer refresh never stops another logged-in session' ($refreshed -and $stopped.Count -eq 1 -and $stopped[0] -eq 1001)
} finally { $env:SystemRoot = $oldSystemRoot }

Remove-Module $module
if ($script:failures -gt 0) { exit 1 }
Write-Host 'ALL POWER-OPTIONS WINDOWS ADAPTER SYNTHETIC TESTS PASSED'
exit 0

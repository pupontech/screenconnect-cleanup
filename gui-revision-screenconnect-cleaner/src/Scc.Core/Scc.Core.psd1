@{
    RootModule        = 'Scc.Core.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'a1f2c3d4-0001-4b00-8000-000000000001'
    Author            = 'ScreenConnect Cleaner Team'
    Description       = 'Foundation module: config, paths, runs, logging, caches, file facts, safe JSON, preflight.'
    PowerShellVersion = '5.1'
    RequiredModules = @('Microsoft.PowerShell.Utility', 'Microsoft.PowerShell.Management')
    FunctionsToExport = @(
        'Get-SccConfig',
        'Set-SccConfigValue',
        'Get-SccPaths',
        'New-SccRun',
        'Save-SccRunState',
        'Get-SccRunState',
        'Find-SccRecentRuns',
        'Write-SccLog',
        'Get-SccComputerInfo',
        'Test-SccInternet',
        'Test-SccNas',
        'Get-SccCache',
        'Set-SccCache',
        'Get-SccFileFacts',
        'Resolve-SccEnv',
        'Invoke-SccSafe',
        'ConvertTo-SccJson',
        'ConvertFrom-SccJson',
        'Invoke-SccPreflightStage'
    )
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags       = @('ScreenConnect', 'Cleanup', 'Forensics')
            LicenseUri = 'https://opensource.org/licenses/MIT'
        }
    }
}

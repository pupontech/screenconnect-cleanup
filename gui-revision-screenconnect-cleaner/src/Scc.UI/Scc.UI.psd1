@{
    RootModule             = 'Scc.UI.psm1'
    ModuleVersion          = '1.0.0'
    GUID                   = 'a1c2e3b4-0001-4f00-8000-000000000009'
    Author                 = 'ScreenConnect Cleaner'
    CompanyName            = 'ScreenConnect Cleaner'
    Description            = 'WPF shell and shared stage state machine for ScreenConnect Cleaner.'
    CLRVersion             = '4.0'
    RequiredModules = @('Microsoft.PowerShell.Utility', 'Microsoft.PowerShell.Management')
    FunctionsToExport      = @(
        'New-SccWorkflow',
        'Start-SccWorkflow',
        'Step-SccWorkflow',
        'Get-SccNextStage',
        'Stop-SccWorkflow',
        'Start-SccJob',
        'Update-SccJob',
        'Wait-SccJob',
        'Stop-SccJob',
        'Reset-SccJob',
        'Start-SccApp'
    )
    VariablesToExport      = @()
    AliasesToExport        = @()
    PrivateData            = @{
        PSData = @{
            Tags       = @('ScreenConnect', 'Cleanup', 'WPF', 'Workflow')
            LicenseUri = 'https://opensource.org/licenses/MIT'
        }
    }
}

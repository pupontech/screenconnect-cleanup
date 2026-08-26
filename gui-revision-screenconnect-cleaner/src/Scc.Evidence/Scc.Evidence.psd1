@{
    RootModule        = 'Scc.Evidence.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
    Author            = 'ScreenConnect Cleaner Contributors'
    CompanyName       = 'ScreenConnect Cleaner'
    Copyright         = '(c) 2026 ScreenConnect Cleaner Contributors. MIT License.'
    Description       = 'Evidence snapshot collection for ScreenConnect Cleaner investigation runs.'
    PowerShellVersion = '5.1'
    RequiredModules   = @('Microsoft.PowerShell.Utility')
    FunctionsToExport = @('New-SccSnapshot', 'Get-SccSnapshot')
    CmdletsToExport   = @()
    VariablesToExport  = @()
    AliasesToExport    = @()
    PrivateData       = @{
        PSData = @{
            Tags       = @('Security', 'ScreenConnect', 'Forensics')
            LicenseUri = 'https://opensource.org/licenses/MIT'
        }
    }
}

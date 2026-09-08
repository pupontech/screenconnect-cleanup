@{
    RootModule        = 'Scc.Snapshots.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = 'b2c3d4e5-f6a7-8901-bcde-f12345678901'
    Author            = 'ScreenConnect Cleaner Contributors'
    CompanyName       = 'ScreenConnect Cleaner'
    Copyright         = '(c) 2026 ScreenConnect Cleaner Contributors. MIT License.'
    Description       = 'Before/after snapshot diff and resurrection detection for ScreenConnect Cleaner.'
    RequiredModules = @('Microsoft.PowerShell.Utility', 'Microsoft.PowerShell.Management')
    FunctionsToExport = @('Compare-SccSnapshots', 'Test-SccResurrection')
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

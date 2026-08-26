# Scc.Scanners.psd1 - Scanner management module for ScreenConnect Cleaner
@{
    RootModule        = 'Scc.Scanners.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = 'b2c3d4e5-f6a7-8901-bcde-f12345678901'
    Author            = 'ScreenConnect Cleaner Contributors'
    CompanyName       = 'ScreenConnect Cleaner'
    Copyright         = '(c) 2026 ScreenConnect Cleaner Contributors. MIT License.'
    Description       = 'Centralized scanner management and adapters for CLI and GUI scanners.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('Get-SccScannerList', 'Invoke-SccScanner', 'Invoke-SccGuiScanner')
    CmdletsToExport   = @()
    VariablesToExport  = @()
    AliasesToExport    = @()
    PrivateData       = @{
        PSData = @{
            Tags       = @('Security', 'ScreenConnect', 'Scanners', 'Forensics')
            LicenseUri = 'https://opensource.org/licenses/MIT'
        }
    }
}

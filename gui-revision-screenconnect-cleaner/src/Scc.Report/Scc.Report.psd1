@{
    RootModule        = 'Scc.Report.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'b2e3d4f5-0008-4c00-9000-000000000008'
    Author            = 'ScreenConnect Cleaner Team'
    Description       = 'Reporting engine: report.html, report.json, technician-summary.txt with XSS-safe escaping and deterministic output.'
    PowerShellVersion = '5.1'
    RequiredModules = @('Microsoft.PowerShell.Utility', 'Microsoft.PowerShell.Management')
    FunctionsToExport = @(
        'New-SccReport',
        'ConvertTo-SccHtml'
    )
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags       = @('ScreenConnect', 'Cleanup', 'Reporting')
            LicenseUri = 'https://opensource.org/licenses/MIT'
        }
    }
}

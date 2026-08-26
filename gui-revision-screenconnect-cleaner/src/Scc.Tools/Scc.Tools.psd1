@{
    RootModule        = 'Scc.Tools.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = '75ca4b0a-0002-4c00-9000-000000000004'
    Author            = 'ScreenConnect Cleaner Contributors'
    CompanyName       = 'ScreenConnect Cleaner'
    Copyright         = '(c) 2026 ScreenConnect Cleaner Contributors. MIT License.'
    Description       = 'ToolManager: NAS-first tool acquisition, validation, cache, and provenance for ScreenConnect Cleaner investigation runs.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'Get-SccToolCatalog',
        'Resolve-SccTool',
        'Test-SccToolIntegrity',
        'Get-SccToolStatus',
        'Save-SccToolToCache',
        'Write-SccToolProvenance'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags       = @('Security', 'ScreenConnect', 'Forensics', 'Tools')
            LicenseUri = 'https://opensource.org/licenses/MIT'
        }
    }
}
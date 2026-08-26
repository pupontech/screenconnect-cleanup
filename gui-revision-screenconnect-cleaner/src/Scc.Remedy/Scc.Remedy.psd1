@{
    RootModule        = 'Scc.Remedy.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = 'c3d4e5f6-a7b8-9012-cdef-3456789ab001'
    Author            = 'ScreenConnect Cleaner Team'
    CompanyName       = 'ScreenConnect Cleaner'
    Copyright         = '(c) 2026 ScreenConnect Cleaner Contributors. MIT License.'
    Description       = 'Remediation engine for ScreenConnect Cleaner: plan-gated, ScreenConnect-only removal with quarantine. Highest safety bar.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'New-SccPlan'
        'Test-SccPlan'
        'Invoke-SccRemediation'
        'Restore-SccQuarantineItem'
        'Clear-SccQuarantine'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags       = @('Security', 'ScreenConnect', 'Forensics', 'Remediation')
            LicenseUri = 'https://opensource.org/licenses/MIT'
        }
    }
}

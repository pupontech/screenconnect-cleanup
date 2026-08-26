# Scc.Detection.psd1 - Detection module manifest for ScreenConnect Cleaner
@{
    RootModule        = 'Scc.Detection.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = 'c3d4e5f6-a7b8-9012-cdef-1234567890ab'
    Author            = 'ScreenConnect Cleaner Contributors'
    CompanyName       = 'ScreenConnect Cleaner'
    Copyright         = '(c) 2026 ScreenConnect Cleaner Contributors. MIT License.'
    Description       = 'ScreenConnect deep detection, other remote-access detection, and trust matching.'
    PowerShellVersion = '5.1'
    RequiredModules = @('Microsoft.PowerShell.Utility', 'Microsoft.PowerShell.Management')
    FunctionsToExport = @(
        'Get-SccScreenConnect',
        'Get-SccRemoteAccess',
        'Invoke-SccDetection',
        'Get-SccTrustedRelays',
        'Test-SccTrustedRelay',
        'Invoke-SccDetectionSelfTest'
    )
    CmdletsToExport   = @()
    VariablesToExport  = @()
    AliasesToExport    = @()
    PrivateData       = @{
        PSData = @{
            Tags       = @('Security', 'ScreenConnect', 'Forensics', 'Detection')
            LicenseUri = 'https://opensource.org/licenses/MIT'
        }
    }
}

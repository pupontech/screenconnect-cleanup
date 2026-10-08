# Read-only inventory worker. Approval/removal always stays in the attended parent.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$OutDir)
$ErrorActionPreference='Stop'
try {
    Import-Module (Join-Path $PSScriptRoot 'Persistence.Inventory.psm1') -Force -ErrorAction Stop
    $null=Get-SccPersistenceInventory -OutDir $OutDir
    exit 0
} catch {
    Write-Error ('Persistence inventory worker failed: '+$_.Exception.Message) -ErrorAction Continue
    exit 1
}

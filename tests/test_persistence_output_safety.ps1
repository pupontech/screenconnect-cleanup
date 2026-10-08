# Production writer refusal probes with fully injected collector data.
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$root=Join-Path ([IO.Path]::GetTempPath()) ('scc-output-fixture-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $root
$failures=0
try {
    Import-Module (Join-Path $repo 'Persistence.Inventory.psm1') -Force
    $module=Get-Module Persistence.Inventory
    $outside=Join-Path $root 'outside';$null=New-Item -ItemType Directory -Path $outside
    $plain=Join-Path $root 'plain'
    $probeResults=& $module {
        param($plain,$outside)
        function Get-SccTaskEvidence { [pscustomobject]@{Items=@();Findings=@();Errors=@()} }
        function Get-SccRegistryEvidence { [pscustomobject]@{Items=@();Findings=@();Errors=@();ProfileErrors=@()} }
        function Get-SccProfileRoots { [pscustomobject]@{Profiles=@();Errors=@()} }
        function Get-SccStartupEvidence { [pscustomobject]@{Items=@();Findings=@();Errors=@()} }
        function Get-SccHiddenTaskEvidence { [pscustomobject]@{Items=@();Errors=@()} }
        function Get-SccGenericEvidence { [pscustomobject]@{Items=@();Errors=@()} }
        function Get-SccBoundedScriptFiles { [pscustomobject]@{Items=@();Errors=@();Truncated=$false;Limits=[pscustomobject]@{MaxFiles=2500}} }
        $baseline=Get-SccPersistenceInventory -OutDir (Join-Path $plain 'persistence')
        if($baseline.Status -ne 'Complete'){throw 'Fully injected normal inventory baseline failed.'}
        $sameRoot=Join-Path $outside 'existing';$null=New-Item -ItemType Directory -Path $sameRoot
        $sentinel=Join-Path $sameRoot 'inventory.json';[IO.File]::WriteAllText($sentinel,'outside sentinel')
        $refused=$false
        try {$null=Get-SccPersistenceInventory -OutDir $sameRoot}catch{$refused=$true}
        [pscustomobject]@{Name='pre-existing inventory refuses overwrite';Passed=($refused -and [IO.File]::ReadAllText($sentinel) -eq 'outside sentinel')}
    } $plain $outside
    foreach($r in $probeResults){if($r.Passed){Write-Host ('PASS: '+$r.Name)}else{Write-Host ('FAIL: '+$r.Name);$failures++}}
    $redirect=Join-Path $root 'redirected'
    $linkMade=$false
    try {
        $type=if($env:OS -eq 'Windows_NT'){'Junction'}else{'SymbolicLink'}
        $null=New-Item -ItemType $type -Path $redirect -Target $outside -ErrorAction Stop
        $linkMade=$true
    }catch{Write-Host 'SKIP: directory redirection fixture cannot be created on this host'}
    if($linkMade) {
        $externalPersistence=Join-Path $outside 'persistence';$null=New-Item -ItemType Directory -Path $externalPersistence
        $resultSentinel=Join-Path $externalPersistence 'result.json';[IO.File]::WriteAllText($resultSentinel,'result sentinel')
        $removalSentinel=Join-Path $externalPersistence 'removal.json';[IO.File]::WriteAllText($removalSentinel,'removal sentinel')
        $hostExe=if($PSVersionTable.PSEdition -eq 'Desktop'){Join-Path $PSHOME 'powershell.exe'}else{Join-Path $PSHOME 'pwsh'}
        # 5.1 turns native stderr into a terminating NativeCommandError under
        # EAP Stop. Capture the expected refusal without losing the sentinel check.
        $oldPreference=$ErrorActionPreference
        try {$ErrorActionPreference='Continue';$output=& $hostExe -NoProfile -File (Join-Path $repo 'Invoke-PersistenceScan.ps1') -WorkDir $redirect -WhatIf 2>&1;$refused=($LASTEXITCODE -ne 0)}
        finally {$ErrorActionPreference=$oldPreference}
        if($refused -and [IO.File]::ReadAllText($resultSentinel) -eq 'result sentinel' -and [IO.File]::ReadAllText($removalSentinel) -eq 'removal sentinel'){Write-Host 'PASS: wrapper refuses redirected output before any artifact write'}else{Write-Host 'FAIL: wrapper refuses redirected output before any artifact write';$failures++}
    }
} finally {
    if(Test-Path -LiteralPath $root){Remove-Item -LiteralPath $root -Recurse -Force}
}
if($failures){throw "$failures persistence output safety probes failed"}
Write-Host 'PASS: persistence output refusal probes; native collection never executed.'

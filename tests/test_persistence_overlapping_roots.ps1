# Overlapping roots must not repeat enumeration/hashing or inflate script counts.
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$temp=Join-Path ([IO.Path]::GetTempPath()) ('scc overlapping roots '+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path (Join-Path $temp 'child') -Force
try {
    foreach($name in @('root.ps1','child/a.ps1','child/b.bat')) {
        [IO.File]::WriteAllText((Join-Path $temp $name),'harmless fixture')
    }
    Import-Module (Join-Path $repo 'Persistence.Inventory.psm1') -Force
    $module=Get-Module Persistence.Inventory
    & $module {
        param($fixture)
        $script:RootReads=0;$script:HashReads=0
        function Get-FileHash {
            param($LiteralPath,$Algorithm,$ErrorAction)
            $script:HashReads++
            Microsoft.PowerShell.Utility\Get-FileHash -LiteralPath $LiteralPath -Algorithm $Algorithm -ErrorAction Stop
        }
        $reader={param($path) $script:RootReads++;Get-ChildItem -LiteralPath $path -Force -ErrorAction Stop}
        $clock=[Diagnostics.Stopwatch]::StartNew()
        $result=Get-SccBoundedScriptFiles -Roots @($fixture,$fixture,(Join-Path $fixture 'child')) -MaxFiles 50 -MaxSeconds 20 -DirectoryReader $reader
        Write-Host ('MEASURE: overlapping roots; directory reads='+$script:RootReads+'; hash reads='+$script:HashReads+'; records='+$result.Items.Count+'; elapsed='+$clock.Elapsed.TotalSeconds.ToString('F3',[Globalization.CultureInfo]::InvariantCulture)+'s')
        if($result.Items.Count -ne 3 -or $script:RootReads -ne 2 -or $script:HashReads -ne 3){throw 'Overlapping roots repeated traversal/hash work or duplicated inventory records.'}
        if($result.Truncated -or $result.Errors.Count){throw 'Deduplication introduced incomplete coverage for a complete fixture.'}
        if(@($result.Items | Where-Object {-not $_.SHA256}).Count){throw 'Deduplication dropped content hashes.'}
        Write-Host 'PASS: repeated/nested roots keep exactly one inventory and hash per file.'
    } $temp
} finally {Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue}

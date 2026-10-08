# Exercise the actual native file-info layout and disposable file link counts.
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$source=[IO.File]::ReadAllText((Join-Path $repo 'Persistence.Removal.psm1'))
$csharp=[regex]::Match($source,"(?s)Add-Type -TypeDefinition @'\r?\n(.*?)\r?\n'@").Groups[1].Value
if(-not $csharp){throw 'Production native file-info declaration not found.'}
Add-Type -TypeDefinition $csharp
$infoType='SccPersistenceFileInfo+Info' -as [type]
$infoValue=New-Object 'SccPersistenceFileInfo+Info'
$size=[Runtime.InteropServices.Marshal]::SizeOf($infoValue)
$linksOffset=[Runtime.InteropServices.Marshal]::OffsetOf($infoType,'Links').ToInt32()
# BY_HANDLE_FILE_INFORMATION: DWORD + three FILETIMEs + six DWORDs.
if($size -ne 52 -or $linksOffset -ne 40){throw "Invalid BY_HANDLE_FILE_INFORMATION layout: size=$size LinksOffset=$linksOffset"}
Write-Host 'PASS: production BY_HANDLE_FILE_INFORMATION size and Links offset'
if($env:OS -ne 'Windows_NT'){Write-Host 'SKIP: Windows native link-count runtime requires Windows';exit 0}
$root=Join-Path ([IO.Path]::GetTempPath()) ('scc-native-links-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $root
try {
    $file=Join-Path $root 'fixture.txt';[IO.File]::WriteAllText($file,'harmless link-count fixture')
    Import-Module (Join-Path $repo 'Persistence.Removal.psm1') -Force
    $module=Get-Module Persistence.Removal
    $one=& $module {param($p) Get-SccStartupLinkCount $p} $file
    if($one -ne 1){throw "Normal file link count was $one instead of one"}
    $link=Join-Path $root 'hardlink.txt';$null=New-Item -ItemType HardLink -Path $link -Target $file
    $two=& $module {param($p) Get-SccStartupLinkCount $p} $file
    if($two -ne 2){throw "Hard-linked file link count was $two instead of two"}
    Write-Host 'PASS: real Windows native link counts for disposable single/hard-linked files'
}finally{Remove-Item -LiteralPath $root -Recurse -Force}

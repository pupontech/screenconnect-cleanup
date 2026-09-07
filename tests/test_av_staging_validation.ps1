# Exercise the real download commit boundary without downloading or running an EXE.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $repoRoot 'tools/Get-AVTools.ps1'), [ref]$tokens, [ref]$errors)
$function = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-DownloadFile' }, $true)
. ([scriptblock]::Create($function.Extent.Text))
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('scc-staging-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $tmp
$dest = Join-Path $tmp 'scanner.exe'
$failures = 0
function Check {
    param([string]$Name, [bool]$Ok)
    if ($Ok) { Write-Host "PASS: $Name" }
    else { Write-Host "FAIL: $Name"; $script:failures++ }
}
function Say { param([string]$Message, [string]$Color) }
function Start-DownloadFast {
    param([string]$Url, [string]$OutFile, [string]$Label)
    [IO.File]::WriteAllText($OutFile, 'untrusted replacement fixture')
}
function Get-Item {
    param([string]$LiteralPath, [string]$ErrorAction)
    if ($script:metadataMode -eq 'item-error') { throw 'synthetic metadata read failure' }
    $item = [pscustomobject]@{ Length = 2MB }
    $item | Add-Member -MemberType ScriptProperty -Name VersionInfo -Value { throw 'synthetic corrupt version resource' }
    return $item
}
function Test-PeExecutable {
    param([string]$Path)
    $script:validationCalls++
    if ($script:metadataMode -eq 'validator-error') { throw 'synthetic validator failure' }
    return $script:peValid
}
try {
    foreach ($mode in @('version-error', 'item-error', 'validator-error')) {
        $script:metadataMode = $mode
        $script:peValid = $false
        $script:validationCalls = 0
        [IO.File]::WriteAllText($dest, 'known-good existing fixture')
        $ok = Get-DownloadFile -Url 'https://invalid.example/scanner' -Dest $dest -Label 'fixture'
        Check "$mode cannot report success for an unvalidated download" ($ok -eq $false)
        Check "$mode preserves the existing scanner" ([IO.File]::ReadAllText($dest) -eq 'known-good existing fixture')
        Check "$mode cleans the owned partial file" (-not (Test-Path -LiteralPath ($dest + '.part')))
    }
    $script:metadataMode = 'version-error'
    $script:peValid = $true
    $script:validationCalls = 0
    $ok = Get-DownloadFile -Url 'https://invalid.example/scanner' -Dest $dest -Label 'fixture'
    Check 'optional version metadata failure does not reject a validated download' ($ok -eq $true -and $script:validationCalls -eq 1)
    Check 'validated replacement is committed' ([IO.File]::ReadAllText($dest) -eq 'untrusted replacement fixture')
} finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force
}
if ($failures) { throw "$failures staging regression(s) failed" }
Write-Host 'PASS: AV staging commit-boundary regressions'

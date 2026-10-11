<#
  Regression for Test-ResumeMaterialsTrusted (remove-screenconnect.ps1).

  The resume-materials trust check is the gate that decides whether a deferred
  (reboot) ScreenConnect removal may point a RunOnce task at a location. It
  must FAIL CLOSED: a location any non-SYSTEM/Administrators/TrustedInstaller
  identity can write, delete or take over must be rejected, and the check must
  not be weakened into always-true.

  The ACL comparison is Windows-only; on a non-Windows host the production
  function returns $true by contract, so this test asserts that contract and
  skips the ACL assertions (it is exercised for real on the Windows CI matrix).

  Run: pwsh -NoProfile -File tests/test_resume_materials_trust.ps1
#>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $PSScriptRoot

function Get-FunctionAst {
    param([string]$Path, [string]$Name)
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null)
    return $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $Name }, $true) | Select-Object -First 1
}

$scriptPath = Join-Path $RepoRoot 'remove-screenconnect.ps1'
$fn = Get-FunctionAst -Path $scriptPath -Name 'Test-ResumeMaterialsTrusted'
if (-not $fn) { throw 'Test-ResumeMaterialsTrusted not found in remove-screenconnect.ps1' }
. ([scriptblock]::Create($fn.Extent.Text))

$failures = New-Object System.Collections.Generic.List[string]
function Assert-True { param([bool]$Condition, [string]$Message) if (-not $Condition) { $script:failures.Add($Message); Write-Host ("FAIL: " + $Message) } else { Write-Host ("ok:   " + $Message) } }

# Contract assertion on every platform: an empty/whitespace path is never
# trusted. An empty element is rejected at parameter binding (the in-function
# IsNullOrWhiteSpace guard is unreachable because [string[]] refuses '' unless
# [AllowEmptyString()] is set) - a throw is still fail-closed, so accept either.
$emptyOutcome = $false
try { $emptyOutcome = ((Test-ResumeMaterialsTrusted -Paths @('')) -eq $false) } catch { $emptyOutcome = $true }
Assert-True $emptyOutcome 'empty path is refused (throws or returns false)'

if ($env:OS -ne 'Windows_NT') {
    Write-Host 'skip: ACL assertions are Windows-only (production returns $true off-Windows)'
    Assert-True ((Test-ResumeMaterialsTrusted -Paths @('C:\anything')) -eq $true) 'off-Windows contract returns $true'
} else {
    Assert-True ((Test-ResumeMaterialsTrusted -Paths @('   ')) -eq $false) 'whitespace path is refused'
    # A location standard users can write must be refused (fail closed).
    $writable = Join-Path $env:TEMP ('scc-resume-trust-' + [guid]::NewGuid().ToString('N'))
    $null = New-Item -ItemType Directory -Path $writable -Force
    try {
        Assert-True ((Test-ResumeMaterialsTrusted -Paths @($writable)) -eq $false) 'user-writable temp location is refused'
    } finally { Remove-Item -LiteralPath $writable -Recurse -Force -ErrorAction SilentlyContinue }

    # A protected OS location must be accepted (the check must not be always-false).
    $protected = Join-Path $env:SystemRoot 'System32\drivers'
    if (Test-Path -LiteralPath $protected) {
        Assert-True ((Test-ResumeMaterialsTrusted -Paths @($protected)) -eq $true) 'protected System32\drivers is accepted'
    } else {
        Write-Host ('skip: ' + $protected + ' not present')
    }

    # A file the current (elevated) context owns under a per-user profile must
    # not be treated as trusted merely because the file itself exists.
    $mixed = Join-Path $env:USERPROFILE 'scc-resume-mixed.txt'
    [IO.File]::WriteAllText($mixed, 'x')
    try {
        Assert-True ((Test-ResumeMaterialsTrusted -Paths @($mixed)) -eq $false) 'per-user file under a writable profile is refused'
    } finally { Remove-Item -LiteralPath $mixed -Force -ErrorAction SilentlyContinue }
}

if ($failures.Count -gt 0) { Write-Host ("`n" + $failures.Count + ' failure(s)') -ForegroundColor Red; exit 1 }
Write-Host "`nPASS: resume-materials trust check fails closed"
exit 0

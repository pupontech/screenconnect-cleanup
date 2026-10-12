[CmdletBinding()]
param(
    [string]$ScratchRoot = $env:TMPDIR
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrEmpty($ScratchRoot)) { throw 'ScratchRoot or TMPDIR is required.' }
$scratch = [IO.Path]::GetFullPath($ScratchRoot)
if (-not [IO.Directory]::Exists($scratch)) { [void][IO.Directory]::CreateDirectory($scratch) }
$smokePath = Join-Path (Split-Path -Parent $PSCommandPath) 'PublishedGuiSmoke.ps1'
function Assert-AsciiFile {
    param([string]$Path)
    $bytes = [IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 239 -and $bytes[1] -eq 187 -and $bytes[2] -eq 191) {
        throw 'Cleanup smoke source and tests must be UTF-8 without BOM.'
    }
    foreach ($byte in $bytes) {
        if ($byte -gt 127) { throw 'Cleanup smoke source and tests must contain ASCII bytes only.' }
    }
}
Assert-AsciiFile -Path $smokePath
Assert-AsciiFile -Path $PSCommandPath
$tokens = $null
$parseErrors = $null
$smokeAst = [System.Management.Automation.Language.Parser]::ParseFile($smokePath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) { throw "Published GUI smoke parse failed: $($parseErrors[0].Message)" }
$script:Assertions = 0
function Assert-True {
    param([bool]$Condition, [string]$Message)
    $script:Assertions++
    if (-not $Condition) { throw "FAIL: $Message" }
}
function Assert-Throws {
    param([scriptblock]$Action, [string]$Message, [string]$ExpectedText)
    $script:Assertions++
    $exceptionText = $null
    try { & $Action } catch { $exceptionText = $_.Exception.ToString() }
    if ($null -eq $exceptionText) { throw "FAIL: expected rejection: $Message" }
    if (-not $exceptionText.Contains($ExpectedText)) {
        throw "FAIL: $Message rejected for the wrong reason: $exceptionText"
    }
}
function New-FakeProcess {
    param([bool]$WaitResult, [bool]$AlreadyExited = $false)
    $fake = [pscustomobject]@{
        Id = 424242
        HasExited = $AlreadyExited
        WaitResult = $WaitResult
        WaitCalls = 0
        WaitTimeoutMilliseconds = -1
        StopRequested = $false
    }
    $fake | Add-Member -MemberType ScriptMethod -Name Refresh -Value { }
    $fake | Add-Member -MemberType ScriptMethod -Name WaitForExit -Value {
        param([int]$Milliseconds)
        $this.WaitCalls++
        $this.WaitTimeoutMilliseconds = $Milliseconds
        return [bool]$this.WaitResult
    }
    return $fake
}
function New-FixtureDirectory {
    param([string]$Name)
    $path = Join-Path $testRoot ($Name + '-' + [Guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($path)
    [IO.File]::WriteAllText((Join-Path $path 'fixture.txt'), 'synthetic-only')
    return $path
}

$testRoot = Join-Path $scratch ('published-gui-cleanup-' + [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($testRoot)
try {
$cleanupDefinition = $smokeAst.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Invoke-PublishedGuiSmokeCleanup'
}, $true) | Select-Object -First 1
if ($null -eq $cleanupDefinition) { throw 'FAIL: expected cleanup helper Invoke-PublishedGuiSmokeCleanup.' }
Invoke-Expression $cleanupDefinition.Extent.Text

$mainTry = $smokeAst.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.TryStatementAst] -and
        $node.Body.Extent.Text.Contains('Expand-Archive') -and
        $node.Body.Extent.Text.Contains('Start-Process')
}, $true) | Select-Object -First 1
Assert-True ($null -ne $mainTry) 'archive extraction and GUI startup share a try/finally cleanup scope'
Assert-True ($mainTry.Finally.Extent.Text.Contains('Invoke-PublishedGuiSmokeCleanup')) 'the shared finally always calls the cleanup helper'
$initializationOffset = $smokeAst.Extent.Text.IndexOf('$process = $null', [StringComparison]::Ordinal)
$extractionOffset = $smokeAst.Extent.Text.IndexOf('Expand-Archive -LiteralPath $zip', [StringComparison]::Ordinal)
Assert-True ($initializationOffset -ge 0 -and $initializationOffset -lt $extractionOffset) 'process is initialized to null before archive extraction or process startup can fail'

$confirmedRoot = New-FixtureDirectory 'confirmed-exit'
$confirmedProcess = New-FakeProcess -WaitResult $true
$confirmedStop = { param($process) $process.StopRequested = $true }
$confirmedDelete = { param($path) [IO.Directory]::Delete($path, $true) }
Invoke-PublishedGuiSmokeCleanup -Process $confirmedProcess -FixtureRoot $confirmedRoot `
    -ExitTimeoutMilliseconds 37 -StopProcess $confirmedStop -DeleteFixture $confirmedDelete
Assert-True $confirmedProcess.StopRequested 'a live synthetic process receives a stop request'
Assert-True ($confirmedProcess.WaitCalls -eq 1 -and $confirmedProcess.WaitTimeoutMilliseconds -eq 37) 'cleanup waits once with the bounded timeout before deletion'
Assert-True (-not [IO.Directory]::Exists($confirmedRoot)) 'a confirmed process exit permits fixture deletion'

$unconfirmedRoot = New-FixtureDirectory 'unconfirmed-exit'
$unconfirmedProcess = New-FakeProcess -WaitResult $false
$unconfirmedDelete = { param($path) [IO.Directory]::Delete($path, $true) }
Assert-Throws {
    Invoke-PublishedGuiSmokeCleanup -Process $unconfirmedProcess -FixtureRoot $unconfirmedRoot `
        -ExitTimeoutMilliseconds 37 -StopProcess $confirmedStop -DeleteFixture $unconfirmedDelete
} 'an unsignaled process exit blocks cleanup' 'did not exit within 37 ms; retaining fixture'
Assert-True $unconfirmedProcess.StopRequested 'an unconfirmed synthetic process received a stop request'
Assert-True ($unconfirmedProcess.WaitCalls -eq 1 -and $unconfirmedProcess.WaitTimeoutMilliseconds -eq 37) 'unconfirmed exit was checked with bounded WaitForExit'
Assert-True ([IO.Directory]::Exists($unconfirmedRoot)) 'an unconfirmed process exit retains the fixture'

$alreadyExitedRoot = New-FixtureDirectory 'already-exited'
$alreadyExitedProcess = New-FakeProcess -WaitResult $true -AlreadyExited $true
$alreadyExitedDelete = { param($path) [IO.Directory]::Delete($path, $true) }
Invoke-PublishedGuiSmokeCleanup -Process $alreadyExitedProcess -FixtureRoot $alreadyExitedRoot `
    -ExitTimeoutMilliseconds 37 -StopProcess $confirmedStop -DeleteFixture $alreadyExitedDelete
Assert-True (-not $alreadyExitedProcess.StopRequested) 'an already exited process is not stopped again'
Assert-True ($alreadyExitedProcess.WaitCalls -eq 1) 'already-exited state is confirmed through WaitForExit'
Assert-True (-not [IO.Directory]::Exists($alreadyExitedRoot)) 'an already exited process permits fixture deletion'

$noProcessRoot = New-FixtureDirectory 'no-process'
$noProcessDelete = { param($path) [IO.Directory]::Delete($path, $true) }
Invoke-PublishedGuiSmokeCleanup -Process $null -FixtureRoot $noProcessRoot `
    -ExitTimeoutMilliseconds 37 -StopProcess $confirmedStop -DeleteFixture $noProcessDelete
Assert-True (-not [IO.Directory]::Exists($noProcessRoot)) 'failed extraction or process start without a process still cleans the fixture'

$accessDeniedRoot = New-FixtureDirectory 'access-denied'
$accessDeniedDelete = { param($path) throw 'Access denied deleting synthetic fixture.' }
Assert-Throws {
    Invoke-PublishedGuiSmokeCleanup -Process $null -FixtureRoot $accessDeniedRoot `
        -ExitTimeoutMilliseconds 37 -StopProcess $confirmedStop -DeleteFixture $accessDeniedDelete
} 'fixture deletion errors are not swallowed' 'Access denied'
Assert-True ([IO.Directory]::Exists($accessDeniedRoot)) 'a failed fixture deletion remains observable and leaves the fixture intact'

Write-Output "PASS: $script:Assertions assertions; synthetic-only bounded process-exit confirmation and fixture cleanup."
} finally {
    if ([IO.Directory]::Exists($testRoot)) { [IO.Directory]::Delete($testRoot, $true) }
}

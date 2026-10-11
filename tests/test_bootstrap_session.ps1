# Execute the documented iex bootstrap shape without network or cleanup launch.
[CmdletBinding()]
param([string]$SourceRoot='', [switch]$CheckTls)
$ErrorActionPreference='Stop'
if(-not $SourceRoot){$SourceRoot=Split-Path -Parent $PSScriptRoot}
$temp=Join-Path ([IO.Path]::GetTempPath()) ('scc bootstrap session '+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $temp
try {
    $installed=Join-Path $temp 'v99.9.9';$null=New-Item -ItemType Directory -Path $installed
    [IO.File]::WriteAllText((Join-Path $installed 'VERSION'),'99.9.9')
    [IO.File]::WriteAllText((Join-Path $installed 'START-HERE.bat'),'rem harmless cached fixture')
    $harness=@'
$ErrorActionPreference='Continue'
$ProgressPreference='Continue'
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]0
$beforeTls=[int][Net.ServicePointManager]::SecurityProtocol
function Invoke-RestMethod {param($Uri,$Headers,[switch]$UseBasicParsing,$ErrorAction) [pscustomobject]@{tag_name='v99.9.9';assets=@([pscustomobject]@{name='screenconnect-cleanup-v99.9.9.zip';size=1;browser_download_url='https://example.invalid/fixture'})}}
function Invoke-WebRequest {throw 'A cached run must not download.'}
function Start-Process {throw 'Fixture must never launch cleanup.'}
$source=[IO.File]::ReadAllText($env:SCC_BOOTSTRAP_SOURCE)
# Change only default parameter values to invoke the literal iex path safely.
$source=$source.Replace("[string]`$Destination = ''",'[string]$Destination = $env:SCC_BOOTSTRAP_DEST')
$source=$source.Replace('[switch]$NoLaunch,','[switch]$NoLaunch = $true,')
Invoke-Expression $source
[pscustomobject]@{Continued=$true;ErrorPreference=[string]$ErrorActionPreference;ProgressPreference=[string]$ProgressPreference;TlsBefore=$beforeTls;TlsAfter=[int][Net.ServicePointManager]::SecurityProtocol}|ConvertTo-Json|Set-Content -LiteralPath $env:SCC_BOOTSTRAP_RESULT -Encoding UTF8
'@
    $harnessPath=Join-Path $temp 'harness.ps1';[IO.File]::WriteAllText($harnessPath,$harness,[Text.Encoding]::ASCII)
    $output=Join-Path $temp 'result.json'
    $psi=New-Object Diagnostics.ProcessStartInfo
    $psi.FileName=(Get-Process -Id $PID).Path
    $psi.Arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$harnessPath+'"'
    $psi.UseShellExecute=$false;$psi.RedirectStandardOutput=$true;$psi.RedirectStandardError=$true
    $psi.EnvironmentVariables['SCC_BOOTSTRAP_SOURCE']=Join-Path $SourceRoot 'install-latest.ps1'
    $psi.EnvironmentVariables['SCC_BOOTSTRAP_DEST']=$temp
    $psi.EnvironmentVariables['SCC_BOOTSTRAP_RESULT']=$output
    $p=[Diagnostics.Process]::Start($psi)
    try {
        $outTask=$p.StandardOutput.ReadToEndAsync();$errTask=$p.StandardError.ReadToEndAsync()
        if(-not $p.WaitForExit(15000)){$p.Kill();throw 'Bootstrap fixture exceeded its bound.'}
        if($p.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $output)){throw ('Cached iex bootstrap terminated the caller or failed: '+$outTask.Result+' '+$errTask.Result)}
        $result=Get-Content -LiteralPath $output -Raw -Encoding UTF8 | ConvertFrom-Json
        if(-not $result.Continued -or $result.ErrorPreference -ne 'Continue' -or $result.ProgressPreference -ne 'Continue'){throw 'Bootstrap changed the caller preferences or failed to return.'}
        if($CheckTls -and $env:OS -eq 'Windows_NT' -and $result.TlsBefore -ne $result.TlsAfter){throw 'Bootstrap leaked a static TLS protocol change into the caller session.'}
        Write-Host 'PASS: cached iex bootstrap returns to caller, keeps preferences, downloads nothing and launches nothing.'
        if($CheckTls){Write-Host ('NOTE: TLS baseline before='+$result.TlsBefore+' after='+$result.TlsAfter+' (the OR-in place is gated to real Windows: on Linux pwsh the enum set is empty so the numeric compare is meaningless); verify the Windows CI step instead.')}
    } finally {$p.Dispose()}
} finally {Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue}

# Replay both real report argument lists. On Windows, also execute the real
# Step 8 batch region with harmless child stubs and assert its process exit.
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$text=[IO.File]::ReadAllText((Join-Path $repo 'START-HERE.bat'))
$temp=Join-Path ([IO.Path]::GetTempPath()) ('scc-guided-diff-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $temp
try {
    $findings=Join-Path $temp 'findings.json';$diff=Join-Path $temp 'snapshot_diff.json'
    [IO.File]::WriteAllText($findings,'{"ComputerName":"Fixture","ScreenConnect":{"Instances":[],"Historical":[],"ParseIssues":[]},"OtherTargets":[]}')
    [IO.File]::WriteAllText($diff,'{"Verdict":"INCOMPLETE","BeforeCollectionComplete":true,"AfterCollectionComplete":false,"BeforeCollectionErrors":[],"AfterCollectionErrors":[{"Section":"Services","Error":"GUIDED_DIFF_FAILURE_SENTINEL"}],"Sections":[]}')
    $lines=@($text -split "`r?`n" | Where-Object {$_ -match '^\s*powershell .*New-InvestigationReport\.ps1'})
    if($lines.Count -ne 2){throw 'Expected both guided report branches.'}
    foreach($line in $lines) {
        $map=@{}
        foreach($m in [regex]::Matches($line,'-(\w+) "([^"]*)"')) {
            if($m.Groups[1].Value -eq 'File'){continue}
            $value=$m.Groups[2].Value.Replace('!FINDINGS_JSON!',$findings).Replace('!SCC_RUN_ROOT!',$temp)
            if([IO.Path]::DirectorySeparatorChar -eq '/'){$value=$value.Replace('\','/')}
            $map[$m.Groups[1].Value]=$value
        }
        if(-not $map.ContainsKey('DiffPath')){throw 'Guided report invocation drops the current-run snapshot diff.'}
        & (Join-Path $repo 'New-InvestigationReport.ps1') @map
        if(-not [IO.File]::ReadAllText($map.OutputPath).Contains('GUIDED_DIFF_FAILURE_SENTINEL')){throw 'Guided report failed to render collection failure evidence.'}
    }
    if([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        $region=[regex]::Match($text,'(?s)rem ---- Step 8:.*?(?=rem ---- Step 9:)').Value
        if(-not $region){throw 'Step 8 region not found.'}
        $stub=Join-Path $temp 'stub';$null=New-Item -ItemType Directory -Path $stub
        $stubScript=@'
$ErrorActionPreference='Stop'
$cli=@($args);$fileIndex=[array]::IndexOf($cli,'-File');$file=$cli[$fileIndex+1]
if($file -like '*collect-snapshot.ps1'){
    $i=[array]::IndexOf($cli,'-OutFile')
    if($env:SCC_FIXTURE_COLLECT_RC -eq '0'){[IO.File]::WriteAllText($cli[$i+1],'{}')}
    exit ([int]$env:SCC_FIXTURE_COLLECT_RC)
}
if($file -like '*diff-snapshots.ps1'){
    $i=[array]::IndexOf($cli,'-OutFile')
    [IO.File]::WriteAllText($cli[$i+1],'{"Verdict":"INCOMPLETE"}')
    exit ([int]$env:SCC_FIXTURE_DIFF_RC)
}
throw ('Fixture refused unexpected child: '+$file)
'@
        [IO.File]::WriteAllText((Join-Path $stub 'stub.ps1'),$stubScript,[Text.Encoding]::ASCII)
        $realHost=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        [IO.File]::WriteAllText((Join-Path $stub 'powershell.cmd'),('@echo off'+"`r`n"+'"'+$realHost+'" -NoProfile -ExecutionPolicy Bypass -File "%~dp0stub.ps1" %*'+"`r`n"+'exit /b %errorlevel%'+"`r`n"),[Text.Encoding]::ASCII)
        # A batch stub must be called explicitly to return to the real stage.
        # Substitute only the child launcher seam; preserve stage logic/arguments.
        $region=$region.Replace('powershell -NoProfile', ('call "'+(Join-Path $stub 'powershell.cmd')+'" -NoProfile'))
        $batch=Join-Path $temp 'step8.bat'
        foreach($scenario in @(@{Collect=4;Diff=0;Fail=$true},@{Collect=0;Diff=2;Fail=$true},@{Collect=0;Diff=1;Fail=$false},@{Collect=0;Diff=0;Fail=$false})) {
            $run=Join-Path $temp ([guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory -Path $run
            [IO.File]::WriteAllText((Join-Path $run 'snapshot_before.json'),'{}')
            $preamble='@echo off'+"`r`n"+'setlocal EnableDelayedExpansion'+"`r`n"+'set "SCC_DP0='+$repo+'\"'+"`r`n"+'set "SCC_RUN_ROOT='+$run+'"'+"`r`n"+'set "PIPE_RC=0"'+"`r`n"
            [IO.File]::WriteAllText($batch,($preamble+$region+"`r`nexit /b !PIPE_RC!`r`n"),[Text.Encoding]::ASCII)
            $psi=New-Object Diagnostics.ProcessStartInfo;$psi.FileName=$env:ComSpec;$psi.Arguments='/d /c ""'+$batch+'""';$psi.UseShellExecute=$false;$psi.RedirectStandardOutput=$true;$psi.RedirectStandardError=$true
            $psi.EnvironmentVariables['PATH']=$stub+';'+$env:PATH
            $psi.EnvironmentVariables['SCC_FIXTURE_COLLECT_RC']=[string]$scenario.Collect;$psi.EnvironmentVariables['SCC_FIXTURE_DIFF_RC']=[string]$scenario.Diff
            $p=New-Object Diagnostics.Process;$p.StartInfo=$psi
            try {
                if(-not $p.Start()){throw 'Batch fixture did not start.'}
                $stdout=$p.StandardOutput.ReadToEndAsync();$stderr=$p.StandardError.ReadToEndAsync()
                if(-not $p.WaitForExit(30000)){$p.Kill();throw 'Batch fixture timed out.'}
                if(($p.ExitCode -ne 0) -ne $scenario.Fail){throw ('Step 8 exit mismatch: collect='+$scenario.Collect+' diff='+$scenario.Diff+' exit='+$p.ExitCode+' '+$stdout.Result+' '+$stderr.Result)}
            } finally {$p.Dispose()}
        }
        Write-Host 'PASS: real Step 8 batch preserves collection/diff failure exits; resurrection remains a finding.'
    } else {Write-Host 'SKIP: batch execution requires Windows; both actual report argument lists were replayed.'}
    Write-Host 'PASS: both guided report branches include current-run comparison failure evidence.'
} finally {Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue}

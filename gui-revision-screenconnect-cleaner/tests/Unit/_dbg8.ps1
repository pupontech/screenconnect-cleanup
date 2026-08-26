$ErrorActionPreference = "Stop"
Import-Module "/root/screenconnect-cleanup/gui-revision-screenconnect-cleaner/src/Scc.Remedy/Scc.Remedy.psd1" -Force -ErrorAction Stop
$run = [PSCustomObject]@{ RunId='TESTRUN'; RunDir=(Join-Path ([System.IO.Path]::GetTempPath()) ('dbg_'+[guid]::NewGuid().ToString('N'))) }
New-Item -ItemType Directory -Path $run.RunDir -Force | Out-Null
$mp = Join-Path $run.RunDir 'Quarantine' 'quarantine-manifest.json'
$qd = Join-Path $run.RunDir 'Quarantine'; New-Item -ItemType Directory -Path $qd -Force | Out-Null
$entry = [PSCustomObject]@{ ItemId='aaaa'; OriginalPath='/x'; QuarantinePath='/y' }
[System.IO.File]::WriteAllText($mp, (ConvertTo-Json -InputObject @($entry) -Compress -Depth 10), [System.Text.Encoding]::ASCII)
Write-Host "before: $([System.IO.File]::ReadAllText($mp))"
Remove-SccQuarantineManifestEntry -Run $run -ItemId 'aaaa'
Write-Host "after: $([System.IO.File]::ReadAllText($mp))"
Remove-Item -Path $run.RunDir -Recurse -Force -ErrorAction SilentlyContinue

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$modulePath = Join-Path $repo 'Persistence.Removal.psm1'
$root = Join-Path ([IO.Path]::GetTempPath()) ('scc-removal-test-' + [guid]::NewGuid().ToString('N'))
$startup = Join-Path $root 'startup-fixture'
$out = Join-Path $root 'persistence'
$failures = 0
function Check([bool]$ok,[string]$message) { if ($ok) { Write-Host "PASS: $message" } else { Write-Host "FAIL: $message"; $script:failures++ } }
function New-Row([string]$Kind,[string]$Target,$Details,[bool]$ReviewOnly=$false) {
    $identity=$Kind+'|'+$Target; $sha=[Security.Cryptography.SHA256]::Create()
    try { $id=([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($identity)))).Replace('-','').Substring(0,24) } finally { $sha.Dispose() }
    return [pscustomobject]@{Id=$id;Kind=$Kind;Target=$Target;Command='fixture command';Reason='synthetic test';ReviewOnly=$ReviewOnly;Details=$Details}
}
function New-Inventory($Rows) {
    return [pscustomobject]@{SchemaVersion=1;Status='Complete';RunId=(Split-Path -Leaf $root);Findings=@($Rows);Sections=[pscustomobject]@{
        ScheduledTasks=[pscustomobject]@{Status='Complete';Errors=@()}
        TaskXml=[pscustomobject]@{Status='Complete';Errors=@()}
        RunKeys=[pscustomobject]@{Status='Complete';Errors=@()}
        StartupFiles=[pscustomobject]@{Status='Complete';Errors=@()}
        ScriptFiles=[pscustomobject]@{Status='Complete';Errors=@()}
    }}
}
function Set-Approval { function global:Read-Host { param([string]$Prompt) if ($Prompt -like 'Type REMOVE*') { 'REMOVE' } else { '1' } } }
try {
    $null=New-Item -ItemType Directory -Path $startup -Force
    $null=New-Item -ItemType Directory -Path $out -Force
    Import-Module $modulePath -Force
    $module=Get-Module Persistence.Removal
    $xml='<Task><Actions>fixture</Actions></Task>'
    $xmlHash=([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($xml)))).Replace('-','')
    $state=@{TaskPresent=$true;TaskXml=$xml;RegPresent=$true;RegValue='%TEMP%\agent.exe';RegKind='ExpandString';DenyReadback=$false;CopyFails=$false;Hardlink=$false;RemoveCalls=0;TaskRemoveCalls=0;RegistryRemoveCalls=0;MoveCalls=0}
    $task=New-Row 'ScheduledTask' '\Fixture\Fixture' ([pscustomobject]@{TaskName='Fixture';TaskPath='\Fixture\';XmlSha256=$xmlHash})
    $microsoft=New-Row 'ScheduledTask' '\Microsoft\Windows\Fixture' ([pscustomobject]@{TaskName='Fixture';TaskPath='\Microsoft\Windows\';XmlSha256=$xmlHash}) $true
    $registryPath='Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run'
    $reg=New-Row 'RunKey' ($registryPath+'|Agent') ([pscustomobject]@{RegistryPath=$registryPath;ValueName='Agent';OriginalValue='%TEMP%\agent.exe';ValueKind='ExpandString'})
    $sid='S-1-5-21-111-222-333-1001'
    $sidPath='Registry::HKEY_USERS\'+$sid+'\Software\Microsoft\Windows\CurrentVersion\Run'
    $sidReg=New-Row 'RunKey' ($sidPath+'|Agent') ([pscustomobject]@{RegistryPath=$sidPath;ValueName='Agent';OriginalValue='%TEMP%\agent.exe';ValueKind='ExpandString'})
    $hooks=@{
        GetTasks={ if ($state.TaskPresent) { ,([pscustomobject]@{TaskName='Fixture';TaskPath='\Fixture\'}) } }.GetNewClosure()
        ExportTask={ param($n,$p) $state.TaskXml }.GetNewClosure()
        RemoveTask={ param($n,$p) $state.TaskPresent=$false;$state.TaskRemoveCalls++;$state.RemoveCalls++ }.GetNewClosure()
        GetRegistry={ param($p,$n) if (-not $state.RegPresent) { throw 'Value absent' }; [pscustomobject]@{Value=$state.RegValue;Kind=$state.RegKind} }.GetNewClosure()
        RemoveRegistry={ param($p,$n) $state.RegPresent=$false;$state.RegistryRemoveCalls++;$state.RemoveCalls++ }.GetNewClosure()
        CheckRegistry={ param($p,$n) if ($state.DenyReadback) { throw 'Access denied during readback' }; $state.RegPresent }.GetNewClosure()
        CopyFile={ param($src,$dst) if ($state.CopyFails) { throw 'Synthetic backup failure' }; [IO.File]::Copy($src,$dst,$false) }.GetNewClosure()
        MoveFile={ param($src,$dst) if (Test-Path -LiteralPath $dst) { throw 'Destination exists' }; [IO.File]::Move($src,$dst);$state.MoveCalls++ }.GetNewClosure()
        LinkCount={ param($p) if ($state.Hardlink -and [string]::Equals($p,$state.HardlinkPath,[StringComparison]::OrdinalIgnoreCase)) { 2 } else { 1 } }.GetNewClosure()
    }
    & $module { param($h) $script:TestHooks=$h } $hooks
    & $module { param($r) $script:StartupRootOverride=@($r) } $startup

    $partial=New-Inventory @($task);$partial.Status='Incomplete';$partial.Sections.ScheduledTasks.Status='Incomplete'
    Set-Approval
    $partialResult=Invoke-SccPersistenceReview -Inventory $partial -OutDir $out -AllowRemoval $true
    Remove-Item Function:\global:Read-Host -ErrorAction SilentlyContinue
    if($partialResult.Status -ne 'Incomplete' -or $state.RemoveCalls -ne 0){throw 'Incomplete relevant task collection authorized a mutation despite typed approval.'}
    Write-Host 'PASS: incomplete relevant collection cannot authorize selected cleanup'
    $missingErrors=New-Inventory @($task);$missingErrors.Sections.ScheduledTasks.PSObject.Properties.Remove('Errors')
    Set-Approval
    $missingResult=Invoke-SccPersistenceReview -Inventory $missingErrors -OutDir $out -AllowRemoval $true
    Remove-Item Function:\global:Read-Host -ErrorAction SilentlyContinue
    if($missingResult.Status -ne 'Incomplete' -or $state.RemoveCalls -ne 0){throw 'Missing category Errors metadata authorized mutation despite typed approval.'}
    Write-Host 'PASS: missing source-category error metadata cannot authorize cleanup'

    $r=Invoke-SccPersistenceReview -Inventory (New-Inventory @($task)) -OutDir $out -AllowRemoval $true -NoPrompt
    Check ($r.Status -eq 'Declined' -and $state.RemoveCalls -eq 0) 'NoPrompt cannot approve from inventory alone'
    $r=Invoke-SccPersistenceReview -Inventory (New-Inventory @($task)) -OutDir $out -AllowRemoval $false
    Check ($r.Status -eq 'Skipped' -and $state.RemoveCalls -eq 0) 'AllowRemoval false never mutates'
    $r=Invoke-SccPersistenceReview -Inventory (New-Inventory @($task)) -OutDir $out -AllowRemoval 'true' -NoPrompt
    Check ($r.Status -eq 'Incomplete' -and $state.RemoveCalls -eq 0) 'non-Boolean AllowRemoval is refused without mutation'
    $wrongRun=New-Inventory @($task); $wrongRun.RunId='another-run'
    $r=Invoke-SccPersistenceReview -Inventory $wrongRun -OutDir $out -AllowRemoval $true -NoPrompt
    Check ($r.Status -eq 'Incomplete' -and $state.RemoveCalls -eq 0) 'inventory from a different run cannot authorize removal'
    $r=Invoke-SccPersistenceReview -Inventory (New-Inventory @($microsoft,$task)) -OutDir $out -AllowRemoval $true -NoPrompt
    Check ($r.Status -eq 'Declined' -and $r.Errors.Count -eq 0) 'literal ReviewOnly Microsoft task is skipped without blocking valid candidate'
    $badReview=New-Row 'ScheduledTask' '\Fixture\BadReview' ([pscustomobject]@{TaskName='BadReview';TaskPath='\Fixture\';XmlSha256=$xmlHash})
    $badReview.PSObject.Properties.Remove('ReviewOnly')
    $r=Invoke-SccPersistenceReview -Inventory (New-Inventory @($badReview)) -OutDir $out -AllowRemoval $true -NoPrompt
    Check ($r.Status -eq 'Incomplete' -and $r.Errors.Count -gt 0) 'missing ReviewOnly type is refused'

    $wild=New-Row 'ScheduledTask' '\Fixture\*' ([pscustomobject]@{TaskName='*';TaskPath='\Fixture\';XmlSha256=$xmlHash})
    $r=Invoke-SccPersistenceReview -Inventory (New-Inventory @($wild)) -OutDir $out -AllowRemoval $true
    Check ($r.Status -eq 'Incomplete' -and $r.Actions.Count -eq 0) 'wildcard task target is refused'
    $outside=New-Row 'RunKey' ('Registry::HKEY_CURRENT_USER\Software\Vendor\Run|Agent') ([pscustomobject]@{RegistryPath='Registry::HKEY_CURRENT_USER\Software\Vendor\Run';ValueName='Agent';OriginalValue='x';ValueKind='String'})
    $r=Invoke-SccPersistenceReview -Inventory (New-Inventory @($outside)) -OutDir $out -AllowRemoval $true
    Check ($r.Status -eq 'Incomplete' -and $state.RemoveCalls -eq 0) 'registry key outside exact allowlist is refused'

    $deniedReg=New-Row 'RunKey' ($registryPath+'|Denied') ([pscustomobject]@{RegistryPath=$registryPath;ValueName='Denied';OriginalValue='%TEMP%\agent.exe';ValueKind='ExpandString'})
    $state.DenyReadback=$true; $state.RegPresent=$true; Set-Approval
    $r=Invoke-SccPersistenceReview -Inventory (New-Inventory @($deniedReg)) -OutDir $out -AllowRemoval $true
    Check ($r.Status -eq 'Incomplete' -and $r.Actions[0].Status -eq 'Failed' -and $state.RegistryRemoveCalls -eq 1) 'registry readback denial fails after mocked removal'
    Remove-Item Function:\global:Read-Host -ErrorAction SilentlyContinue
    $state.DenyReadback=$false; $state.RegPresent=$true; $state.RegistryRemoveCalls=0

    function global:Read-Host { param([string]$Prompt) '2147483648' }
    $before=$state.RemoveCalls
    $r=Invoke-SccPersistenceReview -Inventory (New-Inventory @($task)) -OutDir $out -AllowRemoval $true
    Check ($r.Status -eq 'Declined' -and $state.RemoveCalls -eq $before) 'overflow selection declines with zero mutations'
    Remove-Item Function:\global:Read-Host -ErrorAction SilentlyContinue
    function global:Read-Host { param([string]$Prompt) throw 'EOF' }
    $r=Invoke-SccPersistenceReview -Inventory (New-Inventory @($task)) -OutDir $out -AllowRemoval $true
    Check ($r.Status -eq 'Declined' -and $state.RemoveCalls -eq $before) 'prompt exception/EOF declines with zero mutations'
    Remove-Item Function:\global:Read-Host -ErrorAction SilentlyContinue

    $state.TaskPresent=$true; $state.TaskXml='<Task><Actions>changed</Actions></Task>'; Set-Approval
    $r=Invoke-SccPersistenceReview -Inventory (New-Inventory @($task)) -OutDir $out -AllowRemoval $true
    Check ($r.Status -eq 'Incomplete' -and $state.TaskRemoveCalls -eq 0 -and $state.TaskPresent) 'stale scheduled-task XML is refused before unregister'
    Remove-Item Function:\global:Read-Host -ErrorAction SilentlyContinue
    $state.TaskXml=$xml; $state.TaskPresent=$true; function global:Read-Host { param([string]$Prompt) if ($Prompt -like 'Type REMOVE*') { 'REMOVE' } else { '1' } }
    $contextGap=New-Inventory @($microsoft,$task);$contextGap.Status='Incomplete';$contextGap.Sections.ScriptFiles.Status='Incomplete'
    $r=Invoke-SccPersistenceReview -Inventory $contextGap -OutDir $out -AllowRemoval $true
    Check ($r.Status -eq 'Completed' -and $r.Actions.Count -eq 1 -and $state.TaskRemoveCalls -eq 1 -and (Test-Path $r.Actions[0].BackupPath) -and -not $state.TaskPresent) 'complete task evidence allows exact mocked cleanup despite unrelated context gap'
    Remove-Item Function:\global:Read-Host -ErrorAction SilentlyContinue

    $state.RegPresent=$true; function global:Read-Host { param([string]$Prompt) if ($Prompt -like 'Type REMOVE*') { 'REMOVE' } else { '1' } }
    $r=Invoke-SccPersistenceReview -Inventory (New-Inventory @($reg)) -OutDir $out -AllowRemoval $true
    Check ($r.Status -eq 'Completed' -and $state.RegistryRemoveCalls -eq 1 -and -not $state.RegPresent -and (Test-Path $r.Actions[0].BackupPath)) 'ExpandString Run value success preserves literal percent-variable value'
    Remove-Item Function:\global:Read-Host -ErrorAction SilentlyContinue
    $state.RegPresent=$true; $state.RegistryRemoveCalls=0; function global:Read-Host { param([string]$Prompt) if ($Prompt -like 'Type REMOVE*') { 'REMOVE' } else { '1' } }
    $r=Invoke-SccPersistenceReview -Inventory (New-Inventory @($sidReg)) -OutDir $out -AllowRemoval $true
    Check ($r.Status -eq 'Completed' -and $state.RegistryRemoveCalls -eq 1) 'four-component user SID Run key is allowlisted and mocked successfully'
    Remove-Item Function:\global:Read-Host -ErrorAction SilentlyContinue

    $dup=New-Row 'RunKey' ($registryPath+'|Duplicate') ([pscustomobject]@{RegistryPath=$registryPath;ValueName='Duplicate';OriginalValue='x';ValueKind='String'})
    $r=Invoke-SccPersistenceReview -Inventory (New-Inventory @($dup,$dup)) -OutDir $out -AllowRemoval $true
    Check ($r.Status -eq 'Incomplete' -and $r.Errors.Count -gt 0) 'duplicate finding IDs cause explicit refusal'

    $state.CopyFails=$true
    $file=Join-Path $startup 'backup-failure.txt'; [IO.File]::WriteAllText($file,'startup fixture')
    $fileRow=New-Row 'StartupFile' $file ([pscustomobject]@{FilePath=$file;SHA256=(Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash})
    function global:Read-Host { param([string]$Prompt) if ($Prompt -like 'Type REMOVE*') { 'REMOVE' } else { '1' } }
    $r=Invoke-SccPersistenceReview -Inventory (New-Inventory @($fileRow)) -OutDir $out -AllowRemoval $true
    Check ($r.Status -eq 'Incomplete' -and (Test-Path $file)) 'backup failure leaves startup source untouched'
    Remove-Item Function:\global:Read-Host -ErrorAction SilentlyContinue
    $state.CopyFails=$false; $state.Hardlink=$true
    $hard=Join-Path $startup 'hardlink.txt'; [IO.File]::WriteAllText($hard,'hardlink fixture')
    $state.HardlinkPath=$hard
    $hardRow=New-Row 'StartupFile' $hard ([pscustomobject]@{FilePath=$hard;SHA256=(Get-FileHash -LiteralPath $hard -Algorithm SHA256).Hash})
    function global:Read-Host { param([string]$Prompt) if ($Prompt -like 'Type REMOVE*') { 'REMOVE' } else { '1' } }
    $r=Invoke-SccPersistenceReview -Inventory (New-Inventory @($hardRow)) -OutDir $out -AllowRemoval $true
    Check ($r.Status -eq 'Incomplete' -and (Test-Path $hard)) 'hard-linked startup file is refused'
    Remove-Item Function:\global:Read-Host -ErrorAction SilentlyContinue; $state.Hardlink=$false

    $collision=Join-Path $startup 'collision.txt'; [IO.File]::WriteAllText($collision,'collision fixture')
    $collisionRow=New-Row 'StartupFile' $collision ([pscustomobject]@{FilePath=$collision;SHA256=(Get-FileHash -LiteralPath $collision -Algorithm SHA256).Hash})
    $dest=Join-Path (Join-Path $out 'quarantine') ($collisionRow.Id+'-'+[IO.Path]::GetFileName($collision)); $null=New-Item -ItemType Directory -Path (Split-Path -Parent $dest) -Force; [IO.File]::WriteAllText($dest,'do not overwrite')
    function global:Read-Host { param([string]$Prompt) if ($Prompt -like 'Type REMOVE*') { 'REMOVE' } else { '1' } }
    $r=Invoke-SccPersistenceReview -Inventory (New-Inventory @($collisionRow)) -OutDir $out -AllowRemoval $true
    Check ($r.Status -eq 'Incomplete' -and (Test-Path $collision) -and [IO.File]::ReadAllText($dest) -eq 'do not overwrite') 'quarantine collision refuses overwrite'
    Remove-Item Function:\global:Read-Host -ErrorAction SilentlyContinue

    $startupSuccess=Join-Path $startup 'quarantine-success.txt'; [IO.File]::WriteAllText($startupSuccess,'startup success fixture')
    $startupRow=New-Row 'StartupFile' $startupSuccess ([pscustomobject]@{FilePath=$startupSuccess;SHA256=(Get-FileHash -LiteralPath $startupSuccess -Algorithm SHA256).Hash})
    function global:Read-Host { param([string]$Prompt) if ($Prompt -like 'Type REMOVE*') { 'REMOVE' } else { '1' } }
    $r=Invoke-SccPersistenceReview -Inventory (New-Inventory @($startupRow)) -OutDir $out -AllowRemoval $true
    $quarantined=Join-Path (Join-Path $out 'quarantine') ($startupRow.Id+'-'+[IO.Path]::GetFileName($startupSuccess))
    Check ($r.Status -eq 'Completed' -and $state.MoveCalls -eq 1 -and -not (Test-Path $startupSuccess) -and (Test-Path $quarantined) -and (Get-FileHash $quarantined -Algorithm SHA256).Hash -eq $startupRow.Details.SHA256) 'startup fixture is copied, verified, moved, and read back'
    Remove-Item Function:\global:Read-Host -ErrorAction SilentlyContinue

    $previous=@(Get-ChildItem -LiteralPath $out -Filter 'removal.previous.*.json' -File).Count
    $r=Invoke-SccPersistenceReview -Inventory (New-Inventory @()) -OutDir $out -AllowRemoval $false
    $after=@(Get-ChildItem -LiteralPath $out -Filter 'removal.previous.*.json' -File).Count
    Check ($r.Status -eq 'NoCandidates' -and $after -eq ($previous+1)) 'prior removal report is archived instead of overwritten'
    $report=Join-Path $out 'removal.json'; $held=Join-Path $out 'removal.saved.json'; [IO.File]::Move($report,$held)
    try {
        $target=Join-Path $out 'safe-target.json'; [IO.File]::WriteAllText($target,'safe fixture')
        $null=New-Item -ItemType SymbolicLink -Path $report -Target $target -ErrorAction Stop
        $blocked=$false
        try { $null=Invoke-SccPersistenceReview -Inventory (New-Inventory @()) -OutDir $out -AllowRemoval $false } catch { $blocked=$true }
        Check ($blocked -and (Test-Path -LiteralPath $report) -and [IO.File]::ReadAllText($held).Length -gt 0) 'reparse-point removal.json is rejected before review'
    } catch { Write-Host 'SKIP: removal.json symlink fixture unavailable on this host' }
    & $module { $script:TestHooks=$null; $script:StartupRootOverride=$null }
} finally {
    Remove-Item Function:\global:Read-Host -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
}
if ($failures -gt 0) { throw "$failures persistence removal regression(s) failed" }
Write-Host 'Persistence removal regression tests passed.'

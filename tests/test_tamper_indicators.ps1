# Fixture tests for the review-only tampering indicators (AutoHotkey, UAC policy,
# UAC-bypass hijack keys, out-of-place ScreenConnect binaries) added in inventory
# schema 2. No live registry value is changed and no bypass is ever exercised:
# registry readers are injected, files are synthetic bytes in a temp folder.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'Persistence.Inventory.psm1') -Force
Import-Module (Join-Path $root 'Persistence.Removal.psm1') -Force
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('scc-indicator-fixture-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $tmp
$script:passed = 0
function Check { param([bool]$Condition,[string]$Name) if(-not $Condition){throw ('FAIL: '+$Name)}; $script:passed++; Write-Host ('  ok  '+$Name) }
try {
    $module = Get-Module Persistence.Inventory
    $result = & $module {
        param($fixtureDir)
        $checks = New-Object System.Collections.ArrayList
        function Add-Check { param([bool]$c,[string]$n) [void]$checks.Add([pscustomobject]@{Ok=$c;Name=$n}) }

        # ---- UAC policy -------------------------------------------------------
        $weak = Get-SccUacPolicyEvidence -ValueReader { param($p) @{EnableLUA=0;ConsentPromptBehaviorAdmin=0;PromptOnSecureDesktop=1} }
        Add-Check ($weak.Findings.Count -eq 2) 'UAC: EnableLUA=0 and ConsentPromptBehaviorAdmin=0 are both flagged'
        Add-Check (@($weak.Findings | Where-Object { $_.Kind -ne 'UacPolicy' -or $_.ReviewOnly -ne $true }).Count -eq 0) 'UAC: findings are UacPolicy and review-only'
        Add-Check (@($weak.Findings | Where-Object { $_.Id -ne (Get-SccStableId $_.Kind $_.Target) }).Count -eq 0) 'UAC: finding ids are the Kind|Target hash'
        Add-Check ($weak.Items.Count -eq 6) 'UAC: every policy value is recorded'
        $ltfp = @($weak.Items | Where-Object { $_.Name -eq 'LocalAccountTokenFilterPolicy' })[0]
        Add-Check ($null -eq $ltfp.Value -and $ltfp.Effective -eq 0 -and -not $ltfp.Weakened) 'UAC: a missing value reads as the Windows default'
        $defaults = Get-SccUacPolicyEvidence -ValueReader { param($p) @{} }
        Add-Check ($defaults.Findings.Count -eq 0 -and $defaults.Errors.Count -eq 0) 'UAC: Windows defaults produce no findings'
        $absent = Get-SccUacPolicyEvidence -ValueReader { param($p) $null }
        Add-Check ($absent.Findings.Count -eq 0) 'UAC: a missing policy key produces no findings'
        $remote = Get-SccUacPolicyEvidence -ValueReader { param($p) @{LocalAccountTokenFilterPolicy=1;PromptOnSecureDesktop=0} }
        Add-Check ($remote.Findings.Count -eq 2) 'UAC: LocalAccountTokenFilterPolicy=1 and PromptOnSecureDesktop=0 are flagged'
        $denied = Get-SccUacPolicyEvidence -ValueReader { param($p) throw 'access denied fixture' }
        Add-Check ($denied.Errors.Count -eq 1 -and $denied.Findings.Count -eq 0) 'UAC: a read failure is recorded, not treated as clean'

        # ---- UAC-bypass hijack keys -------------------------------------------
        $profiles = @(
            [pscustomobject]@{Sid='S-1-5-21-1-2-3-1001';Name='alice';Root='Registry::HKEY_USERS\S-1-5-21-1-2-3-1001';Loaded=$true;ProfilePath='C:\Users\alice'}
            [pscustomobject]@{Sid='S-1-5-21-1-2-3-1002';Name='bob';Root='Registry::HKEY_USERS\S-1-5-21-1-2-3-1002';Loaded=$false;ProfilePath='C:\Users\bob'}
        )
        $script:Queried = New-Object System.Collections.ArrayList
        $hijack = Get-SccUacBypassEvidence -Profiles $profiles -KeyReader {
            param($p) [void]$script:Queried.Add($p)
            if($p -like '*\ms-settings\shell\open\command'){ return @{''='C:\Users\Public\x.exe';DelegateExecute=''} }
            if($p -like '*\Environment'){ return @{windir='cmd /c C:\Users\Public\x.exe &&';TEMP='C:\Temp'} }
            return $null
        }
        Add-Check ($hijack.Findings.Count -eq 2) 'Bypass: ms-settings command key and windir override are flagged'
        Add-Check (@($hijack.Findings | Where-Object { $_.Kind -ne 'UacBypassHijack' -or $_.ReviewOnly -ne $true }).Count -eq 0) 'Bypass: findings are UacBypassHijack and review-only'
        Add-Check (@($hijack.Findings | Where-Object { $_.Command -like '*DelegateExecute*' }).Count -eq 1) 'Bypass: DelegateExecute is reported'
        Add-Check (@($script:Queried | Where-Object { $_ -like '*1002*' }).Count -eq 0) 'Bypass: unloaded profiles are not queried'
        Add-Check (@($hijack.Findings | Where-Object { $_.Target -like '*TEMP*' }).Count -eq 0) 'Bypass: ordinary environment values are ignored'
        $clean = Get-SccUacBypassEvidence -Profiles $profiles -KeyReader { param($p) if($p -like '*\Environment'){ @{TEMP='x'} } else { $null } }
        Add-Check ($clean.Findings.Count -eq 0 -and $clean.Errors.Count -eq 0) 'Bypass: a clean profile produces no findings'

        # ---- Bounded user-writable binary walk --------------------------------
        $userRoot = Join-Path $fixtureDir 'profile'
        $mz = [byte[]](0x4D,0x5A,0x90,0x00)
        function New-Fixture { param([string]$Rel,[byte[]]$Bytes) $p = Join-Path $userRoot $Rel; $null = New-Item -ItemType Directory -Force -Path (Split-Path -Parent $p); [IO.File]::WriteAllBytes($p,$Bytes); $p }
        $marker = $mz + [Text.Encoding]::Unicode.GetBytes('RCDATA >AUTOHOTKEY SCRIPT< x')
        $interp = New-Fixture 'AppData\Roaming\tools\AutoHotkey64.exe' $mz
        $compiled = New-Fixture 'AppData\Roaming\upd\invoice.exe' $marker
        $script1 = New-Fixture 'Downloads\run.ahk' ([Text.Encoding]::ASCII.GetBytes('Run calc'))
        $cleanExe = New-Fixture 'Desktop\clean.exe' $mz
        $scExe = New-Fixture 'Downloads\support.exe' $mz
        $noise = New-Fixture 'AppData\Roaming\node_modules\pkg\x.ahk' $mz
        $deep = New-Fixture 'AppData\Roaming\a\b\c\d\e\deep.ahk' $mz
        $roots = @([pscustomobject]@{Path=$userRoot;MaxDepth=6})
        $versionReader = { param($p) if($p -like '*support.exe'){ [pscustomobject]@{ProductName='ScreenConnect';CompanyName='ConnectWise';FileDescription='ScreenConnect Client'} } else { [pscustomobject]@{ProductName='';CompanyName='';FileDescription=''} } }
        $walk = Get-SccUserWritableBinaryEvidence -Roots $roots -MaxFiles 100 -MaxSeconds 30 -VersionReader $versionReader
        $paths = @($walk.Items | ForEach-Object { $_.Path })
        Add-Check ($paths -contains $interp) 'Walk: AutoHotkey interpreter is flagged by name'
        Add-Check ($paths -contains $compiled) 'Walk: renamed compiled AutoHotkey exe is flagged by its resource marker'
        Add-Check ($paths -contains $script1) 'Walk: .ahk script is flagged'
        Add-Check ($paths -notcontains $cleanExe) 'Walk: an ordinary exe is not flagged'
        Add-Check ($paths -notcontains $noise) 'Walk: noise folders are skipped'
        Add-Check (@($walk.Items | Where-Object { $_.Path -eq $scExe -and $_.Kind -eq 'ScreenConnectOutsideInstall' }).Count -eq 1) 'Walk: ScreenConnect binary outside Program Files is flagged'
        Add-Check (@($walk.Findings | Where-Object { $_.ReviewOnly -ne $true -or $_.Id -ne (Get-SccStableId $_.Kind $_.Target) }).Count -eq 0) 'Walk: findings are review-only with Kind|Target ids'
        Add-Check (-not $walk.Truncated -and $walk.Errors.Count -eq 0) 'Walk: complete when under the caps'
        Add-Check (@($walk.Items | Where-Object { -not $_.SHA256 }).Count -eq 0) 'Walk: hits carry a SHA-256'
        $shallow = Get-SccUserWritableBinaryEvidence -Roots @([pscustomobject]@{Path=$userRoot;MaxDepth=4}) -MaxFiles 100 -MaxSeconds 30 -VersionReader $versionReader
        Add-Check (@($shallow.Items | ForEach-Object { $_.Path }) -notcontains $deep) 'Walk: the per-root depth limit is honoured'
        $capped = Get-SccUserWritableBinaryEvidence -Roots $roots -MaxFiles 1 -MaxSeconds 30 -VersionReader $versionReader
        Add-Check ($capped.Truncated -and $capped.Limits.Examined -eq 1) 'Walk: the file cap reports truncation'
        $slowRoots = @([pscustomobject]@{Path='slow';MaxDepth=1},[pscustomobject]@{Path='fast';MaxDepth=1})
        $share = Get-SccUserWritableBinaryEvidence -Roots $slowRoots -MaxFiles 100 -MaxSeconds 2 -DirectoryReader { param($d) if($d -like 'slow*'){ Start-Sleep -Milliseconds 1500; return @(New-Object IO.DirectoryInfo (Join-Path $d 'sub')) }; @() }
        Add-Check ($share.Truncated -and @($share.Limits.TruncatedRoots) -contains 'slow' -and @($share.Limits.TruncatedRoots) -notcontains 'fast') 'Walk: a slow root is cut and named without starving the next root'
        $saved = $script:IndicatorMaxScanBytes
        try {
            $script:IndicatorMaxScanBytes = 2
            $big = Get-SccUserWritableBinaryEvidence -Roots $roots -MaxFiles 100 -MaxSeconds 30 -VersionReader $versionReader
            Add-Check (@($big.Items | ForEach-Object { $_.Path }) -notcontains $compiled) 'Walk: files over the scan-size limit are not byte-scanned'
        } finally { $script:IndicatorMaxScanBytes = $saved }
        $deniedWalk = Get-SccUserWritableBinaryEvidence -Roots @([pscustomobject]@{Path='mock';MaxDepth=2}) -DirectoryReader { param($d) throw 'access denied fixture' }
        Add-Check ($deniedWalk.Errors.Count -eq 1) 'Walk: directory access errors are recorded'
        $profileRoots = @(Get-SccUserWritableRoots -Profiles @([pscustomobject]@{ProfilePath=$userRoot}))
        Add-Check (@($profileRoots | Where-Object { $_.Path -like ($userRoot+'*') }).Count -eq 3) 'Walk: existing profile folders become roots'

        # ---- AutoHotkey autostart cross-reference ----------------------------
        $auto = Get-SccAutoHotkeyAutostartEvidence -RunKeys @([pscustomobject]@{RegistryPath='Registry::HKEY_USERS\S\Software\Microsoft\Windows\CurrentVersion\Run';ValueName='Helper';OriginalValue='"C:\Tools\AutoHotkey64.exe" C:\Tools\a.ahk'}) -Tasks @([pscustomobject]@{TaskPath='\';TaskName='Upd';Command=($compiled+' /silent')}, [pscustomobject]@{TaskPath='\';TaskName='Ok';Command='C:\Windows\System32\notepad.exe'}) -Services @([pscustomobject]@{Name='Spooler';PathName='C:\Windows\System32\spoolsv.exe'}) -KnownPaths @($compiled)
        Add-Check ($auto.Findings.Count -eq 2) 'Autostart: AutoHotkey Run key and task launching a compiled AHK file are flagged'
        Add-Check (@($auto.Findings | Where-Object { $_.Kind -ne 'AutoHotkeyAutostart' -or $_.ReviewOnly -ne $true }).Count -eq 0) 'Autostart: findings are review-only'

        # ---- Whole inventory: schema 2, warnings do not flip global status ---
        function Get-ScheduledTask { }
        function Get-SccRegistryEvidence { [pscustomobject]@{Items=@();Findings=@();Errors=@();ProfileErrors=@()} }
        function Get-SccStartupEvidence { [pscustomobject]@{Items=@();Findings=@();Errors=@()} }
        function Get-SccHiddenTaskEvidence { [pscustomobject]@{Items=@();Errors=@()} }
        function Get-SccGenericEvidence { [pscustomobject]@{Items=@();Errors=@()} }
        function Get-SccBoundedScriptFiles { [pscustomobject]@{Items=@();Errors=@();Truncated=$false;Limits=$null} }
        function Get-SccProfileRoots { [pscustomobject]@{Profiles=@();Errors=@()} }
        $script:UacFixture = $weak; function Get-SccUacPolicyEvidence { $script:UacFixture }
        $script:BypassFixture = $hijack; function Get-SccUacBypassEvidence { $script:BypassFixture }
        $script:WalkFixture = [pscustomobject]@{Items=$walk.Items;Findings=$walk.Findings;Errors=@();Truncated=$true;Limits=[pscustomobject]@{TruncatedRoots=@('fixture-cut-root')}}; function Get-SccUserWritableBinaryEvidence { $script:WalkFixture }
        function Get-SccUserWritableRoots { @() }
        $out = Join-Path (Join-Path $fixtureDir 'indicator-run') 'persistence'
        $inv = Get-SccPersistenceInventory -OutDir $out
        $saved = [IO.File]::ReadAllText((Join-Path $out 'inventory.json')) | ConvertFrom-Json
        Add-Check ([int]$saved.SchemaVersion -eq 2) 'Inventory: schema version is 2'
        Add-Check ($saved.Status -eq 'Complete') 'Inventory: a truncated indicator scan does not flip the global status'
        Add-Check (@($saved.Warnings | Where-Object { $_ -like '*AutoHotkey scan truncated*fixture*' }).Count -eq 1) 'Inventory: truncation and the cut roots are recorded in Warnings'
        Add-Check ($saved.Sections.UserWritableBinaries.Status -eq 'Incomplete') 'Inventory: the truncated section still says Incomplete'
        foreach($k in @('UacPolicy','UacBypassHijack','AutoHotkey')) { Add-Check (@($saved.Findings | Where-Object { $_.Kind -eq $k }).Count -ge 1) ('Inventory: '+$k+' findings reach inventory.json') }
        foreach($s in @('UacPolicy','UacBypassKeys','UserWritableBinaries','AutoHotkeyAutostart')) { Add-Check ($null -ne $saved.Sections.PSObject.Properties[$s]) ('Inventory: section '+$s+' is present') }
        [pscustomobject]@{Checks=@($checks.ToArray());InventoryPath=(Join-Path $out 'inventory.json');Out=$out}
    } $tmp
    foreach($c in $result.Checks){ Check $c.Ok $c.Name }

    # ---- Removal never offers the indicator kinds ----------------------------
    $inv = [IO.File]::ReadAllText($result.InventoryPath) | ConvertFrom-Json
    $review = Invoke-SccPersistenceReview -Inventory $inv -OutDir $result.Out -AllowRemoval $true -NoPrompt
    Check ($review.Status -eq 'NoCandidates' -and @($review.Errors).Count -eq 0) 'Removal: indicator findings are never removal candidates'
    $oldDir = Join-Path (Join-Path $tmp 'old-run') 'persistence'
    $null = New-Item -ItemType Directory -Force -Path $oldDir
    $old = [pscustomobject]@{SchemaVersion=1;RunId='old-run';Status='Complete';Errors=@();Findings=@();Sections=[pscustomobject]@{}}
    $oldReview = Invoke-SccPersistenceReview -Inventory $old -OutDir $oldDir -AllowRemoval $true -NoPrompt
    Check ($oldReview.Status -eq 'Incomplete') 'Removal: a schema 1 inventory is refused'
    Write-Host ("PASS: tamper indicator fixtures ({0} checks)" -f $script:passed)
} finally { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }

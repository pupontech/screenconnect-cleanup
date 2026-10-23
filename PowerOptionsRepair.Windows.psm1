Set-StrictMode -Version 2.0

function Test-PowerRepairRegistryKey {
    param([string]$Path)
    return [bool](Test-Path -LiteralPath $Path -PathType Container -ErrorAction SilentlyContinue)
}

function Convert-PowerRepairRegistryPath {
    param([string]$Path)
    if ($Path -match '^HKLM:\\') { return ('HKLM\' + $Path.Substring(5)) }
    if ($Path -match '^HKCU:\\') { return ('HKCU\' + $Path.Substring(5)) }
    if ($Path -match '^Registry::HKEY_USERS\\(.+)$') { return ('HKU\' + $Matches[1]) }
    throw ('Unsupported registry path for backup: ' + $Path)
}

function Backup-PowerRepairRegistryKey {
    param([string]$Path, [string]$BackupRoot)
    if (-not (Test-PowerRepairRegistryKey -Path $Path)) { return $true }
    $regPath = Convert-PowerRepairRegistryPath -Path $Path
    $safeName = [regex]::Replace($regPath, '[^A-Za-z0-9_.-]', '_')
    $backupFile = Join-Path $BackupRoot ('registry-' + $safeName + '.reg')
    $null = New-Item -ItemType Directory -Path $BackupRoot -Force
    $regExe = Join-Path $env:SystemRoot 'System32\reg.exe'
    if (-not (Test-Path -LiteralPath $regExe -PathType Leaf)) { return $false }
    & $regExe export $regPath $backupFile /y
    $exitCode = $LASTEXITCODE
    return ($exitCode -eq 0 -and (Test-Path -LiteralPath $backupFile -PathType Leaf) -and (Get-Item -LiteralPath $backupFile).Length -gt 0)
}

function Get-PowerRepairRegistryValue {
    param([string]$Path, [string]$Name)
    $key = Get-Item -LiteralPath $Path -ErrorAction Stop
    # Absence is different from a provider/access failure. Let unreadable keys
    # fail the action instead of presenting an enforced policy as not present.
    if (@($key.GetValueNames()) -notcontains $Name) {
        return [pscustomobject]@{ Exists = $false; Type = $null; Value = $null }
    }
    $kind = $key.GetValueKind($Name)
    $value = $key.GetValue($Name)
    return [pscustomobject]@{ Exists = $true; Type = [string]$kind; Value = $value }
}

function Remove-PowerRepairRegistryValue {
    param([string]$Path, [string]$Name)
    if (-not (Test-PowerRepairRegistryKey -Path $Path)) { return $true }
    try {
        $existing = Get-PowerRepairRegistryValue -Path $Path -Name $Name
        if (-not $existing.Exists) { return $true }
        Remove-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
        $after = Get-PowerRepairRegistryValue -Path $Path -Name $Name
        return (-not $after.Exists)
    } catch {
        return $false
    }
}

function Remove-PowerRepairRegistryTree {
    param([string]$Path)
    try {
        if (Test-PowerRepairRegistryKey -Path $Path) {
            Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
        }
        return $true
    } catch {
        return $false
    }
}

function Set-PowerRepairRegistryDword {
    param([string]$Path, [string]$Name, [int]$Value)
    try {
        if (-not (Test-PowerRepairRegistryKey -Path $Path)) {
            $null = New-Item -Path $Path -Force -ErrorAction Stop
        }
        $null = New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType DWord -Force -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

function Invoke-PowerRepairPowerCfg {
    param([string[]]$Arguments)
    $exe = Join-Path $env:SystemRoot 'System32\powercfg.exe'
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { return $false }
    $commandOutput = @(& $exe @Arguments)
    $exitCode = $LASTEXITCODE
    return ($exitCode -eq 0)
}

function Backup-PowerRepairSchemes {
    param([string]$BackupRoot)
    $exe = Join-Path $env:SystemRoot 'System32\powercfg.exe'
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { return $false }
    $schemeRoot = Join-Path $BackupRoot 'power-schemes'
    $null = New-Item -ItemType Directory -Path $schemeRoot -Force
    $listOutput = @(& $exe /list)
    $listExitCode = $LASTEXITCODE
    if ($listExitCode -ne 0) { return $false }
    $guidPattern = '(?i)\b[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\b'
    $schemeGuids = @()
    foreach ($line in $listOutput) {
        foreach ($match in [regex]::Matches([string]$line, $guidPattern)) {
            $guid = $match.Value.ToLowerInvariant()
            if ($schemeGuids -notcontains $guid) { $schemeGuids += $guid }
        }
    }
    if (@($schemeGuids).Count -eq 0) { return $false }

    $exports = New-Object System.Collections.ArrayList
    foreach ($guid in $schemeGuids) {
        $destination = Join-Path $schemeRoot ($guid + '.pow')
        $exportOutput = @(& $exe /export $destination $guid)
        $exportExitCode = $LASTEXITCODE
        if ($exportExitCode -ne 0 -or -not (Test-Path -LiteralPath $destination -PathType Leaf) -or (Get-Item -LiteralPath $destination).Length -le 0) {
            return $false
        }
        [void]$exports.Add([pscustomobject]@{ Guid = $guid; File = $destination; Length = (Get-Item -LiteralPath $destination).Length })
    }
    $manifest = [ordered]@{
        SchemaVersion = 1
        GeneratedUtc = [DateTime]::UtcNow.ToString('o')
        Schemes = @($exports.ToArray())
        Note = 'Exported before restoring default schemes; custom plans can be re-imported from these files.'
    }
    $manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $schemeRoot 'manifest.json') -Encoding UTF8 -NoNewline
    return $true
}

function Restore-PowerRepairDefaultSchemes {
    return (Invoke-PowerRepairPowerCfg -Arguments @('/restoredefaultschemes'))
}

function Enable-PowerRepairHibernate {
    return (Invoke-PowerRepairPowerCfg -Arguments @('/hibernate', 'on'))
}

function Set-PowerRepairDefaultButtonActions {
    param($Values)
    $subgroup = '4f971e89-eebd-4455-a8de-9e59040e7347'
    $settings = @{
        PBUTTONACTION = '7648efa3-dd9c-4e3e-b566-50f929386280'
        SBUTTONACTION = '96996bc0-ad50-47ec-923b-6f41874dd9eb'
        LIDACTION = '5ca83367-6e45-459f-a27b-476b1d01c936'
    }
    foreach ($powerSource in @(@{ Name = 'AC'; Switch = '/setacvalueindex' }, @{ Name = 'DC'; Switch = '/setdcvalueindex' })) {
        foreach ($settingName in $settings.Keys) {
            $value = [int]$Values[$powerSource.Name][$settingName]
            if (-not (Invoke-PowerRepairPowerCfg -Arguments @($powerSource.Switch, 'SCHEME_CURRENT', $subgroup, $settings[$settingName], [string]$value))) {
                return $false
            }
        }
    }
    return (Invoke-PowerRepairPowerCfg -Arguments @('/setactive', 'SCHEME_CURRENT'))
}

function Backup-PowerRepairShutdownRights {
    param([string]$BackupRoot)
    $exe = Join-Path $env:SystemRoot 'System32\secedit.exe'
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { return $false }
    $destination = Join-Path $BackupRoot 'shutdown-user-rights.inf'
    $null = New-Item -ItemType Directory -Path $BackupRoot -Force
    $commandOutput = @(& $exe /export /cfg $destination /areas USER_RIGHTS)
    $exitCode = $LASTEXITCODE
    return ($exitCode -eq 0 -and (Test-Path -LiteralPath $destination -PathType Leaf) -and (Get-Item -LiteralPath $destination).Length -gt 0)
}

function Initialize-PowerRepairLsaTypes {
    if ('ScreenConnectPowerRepair.LsaApi' -as [type]) { return }
    $typeSource = @'
using System;
using System.Runtime.InteropServices;
namespace ScreenConnectPowerRepair {
    [StructLayout(LayoutKind.Sequential)]
    public struct LsaUnicodeString {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct LsaObjectAttributes {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }
    public static class LsaApi {
        [DllImport("advapi32.dll", SetLastError=false)]
        public static extern uint LsaOpenPolicy(IntPtr SystemName, ref LsaObjectAttributes ObjectAttributes, uint DesiredAccess, out IntPtr PolicyHandle);
        [DllImport("advapi32.dll", SetLastError=false)]
        public static extern uint LsaEnumerateAccountRights(IntPtr PolicyHandle, IntPtr AccountSid, out IntPtr UserRights, out uint CountOfRights);
        [DllImport("advapi32.dll", SetLastError=false)]
        public static extern uint LsaAddAccountRights(IntPtr PolicyHandle, IntPtr AccountSid, ref LsaUnicodeString UserRights, uint CountOfRights);
        [DllImport("advapi32.dll", SetLastError=false)]
        public static extern uint LsaFreeMemory(IntPtr Buffer);
        [DllImport("advapi32.dll", SetLastError=false)]
        public static extern uint LsaClose(IntPtr ObjectHandle);
        [DllImport("advapi32.dll", SetLastError=false)]
        public static extern uint LsaNtStatusToWinError(uint Status);
    }
}
'@
    Add-Type -TypeDefinition $typeSource -Language CSharp -ErrorAction Stop
}

function Add-PowerRepairShutdownRight {
    param([string]$GroupSid, [string]$RightName)
    $policyHandle = [IntPtr]::Zero
    $sidPointer = [IntPtr]::Zero
    $rightPointer = [IntPtr]::Zero
    $enumeratedPointer = [IntPtr]::Zero
    try {
        Initialize-PowerRepairLsaTypes
        $sidObject = New-Object System.Security.Principal.SecurityIdentifier($GroupSid)
        $sidBytes = New-Object byte[] ($sidObject.BinaryLength)
        $sidObject.GetBinaryForm($sidBytes, 0)
        $sidPointer = [Runtime.InteropServices.Marshal]::AllocHGlobal($sidBytes.Length)
        [Runtime.InteropServices.Marshal]::Copy($sidBytes, 0, $sidPointer, $sidBytes.Length)

        $attributes = New-Object ScreenConnectPowerRepair.LsaObjectAttributes
        $attributes.Length = [Runtime.InteropServices.Marshal]::SizeOf([type][ScreenConnectPowerRepair.LsaObjectAttributes])
        $desiredAccess = [uint32]0x0810
        $status = [ScreenConnectPowerRepair.LsaApi]::LsaOpenPolicy([IntPtr]::Zero, [ref]$attributes, $desiredAccess, [ref]$policyHandle)
        if ($status -ne 0) { throw ('LsaOpenPolicy failed with Win32 error ' + [ScreenConnectPowerRepair.LsaApi]::LsaNtStatusToWinError($status)) }

        [uint32]$rightCount = 0
        $enumStatus = [ScreenConnectPowerRepair.LsaApi]::LsaEnumerateAccountRights($policyHandle, $sidPointer, [ref]$enumeratedPointer, [ref]$rightCount)
        if ($enumStatus -eq 0) {
            $entrySize = [Runtime.InteropServices.Marshal]::SizeOf([type][ScreenConnectPowerRepair.LsaUnicodeString])
            for ($i = 0; $i -lt $rightCount; $i++) {
                $entryPointer = [IntPtr]::Add($enumeratedPointer, ($i * $entrySize))
                $entry = [Runtime.InteropServices.Marshal]::PtrToStructure($entryPointer, [type][ScreenConnectPowerRepair.LsaUnicodeString])
                $existingName = [Runtime.InteropServices.Marshal]::PtrToStringUni($entry.Buffer, [int]($entry.Length / 2))
                if ([string]::Equals($existingName, $RightName, [StringComparison]::OrdinalIgnoreCase)) { return $true }
            }
        } elseif ($enumStatus -ne [uint32]3221225524) {
            throw ('LsaEnumerateAccountRights failed with Win32 error ' + [ScreenConnectPowerRepair.LsaApi]::LsaNtStatusToWinError($enumStatus))
        }

        $rightPointer = [Runtime.InteropServices.Marshal]::StringToHGlobalUni($RightName)
        $right = New-Object ScreenConnectPowerRepair.LsaUnicodeString
        $right.Length = [uint16]($RightName.Length * 2)
        $right.MaximumLength = [uint16](($RightName.Length * 2) + 2)
        $right.Buffer = $rightPointer
        $addStatus = [ScreenConnectPowerRepair.LsaApi]::LsaAddAccountRights($policyHandle, $sidPointer, [ref]$right, 1)
        if ($addStatus -eq 0) { return $true }
        $winError = [ScreenConnectPowerRepair.LsaApi]::LsaNtStatusToWinError($addStatus)
        if ($winError -eq 183) { return $true }
        throw ('LsaAddAccountRights failed with Win32 error ' + $winError)
    } catch {
        Write-Warning ('Could not assign ' + $RightName + ' to ' + $GroupSid + ': ' + $_.Exception.Message)
        return $false
    } finally {
        if ($enumeratedPointer -ne [IntPtr]::Zero) { $null = [ScreenConnectPowerRepair.LsaApi]::LsaFreeMemory($enumeratedPointer) }
        if ($rightPointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::FreeHGlobal($rightPointer) }
        if ($sidPointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::FreeHGlobal($sidPointer) }
        if ($policyHandle -ne [IntPtr]::Zero) { $null = [ScreenConnectPowerRepair.LsaApi]::LsaClose($policyHandle) }
    }
}

function Test-PowerRepairTreeNoReparsePoints {
    param([string]$Path)
    $pending = New-Object System.Collections.Stack
    $pending.Push($Path)
    try {
        while ($pending.Count -gt 0) {
            $current = [string]$pending.Pop()
            $attributes = [System.IO.File]::GetAttributes($current)
            if (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { return $false }
            if (($attributes -band [System.IO.FileAttributes]::Directory) -ne 0) {
                foreach ($entry in [System.IO.Directory]::GetFileSystemEntries($current)) { $pending.Push($entry) }
            }
        }
        return $true
    } catch {
        return $false
    }
}

function Get-PowerRepairTreeManifest {
    param([string]$Path)
    $records = New-Object System.Collections.ArrayList
    if (-not [System.IO.Directory]::Exists($Path)) { return ,@() }
    if (-not (Test-PowerRepairTreeNoReparsePoints -Path $Path)) { throw ('Reparse point or unreadable path detected: ' + $Path) }
    $root = [System.IO.Path]::GetFullPath($Path).TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
    $pending = New-Object System.Collections.Stack
    $pending.Push($root)
    while ($pending.Count -gt 0) {
        $current = [string]$pending.Pop()
        foreach ($entryPath in [System.IO.Directory]::GetFileSystemEntries($current)) {
            $relative = $entryPath.Substring($root.Length).TrimStart([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
            $attributes = [System.IO.File]::GetAttributes($entryPath)
            if (($attributes -band [System.IO.FileAttributes]::Directory) -ne 0) {
                [void]$records.Add([pscustomobject]@{ Path = $relative; Kind = 'Directory'; Length = 0; Sha256 = $null })
                $pending.Push($entryPath)
            } else {
                $stream = [System.IO.File]::OpenRead($entryPath)
                $sha = [System.Security.Cryptography.SHA256]::Create()
                try {
                    $hashBytes = $sha.ComputeHash($stream)
                    $hash = [BitConverter]::ToString($hashBytes).Replace('-', '')
                } finally {
                    $stream.Dispose()
                    $sha.Dispose()
                }
                [void]$records.Add([pscustomobject]@{ Path = $relative; Kind = 'File'; Length = (Get-Item -LiteralPath $entryPath).Length; Sha256 = $hash })
            }
        }
    }
    $sorted = @($records.ToArray() | Sort-Object Path)
    return ,$sorted
}

function Backup-PowerRepairLocalGpo {
    param([string]$BackupRoot, [string[]]$Paths)
    $gpoRoot = Join-Path $BackupRoot 'local-group-policy'
    $null = New-Item -ItemType Directory -Path $gpoRoot -Force
    $robocopy = Join-Path $env:SystemRoot 'System32\robocopy.exe'
    $manifestEntries = New-Object System.Collections.ArrayList
    foreach ($source in $Paths) {
        if (-not [System.IO.Directory]::Exists($source)) {
            [void]$manifestEntries.Add([pscustomobject]@{ Source = $source; Present = $false; Files = @() })
            continue
        }
        if (-not (Test-PowerRepairTreeNoReparsePoints -Path $source)) { return $false }
        $leaf = [System.IO.Path]::GetFileName($source.TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar))
        $destination = Join-Path $gpoRoot $leaf
        $null = New-Item -ItemType Directory -Path $destination -Force
        $copyOutput = @(& $robocopy $source $destination /E /COPYALL /DCOPY:DAT /R:1 /W:1 /XJ)
        $copyExitCode = $LASTEXITCODE
        if ($copyExitCode -ge 8) { return $false }
        $sourceManifest = @(Get-PowerRepairTreeManifest -Path $source)
        $backupManifest = @(Get-PowerRepairTreeManifest -Path $destination)
        $sourceJson = ConvertTo-Json -InputObject $sourceManifest -Depth 5 -Compress
        $backupJson = ConvertTo-Json -InputObject $backupManifest -Depth 5 -Compress
        if ($sourceJson -cne $backupJson) { return $false }
        [void]$manifestEntries.Add([pscustomobject]@{ Source = $source; Present = $true; Destination = $destination; Files = $sourceManifest })
    }
    $manifest = [ordered]@{ SchemaVersion = 1; GeneratedUtc = [DateTime]::UtcNow.ToString('o'); Paths = @($manifestEntries.ToArray()) }
    $manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $gpoRoot 'manifest.json') -Encoding UTF8 -NoNewline
    return $true
}

function Reset-PowerRepairLocalGpo {
    param([string[]]$Paths)
    foreach ($path in $Paths) {
        if (-not [System.IO.Directory]::Exists($path)) { continue }
        if (-not (Test-PowerRepairTreeNoReparsePoints -Path $path)) { return $false }
        try {
            Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop
        } catch {
            return $false
        }
    }
    return $true
}

function Invoke-PowerRepairGpUpdate {
    $exe = Join-Path $env:SystemRoot 'System32\gpupdate.exe'
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { return $false }
    $commandOutput = @(& $exe /force /wait:60)
    $exitCode = $LASTEXITCODE
    return ($exitCode -eq 0)
}

function Restart-PowerRepairExplorer {
    try {
        $explorerPath = Join-Path $env:SystemRoot 'explorer.exe'
        $currentSession = [Diagnostics.Process]::GetCurrentProcess().SessionId
        $running = @(Get-Process -Name explorer -ErrorAction SilentlyContinue |
            Where-Object { $_.SessionId -eq $currentSession })
        foreach ($process in $running) {
            Stop-Process -Id $process.Id -Force -ErrorAction Stop
        }
        Start-Sleep -Seconds 1
        $null = Start-Process -FilePath $explorerPath -ErrorAction Stop
        return $true
    } catch {
        Write-Warning ('Explorer could not be restarted: ' + $_.Exception.Message)
        return $false
    }
}

function New-WindowsPowerOptionsRepairAdapter {
    [CmdletBinding()]
    param()
    return @{
        TestRegistryKey = { param($path) Test-PowerRepairRegistryKey -Path $path }
        BackupRegistryKey = { param($path, $backupRoot) Backup-PowerRepairRegistryKey -Path $path -BackupRoot $backupRoot }
        GetRegistryValue = { param($path, $name) Get-PowerRepairRegistryValue -Path $path -Name $name }
        RemoveRegistryValue = { param($path, $name) Remove-PowerRepairRegistryValue -Path $path -Name $name }
        RemoveRegistryTree = { param($path) Remove-PowerRepairRegistryTree -Path $path }
        SetRegistryDword = { param($path, $name, $value) Set-PowerRepairRegistryDword -Path $path -Name $name -Value $value }
        BackupPowerSchemes = { param($backupRoot) Backup-PowerRepairSchemes -BackupRoot $backupRoot }
        RestoreDefaultPowerSchemes = { Restore-PowerRepairDefaultSchemes }
        EnableHibernate = { Enable-PowerRepairHibernate }
        SetDefaultButtonActions = { param($values) Set-PowerRepairDefaultButtonActions -Values $values }
        BackupShutdownRights = { param($backupRoot) Backup-PowerRepairShutdownRights -BackupRoot $backupRoot }
        GrantShutdownRight = { param($groupSid, $rightName) Add-PowerRepairShutdownRight -GroupSid $groupSid -RightName $rightName }
        BackupLocalGpo = { param($backupRoot, $paths) Backup-PowerRepairLocalGpo -BackupRoot $backupRoot -Paths $paths }
        ResetLocalGpo = { param($paths) Reset-PowerRepairLocalGpo -Paths $paths }
        RunGpUpdate = { Invoke-PowerRepairGpUpdate }
        RestartExplorer = { Restart-PowerRepairExplorer }
    }
}

function Assert-PowerRepairSafePath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [string]$Root
    )
    if (-not [IO.Path]::IsPathRooted($Path)) { throw 'Repair destinations must be absolute paths.' }
    $fullPath = [IO.Path]::GetFullPath($Path)
    if ($env:OS -eq 'Windows_NT') {
        if ($fullPath -notmatch '^[A-Za-z]:[\\/]') { throw 'Repair destinations must use a local drive path.' }
        if ($fullPath.Substring(3).Contains(':')) { throw 'Alternate data streams are not allowed.' }
    }
    if ($Root) {
        if (-not [IO.Path]::IsPathRooted($Root)) { throw 'Repair root must be absolute.' }
        $fullRoot = [IO.Path]::GetFullPath($Root).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
        $prefix = $fullRoot + [IO.Path]::DirectorySeparatorChar
        $comparison = [StringComparison]::Ordinal
        if ($env:OS -eq 'Windows_NT') { $comparison = [StringComparison]::OrdinalIgnoreCase }
        if (-not $fullPath.StartsWith($prefix, $comparison)) { throw 'Repair destination must stay below the work root.' }
    }
    # Inspect existing ancestors even when the final destination does not exist.
    # Unlike Test-Path, GetAttributes distinguishes absent paths from access errors
    # and observes links themselves (including dangling symlinks).
    $current = $fullPath
    while ($current) {
        try {
            $attributes = [IO.File]::GetAttributes($current)
            if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw ('Reparse-point repair destination refused: ' + $current)
            }
        } catch [IO.FileNotFoundException] {
            # A not-yet-created child is allowed; its ancestors must still pass.
        } catch [IO.DirectoryNotFoundException] {
            # Continue checking the nearest existing parent.
        }
        $parent = [IO.Path]::GetDirectoryName($current)
        if ($parent -eq $current) { break }
        $current = $parent
    }
}

Export-ModuleMember -Function New-WindowsPowerOptionsRepairAdapter, Assert-PowerRepairSafePath

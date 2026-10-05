<#
  Read-only Windows object and ancestor protection verification tests.
  PowerShell 5.1 compatible. Native proof runs only on Windows.
  Windows fixtures are confined to one GUID directory under runner temp.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
$sourcePath = Join-Path $repoRoot 'gui-bridge/ProtectedWindowsTrust.ps1'
if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) { throw 'Missing ProtectedWindowsTrust.ps1.' }

foreach ($path in @($sourcePath, $MyInvocation.MyCommand.Path)) {
    $bytes = [System.IO.File]::ReadAllBytes($path)
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 239 -and $bytes[1] -eq 187 -and $bytes[2] -eq 191) { throw 'UTF-8 BOM is not allowed.' }
    foreach ($byte in $bytes) { if ($byte -gt 127) { throw 'PowerShell source and tests must be pure ASCII.' } }
    $tokens = $null
    $parseErrors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count -gt 0) { throw 'PowerShell parser rejected a source file.' }
}

. $sourcePath
$script:Assertions = 0
function Assert-True {
    param([bool]$Condition, [string]$Message)
    $script:Assertions++
    if (-not $Condition) { throw "FAIL: $Message" }
}
function Assert-Refused {
    param($Result, [string]$Message)
    Assert-True (-not $Result.ProtectionVerifiedForCurrentToken) $Message
    Assert-True (-not $Result.TrustEstablished -and -not $Result.InstallationAuthorized -and -not $Result.RemovalAuthorized) "$Message never authorizes a side effect"
}

$sourceTextForCompile = [System.IO.File]::ReadAllText($sourcePath)
$testTextForCompile = [System.IO.File]::ReadAllText($MyInvocation.MyCommand.Path)
$nativeSourceMatch = [regex]::Match($sourceTextForCompile, "(?s)\`$script:ProtectedWindowsTrustNativeSource\s*=\s*@'\r?\n(.*?)\r?\n'@")
$fixtureSourceMatch = [regex]::Match($testTextForCompile, "(?s)\`$fixtureNativeSource\s*=\s*@'\r?\n(.*?)\r?\n'@")
Assert-True $nativeSourceMatch.Success 'the exact production C# here-string is present for compilation on every platform'
Assert-True $fixtureSourceMatch.Success 'the exact fixture C# here-string is present for compilation on every platform'
Add-Type -TypeDefinition $nativeSourceMatch.Groups[1].Value -Language CSharp -ErrorAction Stop | Out-Null
Add-Type -TypeDefinition $fixtureSourceMatch.Groups[1].Value -Language CSharp -ErrorAction Stop | Out-Null

$normalizer = @([ProtectedWindowsTrust.NativeVerifier].GetMethods([System.Reflection.BindingFlags]::NonPublic -bor [System.Reflection.BindingFlags]::Static) | Where-Object {
    $_.Name -ceq 'MarkIncompleteEvidence' -and $_.GetParameters().Count -eq 2 -and $_.GetParameters()[0].ParameterType.Name -ceq 'ObjectEvidence'
})[0]
Assert-True ($null -ne $normalizer) 'private evidence normalization helper exists without exposing a production fault-injection API'
foreach ($status in @('WalkIncomplete', 'RecheckIncomplete')) {
    $row = New-Object 'ProtectedWindowsTrust.ObjectEvidence'
    $row.InitialProtectionObserved = $true
    $row.ProtectionObserved = $true
    $row.FinalRecheckConfirmed = $true
    $normalizer.Invoke($null, [object[]]@($row.PSObject.BaseObject, $status)) | Out-Null
    Assert-True ($row.InitialProtectionObserved -and -not $row.ProtectionObserved -and -not $row.FinalRecheckConfirmed) ("incomplete $status preserves only the explicitly initial diagnostic, not a final positive")
    Assert-True ($row.ObservationStatus -ceq $status) ("incomplete $status is explicitly labeled")
}

$testAst = [System.Management.Automation.Language.Parser]::ParseFile($MyInvocation.MyCommand.Path, [ref]$tokens, [ref]$parseErrors)
$rightsMembers = @($testAst.FindAll({ param($node)
    $node -is [System.Management.Automation.Language.MemberExpressionAst] -and
    $node.Expression -is [System.Management.Automation.Language.TypeExpressionAst] -and
    $node.Expression.TypeName.FullName -ceq 'System.Security.AccessControl.FileSystemRights'
}, $true))
$validRightsMembers = [Enum]::GetNames([System.Security.AccessControl.FileSystemRights])
foreach ($member in $rightsMembers) {
    Assert-True ($validRightsMembers -ccontains $member.Member.Value) 'Windows fixture uses an actual FileSystemRights enum member'
}

$pathCases = @(
    @{ Path = 'C:\'; Valid = $false; Code = 'RootPathRefused' },
    @{ Path = 'C:\ProgramData\Safe'; Valid = $true; Code = 'None' },
    @{ Path = 'C:\ProgramData\..\Windows'; Valid = $false; Code = 'TraversalComponent' },
    @{ Path = 'C:\ProgramData\\Safe'; Valid = $false; Code = 'EmptyComponent' },
    @{ Path = 'C:\ProgramData\Safe:stream'; Valid = $false; Code = 'AlternateDataStreamRefused' },
    @{ Path = '\\server\share\Safe'; Valid = $false; Code = 'NonLocalPathRefused' },
    @{ Path = '\\?\C:\Safe'; Valid = $false; Code = 'NonLocalPathRefused' },
    @{ Path = 'C:/ProgramData/Safe'; Valid = $false; Code = 'NonLocalPathRefused' },
    @{ Path = 'C:\ProgramData\Safe\'; Valid = $false; Code = 'EmptyComponent' },
    @{ Path = 'C:\ProgramData\NUL'; Valid = $false; Code = 'DeviceComponentRefused' },
    @{ Path = ('C:\' + ('x\' * 65) + 'leaf'); Valid = $false; Code = 'PathDepthExceeded' }
)
foreach ($case in $pathCases) {
    $parsed = Get-ProtectedWindowsTrustPathComponents -Path $case.Path
    Assert-True ($parsed.Valid -eq $case.Valid) ("path policy validity: " + $case.Code)
    Assert-True ($parsed.FailureCode -ceq $case.Code) ("path policy code: " + $case.Code)
}
$parsedSafe = Get-ProtectedWindowsTrustPathComponents -Path 'C:\ProgramData\Safe'
Assert-True ($parsedSafe.DriveRoot -ceq 'C:\' -and $parsedSafe.Segments.Count -eq 2) 'local canonical components include a drive root and exact descendants'

$rightsCases = @(
    @{ Mask = [uint32]0x00120089; Expected = 0; Name = 'GENERIC_READ' },
    @{ Mask = [uint32]0x40000000; Expected = 4; Name = 'GENERIC_WRITE' },
    @{ Mask = [uint32]0x10000000; Expected = 8; Name = 'GENERIC_ALL' },
    @{ Mask = [uint32]0x00010000; Expected = 1; Name = 'DELETE' },
    @{ Mask = [uint32]0x00040000; Expected = 1; Name = 'WRITE_DAC' },
    @{ Mask = [uint32]0x00080000; Expected = 1; Name = 'WRITE_OWNER' },
    @{ Mask = [uint32]0x00000040; Expected = 1; Name = 'FILE_DELETE_CHILD' }
)
foreach ($case in $rightsCases) {
    $policy = Get-ProtectedWindowsTrustRightsPolicy -AccessMask $case.Mask
    Assert-True ($policy.DangerousRights.Count -eq $case.Expected) ("generic mapping and dangerous rights: " + $case.Name)
}
Assert-True ((Get-ProtectedWindowsTrustRightsPolicy -AccessMask ([uint32]0x00000004)).DangerousRights -contains 'AppendDataOrAddSubdirectory') 'append/create-subdirectory right is included'
Assert-True ((Get-ProtectedWindowsTrustRightsPolicy -AccessMask ([uint32]0x00000002)).DangerousRights -contains 'WriteDataOrAddFile') 'write/create-file right is included'
$genericReadPolicy = Get-ProtectedWindowsTrustRightsPolicy -AccessMask ([uint32]2147483648)
$genericWritePolicy = Get-ProtectedWindowsTrustRightsPolicy -AccessMask ([uint32]0x40000000)
$genericAllPolicy = Get-ProtectedWindowsTrustRightsPolicy -AccessMask ([uint32]0x10000000)
Assert-True ($genericReadPolicy.MappedMask -eq [uint32]0x00120089 -and $genericReadPolicy.DangerousRights.Count -eq 0) 'GENERIC_READ maps exactly without dangerous rights'
Assert-True ($genericWritePolicy.MappedMask -eq [uint32]0x00120116 -and $genericWritePolicy.DangerousRights.Count -eq 4) 'GENERIC_WRITE maps write, append/create, attribute, and extended-attribute rights'
Assert-True ($genericAllPolicy.MappedMask -eq [uint32]0x001F01FF -and $genericAllPolicy.DangerousRights.Count -eq 8) 'GENERIC_ALL maps all protected mutation rights'
$readControlPolicy = Get-ProtectedWindowsTrustRightsPolicy -AccessMask ([uint32]131072)
$writeOwnerPolicy = Get-ProtectedWindowsTrustRightsPolicy -AccessMask ([uint32]524288)
Assert-True ($readControlPolicy.DangerousRights.Count -eq 0 -and $readControlPolicy.DangerousMask -eq [uint32]0) 'READ_CONTROL is not ownership or a dangerous mutation right'
Assert-True ($writeOwnerPolicy.DangerousRights.Count -eq 1 -and $writeOwnerPolicy.DangerousRights[0] -ceq 'WriteOwner') 'WRITE_OWNER is a single dangerous right, not an ownership sentinel'

$sourceAst = [System.Management.Automation.Language.Parser]::ParseFile($sourcePath, [ref]$tokens, [ref]$parseErrors)
$forbiddenCommands = @('Set-Acl', 'Remove-Item', 'New-Item', 'Move-Item', 'Start-Process', 'Invoke-Expression', 'Set-Content', 'Out-File')
$commandAsts = @($sourceAst.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true))
foreach ($commandAst in $commandAsts) {
    Assert-True ($forbiddenCommands -notcontains $commandAst.GetCommandName()) 'production verifier contains no filesystem mutation, process launch, or dynamic execution command'
}
$sourceText = [System.IO.File]::ReadAllText($sourcePath)
Assert-True ($sourceText -notmatch '(?i)\b(SetSecurityInfo|SetFileSecurity|NtSetSecurityObject|CreateDirectoryW|DeleteFileW)\b') 'production native interop contains no ACL or filesystem mutation API'
$nativeRightsMatch = [regex]::Match($sourceText, '(?s)private static readonly uint\[\] DangerousRights = new uint\[\]\s*\{([^}]*)\}')
$nativeNamesMatch = [regex]::Match($sourceText, '(?s)private static readonly string\[\] DangerousNames = new string\[\]\s*\{([^}]*)\}')
Assert-True ($nativeRightsMatch.Success -and $nativeNamesMatch.Success) 'native effective-access right and name lists are present'
Assert-True ($nativeRightsMatch.Groups[1].Value -notmatch '\bReadControl\b') 'READ_CONTROL is absent from the native dangerous-right access checks'
Assert-True ($nativeNamesMatch.Groups[1].Value -notmatch 'Ownership') 'owner identity is not serialized as an invented mask-based ownership right'

$command = Get-Command Get-ProtectedWindowsTrust -ErrorAction Stop
$commonParameters = @('Verbose', 'Debug', 'ErrorAction', 'WarningAction', 'InformationAction', 'ProgressAction', 'ErrorVariable', 'WarningVariable', 'InformationVariable', 'OutVariable', 'OutBuffer', 'PipelineVariable')
$publicParameters = @($command.Parameters.Keys | Where-Object { $commonParameters -notcontains $_ })
Assert-True ($publicParameters.Count -eq 1 -and $publicParameters[0] -ceq 'Path') 'native verifier accepts only an untrusted target path, never assertion callbacks or expected booleans'
$validUntrustedPath = 'C:\ProgramData\Synthetic\Object.bin'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    $unsupported = Get-ProtectedWindowsTrust -Path $validUntrustedPath
    Assert-Refused $unsupported 'non-Windows platform refuses native trust'
    Assert-True ($unsupported.ReasonCode -ceq 'UnsupportedPlatform' -and -not $unsupported.NativeChecksPerformed) 'non-Windows refusal is explicit and is not counted as native execution'
    Assert-True ($unsupported.ObservationStatus -ceq 'NotStarted') 'non-Windows result says native observation did not start'
    Assert-True ($unsupported.Scope -match 'current effective caller token only' -and $unsupported.Scope -match 'future token changes') 'result states the bounded token snapshot scope'
    $serialized = ConvertTo-Json -InputObject $unsupported -Depth 8 -Compress
    $roundTrip = ConvertFrom-Json -InputObject $serialized -ErrorAction Stop
    Assert-True (-not $roundTrip.TrustEstablished -and -not $roundTrip.ProtectionVerifiedForCurrentToken) 'serialized refusal cannot become trust'
    Assert-True ($roundTrip.InstallationAuthorized -eq $false -and $roundTrip.RemovalAuthorized -eq $false) 'serialized refusal never authorizes install or removal'
    Assert-True ($serialized.Length -lt 8192) 'serialized result remains bounded'
    Assert-True (-not $serialized.Contains($validUntrustedPath)) 'serialized refusal omits caller path diagnostics'
    Write-Output "PASS: $script:Assertions portable assertions; native Windows execution NOT RUN on this non-Windows host."
    return
}

$fixtureRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('ProtectedWindowsTrust-' + [Guid]::NewGuid().ToString('N'))
$fixturePaths = @{}
$failure = $null
$cleanupFailure = $null
$impersonationActive = $false
try {
    [void][System.IO.Directory]::CreateDirectory($fixtureRoot)
    $fixtureNames = @('safe', 'read-control-only', 'unsafe-write', 'unsafe-denied-write', 'unsafe-append', 'unsafe-create-child', 'unsafe-delete', 'unsafe-delete-child', 'unsafe-acl', 'unsafe-owner-right', 'unsafe-owner', 'unknown-principal', 'generic-write', 'generic-all', 'unsupported-ace', 'owner-missing-write-dac', 'owner-missing-write-owner', 'owner-inherit-only', 'ProgramData', 'target')
    foreach ($name in $fixtureNames) {
        $dir = Join-Path $fixtureRoot $name
        [void][System.IO.Directory]::CreateDirectory($dir)
        $file = Join-Path $dir 'object.bin'
        [System.IO.File]::WriteAllBytes($file, [byte[]]@(1, 2, 3, 4))
        if ($name -in @('unsafe-create-child', 'unsafe-delete-child', 'owner-inherit-only')) { $fixturePaths[$name] = $dir }
        else { $fixturePaths[$name] = $file }
    }
    $linkPath = Join-Path $fixtureRoot 'reparse-link'
    $ancestorLinkPath = Join-Path $fixtureRoot 'reparse-ancestor'
    $targetPath = Join-Path $fixtureRoot 'target'
    $fixtureNativeSource = @'
using System;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Security.Principal;
public static class ProtectedWindowsTrustFixtureNative
{
    private static readonly List<IntPtr> HeldHandles = new List<IntPtr>();
    private static IntPtr RestrictedImpersonationToken = IntPtr.Zero;
    [StructLayout(LayoutKind.Sequential)]
    private struct SidAndAttributes
    {
        public IntPtr Sid;
        public uint Attributes;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct Luid
    {
        public uint LowPart;
        public int HighPart;
    }
    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateFile(string path, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", EntryPoint = "CreateSymbolicLinkW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CreateDirectorySymbolicLink(string link, string target, uint flags);
    [DllImport("advapi32.dll", EntryPoint = "ConvertStringSecurityDescriptorToSecurityDescriptorW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ConvertSecurityDescriptor(string sddl, uint revision, out IntPtr descriptor, out uint size);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetSecurityDescriptorDacl(IntPtr descriptor, out bool present, out IntPtr dacl, out bool defaulted);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern int SetSecurityInfo(IntPtr handle, int objectType, uint information, IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr LocalFree(IntPtr memory);
    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentThread();
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenThreadToken(IntPtr thread, uint access, bool openAsSelf, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(IntPtr token, int infoClass, IntPtr information, uint length, out uint returnLength);
    [DllImport("advapi32.dll", EntryPoint = "LookupPrivilegeValueW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool LookupPrivilegeValue(string systemName, string name, out Luid luid);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateRestrictedToken(IntPtr existingToken, uint flags, uint disableSidCount, IntPtr sidsToDisable, uint deletePrivilegeCount, IntPtr privilegesToDelete, uint restrictedSidCount, IntPtr sidsToRestrict, out IntPtr newToken);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateTokenEx(IntPtr existingToken, uint access, IntPtr attributes, int impersonationLevel, int tokenType, out IntPtr newToken);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetThreadToken(IntPtr thread, IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool RevertToSelf();
    [DllImport("advapi32.dll", EntryPoint = "ConvertStringSidToSidW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ConvertStringSidToSid(string text, out IntPtr sid);
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EqualSid(IntPtr firstSid, IntPtr secondSid);

    private static bool ReadTokenUInt32(IntPtr token, int infoClass, out uint value)
    {
        value = 0;
        IntPtr buffer = IntPtr.Zero;
        uint needed;
        GetTokenInformation(token, infoClass, IntPtr.Zero, 0, out needed);
        if (needed < 4 || needed > 1048576) return false;
        try
        {
            buffer = Marshal.AllocHGlobal((int)needed);
            uint returned;
            if (!GetTokenInformation(token, infoClass, buffer, needed, out returned) || returned < 4) return false;
            value = unchecked((uint)Marshal.ReadInt32(buffer));
            return true;
        }
        finally { if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer); }
    }

    private static bool ReadLinkedToken(IntPtr token, out IntPtr linkedToken)
    {
        linkedToken = IntPtr.Zero;
        IntPtr buffer = IntPtr.Zero;
        uint needed;
        GetTokenInformation(token, 19, IntPtr.Zero, 0, out needed);
        if (needed < (uint)IntPtr.Size || needed > 1048576) return false;
        try
        {
            buffer = Marshal.AllocHGlobal((int)needed);
            uint returned;
            if (!GetTokenInformation(token, 19, buffer, needed, out returned) || returned < (uint)IntPtr.Size) return false;
            linkedToken = Marshal.ReadIntPtr(buffer);
            return linkedToken != IntPtr.Zero;
        }
        finally { if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer); }
    }

    private static bool TokenContainsEnabledAdministrators(IntPtr token, out bool containsAdministrators)
    {
        containsAdministrators = false;
        IntPtr groups = IntPtr.Zero;
        IntPtr adminSid = IntPtr.Zero;
        uint needed;
        GetTokenInformation(token, 2, IntPtr.Zero, 0, out needed);
        if (needed == 0 || needed > 1048576) return false;
        try
        {
            groups = Marshal.AllocHGlobal((int)needed);
            uint returned;
            if (!GetTokenInformation(token, 2, groups, needed, out returned) || returned < 4) return false;
            if (!ConvertStringSidToSid("S-1-5-32-544", out adminSid)) return false;
            int count = Marshal.ReadInt32(groups);
            int first = IntPtr.Size == 8 ? 8 : 4;
            int stride = IntPtr.Size == 8 ? 16 : 8;
            if (count < 0 || count > 4096 || returned < first + (count * stride)) return false;
            for (int i = 0; i < count; i++)
            {
                IntPtr entry = IntPtr.Add(groups, first + (i * stride));
                uint attributes = unchecked((uint)Marshal.ReadInt32(entry, IntPtr.Size));
                if (EqualSid(Marshal.ReadIntPtr(entry), adminSid) && (attributes & 0x00000004) != 0)
                    containsAdministrators = true;
            }
            return true;
        }
        finally
        {
            if (adminSid != IntPtr.Zero) LocalFree(adminSid);
            if (groups != IntPtr.Zero) Marshal.FreeHGlobal(groups);
        }
    }

    public static string[] GetCurrentTokenAttributeFacts()
    {
        List<string> facts = new List<string>();
        IntPtr token = IntPtr.Zero;
        IntPtr adminSid = IntPtr.Zero;
        IntPtr integrity = IntPtr.Zero;
        IntPtr groups = IntPtr.Zero;
        IntPtr privileges = IntPtr.Zero;
        try
        {
            if (!OpenThreadToken(GetCurrentThread(), 0x0008, false, out token)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            uint elevation;
            if (!ReadTokenUInt32(token, 20, out elevation)) throw new InvalidOperationException("Token elevation could not be read.");
            facts.Add("Elevation=" + elevation.ToString());

            uint needed;
            uint returned;
            GetTokenInformation(token, 25, IntPtr.Zero, 0, out needed);
            if (needed == 0 || needed > 1048576) throw new InvalidOperationException("Token integrity buffer is invalid.");
            integrity = Marshal.AllocHGlobal((int)needed);
            if (!GetTokenInformation(token, 25, integrity, needed, out returned) || returned < (uint)IntPtr.Size) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            string integritySid = new SecurityIdentifier(Marshal.ReadIntPtr(integrity)).Value;
            string[] integrityParts = integritySid.Split('-');
            facts.Add("IntegrityRid=" + integrityParts[integrityParts.Length - 1]);

            if (!ConvertStringSidToSid("S-1-5-32-544", out adminSid)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            GetTokenInformation(token, 2, IntPtr.Zero, 0, out needed);
            if (needed == 0 || needed > 1048576) throw new InvalidOperationException("Token group buffer is invalid.");
            groups = Marshal.AllocHGlobal((int)needed);
            if (!GetTokenInformation(token, 2, groups, needed, out returned) || returned < 4) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            int groupCount = Marshal.ReadInt32(groups);
            int first = IntPtr.Size == 8 ? 8 : 4;
            int groupStride = IntPtr.Size == 8 ? 16 : 8;
            if (groupCount < 0 || groupCount > 4096 || returned < (uint)(first + (groupCount * groupStride))) throw new InvalidOperationException("Token group count is invalid.");
            string adminState = "Absent";
            for (int i = 0; i < groupCount; i++)
            {
                IntPtr entry = IntPtr.Add(groups, first + (i * groupStride));
                if (!EqualSid(Marshal.ReadIntPtr(entry), adminSid)) continue;
                uint attributes = unchecked((uint)Marshal.ReadInt32(entry, IntPtr.Size));
                adminState = (attributes & 0x00000010) != 0 ? "DenyOnly" : ((attributes & 0x00000004) != 0 ? "Enabled" : "Disabled");
            }
            facts.Add("AdminGroup=" + adminState);

            GetTokenInformation(token, 3, IntPtr.Zero, 0, out needed);
            if (needed < 4 || needed > 1048576) throw new InvalidOperationException("Token privilege buffer is invalid.");
            privileges = Marshal.AllocHGlobal((int)needed);
            if (!GetTokenInformation(token, 3, privileges, needed, out returned) || returned < 4) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            int privilegeCount = Marshal.ReadInt32(privileges);
            int privilegeStride = 12;
            if (privilegeCount < 0 || privilegeCount > 4096 || returned < (uint)(4 + (privilegeCount * privilegeStride))) throw new InvalidOperationException("Token privilege count is invalid.");
            string[] dangerousNames = new string[] { "SeTakeOwnershipPrivilege", "SeRestorePrivilege", "SeBackupPrivilege", "SeRelabelPrivilege", "SeSecurityPrivilege" };
            for (int nameIndex = 0; nameIndex < dangerousNames.Length; nameIndex++)
            {
                Luid wanted;
                if (!LookupPrivilegeValue(null, dangerousNames[nameIndex], out wanted)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
                string state = "Absent";
                for (int i = 0; i < privilegeCount; i++)
                {
                    IntPtr entry = IntPtr.Add(privileges, 4 + (i * privilegeStride));
                    uint low = unchecked((uint)Marshal.ReadInt32(entry));
                    int high = Marshal.ReadInt32(entry, 4);
                    if (low == wanted.LowPart && high == wanted.HighPart)
                        state = (unchecked((uint)Marshal.ReadInt32(entry, 8)) & 0x00000002) != 0 ? "Enabled" : "Disabled";
                }
                facts.Add(dangerousNames[nameIndex] + "=" + state);
            }
            return facts.ToArray();
        }
        finally
        {
            if (privileges != IntPtr.Zero) Marshal.FreeHGlobal(privileges);
            if (groups != IntPtr.Zero) Marshal.FreeHGlobal(groups);
            if (integrity != IntPtr.Zero) Marshal.FreeHGlobal(integrity);
            if (adminSid != IntPtr.Zero) LocalFree(adminSid);
            if (token != IntPtr.Zero) CloseHandle(token);
        }
    }

    public static bool BeginRestrictedStandardTokenImpersonation()
    {
        IntPtr processToken = IntPtr.Zero;
        IntPtr linkedToken = IntPtr.Zero;
        IntPtr baseToken = IntPtr.Zero;
        IntPtr adminSid = IntPtr.Zero;
        IntPtr disabledSid = IntPtr.Zero;
        IntPtr restrictedPrimary = IntPtr.Zero;
        IntPtr impersonationToken = IntPtr.Zero;
        bool success = false;
        try
        {
            if (!OpenProcessToken(GetCurrentProcess(), 0x0000000A, out processToken)) return false;
            baseToken = processToken;
            uint elevation;
            if (!ReadTokenUInt32(processToken, 20, out elevation)) return false;
            if (elevation != 0)
            {
                if (!ReadLinkedToken(processToken, out linkedToken)) return false;
                baseToken = linkedToken;
                if (!ReadTokenUInt32(baseToken, 20, out elevation) || elevation != 0) return false;
            }

            bool hasEnabledAdministratorsGroup;
            if (!TokenContainsEnabledAdministrators(baseToken, out hasEnabledAdministratorsGroup)) return false;
            uint disableSidCount = 0;
            if (hasEnabledAdministratorsGroup)
            {
                if (!ConvertStringSidToSid("S-1-5-32-544", out adminSid)) return false;
                SidAndAttributes disabledGroup = new SidAndAttributes();
                disabledGroup.Sid = adminSid;
                disabledGroup.Attributes = 0;
                disabledSid = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SidAndAttributes)));
                Marshal.StructureToPtr(disabledGroup, disabledSid, false);
                disableSidCount = 1;
            }
            if (!CreateRestrictedToken(baseToken, 0x00000001, disableSidCount, disabledSid, 0, IntPtr.Zero, 0, IntPtr.Zero, out restrictedPrimary)) return false;
            if (!DuplicateTokenEx(restrictedPrimary, 0x0000000E, IntPtr.Zero, 2, 2, out impersonationToken)) return false;
            if (!SetThreadToken(IntPtr.Zero, impersonationToken)) return false;
            RestrictedImpersonationToken = impersonationToken;
            impersonationToken = IntPtr.Zero;
            success = true;
            return true;
        }
        finally
        {
            if (disabledSid != IntPtr.Zero) Marshal.FreeHGlobal(disabledSid);
            if (adminSid != IntPtr.Zero) LocalFree(adminSid);
            if (impersonationToken != IntPtr.Zero) CloseHandle(impersonationToken);
            if (restrictedPrimary != IntPtr.Zero) CloseHandle(restrictedPrimary);
            if (linkedToken != IntPtr.Zero) CloseHandle(linkedToken);
            if (processToken != IntPtr.Zero) CloseHandle(processToken);
            if (!success && RestrictedImpersonationToken != IntPtr.Zero)
            {
                RevertToSelf();
                CloseHandle(RestrictedImpersonationToken);
                RestrictedImpersonationToken = IntPtr.Zero;
            }
        }
    }

    public static bool EndRestrictedStandardTokenImpersonation()
    {
        bool success = RevertToSelf();
        if (RestrictedImpersonationToken != IntPtr.Zero)
        {
            if (!CloseHandle(RestrictedImpersonationToken)) success = false;
            RestrictedImpersonationToken = IntPtr.Zero;
        }
        return success;
    }

    public static bool HoldRestoreHandle(string path, bool directory, bool reparse)
    {
        uint flags = directory ? 0x02000000 : 0u;
        if (reparse) flags |= 0x00200000;
        IntPtr handle = CreateFile(path, 0x00040000 | 0x00020000, 7, IntPtr.Zero, 3, flags, IntPtr.Zero);
        if (handle == IntPtr.Zero || handle == new IntPtr(-1)) return false;
        HeldHandles.Add(handle);
        return true;
    }

    public static bool SetDaclSddl(string path, bool directory, string sddl)
    {
        IntPtr descriptor = IntPtr.Zero;
        IntPtr handle = IntPtr.Zero;
        uint descriptorSize;
        try
        {
            if (!ConvertSecurityDescriptor(sddl, 1, out descriptor, out descriptorSize)) return false;
            uint flags = directory ? 0x02000000 : 0u;
            handle = CreateFile(path, 0x00040000 | 0x00020000, 7, IntPtr.Zero, 3, flags, IntPtr.Zero);
            if (handle == IntPtr.Zero || handle == new IntPtr(-1)) return false;
            IntPtr dacl;
            bool present;
            bool defaulted;
            if (!GetSecurityDescriptorDacl(descriptor, out present, out dacl, out defaulted) || !present || dacl == IntPtr.Zero) return false;
            return SetSecurityInfo(handle, 1, 4, IntPtr.Zero, IntPtr.Zero, dacl, IntPtr.Zero) == 0;
        }
        finally
        {
            if (handle != IntPtr.Zero && handle != new IntPtr(-1)) CloseHandle(handle);
            if (descriptor != IntPtr.Zero) LocalFree(descriptor);
        }
    }

    public static bool RestoreAndClose()
    {
        IntPtr descriptor = IntPtr.Zero;
        uint ignoredSize;
        bool success = ConvertSecurityDescriptor("D:(A;;GA;;;WD)", 1, out descriptor, out ignoredSize);
        IntPtr dacl = IntPtr.Zero;
        bool present = false;
        bool defaulted = false;
        if (success) success = GetSecurityDescriptorDacl(descriptor, out present, out dacl, out defaulted) && present && dacl != IntPtr.Zero;
        if (success)
        {
            foreach (IntPtr handle in HeldHandles)
                if (SetSecurityInfo(handle, 1, 4, IntPtr.Zero, IntPtr.Zero, dacl, IntPtr.Zero) != 0) success = false;
        }
        if (descriptor != IntPtr.Zero) LocalFree(descriptor);
        foreach (IntPtr handle in HeldHandles) if (!CloseHandle(handle)) success = false;
        HeldHandles.Clear();
        return success;
    }
}
'@
    if ($null -eq ('ProtectedWindowsTrustFixtureNative' -as [type])) {
        Add-Type -TypeDefinition $fixtureNativeSource -Language CSharp -ErrorAction Stop
    }
    $linkCreated = [ProtectedWindowsTrustFixtureNative]::CreateDirectorySymbolicLink($linkPath, $targetPath, 3)
    if (-not $linkCreated) { throw 'Windows test fixture could not create a directory symlink.' }
    if (-not [ProtectedWindowsTrustFixtureNative]::CreateDirectorySymbolicLink($ancestorLinkPath, $targetPath, 3)) { throw 'Windows ancestor reparse fixture could not be created.' }
    if (-not [ProtectedWindowsTrustFixtureNative]::HoldRestoreHandle($fixtureRoot, $true, $false)) { throw 'Windows fixture recovery handle acquisition failed.' }
    foreach ($name in $fixtureNames) {
        $dir = Join-Path $fixtureRoot $name
        $file = Join-Path $dir 'object.bin'
        if (-not [ProtectedWindowsTrustFixtureNative]::HoldRestoreHandle($dir, $true, $false)) { throw 'Windows fixture recovery handle acquisition failed.' }
        if (-not [ProtectedWindowsTrustFixtureNative]::HoldRestoreHandle($file, $false, $false)) { throw 'Windows fixture recovery handle acquisition failed.' }
    }
    if (-not [ProtectedWindowsTrustFixtureNative]::HoldRestoreHandle($linkPath, $true, $true)) { throw 'Windows fixture reparse recovery handle acquisition failed.' }
    if (-not [ProtectedWindowsTrustFixtureNative]::HoldRestoreHandle($ancestorLinkPath, $true, $true)) { throw 'Windows ancestor reparse recovery handle acquisition failed.' }

    $adminSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $systemSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
    $usersSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-545')
    $ownerRightsSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-3-4')
    $unknownSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-21-987654321-987654321-987654321-7777')
    $currentUserSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    function Set-TestAcl {
        param([string]$Path, [bool]$IsDirectory, [System.Security.Principal.SecurityIdentifier]$Owner, [System.Security.AccessControl.FileSystemRights]$UsersRights, [System.Security.Principal.SecurityIdentifier]$ExtraSid, [bool]$ProtectOwnerRights = $true, [System.Security.AccessControl.FileSystemRights]$DenyUsersRights = [System.Security.AccessControl.FileSystemRights]0, [bool]$IncludeReadRule = $true, [string]$OwnerRightsMode = 'Both')
        if ($IsDirectory) { $acl = New-Object System.Security.AccessControl.DirectorySecurity }
        else { $acl = New-Object System.Security.AccessControl.FileSecurity }
        $acl.SetAccessRuleProtection($true, $false)
        $acl.SetOwner($Owner)
        $inheritance = if ($IsDirectory) { [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit } else { [System.Security.AccessControl.InheritanceFlags]::None }
        $propagation = [System.Security.AccessControl.PropagationFlags]::None
        foreach ($sid in @($adminSid, $systemSid)) {
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, [System.Security.AccessControl.FileSystemRights]::FullControl, $inheritance, $propagation, [System.Security.AccessControl.AccessControlType]::Allow)
            $acl.AddAccessRule($rule)
        }
        if ($ProtectOwnerRights) {
            $ownerRights = switch ($OwnerRightsMode) {
                'Both' { [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor [System.Security.AccessControl.FileSystemRights]::TakeOwnership }
                'MissingWriteDac' { [System.Security.AccessControl.FileSystemRights]::TakeOwnership }
                'MissingWriteOwner' { [System.Security.AccessControl.FileSystemRights]::ChangePermissions }
                'InheritOnly' { [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor [System.Security.AccessControl.FileSystemRights]::TakeOwnership }
                default { throw 'Unsupported OWNER RIGHTS fixture mode.' }
            }
            $ownerPropagation = if ($OwnerRightsMode -ceq 'InheritOnly') { [System.Security.AccessControl.PropagationFlags]::InheritOnly } else { $propagation }
            $ownerRule = New-Object System.Security.AccessControl.FileSystemAccessRule($ownerRightsSid, $ownerRights, $inheritance, $ownerPropagation, [System.Security.AccessControl.AccessControlType]::Deny)
            $acl.AddAccessRule($ownerRule)
        }
        if ($IncludeReadRule) {
            $readRule = New-Object System.Security.AccessControl.FileSystemAccessRule($usersSid, [System.Security.AccessControl.FileSystemRights]::ReadAndExecute, $inheritance, $propagation, [System.Security.AccessControl.AccessControlType]::Allow)
            $acl.AddAccessRule($readRule)
        }
        if ($UsersRights -ne [System.Security.AccessControl.FileSystemRights]0) {
            $writeRule = New-Object System.Security.AccessControl.FileSystemAccessRule($usersSid, $UsersRights, $inheritance, $propagation, [System.Security.AccessControl.AccessControlType]::Allow)
            $acl.AddAccessRule($writeRule)
        }
        if ($DenyUsersRights -ne [System.Security.AccessControl.FileSystemRights]0) {
            $denyRule = New-Object System.Security.AccessControl.FileSystemAccessRule($usersSid, $DenyUsersRights, $inheritance, $propagation, [System.Security.AccessControl.AccessControlType]::Deny)
            $acl.AddAccessRule($denyRule)
        }
        if ($null -ne $ExtraSid) {
            $extraRule = New-Object System.Security.AccessControl.FileSystemAccessRule($ExtraSid, [System.Security.AccessControl.FileSystemRights]::ReadAndExecute, $inheritance, $propagation, [System.Security.AccessControl.AccessControlType]::Allow)
            $acl.AddAccessRule($extraRule)
        }
        Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
    }
    Set-TestAcl -Path $fixtureRoot -IsDirectory $true -Owner $currentUserSid -UsersRights ([System.Security.AccessControl.FileSystemRights]0) -ExtraSid $null
    foreach ($name in $fixtureNames) {
        Set-TestAcl -Path (Split-Path -Parent $fixturePaths[$name]) -IsDirectory $true -Owner $currentUserSid -UsersRights ([System.Security.AccessControl.FileSystemRights]0) -ExtraSid $null
    }
    Set-TestAcl -Path $fixturePaths.safe -IsDirectory $false -Owner $currentUserSid -UsersRights ([System.Security.AccessControl.FileSystemRights]0) -ExtraSid $null
    Set-TestAcl -Path $fixturePaths['read-control-only'] -IsDirectory $false -Owner $currentUserSid -UsersRights ([System.Security.AccessControl.FileSystemRights]::ReadPermissions) -ExtraSid $null -IncludeReadRule $false
    Set-TestAcl -Path $fixturePaths['unsafe-write'] -IsDirectory $false -Owner $currentUserSid -UsersRights ([System.Security.AccessControl.FileSystemRights]::WriteData) -ExtraSid $null
    Set-TestAcl -Path $fixturePaths['unsafe-denied-write'] -IsDirectory $false -Owner $currentUserSid -UsersRights ([System.Security.AccessControl.FileSystemRights]::WriteData) -ExtraSid $null -DenyUsersRights ([System.Security.AccessControl.FileSystemRights]::WriteData)
    Set-TestAcl -Path $fixturePaths['unsafe-append'] -IsDirectory $false -Owner $currentUserSid -UsersRights ([System.Security.AccessControl.FileSystemRights]::AppendData) -ExtraSid $null
    Set-TestAcl -Path $fixturePaths['unsafe-create-child'] -IsDirectory $true -Owner $currentUserSid -UsersRights ([System.Security.AccessControl.FileSystemRights]::AppendData) -ExtraSid $null
    Set-TestAcl -Path $fixturePaths['unsafe-delete'] -IsDirectory $false -Owner $currentUserSid -UsersRights ([System.Security.AccessControl.FileSystemRights]::Delete) -ExtraSid $null
    Set-TestAcl -Path $fixturePaths['unsafe-delete-child'] -IsDirectory $true -Owner $currentUserSid -UsersRights ([System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles) -ExtraSid $null
    Set-TestAcl -Path $fixturePaths['unsafe-acl'] -IsDirectory $false -Owner $currentUserSid -UsersRights ([System.Security.AccessControl.FileSystemRights]::ChangePermissions) -ExtraSid $null
    Set-TestAcl -Path $fixturePaths['unsafe-owner-right'] -IsDirectory $false -Owner $currentUserSid -UsersRights ([System.Security.AccessControl.FileSystemRights]::TakeOwnership) -ExtraSid $null -ProtectOwnerRights $false
    Set-TestAcl -Path $fixturePaths['unsafe-owner'] -IsDirectory $false -Owner $currentUserSid -UsersRights ([System.Security.AccessControl.FileSystemRights]0) -ExtraSid $null -ProtectOwnerRights $false
    Set-TestAcl -Path $fixturePaths['unknown-principal'] -IsDirectory $false -Owner $currentUserSid -UsersRights ([System.Security.AccessControl.FileSystemRights]0) -ExtraSid $unknownSid
    Set-TestAcl -Path $fixturePaths['generic-write'] -IsDirectory $false -Owner $currentUserSid -UsersRights ([System.Security.AccessControl.FileSystemRights]0) -ExtraSid $null
    if (-not [ProtectedWindowsTrustFixtureNative]::SetDaclSddl($fixturePaths['generic-write'], $false, 'D:(A;;FA;;;SY)(A;;FA;;;BA)(D;;0x00060000;;;OW)(A;;GW;;;BU)')) { throw 'Native GENERIC_WRITE ACE fixture setup failed.' }
    Set-TestAcl -Path $fixturePaths['generic-all'] -IsDirectory $false -Owner $currentUserSid -UsersRights ([System.Security.AccessControl.FileSystemRights]0) -ExtraSid $null
    if (-not [ProtectedWindowsTrustFixtureNative]::SetDaclSddl($fixturePaths['generic-all'], $false, 'D:(A;;FA;;;SY)(A;;FA;;;BA)(D;;0x00060000;;;OW)(A;;GA;;;BU)')) { throw 'Native GENERIC_ALL ACE fixture setup failed.' }
    Set-TestAcl -Path $fixturePaths['unsupported-ace'] -IsDirectory $false -Owner $currentUserSid -UsersRights ([System.Security.AccessControl.FileSystemRights]0) -ExtraSid $null
    if (-not [ProtectedWindowsTrustFixtureNative]::SetDaclSddl($fixturePaths['unsupported-ace'], $false, 'D:(A;;FA;;;SY)(A;;FA;;;BA)(D;;0x00060000;;;OW)(OA;;0x00000002;00000000-0000-0000-0000-000000000000;;BU)')) { throw 'Native unsupported object-ACE fixture setup failed.' }
    Set-TestAcl -Path $fixturePaths['owner-missing-write-dac'] -IsDirectory $false -Owner $currentUserSid -UsersRights ([System.Security.AccessControl.FileSystemRights]0) -ExtraSid $null -OwnerRightsMode 'MissingWriteDac'
    Set-TestAcl -Path $fixturePaths['owner-missing-write-owner'] -IsDirectory $false -Owner $currentUserSid -UsersRights ([System.Security.AccessControl.FileSystemRights]0) -ExtraSid $null -OwnerRightsMode 'MissingWriteOwner'
    Set-TestAcl -Path $fixturePaths['owner-inherit-only'] -IsDirectory $true -Owner $currentUserSid -UsersRights ([System.Security.AccessControl.FileSystemRights]0) -ExtraSid $null -OwnerRightsMode 'InheritOnly'
    Set-TestAcl -Path $fixturePaths['ProgramData'] -IsDirectory $true -Owner $currentUserSid -UsersRights ([System.Security.AccessControl.FileSystemRights]::AppendData) -ExtraSid $null

    if (-not [ProtectedWindowsTrustFixtureNative]::BeginRestrictedStandardTokenImpersonation()) {
        throw 'A non-elevated medium-integrity restricted impersonation token could not be established; native tests were not counted.'
    }
    $impersonationActive = $true
    $tokenFacts = @([ProtectedWindowsTrustFixtureNative]::GetCurrentTokenAttributeFacts())
    Assert-True ($tokenFacts -contains 'Elevation=0' -and $tokenFacts -contains 'IntegrityRid=8192') 'actual thread fixture token attributes are non-elevated and medium-integrity'
    Assert-True ($tokenFacts -contains 'AdminGroup=Absent' -or $tokenFacts -contains 'AdminGroup=DenyOnly' -or $tokenFacts -contains 'AdminGroup=Disabled') 'actual Administrators SID is absent, deny-only, or disabled; it is never treated as enabled standard-user proof'
    Assert-True (@($tokenFacts | Where-Object { $_ -match '^Se(TakeOwnership|Restore|Backup|Relabel|Security)Privilege=Enabled$' }).Count -eq 0) 'actual fixture privilege attributes contain no enabled dangerous privilege'
    $safeResult = Get-ProtectedWindowsTrust -Path $fixturePaths.safe
    Assert-True $safeResult.NativeChecksPerformed 'Windows positive case executed native handle, owner, DACL, and effective-access checks'
    Assert-True $safeResult.StandardUserTokenVerified 'native proof used the actual restricted thread-impersonation token, not caller booleans or the process token'
    Assert-True $safeResult.HandlesReleased -and $safeResult.HandlesOpened -eq $safeResult.HandlesClosed 'native handles are released before return'
    $safeExpectedObjectCount = (Get-ProtectedWindowsTrustPathComponents -Path $fixturePaths.safe).Segments.Count + 1
    Assert-True ($safeResult.CheckedObjectCount -eq $safeExpectedObjectCount -and $safeResult.Objects.Count -eq $safeExpectedObjectCount) 'native evidence has one actual row for the drive root and every path ancestor through the leaf'
    Assert-True ($safeResult.ObservationStatus -ceq 'Complete' -and $safeResult.Objects[0].Index -eq 0 -and $safeResult.Objects[0].FinalRecheckConfirmed) 'drive-root outcome and complete final-recheck status are explicit'
    for ($rowIndex = 0; $rowIndex -lt $safeResult.Objects.Count; $rowIndex++) {
        Assert-True ($safeResult.Objects[$rowIndex].Index -eq $rowIndex -and $safeResult.Objects[$rowIndex].ObservationStatus -ceq 'Complete' -and $safeResult.Objects[$rowIndex].FinalRecheckConfirmed) ("safe-chain row " + $rowIndex + ' is individually identified and finally rechecked')
    }
    Assert-True ($safeResult.Objects[-1].InitialProtectionObserved -and $safeResult.Objects[-1].FinalRecheckConfirmed -and $safeResult.Objects[-1].ProtectionObserved) 'safe synthetic leaf is positive both initially and after its final handle recheck'
    $everySafeRowFinal = @($safeResult.Objects | Where-Object { -not $_.FinalRecheckConfirmed }).Count -eq 0
    $everySafeRowPositive = @($safeResult.Objects | Where-Object { -not $_.ProtectionObserved }).Count -eq 0
    $expectedSafeChainPositive = $safeResult.StandardUserTokenVerified -and $safeResult.HandlesReleased -and $everySafeRowFinal -and $everySafeRowPositive
    Assert-True ($safeResult.ProtectionVerifiedForCurrentToken -eq $expectedSafeChainPositive) 'top-level protection equals a fully rechecked positive result for every actual ancestor and leaf row'
    Assert-True (($safeResult.Decision -ceq 'ProtectionObserved') -eq $expectedSafeChainPositive) 'safe-leaf decision cannot conceal a conflicting or incomplete ancestor'
    if (-not $safeResult.Objects[0].ProtectionObserved) { Assert-Refused $safeResult 'an actual drive-root conflict remains a whole-chain refusal' }
    Assert-True ($safeResult.Objects[-1].OwnerSid -ceq $currentUserSid.Value -and $safeResult.Objects[-1].OwnerProfileAccepted) 'native owner SID is read from the handle and accepted only with OWNER RIGHTS restrictions'
    Assert-True (-not ($safeResult.Objects[-1].GrantedDangerousRights -contains 'Ownership')) 'native evidence keeps owner SID/OWNER RIGHTS semantics separate from mask-based dangerous rights'
    Assert-True ($safeResult.Scope -match 'current effective caller token only' -and $safeResult.Scope -match 'future token changes') 'positive result is limited to one current token snapshot, not future privilege changes or other users'
    Assert-True (-not $safeResult.TrustEstablished -and -not $safeResult.InstallationAuthorized -and -not $safeResult.RemovalAuthorized) 'even positive native evidence is never installation, approval, or removal authorization'
    $positiveJson = ConvertTo-Json -InputObject $safeResult -Depth 8 -Compress
    Assert-True ($positiveJson.Length -lt 32768 -and -not $positiveJson.Contains($fixtureRoot)) 'native diagnostics are bounded and omit sensitive fixture paths'

    $readControlResult = Get-ProtectedWindowsTrust -Path $fixturePaths['read-control-only']
    Assert-True ($readControlResult.StandardUserTokenVerified -and $readControlResult.NativeChecksPerformed) 'READ_CONTROL case used the verified restricted token and native AccessCheck'
    Assert-True $readControlResult.Objects[-1].ProtectionObserved 'READ_CONTROL-only allow does not make the object ownership-unsafe when OWNER RIGHTS deny mutation'
    Assert-True ($readControlResult.Objects[-1].GrantedDangerousRights.Count -eq 0 -and $readControlResult.Objects[-1].OwnerSid -ceq $currentUserSid.Value) 'READ_CONTROL remains separate from the actual owner SID and dangerous-right results'

    $writeResult = Get-ProtectedWindowsTrust -Path $fixturePaths['unsafe-write']
    Assert-Refused $writeResult 'ordinary-user write right refuses protection'
    Assert-True ($writeResult.Objects[-1].GrantedDangerousRights -contains 'WriteDataOrAddFile') 'native effective access reports generic-mapped write/create-file rights'
    $deniedWriteResult = Get-ProtectedWindowsTrust -Path $fixturePaths['unsafe-denied-write']
    Assert-Refused $deniedWriteResult 'a deny cannot repair an overbroad allow under the restrictive profile'
    Assert-True $deniedWriteResult.Objects[-1].EffectiveAccessCheckCompleted 'native refusal path completed Windows AccessCheck rather than relying on a caller-supplied result'
    Assert-True (-not ($deniedWriteResult.Objects[-1].GrantedDangerousRights -contains 'WriteDataOrAddFile')) 'native AccessCheck honors the group deny for this token while the ACL profile still refuses the broad allow'
    $genericWriteResult = Get-ProtectedWindowsTrust -Path $fixturePaths['generic-write']
    Assert-Refused $genericWriteResult 'native GENERIC_WRITE ACE refuses protection'
    Assert-True ($genericWriteResult.Objects[-1].AclProfileRestrictive -eq $false -and $genericWriteResult.Objects[-1].EffectiveAccessCheckCompleted) 'native GENERIC_WRITE mapping is inspected and then checked by Windows AccessCheck'
    foreach ($right in @('WriteDataOrAddFile', 'AppendDataOrAddSubdirectory', 'WriteExtendedAttributes', 'WriteAttributes')) {
        Assert-True ($genericWriteResult.Objects[-1].PolicyConflictRights -contains $right -and $genericWriteResult.Objects[-1].GrantedDangerousRights -contains $right) ("native GENERIC_WRITE maps and grants " + $right)
    }
    $genericAllResult = Get-ProtectedWindowsTrust -Path $fixturePaths['generic-all']
    Assert-Refused $genericAllResult 'native GENERIC_ALL ACE refuses protection'
    foreach ($right in @('WriteDataOrAddFile', 'AppendDataOrAddSubdirectory', 'WriteExtendedAttributes', 'WriteAttributes', 'DeleteChild', 'Delete', 'WriteDac', 'WriteOwner')) {
        Assert-True ($genericAllResult.Objects[-1].PolicyConflictRights -contains $right -and $genericAllResult.Objects[-1].GrantedDangerousRights -contains $right) ("native GENERIC_ALL maps and grants " + $right)
    }
    $unsupportedAceResult = Get-ProtectedWindowsTrust -Path $fixturePaths['unsupported-ace']
    Assert-Refused $unsupportedAceResult 'native unsupported object ACE refuses protection'
    Assert-True ($unsupportedAceResult.ReasonCode -ceq 'UnsupportedAce' -or $unsupportedAceResult.ReasonCode -ceq 'EffectiveAccessCheckFailed') 'unsupported native ACE form is an explicit fail-closed refusal'
    $appendResult = Get-ProtectedWindowsTrust -Path $fixturePaths['unsafe-append']
    Assert-Refused $appendResult 'ordinary-user append right refuses protection'
    Assert-True ($appendResult.Objects[-1].GrantedDangerousRights -contains 'AppendDataOrAddSubdirectory') 'native effective access reports append rights'
    $createChildResult = Get-ProtectedWindowsTrust -Path $fixturePaths['unsafe-create-child']
    Assert-Refused $createChildResult 'ordinary-user directory create-child right refuses protection'
    Assert-True ($createChildResult.Objects[-1].GrantedDangerousRights -contains 'AppendDataOrAddSubdirectory') 'native effective access reports create-subdirectory rights'
    $deleteResult = Get-ProtectedWindowsTrust -Path $fixturePaths['unsafe-delete']
    Assert-Refused $deleteResult 'ordinary-user delete right refuses protection'
    Assert-True ($deleteResult.Objects[-1].GrantedDangerousRights -contains 'Delete') 'native effective access reports delete rights'
    $deleteChildResult = Get-ProtectedWindowsTrust -Path $fixturePaths['unsafe-delete-child']
    Assert-Refused $deleteChildResult 'ordinary-user delete-child right refuses protection'
    Assert-True ($deleteChildResult.Objects[-1].GrantedDangerousRights -contains 'DeleteChild') 'native effective access reports delete-child rights'
    $aclResult = Get-ProtectedWindowsTrust -Path $fixturePaths['unsafe-acl']
    Assert-Refused $aclResult 'ordinary-user WRITE_DAC right refuses protection'
    Assert-True ($aclResult.Objects[-1].GrantedDangerousRights -contains 'WriteDac') 'native effective access reports WRITE_DAC'
    $ownerRightResult = Get-ProtectedWindowsTrust -Path $fixturePaths['unsafe-owner-right']
    Assert-Refused $ownerRightResult 'ordinary-user WRITE_OWNER right refuses protection'
    Assert-True ($ownerRightResult.Objects[-1].GrantedDangerousRights -contains 'WriteOwner') 'native effective access reports WRITE_OWNER'
    $ownerResult = Get-ProtectedWindowsTrust -Path $fixturePaths['unsafe-owner']
    Assert-Refused $ownerResult 'ordinary-user object owner is untrusted even when the DACL is restrictive'
    Assert-True ($ownerResult.Objects[-1].FailureCode -ceq 'UntrustedOwner') 'native owner SID is checked against the restrictive owner profile'
    $ownerMissingWriteDacResult = Get-ProtectedWindowsTrust -Path $fixturePaths['owner-missing-write-dac']
    Assert-Refused $ownerMissingWriteDacResult 'OWNER RIGHTS missing WRITE_DAC denial refuses protection'
    Assert-True (-not $ownerMissingWriteDacResult.Objects[-1].OwnerProfileAccepted) 'an OWNER RIGHTS WRITE_OWNER-only deny does not satisfy the owner profile'
    $ownerMissingWriteOwnerResult = Get-ProtectedWindowsTrust -Path $fixturePaths['owner-missing-write-owner']
    Assert-Refused $ownerMissingWriteOwnerResult 'OWNER RIGHTS missing WRITE_OWNER denial refuses protection'
    Assert-True (-not $ownerMissingWriteOwnerResult.Objects[-1].OwnerProfileAccepted) 'an OWNER RIGHTS WRITE_DAC-only deny does not satisfy the owner profile'
    $ownerInheritOnlyResult = Get-ProtectedWindowsTrust -Path $fixturePaths['owner-inherit-only']
    Assert-Refused $ownerInheritOnlyResult 'inherit-only OWNER RIGHTS deny does not protect the current directory'
    Assert-True (-not $ownerInheritOnlyResult.Objects[-1].OwnerProfileAccepted) 'an inherit-only OWNER RIGHTS ACE is not counted as a current-object denial'
    $unknownResult = Get-ProtectedWindowsTrust -Path $fixturePaths['unknown-principal']
    Assert-Refused $unknownResult 'unknown ACL principal cannot establish protection'
    Assert-True ($unknownResult.Objects[-1].FailureCode -ceq 'UnknownPrincipal') 'unresolvable native ACL SID is reported as a bounded refusal'
    $reparseResult = Get-ProtectedWindowsTrust -Path $linkPath
    Assert-Refused $reparseResult 'reparse-point path refuses protection'
    Assert-True ($reparseResult.ReasonCode -ceq 'ReparsePointRefused' -or $reparseResult.Objects[-1].FailureCode -ceq 'ReparsePointRefused') 'native handle reparse attributes are checked'
    $ancestorReparseResult = Get-ProtectedWindowsTrust -Path (Join-Path $ancestorLinkPath 'object.bin')
    Assert-Refused $ancestorReparseResult 'reparse-point ancestor refuses protection before following its target'
    Assert-True ($ancestorReparseResult.ReasonCode -ceq 'ReparsePointRefused' -and $ancestorReparseResult.Objects[-1].IsReparsePoint) 'native relative open identifies the ancestor reparse point'

    $programDataSyntheticPath = Join-Path (Split-Path -Parent $fixturePaths['ProgramData']) 'object.bin'
    $programDataResult = Get-ProtectedWindowsTrust -Path $programDataSyntheticPath
    Assert-Refused $programDataResult 'temp-only ProgramData-named ancestor with an ordinary create-child ACE refuses protection'
    $programDataRows = @($programDataResult.Objects | Where-Object { $_.IsProgramDataAncestor })
    Assert-True ($programDataResult.ProgramDataAncestorPolicyConflict -and $programDataResult.ReasonCode -ceq 'ProgramDataAncestorPolicyConflict') 'synthetic ProgramData ancestor conflict is explicitly surfaced at the top level'
    Assert-True ($programDataRows.Count -eq 1 -and $programDataRows[0].PolicyConflictRights -contains 'AppendDataOrAddSubdirectory') 'the exact temp-only ProgramData-named row reports create-child conflict'
    $programDataJson = ConvertTo-Json -InputObject $programDataResult -Depth 8 -Compress
    Assert-True (-not $programDataJson.Contains($fixtureRoot)) 'synthetic ProgramData conflict diagnostics omit the fixture path'

    $fixtureRootParts = Get-ProtectedWindowsTrustPathComponents -Path $fixtureRoot
    $missingRelativeChild = 'missing-' + [Guid]::NewGuid().ToString('N')
    $relativeOpenFailurePath = Join-Path $fixtureRoot $missingRelativeChild
    $relativeOpenFailureResult = Get-ProtectedWindowsTrust -Path $relativeOpenFailurePath
    Assert-Refused $relativeOpenFailureResult 'a failed relative open after a positive fixture ancestor refuses the incomplete walk'
    $fixtureRootRow = $relativeOpenFailureResult.Objects[$fixtureRootParts.Segments.Count]
    Assert-True ($relativeOpenFailureResult.ReasonCode -ceq 'OpenFailed' -and $relativeOpenFailureResult.ObservationStatus -ceq 'Incomplete') 'relative-open failure is explicitly incomplete'
    Assert-True ($fixtureRootRow.InitialProtectionObserved -and -not $fixtureRootRow.ProtectionObserved -and -not $fixtureRootRow.FinalRecheckConfirmed -and $fixtureRootRow.ObservationStatus -ceq 'WalkIncomplete') 'positive fixture ancestor remains initial-only after later open failure'
    Assert-True (@($relativeOpenFailureResult.Objects | Where-Object { $_.ProtectionObserved -or $_.FinalRecheckConfirmed }).Count -eq 0) 'no per-object final positive survives an incomplete walk'
    Assert-True ($relativeOpenFailureResult.HandlesReleased -and $relativeOpenFailureResult.HandlesOpened -eq $relativeOpenFailureResult.HandlesClosed) 'relative-open failure releases all acquired native handles'
    $relativeFailureJson = ConvertTo-Json -InputObject $relativeOpenFailureResult -Depth 8 -Compress
    Assert-True (-not $relativeFailureJson.Contains($fixtureRoot)) 'relative-open failure diagnostics omit the fixture path'

    $allResults = @($safeResult, $readControlResult, $writeResult, $deniedWriteResult, $genericWriteResult, $genericAllResult, $unsupportedAceResult, $appendResult, $createChildResult, $deleteResult, $deleteChildResult, $aclResult, $ownerRightResult, $ownerResult, $ownerMissingWriteDacResult, $ownerMissingWriteOwnerResult, $ownerInheritOnlyResult, $unknownResult, $reparseResult, $ancestorReparseResult, $programDataResult, $relativeOpenFailureResult)
    foreach ($item in $allResults) {
        Assert-True ($item.NativeChecksPerformed -and $item.StandardUserTokenVerified) 'every native fixture outcome evaluated the restricted effective token'
        Assert-True ($item.HandlesReleased -and $item.HandlesOpened -eq $item.HandlesClosed) 'every native outcome releases every acquired handle'
        Assert-True ($item.ObservationStatus -ceq 'Complete' -or $item.ObservationStatus -ceq 'Incomplete' -or $item.ObservationStatus -ceq 'CleanupUncertain') 'every native outcome explicitly labels walk and cleanup completion'
        if ($item.ObservationStatus -ceq 'Incomplete' -or $item.ObservationStatus -ceq 'CleanupUncertain') {
            Assert-Refused $item 'incomplete observation or uncertain cleanup cannot retain top-level protection'
            Assert-True (@($item.Objects | Where-Object { $_.ProtectionObserved -or $_.FinalRecheckConfirmed }).Count -eq 0) 'incomplete observation or uncertain cleanup clears every unconfirmed per-object positive'
        }
        Assert-True (-not $item.InstallationAuthorized -and -not $item.RemovalAuthorized) 'no native outcome grants a destructive capability'
    }
    Write-Output "PASS: $script:Assertions assertions; Windows-native fixture checks executed."
} catch {
    $failure = $_.Exception
} finally {
    try {
        if ($impersonationActive) {
            if (-not [ProtectedWindowsTrustFixtureNative]::EndRestrictedStandardTokenImpersonation()) { throw 'Restricted token impersonation could not be reverted.' }
            $impersonationActive = $false
        }
        if ($null -ne ('ProtectedWindowsTrustFixtureNative' -as [type])) {
            if (-not [ProtectedWindowsTrustFixtureNative]::RestoreAndClose()) { throw 'Fixture ACL restoration failed.' }
        }
        if ([System.IO.Directory]::Exists($fixtureRoot)) { [System.IO.Directory]::Delete($fixtureRoot, $true) }
    } catch {
        $cleanupFailure = $_.Exception
    }
}
if ($null -ne $cleanupFailure) { throw 'Windows fixture cleanup failed; inspect only the GUID test directory under runner temp.' }
if ($null -ne $failure) { throw $failure }

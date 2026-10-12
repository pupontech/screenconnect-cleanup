# Read-only Windows object and ancestor protection observation.
# Positive observations are scoped to the current standard-user process token and never authorize an operation.

function Get-ProtectedWindowsTrustPathComponents {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Path
    )

    $invalid = {
        param($Code)
        return [pscustomobject][ordered]@{
            Valid = $false
            FailureCode = [string]$Code
            DriveRoot = ''
            Segments = @()
        }
    }

    if ([string]::IsNullOrEmpty($Path) -or $Path.Length -gt 32760 -or $Path.IndexOf([char]0) -ge 0) {
        return (& $invalid 'InvalidPath')
    }
    if ($Path -notmatch '^[A-Za-z]:\\' -or $Path.StartsWith('\\', [System.StringComparison]::Ordinal) -or $Path.Contains('/')) {
        return (& $invalid 'NonLocalPathRefused')
    }

    $tail = $Path.Substring(3)
    if ([string]::IsNullOrEmpty($tail) -or $tail.EndsWith('\', [System.StringComparison]::Ordinal)) {
        if ([string]::IsNullOrEmpty($tail)) { return (& $invalid 'RootPathRefused') }
        return (& $invalid 'EmptyComponent')
    }
    $segments = $tail.Split([char]92)
    if ($segments.Count -gt 64) { return (& $invalid 'PathDepthExceeded') }

    $reservedNames = @('CON', 'PRN', 'AUX', 'NUL', 'CLOCK$')
    foreach ($segment in $segments) {
        if ([string]::IsNullOrEmpty($segment)) { return (& $invalid 'EmptyComponent') }
        if ($segment.Length -gt 255) { return (& $invalid 'InvalidComponent') }
        if ($segment -ceq '.' -or $segment -ceq '..') { return (& $invalid 'TraversalComponent') }
        if ($segment.Contains(':')) { return (& $invalid 'AlternateDataStreamRefused') }
        if ($segment -match '[<>"|?*]' -or $segment -match '[\x00-\x1f]' -or $segment.EndsWith('.') -or $segment.EndsWith(' ')) {
            return (& $invalid 'InvalidComponent')
        }
        $deviceBase = $segment.Split([char]'.')[0].ToUpperInvariant()
        if ($reservedNames -contains $deviceBase -or $deviceBase -match '^(COM|LPT)[1-9]$') {
            return (& $invalid 'DeviceComponentRefused')
        }
    }

    return [pscustomobject][ordered]@{
        Valid = $true
        FailureCode = 'None'
        DriveRoot = $Path.Substring(0, 3)
        Segments = [string[]]$segments
    }
}

function Get-ProtectedWindowsTrustRightsPolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [uint32]$AccessMask
    )

    $mask = [uint64]$AccessMask
    if (($mask -band [uint64]2147483648) -ne 0) { $mask = ($mask -band [uint64]2147483647) -bor [uint64]1179785 }
    if (($mask -band [uint64]1073741824) -ne 0) { $mask = ($mask -band [uint64]3221225471) -bor [uint64]1179926 }
    if (($mask -band [uint64]536870912) -ne 0) { $mask = ($mask -band [uint64]3758096383) -bor [uint64]1179808 }
    if (($mask -band [uint64]268435456) -ne 0) { $mask = ($mask -band [uint64]4026531839) -bor [uint64]2032127 }

    $rights = New-Object 'System.Collections.Generic.List[string]'
    $dangerous = @(
        [pscustomobject]@{ Mask = [uint64]2; Name = 'WriteDataOrAddFile' },
        [pscustomobject]@{ Mask = [uint64]4; Name = 'AppendDataOrAddSubdirectory' },
        [pscustomobject]@{ Mask = [uint64]16; Name = 'WriteExtendedAttributes' },
        [pscustomobject]@{ Mask = [uint64]256; Name = 'WriteAttributes' },
        [pscustomobject]@{ Mask = [uint64]64; Name = 'DeleteChild' },
        [pscustomobject]@{ Mask = [uint64]65536; Name = 'Delete' },
        [pscustomobject]@{ Mask = [uint64]262144; Name = 'WriteDac' },
        [pscustomobject]@{ Mask = [uint64]524288; Name = 'WriteOwner' }
    )
    $dangerousMask = [uint64]0
    foreach ($right in $dangerous) {
        if (($mask -band $right.Mask) -ne 0) {
            [void]$rights.Add($right.Name)
            $dangerousMask = $dangerousMask -bor $right.Mask
        }
    }
    return [pscustomobject][ordered]@{
        MappedMask = [uint32]($mask -band [uint64]4294967295)
        DangerousMask = [uint32]$dangerousMask
        DangerousRights = $rights.ToArray()
    }
}

function New-ProtectedWindowsTrustRefusal {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ReasonCode,
        [int]$NativeErrorCode = 0,
        [string]$ExceptionType = ''
    )

    $boundedExceptionType = if ($ExceptionType.Length -gt 64) { $ExceptionType.Substring(0, 64) } else { $ExceptionType }
    return [pscustomobject][ordered]@{
        SchemaVersion = 1
        Decision = 'Refused'
        ReasonCode = $ReasonCode
        NativeChecksPerformed = $false
        StandardUserTokenVerified = $false
        ProtectionVerifiedForCurrentToken = $false
        ObservationStatus = 'NotStarted'
        Scope = 'One snapshot of the current effective caller token only: a thread impersonation token when present, otherwise the process token, verified as non-elevated and medium-integrity with its actual group and currently enabled privilege attributes evaluated by Windows AccessCheck. Any later token, group, or privilege adjustment requires a new observation. This does not establish access for other users, other token configurations, future token changes, or all standard users.'
        CheckedObjectCount = 0
        Objects = @()
        ProgramDataAncestorPolicyConflict = $false
        HandlesOpened = 0
        HandlesClosed = 0
        HandlesReleased = $true
        NativeErrorCode = $NativeErrorCode
        ExceptionType = $boundedExceptionType
        TrustEstablished = $false
        InstallationAuthorized = $false
        RemovalAuthorized = $false
    }
}

$script:ProtectedWindowsTrustNativeSource = @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace ProtectedWindowsTrust
{
    public sealed class ObjectEvidence
    {
        public int Index { get; set; }
        public string ObjectType { get; set; }
        public string ObjectIdentity { get; set; }
        public string OwnerSid { get; set; }
        public bool IsProgramDataAncestor { get; set; }
        public bool IsReparsePoint { get; set; }
        public bool CanonicalPathVerified { get; set; }
        public bool DaclPresent { get; set; }
        public bool OwnerProfileAccepted { get; set; }
        public bool AclProfileRestrictive { get; set; }
        public bool EffectiveAccessCheckCompleted { get; set; }
        public bool InitialProtectionObserved { get; set; }
        public bool FinalRecheckConfirmed { get; set; }
        public string ObservationStatus { get; set; }
        public string[] GrantedDangerousRights { get; set; }
        public string[] PolicyConflictRights { get; set; }
        public bool ProtectionObserved { get; set; }
        public string FailureCode { get; set; }
        public int NativeErrorCode { get; set; }
    }

    public sealed class VerificationResult
    {
        public bool NativeChecksPerformed { get; set; }
        public bool StandardUserTokenVerified { get; set; }
        public bool ProtectionVerifiedForCurrentToken { get; set; }
        public string ObservationStatus { get; set; }
        public bool ProgramDataAncestorPolicyConflict { get; set; }
        public bool HandlesReleased { get; set; }
        public int HandlesOpened { get; set; }
        public int HandlesClosed { get; set; }
        public int NativeErrorCode { get; set; }
        public string FailureCode { get; set; }
        public string ExceptionType { get; set; }
        public ObjectEvidence[] Objects { get; set; }
    }

    internal sealed class NativeFailure : Exception
    {
        internal readonly string Code;
        internal readonly int Error;
        internal NativeFailure(string code, int error) { Code = code; Error = error; }
    }

    internal sealed class SafeNativeHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        internal bool CloseSucceeded;
        internal SafeNativeHandle(IntPtr handle) : base(true) { SetHandle(handle); }
        protected override bool ReleaseHandle()
        {
            CloseSucceeded = NativeMethods.CloseHandle(handle);
            return CloseSucceeded;
        }
    }

    internal struct UnicodeString
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    internal struct ObjectAttributes
    {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    internal struct IoStatusBlock
    {
        public IntPtr StatusOrPointer;
        public UIntPtr Information;
    }

    internal struct GenericMapping
    {
        public uint GenericRead;
        public uint GenericWrite;
        public uint GenericExecute;
        public uint GenericAll;
    }

    internal struct AclSizeInformation
    {
        public uint AceCount;
        public uint AclBytesInUse;
        public uint AclBytesFree;
    }

    internal struct FileAttributeTagInformation
    {
        public uint FileAttributes;
        public uint ReparseTag;
    }

    internal struct FileStandardInformation
    {
        public long AllocationSize;
        public long EndOfFile;
        public uint NumberOfLinks;
        public byte DeletePending;
        public byte Directory;
    }

    internal struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    internal struct Luid
    {
        public uint LowPart;
        public int HighPart;
    }

    internal static class NativeMethods
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern IntPtr CreateFile(string name, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr template);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool GetFileInformationByHandle(SafeNativeHandle handle, out ByHandleFileInformation info);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool GetFileInformationByHandleEx(SafeNativeHandle handle, int infoClass, out FileAttributeTagInformation info, uint size);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool GetFileInformationByHandleEx(SafeNativeHandle handle, int infoClass, out FileStandardInformation info, uint size);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern uint GetFileType(SafeNativeHandle handle);

        [DllImport("kernel32.dll", EntryPoint = "GetFinalPathNameByHandleW", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern uint GetFinalPathNameByHandle(SafeNativeHandle handle, StringBuilder path, uint length, uint flags);

        [DllImport("ntdll.dll")]
        internal static extern int NtCreateFile(out IntPtr handle, uint access, ref ObjectAttributes attributes, out IoStatusBlock ioStatus, IntPtr allocationSize, uint fileAttributes, uint share, uint disposition, uint options, IntPtr eaBuffer, uint eaLength);

        [DllImport("ntdll.dll")]
        internal static extern uint RtlNtStatusToDosError(int status);

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern int GetSecurityInfo(SafeNativeHandle handle, int objectType, uint securityInfo, out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool GetSecurityDescriptorDacl(IntPtr descriptor, out bool daclPresent, out IntPtr dacl, out bool defaulted);

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool GetAclInformation(IntPtr acl, out AclSizeInformation info, uint length, int infoClass);

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool GetAce(IntPtr acl, uint index, out IntPtr ace);

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool IsValidSid(IntPtr sid);

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool EqualSid(IntPtr firstSid, IntPtr secondSid);

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern uint GetLengthSid(IntPtr sid);

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern IntPtr GetSidSubAuthority(IntPtr sid, uint index);

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool LookupAccountSidW(string systemName, IntPtr sid, StringBuilder name, ref uint nameLength, StringBuilder domain, ref uint domainLength, out int use);

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool OpenThreadToken(IntPtr thread, uint access, bool openAsSelf, out IntPtr token);

        [DllImport("kernel32.dll")]
        internal static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll")]
        internal static extern IntPtr GetCurrentThread();

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool DuplicateTokenEx(IntPtr existingToken, uint access, IntPtr attributes, int impersonationLevel, int tokenType, out IntPtr newToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool GetTokenInformation(SafeNativeHandle token, int infoClass, IntPtr info, uint infoLength, out uint returnLength);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool LookupPrivilegeValueW(string systemName, string name, out Luid luid);

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool AccessCheck(IntPtr descriptor, SafeNativeHandle token, uint desiredAccess, ref GenericMapping mapping, IntPtr privileges, ref uint privilegeLength, out uint grantedAccess, [MarshalAs(UnmanagedType.Bool)] out bool accessStatus);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr LocalFree(IntPtr memory);
    }

    public static class NativeVerifier
    {
        // Restrictive profile: require a present non-null DACL; resolve every
        // ACE SID; accept only simple allow/deny ACEs; permit dangerous allow
        // bits only for SYSTEM or BUILTIN\Administrators. The owner must be
        // SYSTEM/Administrators, or exactly this token user with OWNER RIGHTS
        // explicitly denying WRITE_DAC and WRITE_OWNER. Windows AccessCheck
        // still evaluates the complete current token, group denies, generic
        // mapping, and owner semantics for each dangerous right.
        // This is a one-token observation, not a population-wide trust policy.
        private const uint FileReadAttributes = 0x00000080;
        private const uint ReadControl = 0x00020000;
        private const uint Synchronize = 0x00100000;
        private const uint FileShareRead = 0x00000001;
        private const uint FileShareWrite = 0x00000002;
        private const uint OpenExisting = 3;
        private const uint FileFlagBackupSemantics = 0x02000000;
        private const uint FileFlagOpenReparsePoint = 0x00200000;
        private const uint FileOpen = 1;
        private const uint FileDirectoryFile = 0x00000001;
        private const uint FileSynchronousIoNonAlert = 0x00000020;
        private const uint FileOpenReparsePoint = 0x00200000;
        private const uint ObjectCaseInsensitive = 0x00000040;
        private const uint GenericRead = 0x80000000;
        private const uint GenericWrite = 0x40000000;
        private const uint GenericExecute = 0x20000000;
        private const uint GenericAll = 0x10000000;
        private const uint FileReadData = 0x00000001;
        private const uint FileWriteData = 0x00000002;
        private const uint FileAppendData = 0x00000004;
        private const uint FileWriteExtendedAttributes = 0x00000010;
        private const uint FileWriteAttributes = 0x00000100;
        private const uint FileDeleteChild = 0x00000040;
        private const uint Delete = 0x00010000;
        private const uint WriteDac = 0x00040000;
        private const uint WriteOwner = 0x00080000;
        private const uint FileAttributeReparsePoint = 0x00000400;
        private const uint FileAttributeDevice = 0x00000040;
        private const uint TokenDuplicate = 0x00000002;
        private const uint TokenImpersonate = 0x00000004;
        private const uint TokenQuery = 0x00000008;
        private const uint SecurityImpersonation = 2;
        private const uint TokenImpersonation = 2;
        private const uint ErrorInsufficientBuffer = 122;
        private const uint ErrorNoneMapped = 1332;
        private const int FileAttributeTagInfoClass = 9;
        private const int FileStandardInfoClass = 1;
        private const int TokenUserClass = 1;
        private const int TokenGroupsClass = 2;
        private const int TokenPrivilegesClass = 3;
        private const int TokenTypeClass = 8;
        private const int TokenImpersonationLevelClass = 9;
        private const int TokenElevationClass = 20;
        private const int TokenIntegrityLevelClass = 25;
        private const int TokenIsAppContainerClass = 29;
        private const uint OwnerSecurityInformation = 0x00000001;
        private const uint DaclSecurityInformation = 0x00000004;
        private const uint FileObjectType = 1;
        private const uint DangerousMask = FileWriteData | FileAppendData | FileWriteExtendedAttributes | FileWriteAttributes | FileDeleteChild | Delete | WriteDac | WriteOwner;
        private const int AccessAllowedAceType = 0;
        private const int AccessDeniedAceType = 1;
        private const int InheritOnlyAceFlag = 0x08;
        private const int AceHeaderLength = 8;
        private const int AclSizeInformationClass = 2;
        private const int StandardIntegrityRid = 0x2000;
        private const int MaximumGroups = 256;
        private const int LuidAndAttributesSize = 12;
        private const uint TokenGroupEnabled = 0x00000004;
        private const uint TokenGroupUseForDenyOnly = 0x00000010;
        private const uint PrivilegeEnabled = 0x00000002;

        private static GenericMapping FileMapping = new GenericMapping
        {
            GenericRead = 0x00120089,
            GenericWrite = 0x00120116,
            GenericExecute = 0x001200A0,
            GenericAll = 0x001F01FF
        };

        private static readonly uint[] DangerousRights = new uint[]
        {
            FileWriteData, FileAppendData, FileWriteExtendedAttributes, FileWriteAttributes, FileDeleteChild, Delete, WriteDac, WriteOwner
        };

        private static readonly string[] DangerousNames = new string[]
        {
            "WriteDataOrAddFile", "AppendDataOrAddSubdirectory", "WriteExtendedAttributes", "WriteAttributes", "DeleteChild", "Delete", "WriteDac", "WriteOwner"
        };

        public static VerificationResult Verify(string driveRoot, string[] components)
        {
            VerificationResult result = new VerificationResult();
            result.FailureCode = "None";
            result.ExceptionType = String.Empty;
            result.ObservationStatus = "NotStarted";
            result.Objects = new ObjectEvidence[0];
            result.HandlesReleased = true;
            List<SafeNativeHandle> handles = new List<SafeNativeHandle>();
            List<SafeNativeHandle> objectHandles = new List<SafeNativeHandle>();
            List<string> expectedPaths = new List<string>();
            List<bool> directoryRequirements = new List<bool>();
            List<bool> programDataFlags = new List<bool>();
            List<ObjectEvidence> evidence = new List<ObjectEvidence>();
            bool finalRecheckStarted = false;
            try
            {
                result.NativeChecksPerformed = true;
                if (!IsSafeDriveRoot(driveRoot) || components == null || components.Length == 0 || components.Length > 64)
                    throw new NativeFailure("InvalidPath", 0);
                for (int componentIndex = 0; componentIndex < components.Length; componentIndex++)
                    if (!IsSafeComponent(components[componentIndex])) throw new NativeFailure("InvalidPath", 0);

                string userSid;
                SafeNativeHandle accessToken = VerifyCurrentStandardUserToken(handles, result, out userSid);
                string expectedPath = String.Concat("\\\\?\\", driveRoot);
                HashSet<string> identities = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                SafeNativeHandle parent = OpenDriveRoot(expectedPath, handles);
                objectHandles.Add(parent);
                expectedPaths.Add(expectedPath);
                directoryRequirements.Add(true);
                programDataFlags.Add(false);
                ObjectEvidence rootEvidence = InspectObject(parent, 0, expectedPath, true, false, userSid, accessToken, result);
                evidence.Add(rootEvidence);
                if (!rootEvidence.ProtectionObserved) RecordRefusal(result, rootEvidence);
                if (rootEvidence.IsReparsePoint || !rootEvidence.CanonicalPathVerified) throw new NativeFailure(rootEvidence.FailureCode, rootEvidence.NativeErrorCode);
                identities.Add(rootEvidence.ObjectIdentity);

                for (int index = 0; index < components.Length; index++)
                {
                    string component = components[index];
                    if (String.IsNullOrEmpty(component) || component.IndexOfAny(new char[] { '\\', '/', ':' }) >= 0)
                        throw new NativeFailure("InvalidPath", 0);
                    bool isLast = index == components.Length - 1;
                    string expectedChild = expectedPath.EndsWith("\\", StringComparison.Ordinal) ? expectedPath + component : expectedPath + "\\" + component;
                    SafeNativeHandle child = OpenChild(parent, component, !isLast, handles);
                    bool isProgramData = String.Equals(component, "ProgramData", StringComparison.OrdinalIgnoreCase);
                    objectHandles.Add(child);
                    expectedPaths.Add(expectedChild);
                    directoryRequirements.Add(!isLast);
                    programDataFlags.Add(isProgramData);
                    ObjectEvidence item = InspectObject(child, index + 1, expectedChild, !isLast, isProgramData, userSid, accessToken, result);
                    evidence.Add(item);
                    if (identities.Contains(item.ObjectIdentity))
                    {
                        item.FailureCode = "RepeatedObjectIdentity";
                        item.ProtectionObserved = false;
                        RecordRefusal(result, item);
                    }
                    identities.Add(item.ObjectIdentity);
                    if (!item.ProtectionObserved) RecordRefusal(result, item);
                    // Surface existing ProgramData policy conflicts; never alter policy.
                    if (item.IsProgramDataAncestor && item.PolicyConflictRights.Length > 0)
                        result.ProgramDataAncestorPolicyConflict = true;
                    if (item.IsReparsePoint || !item.CanonicalPathVerified) throw new NativeFailure(item.FailureCode, item.NativeErrorCode);
                    expectedPath = expectedChild;
                    parent = child;
                }

                finalRecheckStarted = true;
                for (int i = 0; i < objectHandles.Count; i++)
                {
                    ObjectEvidence rechecked = InspectObject(objectHandles[i], i, expectedPaths[i], directoryRequirements[i], programDataFlags[i], userSid, accessToken, result);
                    if (!SameProtectionObservation(evidence[i], rechecked))
                    {
                        evidence[i].ProtectionObserved = false;
                        evidence[i].FinalRecheckConfirmed = false;
                        evidence[i].ObservationStatus = "FinalRecheckMismatch";
                        evidence[i].FailureCode = "SecurityChangedDuringObservation";
                        RecordRefusal(result, evidence[i]);
                    }
                    else
                    {
                        evidence[i].FinalRecheckConfirmed = true;
                        evidence[i].ObservationStatus = "Complete";
                    }
                }

                result.ObservationStatus = "Complete";
                result.Objects = evidence.ToArray();
                result.ProtectionVerifiedForCurrentToken = result.StandardUserTokenVerified && result.FailureCode == "None" && evidence.Count == components.Length + 1;
                if (result.ProtectionVerifiedForCurrentToken) result.FailureCode = "ProtectionObserved";
                else if (result.ProgramDataAncestorPolicyConflict) result.FailureCode = "ProgramDataAncestorPolicyConflict";
                else if (result.FailureCode == "None") result.FailureCode = "ProtectionNotEstablished";
            }
            catch (NativeFailure failure)
            {
                result.FailureCode = failure.Code;
                result.NativeErrorCode = failure.Error;
                result.ProtectionVerifiedForCurrentToken = false;
                result.ObservationStatus = "Incomplete";
                MarkIncompleteEvidence(evidence, finalRecheckStarted ? "RecheckIncomplete" : "WalkIncomplete");
                result.Objects = evidence.ToArray();
            }
            catch (Exception exception)
            {
                result.FailureCode = "NativeFailure";
                result.NativeErrorCode = exception is Win32Exception ? ((Win32Exception)exception).NativeErrorCode : 0;
                result.ExceptionType = exception.GetType().Name;
                result.ProtectionVerifiedForCurrentToken = false;
                result.ObservationStatus = "Incomplete";
                MarkIncompleteEvidence(evidence, finalRecheckStarted ? "RecheckIncomplete" : "WalkIncomplete");
                result.Objects = evidence.ToArray();
            }
            finally
            {
                for (int i = handles.Count - 1; i >= 0; i--)
                {
                    SafeNativeHandle handle = handles[i];
                    handle.Dispose();
                    if (handle.CloseSucceeded) result.HandlesClosed++;
                }
                result.HandlesOpened = handles.Count;
                result.HandlesReleased = result.HandlesClosed == result.HandlesOpened;
                if (!result.HandlesReleased)
                {
                    result.ProtectionVerifiedForCurrentToken = false;
                    result.FailureCode = "HandleReleaseFailed";
                    result.ObservationStatus = "CleanupUncertain";
                    MarkIncompleteEvidence(evidence, "CleanupUncertain");
                }
                result.Objects = evidence.ToArray();
            }
            return result;
        }

        private static void MarkIncompleteEvidence(List<ObjectEvidence> evidence, string status)
        {
            for (int i = 0; i < evidence.Count; i++) MarkIncompleteEvidence(evidence[i], status);
        }

        private static void MarkIncompleteEvidence(ObjectEvidence item, string status)
        {
            if (item == null) return;
            item.ProtectionObserved = false;
            item.FinalRecheckConfirmed = false;
            item.ObservationStatus = status;
        }

        private static bool SameProtectionObservation(ObjectEvidence first, ObjectEvidence second)
        {
            if (first == null || second == null) return false;
            if (!String.Equals(first.ObjectType, second.ObjectType, StringComparison.Ordinal) ||
                !String.Equals(first.ObjectIdentity, second.ObjectIdentity, StringComparison.Ordinal) ||
                !String.Equals(first.OwnerSid, second.OwnerSid, StringComparison.Ordinal) ||
                first.IsReparsePoint != second.IsReparsePoint || first.CanonicalPathVerified != second.CanonicalPathVerified ||
                first.DaclPresent != second.DaclPresent || first.OwnerProfileAccepted != second.OwnerProfileAccepted ||
                first.AclProfileRestrictive != second.AclProfileRestrictive ||
                first.EffectiveAccessCheckCompleted != second.EffectiveAccessCheckCompleted ||
                first.ProtectionObserved != second.ProtectionObserved) return false;
            if (!SameStringSet(first.GrantedDangerousRights, second.GrantedDangerousRights)) return false;
            return SameStringSet(first.PolicyConflictRights, second.PolicyConflictRights);
        }

        private static bool SameStringSet(string[] first, string[] second)
        {
            if (first == null || second == null || first.Length != second.Length) return false;
            for (int i = 0; i < first.Length; i++)
            {
                bool found = false;
                for (int j = 0; j < second.Length; j++)
                    if (String.Equals(first[i], second[j], StringComparison.Ordinal)) found = true;
                if (!found) return false;
            }
            return true;
        }

        private static bool IsSafeDriveRoot(string driveRoot)
        {
            return driveRoot != null && driveRoot.Length == 3 &&
                ((driveRoot[0] >= 'A' && driveRoot[0] <= 'Z') || (driveRoot[0] >= 'a' && driveRoot[0] <= 'z')) &&
                driveRoot[1] == ':' && driveRoot[2] == '\\';
        }

        private static bool IsSafeComponent(string component)
        {
            if (String.IsNullOrEmpty(component) || component.Length > 255 || component == "." || component == ".." ||
                component.IndexOfAny(new char[] { '\\', '/', ':', '<', '>', '"', '|', '?', '*' }) >= 0 ||
                component[component.Length - 1] == '.' || component[component.Length - 1] == ' ') return false;
            for (int i = 0; i < component.Length; i++) if (component[i] < 32) return false;
            string device = component.Split('.')[0].ToUpperInvariant();
            if (device == "CON" || device == "PRN" || device == "AUX" || device == "NUL" || device == "CLOCK$") return false;
            if (device.Length == 4 && (device.StartsWith("COM", StringComparison.Ordinal) || device.StartsWith("LPT", StringComparison.Ordinal)) && device[3] >= '1' && device[3] <= '9') return false;
            return true;
        }

        private static void RecordRefusal(VerificationResult result, ObjectEvidence item)
        {
            if (item.IsProgramDataAncestor && item.PolicyConflictRights.Length > 0)
                result.ProgramDataAncestorPolicyConflict = true;
            if (result.FailureCode == "None" || result.FailureCode == "ProtectionObserved" || result.FailureCode == "NativeFailure")
            {
                result.FailureCode = String.IsNullOrEmpty(item.FailureCode) ? "ProtectionNotEstablished" : item.FailureCode;
                result.NativeErrorCode = item.NativeErrorCode;
            }
        }

        private static SafeNativeHandle VerifyCurrentStandardUserToken(List<SafeNativeHandle> handles, VerificationResult result, out string userSid)
        {
            IntPtr rawToken;
            bool threadToken = NativeMethods.OpenThreadToken(NativeMethods.GetCurrentThread(), TokenQuery | TokenDuplicate, true, out rawToken);
            if (!threadToken)
            {
                int threadError = Marshal.GetLastWin32Error();
                if (threadError != 1008) throw new NativeFailure("TokenQueryFailed", threadError);
                if (!NativeMethods.OpenProcessToken(NativeMethods.GetCurrentProcess(), TokenQuery | TokenDuplicate, out rawToken))
                    throw new NativeFailure("TokenQueryFailed", Marshal.GetLastWin32Error());
            }
            SafeNativeHandle processToken = Track(rawToken, handles);
            if (threadToken)
            {
                uint tokenType = ReadTokenUInt32(processToken, TokenTypeClass);
                uint impersonationLevel = ReadTokenUInt32(processToken, TokenImpersonationLevelClass);
                if (tokenType != TokenImpersonation || impersonationLevel < SecurityImpersonation)
                    throw new NativeFailure("UnsupportedTokenConfiguration", 0);
            }

            IntPtr userBuffer = ReadTokenInformation(processToken, TokenUserClass);
            try
            {
                IntPtr userPointer = Marshal.ReadIntPtr(userBuffer);
                if (userPointer == IntPtr.Zero || !NativeMethods.IsValidSid(userPointer))
                    throw new NativeFailure("UnverifiableGroupMembership", 0);
                userSid = SidValue(userPointer);
                SecurityIdentifier tokenUser = new SecurityIdentifier(userSid);
                if (tokenUser.IsWellKnown(WellKnownSidType.LocalSystemSid) || tokenUser.IsWellKnown(WellKnownSidType.LocalServiceSid) || tokenUser.IsWellKnown(WellKnownSidType.NetworkServiceSid))
                    throw new NativeFailure("StandardUserTokenRequired", 0);
                string ignoredUserAccount;
                if (!LookupSid(userPointer, out ignoredUserAccount))
                    throw new NativeFailure("UnverifiableGroupMembership", (int)ErrorNoneMapped);
            }
            finally { Marshal.FreeHGlobal(userBuffer); }

            IntPtr groupsBuffer = ReadTokenInformation(processToken, TokenGroupsClass);
            try
            {
                int count = Marshal.ReadInt32(groupsBuffer);
                if (count < 0 || count > MaximumGroups) throw new NativeFailure("UnverifiableGroupMembership", 0);
                int first = IntPtr.Size == 8 ? 8 : 4;
                int stride = IntPtr.Size == 8 ? 16 : 8;
                SecurityIdentifier administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
                IntPtr adminsSid = IntPtr.Zero;
                byte[] adminBytes = new byte[administrators.BinaryLength];
                administrators.GetBinaryForm(adminBytes, 0);
                adminsSid = Marshal.AllocHGlobal(adminBytes.Length);
                try
                {
                    Marshal.Copy(adminBytes, 0, adminsSid, adminBytes.Length);
                    for (int i = 0; i < count; i++)
                    {
                        IntPtr entry = IntPtr.Add(groupsBuffer, first + (i * stride));
                        IntPtr sid = Marshal.ReadIntPtr(entry);
                        uint attributes = unchecked((uint)Marshal.ReadInt32(entry, IntPtr.Size));
                        if (sid == IntPtr.Zero || !NativeMethods.IsValidSid(sid)) throw new NativeFailure("UnverifiableGroupMembership", 0);
                        string ignoredGroupAccount;
                        if (!LookupSid(sid, out ignoredGroupAccount)) throw new NativeFailure("UnverifiableGroupMembership", (int)ErrorNoneMapped);
                        if (NativeMethods.EqualSid(sid, adminsSid) &&
                            (attributes & TokenGroupEnabled) != 0 && (attributes & TokenGroupUseForDenyOnly) == 0)
                            throw new NativeFailure("StandardUserTokenRequired", 0);
                    }
                }
                finally { Marshal.FreeHGlobal(adminsSid); }
            }
            finally { Marshal.FreeHGlobal(groupsBuffer); }

            uint elevation = ReadTokenUInt32(processToken, TokenElevationClass);
            if (elevation != 0) throw new NativeFailure("StandardUserTokenRequired", 0);
            uint appContainer = ReadTokenUInt32(processToken, TokenIsAppContainerClass);
            if (appContainer != 0) throw new NativeFailure("UnsupportedTokenConfiguration", 0);

            IntPtr integrityBuffer = ReadTokenInformation(processToken, TokenIntegrityLevelClass);
            try
            {
                IntPtr integritySid = Marshal.ReadIntPtr(integrityBuffer);
                if (integritySid == IntPtr.Zero || !NativeMethods.IsValidSid(integritySid)) throw new NativeFailure("UnverifiableGroupMembership", 0);
                IntPtr countPointer = NativeMethods.GetSidSubAuthorityCount(integritySid);
                if (countPointer == IntPtr.Zero) throw new NativeFailure("UnverifiableGroupMembership", Marshal.GetLastWin32Error());
                byte subAuthorityCount = Marshal.ReadByte(countPointer);
                if (subAuthorityCount == 0) throw new NativeFailure("UnverifiableGroupMembership", 0);
                IntPtr ridPointer = NativeMethods.GetSidSubAuthority(integritySid, (uint)(subAuthorityCount - 1));
                if (ridPointer == IntPtr.Zero || Marshal.ReadInt32(ridPointer) != StandardIntegrityRid)
                    throw new NativeFailure("StandardUserTokenRequired", 0);
            }
            finally { Marshal.FreeHGlobal(integrityBuffer); }

            VerifyDangerousPrivileges(processToken);
            IntPtr impersonationRaw;
            if (!NativeMethods.DuplicateTokenEx(processToken.DangerousGetHandle(), TokenQuery | TokenImpersonate, IntPtr.Zero, (int)SecurityImpersonation, (int)TokenImpersonation, out impersonationRaw))
                throw new NativeFailure("TokenDuplicationFailed", Marshal.GetLastWin32Error());
            SafeNativeHandle impersonationToken = Track(impersonationRaw, handles);
            result.StandardUserTokenVerified = true;
            return impersonationToken;
        }

        private static IntPtr ReadTokenInformation(SafeNativeHandle token, int infoClass)
        {
            uint needed;
            NativeMethods.GetTokenInformation(token, infoClass, IntPtr.Zero, 0, out needed);
            int firstError = Marshal.GetLastWin32Error();
            if (needed == 0 || (firstError != ErrorInsufficientBuffer && firstError != 0) || needed > 1048576)
                throw new NativeFailure("TokenQueryFailed", firstError);
            IntPtr buffer = Marshal.AllocHGlobal((int)needed);
            uint returned;
            if (!NativeMethods.GetTokenInformation(token, infoClass, buffer, needed, out returned))
            {
                int error = Marshal.GetLastWin32Error();
                Marshal.FreeHGlobal(buffer);
                throw new NativeFailure("TokenQueryFailed", error);
            }
            return buffer;
        }

        private static uint ReadTokenUInt32(SafeNativeHandle token, int infoClass)
        {
            IntPtr buffer = ReadTokenInformation(token, infoClass);
            try { return unchecked((uint)Marshal.ReadInt32(buffer)); }
            finally { Marshal.FreeHGlobal(buffer); }
        }

        private static void VerifyDangerousPrivileges(SafeNativeHandle token)
        {
            IntPtr buffer = ReadTokenInformation(token, TokenPrivilegesClass);
            try
            {
                int count = Marshal.ReadInt32(buffer);
                if (count < 0 || count > 4096) throw new NativeFailure("UnverifiablePrivileges", 0);
                int offset = 4;
                int stride = LuidAndAttributesSize;
                string[] names = new string[] { "SeTakeOwnershipPrivilege", "SeRestorePrivilege", "SeBackupPrivilege", "SeRelabelPrivilege", "SeSecurityPrivilege" };
                Luid[] dangerous = new Luid[names.Length];
                for (int i = 0; i < names.Length; i++)
                {
                    if (!NativeMethods.LookupPrivilegeValueW(null, names[i], out dangerous[i]))
                        throw new NativeFailure("UnverifiablePrivileges", Marshal.GetLastWin32Error());
                }
                for (int i = 0; i < count; i++)
                {
                    IntPtr entry = IntPtr.Add(buffer, offset + (i * stride));
                    Luid luid = new Luid { LowPart = unchecked((uint)Marshal.ReadInt32(entry)), HighPart = Marshal.ReadInt32(entry, 4) };
                    for (int p = 0; p < dangerous.Length; p++)
                    {
                        uint attributes = unchecked((uint)Marshal.ReadInt32(entry, 8));
                        if (luid.LowPart == dangerous[p].LowPart && luid.HighPart == dangerous[p].HighPart &&
                            (attributes & PrivilegeEnabled) != 0)
                            throw new NativeFailure("StandardUserTokenRequired", 0);
                    }
                }
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }

        private static SafeNativeHandle OpenDriveRoot(string path, List<SafeNativeHandle> handles)
        {
            IntPtr raw = NativeMethods.CreateFile(path, FileReadAttributes | ReadControl | Synchronize, FileShareRead | FileShareWrite, IntPtr.Zero, OpenExisting, FileFlagBackupSemantics | FileFlagOpenReparsePoint, IntPtr.Zero);
            if (raw == new IntPtr(-1) || raw == IntPtr.Zero) throw new NativeFailure("OpenFailed", Marshal.GetLastWin32Error());
            return Track(raw, handles);
        }

        private static SafeNativeHandle OpenChild(SafeNativeHandle parent, string component, bool requireDirectory, List<SafeNativeHandle> handles)
        {
            IntPtr nameBuffer = Marshal.StringToHGlobalUni(component);
            IntPtr unicodePointer = IntPtr.Zero;
            try
            {
                UnicodeString name = new UnicodeString();
                name.Length = checked((ushort)(component.Length * 2));
                name.MaximumLength = name.Length;
                name.Buffer = nameBuffer;
                unicodePointer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UnicodeString)));
                Marshal.StructureToPtr(name, unicodePointer, false);
                ObjectAttributes attributes = new ObjectAttributes();
                attributes.Length = Marshal.SizeOf(typeof(ObjectAttributes));
                attributes.RootDirectory = parent.DangerousGetHandle();
                attributes.ObjectName = unicodePointer;
                attributes.Attributes = ObjectCaseInsensitive;
                IoStatusBlock ioStatus;
                IntPtr raw;
                uint options = FileOpenReparsePoint | FileSynchronousIoNonAlert;
                if (requireDirectory) options |= FileDirectoryFile;
                int status = NativeMethods.NtCreateFile(out raw, FileReadAttributes | ReadControl | Synchronize, ref attributes, out ioStatus, IntPtr.Zero, 0x00000080, FileShareRead | FileShareWrite, FileOpen, options, IntPtr.Zero, 0);
                if (status < 0)
                {
                    if (raw != IntPtr.Zero && raw != new IntPtr(-1)) NativeMethods.CloseHandle(raw);
                    throw new NativeFailure("OpenFailed", unchecked((int)NativeMethods.RtlNtStatusToDosError(status)));
                }
                if (raw == IntPtr.Zero || raw == new IntPtr(-1)) throw new NativeFailure("OpenFailed", 0);
                return Track(raw, handles);
            }
            finally
            {
                if (unicodePointer != IntPtr.Zero) Marshal.FreeHGlobal(unicodePointer);
                Marshal.FreeHGlobal(nameBuffer);
            }
        }

        private static SafeNativeHandle Track(IntPtr raw, List<SafeNativeHandle> handles)
        {
            SafeNativeHandle handle = new SafeNativeHandle(raw);
            handles.Add(handle);
            return handle;
        }

        private static ObjectEvidence InspectObject(SafeNativeHandle handle, int index, string expectedPath, bool requireDirectory, bool programData, string userSid, SafeNativeHandle accessToken, VerificationResult result)
        {
            ObjectEvidence item = new ObjectEvidence();
            item.Index = index;
            item.ObjectType = "Unknown";
            item.ObjectIdentity = String.Empty;
            item.OwnerSid = String.Empty;
            item.IsProgramDataAncestor = programData;
            item.GrantedDangerousRights = new string[0];
            item.PolicyConflictRights = new string[0];
            item.FailureCode = "None";
            item.ObservationStatus = "InitialObservation";

            if (NativeMethods.GetFileType(handle) != 1) throw new NativeFailure("UnsupportedObjectType", Marshal.GetLastWin32Error());
            FileAttributeTagInformation tag;
            if (!NativeMethods.GetFileInformationByHandleEx(handle, FileAttributeTagInfoClass, out tag, (uint)Marshal.SizeOf(typeof(FileAttributeTagInformation))))
                throw new NativeFailure("ObjectIdentityQueryFailed", Marshal.GetLastWin32Error());
            item.IsReparsePoint = (tag.FileAttributes & FileAttributeReparsePoint) != 0;
            if ((tag.FileAttributes & FileAttributeDevice) != 0) throw new NativeFailure("UnsupportedObjectType", 0);
            FileStandardInformation standard;
            if (!NativeMethods.GetFileInformationByHandleEx(handle, FileStandardInfoClass, out standard, (uint)Marshal.SizeOf(typeof(FileStandardInformation))))
                throw new NativeFailure("ObjectIdentityQueryFailed", Marshal.GetLastWin32Error());
            if (standard.DeletePending != 0) throw new NativeFailure("DeletePending", 0);
            bool isDirectory = standard.Directory != 0;
            item.ObjectType = isDirectory ? "Directory" : "File";
            if (requireDirectory && !isDirectory) throw new NativeFailure("AncestorNotDirectory", 0);

            if (item.IsReparsePoint)
            {
                item.FailureCode = "ReparsePointRefused";
                return item;
            }

            string actualPath = FinalPath(handle);
            string expectedNativePath = expectedPath.StartsWith("\\\\?\\", StringComparison.Ordinal) ? expectedPath : String.Concat("\\\\?\\", expectedPath);
            item.CanonicalPathVerified = String.Equals(actualPath, expectedNativePath, StringComparison.OrdinalIgnoreCase);
            if (!item.CanonicalPathVerified)
            {
                item.FailureCode = "CanonicalPathMismatch";
                return item;
            }
            ByHandleFileInformation identity;
            if (!NativeMethods.GetFileInformationByHandle(handle, out identity)) throw new NativeFailure("ObjectIdentityQueryFailed", Marshal.GetLastWin32Error());
            item.ObjectIdentity = String.Format("{0:x8}:{1:x8}{2:x8}", identity.VolumeSerialNumber, identity.FileIndexHigh, identity.FileIndexLow);

            IntPtr owner;
            IntPtr group;
            IntPtr dacl;
            IntPtr sacl;
            IntPtr descriptor;
            int securityError = NativeMethods.GetSecurityInfo(handle, (int)FileObjectType, OwnerSecurityInformation | DaclSecurityInformation, out owner, out group, out dacl, out sacl, out descriptor);
            if (securityError != 0) throw new NativeFailure("SecurityDescriptorQueryFailed", securityError);
            try
            {
                bool daclPresent;
                bool defaulted;
                if (!NativeMethods.GetSecurityDescriptorDacl(descriptor, out daclPresent, out dacl, out defaulted))
                    throw new NativeFailure("SecurityDescriptorQueryFailed", Marshal.GetLastWin32Error());
                item.DaclPresent = daclPresent && dacl != IntPtr.Zero;
                if (owner == IntPtr.Zero || !NativeMethods.IsValidSid(owner)) throw new NativeFailure("UnknownPrincipal", (int)ErrorNoneMapped);
                SecurityIdentifier ownerIdentifier = new SecurityIdentifier(owner);
                item.OwnerSid = ownerIdentifier.Value;
                string ignoredOwnerAccount;
                if (!LookupSid(owner, out ignoredOwnerAccount)) throw new NativeFailure("UnknownPrincipal", (int)ErrorNoneMapped);

                List<string> conflictRights = new List<string>();
                bool profileRestrictive;
                uint ownerRightsDenied;
                string aclFailure;
                int aclError;
                profileRestrictive = InspectDacl(dacl, item.DaclPresent, conflictRights, out ownerRightsDenied, out aclFailure, out aclError);
                item.NativeErrorCode = aclError;
                SecurityIdentifier ownerSid = new SecurityIdentifier(owner);
                SecurityIdentifier currentUser = new SecurityIdentifier(userSid);
                bool systemOwner = ownerSid.IsWellKnown(WellKnownSidType.LocalSystemSid);
                bool adminsOwner = ownerSid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid);
                bool currentUserOwner = ownerSid.Equals(currentUser);
                bool ownerRightsProtected = (ownerRightsDenied & (WriteDac | WriteOwner)) == (WriteDac | WriteOwner);
                item.OwnerProfileAccepted = systemOwner || adminsOwner || (currentUserOwner && ownerRightsProtected);
                item.AclProfileRestrictive = profileRestrictive && String.IsNullOrEmpty(aclFailure);
                if (!item.DaclPresent) item.AclProfileRestrictive = false;
                if (!item.OwnerProfileAccepted && item.FailureCode == "None") item.FailureCode = "UntrustedOwner";
                if (!String.IsNullOrEmpty(aclFailure) && item.FailureCode == "None") item.FailureCode = aclFailure;

                List<string> granted = new List<string>();
                for (int i = 0; i < DangerousRights.Length; i++)
                {
                    uint requested = DangerousRights[i];
                    bool allowed = AccessGranted(descriptor, accessToken, requested);
                    if (allowed) granted.Add(DangerousNames[i]);
                }
                item.EffectiveAccessCheckCompleted = true;
                item.GrantedDangerousRights = granted.ToArray();
                foreach (string name in granted) if (!conflictRights.Contains(name)) conflictRights.Add(name);
                item.PolicyConflictRights = conflictRights.ToArray();
                if (granted.Count > 0 && item.FailureCode == "None") item.FailureCode = "DangerousEffectiveAccess";
                if (!item.AclProfileRestrictive && item.FailureCode == "None") item.FailureCode = "AclProfileConflict";
                if (!item.DaclPresent && item.FailureCode == "None") item.FailureCode = "DaclUnavailable";
                item.ProtectionObserved = item.CanonicalPathVerified && !item.IsReparsePoint && item.DaclPresent && item.OwnerProfileAccepted && item.AclProfileRestrictive && item.EffectiveAccessCheckCompleted && granted.Count == 0;
                item.InitialProtectionObserved = item.ProtectionObserved;
                return item;
            }
            finally
            {
                if (descriptor != IntPtr.Zero) NativeMethods.LocalFree(descriptor);
            }
        }

        private static bool InspectDacl(IntPtr dacl, bool daclPresent, List<string> conflictRights, out uint ownerRightsDenied, out string failureCode, out int errorCode)
        {
            ownerRightsDenied = 0;
            failureCode = String.Empty;
            errorCode = 0;
            if (!daclPresent || dacl == IntPtr.Zero) return false;
            AclSizeInformation info;
            if (!NativeMethods.GetAclInformation(dacl, out info, (uint)Marshal.SizeOf(typeof(AclSizeInformation)), AclSizeInformationClass))
                throw new NativeFailure("AclQueryFailed", Marshal.GetLastWin32Error());
            if (info.AceCount > 4096) throw new NativeFailure("AclTooLarge", 0);
            SecurityIdentifier admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            SecurityIdentifier system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            byte[] adminsBytes = new byte[admins.BinaryLength];
            byte[] systemBytes = new byte[system.BinaryLength];
            admins.GetBinaryForm(adminsBytes, 0);
            system.GetBinaryForm(systemBytes, 0);
            IntPtr adminsPtr = Marshal.AllocHGlobal(adminsBytes.Length);
            IntPtr systemPtr = Marshal.AllocHGlobal(systemBytes.Length);
            bool restrictive = true;
            try
            {
                Marshal.Copy(adminsBytes, 0, adminsPtr, adminsBytes.Length);
                Marshal.Copy(systemBytes, 0, systemPtr, systemBytes.Length);
                for (uint i = 0; i < info.AceCount; i++)
                {
                    IntPtr ace;
                    if (!NativeMethods.GetAce(dacl, i, out ace)) throw new NativeFailure("AclQueryFailed", Marshal.GetLastWin32Error());
                    int type = Marshal.ReadByte(ace, 0);
                    int aceFlags = Marshal.ReadByte(ace, 1);
                    ushort aceSize = unchecked((ushort)Marshal.ReadInt16(ace, 2));
                    if (aceSize < AceHeaderLength + 4 || (type != AccessAllowedAceType && type != AccessDeniedAceType))
                    {
                        restrictive = false;
                        if (String.IsNullOrEmpty(failureCode)) failureCode = "UnsupportedAce";
                        continue;
                    }
                    uint mask = unchecked((uint)Marshal.ReadInt32(ace, 4));
                    IntPtr sid = IntPtr.Add(ace, AceHeaderLength);
                    if (!NativeMethods.IsValidSid(sid) || NativeMethods.GetLengthSid(sid) > aceSize - AceHeaderLength)
                    {
                        restrictive = false;
                        if (String.IsNullOrEmpty(failureCode)) failureCode = "UnknownPrincipal";
                        errorCode = (int)ErrorNoneMapped;
                        continue;
                    }
                    string ignored;
                    if (!LookupSid(sid, out ignored))
                    {
                        restrictive = false;
                        if (String.IsNullOrEmpty(failureCode)) failureCode = "UnknownPrincipal";
                        errorCode = (int)ErrorNoneMapped;
                        continue;
                    }
                    uint mapped = MapGenericMask(mask);
                    SecurityIdentifier sidValue = new SecurityIdentifier(sid);
                    SecurityIdentifier ownerRights = new SecurityIdentifier("S-1-3-4");
                    if (type == AccessDeniedAceType && sidValue.Equals(ownerRights) && (aceFlags & InheritOnlyAceFlag) == 0) ownerRightsDenied |= mapped;
                    bool trustedPrincipal = NativeMethods.EqualSid(sid, adminsPtr) || NativeMethods.EqualSid(sid, systemPtr);
                    if (type == AccessAllowedAceType && !trustedPrincipal && (mapped & DangerousMask) != 0)
                    {
                        restrictive = false;
                        AddRights(conflictRights, mapped & DangerousMask);
                    }
                }
            }
            finally
            {
                Marshal.FreeHGlobal(adminsPtr);
                Marshal.FreeHGlobal(systemPtr);
            }
            return restrictive;
        }

        private static bool AccessGranted(IntPtr descriptor, SafeNativeHandle token, uint right)
        {
            IntPtr privileges = Marshal.AllocHGlobal(4096);
            try
            {
                uint length = 4096;
                uint granted;
                bool accessStatus;
                if (!NativeMethods.AccessCheck(descriptor, token, right, ref FileMapping, privileges, ref length, out granted, out accessStatus))
                    throw new NativeFailure("EffectiveAccessCheckFailed", Marshal.GetLastWin32Error());
                return accessStatus && (granted & right) == right;
            }
            finally { Marshal.FreeHGlobal(privileges); }
        }

        private static uint MapGenericMask(uint mask)
        {
            if ((mask & GenericRead) != 0) { mask &= ~GenericRead; mask |= FileMapping.GenericRead; }
            if ((mask & GenericWrite) != 0) { mask &= ~GenericWrite; mask |= FileMapping.GenericWrite; }
            if ((mask & GenericExecute) != 0) { mask &= ~GenericExecute; mask |= FileMapping.GenericExecute; }
            if ((mask & GenericAll) != 0) { mask &= ~GenericAll; mask |= FileMapping.GenericAll; }
            return mask;
        }

        private static void AddRights(List<string> destination, uint mask)
        {
            for (int i = 0; i < DangerousRights.Length; i++)
                if ((mask & DangerousRights[i]) != 0 && !destination.Contains(DangerousNames[i])) destination.Add(DangerousNames[i]);
        }

        private static string FinalPath(SafeNativeHandle handle)
        {
            StringBuilder path = new StringBuilder(32768);
            uint length = NativeMethods.GetFinalPathNameByHandle(handle, path, (uint)path.Capacity, 0);
            if (length == 0 || length >= path.Capacity) throw new NativeFailure("CanonicalPathQueryFailed", Marshal.GetLastWin32Error());
            return path.ToString();
        }

        private static bool LookupSid(IntPtr sid, out string account)
        {
            account = String.Empty;
            uint nameLength = 0;
            uint domainLength = 0;
            int use;
            NativeMethods.LookupAccountSidW(null, sid, null, ref nameLength, null, ref domainLength, out use);
            int error = Marshal.GetLastWin32Error();
            if (nameLength == 0 && domainLength == 0 && error != (int)ErrorInsufficientBuffer && error != 0) return false;
            StringBuilder name = new StringBuilder((int)Math.Max(nameLength, 1));
            StringBuilder domain = new StringBuilder((int)Math.Max(domainLength, 1));
            if (!NativeMethods.LookupAccountSidW(null, sid, name, ref nameLength, domain, ref domainLength, out use)) return false;
            account = domain.Length == 0 ? name.ToString() : domain.ToString() + "\\" + name.ToString();
            return account.Length > 0;
        }

        private static string SidValue(IntPtr sid)
        {
            if (!NativeMethods.IsValidSid(sid)) throw new NativeFailure("UnverifiableGroupMembership", 0);
            try { return new SecurityIdentifier(sid).Value; }
            catch { throw new NativeFailure("UnverifiableGroupMembership", 0); }
        }
    }
}
'@

function Get-ProtectedWindowsTrust {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [AllowEmptyString()]
        [string]$Path
    )

    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        return New-ProtectedWindowsTrustRefusal -ReasonCode 'UnsupportedPlatform'
    }

    $pathParts = Get-ProtectedWindowsTrustPathComponents -Path $Path
    if (-not $pathParts.Valid) {
        return New-ProtectedWindowsTrustRefusal -ReasonCode $pathParts.FailureCode
    }

    try {
        if ($null -eq ('ProtectedWindowsTrust.NativeVerifier' -as [type])) {
            Add-Type -TypeDefinition $script:ProtectedWindowsTrustNativeSource -Language CSharp -ErrorAction Stop
        }
        $native = [ProtectedWindowsTrust.NativeVerifier]::Verify([string]$pathParts.DriveRoot, [string[]]$pathParts.Segments)
        $objects = @($native.Objects | Select-Object -First 65)
        $reasonCode = if ([string]::IsNullOrEmpty([string]$native.FailureCode)) { 'NativeFailure' } else { [string]$native.FailureCode }
        $decision = if ($native.ProtectionVerifiedForCurrentToken -and $native.HandlesReleased) { 'ProtectionObserved' } else { 'Refused' }
        return [pscustomobject][ordered]@{
            SchemaVersion = 1
            Decision = $decision
            ReasonCode = $reasonCode
            NativeChecksPerformed = [bool]$native.NativeChecksPerformed
            StandardUserTokenVerified = [bool]$native.StandardUserTokenVerified
            ProtectionVerifiedForCurrentToken = [bool]($native.ProtectionVerifiedForCurrentToken -and $native.HandlesReleased)
            ObservationStatus = [string]$native.ObservationStatus
            Scope = 'One snapshot of the current effective caller token only: a thread impersonation token when present, otherwise the process token, verified as non-elevated and medium-integrity with its actual group and currently enabled privilege attributes evaluated by Windows AccessCheck. Any later token, group, or privilege adjustment requires a new observation. This does not establish access for other users, other token configurations, future token changes, or all standard users.'
            CheckedObjectCount = $objects.Count
            Objects = $objects
            ProgramDataAncestorPolicyConflict = [bool]$native.ProgramDataAncestorPolicyConflict
            HandlesOpened = [int]$native.HandlesOpened
            HandlesClosed = [int]$native.HandlesClosed
            HandlesReleased = [bool]$native.HandlesReleased
            NativeErrorCode = [int]$native.NativeErrorCode
            ExceptionType = [string]$native.ExceptionType
            TrustEstablished = $false
            InstallationAuthorized = $false
            RemovalAuthorized = $false
        }
    }
    catch {
        $exceptionType = $_.Exception.GetType().Name
        $nativeCode = 0
        if ($_.Exception -is [System.ComponentModel.Win32Exception]) { $nativeCode = $_.Exception.NativeErrorCode }
        return New-ProtectedWindowsTrustRefusal -ReasonCode 'NativeInteropUnavailable' -NativeErrorCode $nativeCode -ExceptionType $exceptionType
    }
}

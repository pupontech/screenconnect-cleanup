using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace ScreenConnectCleanup.Gui.Services;

internal interface IWindowsJobApi
{
    SafeWindowsJobHandle CreateConfiguredJob();
    void AssignToJob(SafeWindowsJobHandle job, IntPtr processHandle);
    uint ResumePrimaryThread(IntPtr threadHandle);
    uint QueryActiveProcessCount(SafeWindowsJobHandle job);
    void TerminateJob(SafeWindowsJobHandle job, uint exitCode);
}

internal sealed class SafeWindowsJobHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    internal SafeWindowsJobHandle(IntPtr handle) : base(ownsHandle: true) => SetHandle(handle);

    protected override bool ReleaseHandle() => WindowsNative.CloseHandle(handle);
}

internal sealed class NativeWindowsJobApi : IWindowsJobApi
{
    private const uint JobObjectLimitKillOnJobClose = 0x00002000;
    private const int JobObjectExtendedLimitInformation = 9;
    private const int JobObjectBasicAccountingInformation = 1;

    public SafeWindowsJobHandle CreateConfiguredJob()
    {
        var rawHandle = WindowsNative.CreateJobObject(IntPtr.Zero, null);
        if (rawHandle == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        var job = new SafeWindowsJobHandle(rawHandle);
        var limits = new WindowsNative.JobObjectExtendedLimitInformation
        {
            BasicLimitInformation = new WindowsNative.JobObjectBasicLimitInformation
            {
                LimitFlags = JobObjectLimitKillOnJobClose
            }
        };
        if (!WindowsNative.SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                ref limits,
                (uint)Marshal.SizeOf<WindowsNative.JobObjectExtendedLimitInformation>()))
        {
            var error = Marshal.GetLastWin32Error();
            job.Dispose();
            throw new Win32Exception(error);
        }
        return job;
    }

    public void AssignToJob(SafeWindowsJobHandle job, IntPtr processHandle)
    {
        if (!WindowsNative.AssignProcessToJobObject(job, processHandle))
            throw new Win32Exception(Marshal.GetLastWin32Error());
    }

    public uint ResumePrimaryThread(IntPtr threadHandle)
    {
        var previousSuspendCount = WindowsNative.ResumeThread(threadHandle);
        if (previousSuspendCount == uint.MaxValue) throw new Win32Exception(Marshal.GetLastWin32Error());
        return previousSuspendCount;
    }

    public uint QueryActiveProcessCount(SafeWindowsJobHandle job)
    {
        if (!WindowsNative.QueryInformationJobObject(
                job,
                JobObjectBasicAccountingInformation,
                out var accounting,
                (uint)Marshal.SizeOf<WindowsNative.JobObjectBasicAccountingInformation>(),
                IntPtr.Zero))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        return accounting.ActiveProcesses;
    }

    public void TerminateJob(SafeWindowsJobHandle job, uint exitCode)
    {
        if (!WindowsNative.TerminateJobObject(job, exitCode))
            throw new Win32Exception(Marshal.GetLastWin32Error());
    }
}

internal sealed class WindowsProcessStartException : Exception
{
    public WindowsProcessStartException(bool terminationConfirmed)
        : base("The suspended adapter process could not be safely contained or started.") =>
        TerminationConfirmed = terminationConfirmed;

    public bool TerminationConfirmed { get; }
}

internal enum WindowsJobEmptyState
{
    Empty,
    StillActive,
    QueryFailed
}

/// <summary>
/// Creates the fixed adapter suspended, assigns it to a non-breakaway kill-on-close
/// job, and only then resumes it. The GUI owns the sole job handle; closing the GUI
/// closes that handle and Windows terminates every remaining process in the job.
/// </summary>
internal sealed class WindowsProcessContainment : IDisposable
{
    private static readonly TimeSpan CleanupTimeout = TimeSpan.FromSeconds(5);
    private readonly IWindowsJobApi _jobApi;
    private readonly SafeWindowsKernelHandle _processHandle;
    private readonly SafeWindowsJobHandle _jobHandle;
    private readonly StreamReader _standardOutput;
    private readonly Stream _standardError;
    private bool _disposed;

    private WindowsProcessContainment(
        IWindowsJobApi jobApi,
        SafeWindowsKernelHandle processHandle,
        SafeWindowsJobHandle jobHandle,
        StreamReader standardOutput,
        Stream standardError)
    {
        _jobApi = jobApi;
        _processHandle = processHandle;
        _jobHandle = jobHandle;
        _standardOutput = standardOutput;
        _standardError = standardError;
    }

    public StreamReader StandardOutput => _standardOutput;
    public Stream StandardError => _standardError;

    public static WindowsProcessContainment Start(LauncherProcessRequest request, IWindowsJobApi jobApi)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(jobApi);
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();

        SafeWindowsJobHandle? job = null;
        SafeWindowsKernelHandle? process = null;
        SafeWindowsKernelHandle? thread = null;
        SafeFileHandle? stdoutRead = null;
        SafeFileHandle? stdoutWrite = null;
        SafeFileHandle? stderrRead = null;
        SafeFileHandle? stderrWrite = null;
        var assignedToJob = false;
        try
        {
            job = jobApi.CreateConfiguredJob();
            (stdoutRead, stdoutWrite) = CreatePipePair();
            (stderrRead, stderrWrite) = CreatePipePair();
            var processInfo = CreateSuspendedProcess(request, stdoutWrite, stderrWrite);
            process = new SafeWindowsKernelHandle(processInfo.ProcessHandle);
            thread = new SafeWindowsKernelHandle(processInfo.ThreadHandle);

            // The parent must close its copies so EOF reflects all contained writers.
            stdoutWrite.Dispose();
            stdoutWrite = null;
            stderrWrite.Dispose();
            stderrWrite = null;

            jobApi.AssignToJob(job, process.DangerousGetHandle());
            assignedToJob = true;
            if (jobApi.ResumePrimaryThread(thread.DangerousGetHandle()) != 1)
                throw new InvalidOperationException("The adapter's primary thread did not resume from its initial suspended state.");
            thread.Dispose();
            thread = null;

            var outputReader = new StreamReader(
                new FileStream(stdoutRead, FileAccess.Read, 4096, isAsync: true),
                Encoding.Default,
                detectEncodingFromByteOrderMarks: true);
            stdoutRead = null;
            var errorStream = new FileStream(stderrRead, FileAccess.Read, 4096, isAsync: true);
            stderrRead = null;
            var result = new WindowsProcessContainment(jobApi, process, job, outputReader, errorStream);
            process = null;
            job = null;
            return result;
        }
        catch
        {
            var terminationConfirmed = TerminatePartialStart(jobApi, job, process, assignedToJob);
            DisposeQuietly(thread);
            DisposeQuietly(process);
            DisposeQuietly(stdoutRead);
            DisposeQuietly(stdoutWrite);
            DisposeQuietly(stderrRead);
            DisposeQuietly(stderrWrite);
            DisposeQuietly(job);
            throw new WindowsProcessStartException(terminationConfirmed);
        }
    }

    public bool HasExited
    {
        get
        {
            var waitResult = WindowsNative.WaitForSingleObject(_processHandle, 0);
            return waitResult switch
            {
                WindowsNative.WaitObject0 => true,
                WindowsNative.WaitTimeout => false,
                _ => throw new Win32Exception(Marshal.GetLastWin32Error())
            };
        }
    }

    public int ExitCode
    {
        get
        {
            if (!WindowsNative.GetExitCodeProcess(_processHandle, out var exitCode))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            if (exitCode == WindowsNative.StillActive)
                throw new InvalidOperationException("The adapter process has not exited.");
            return unchecked((int)exitCode);
        }
    }

    public async Task<WindowsJobEmptyState> WaitForNoActiveProcessesAsync(TimeSpan timeout)
    {
        var deadline = Stopwatch.StartNew();
        while (true)
        {
            uint activeProcesses;
            try
            {
                activeProcesses = _jobApi.QueryActiveProcessCount(_jobHandle);
            }
            catch
            {
                return WindowsJobEmptyState.QueryFailed;
            }
            if (activeProcesses == 0) return WindowsJobEmptyState.Empty;
            if (deadline.Elapsed >= timeout) return WindowsJobEmptyState.StillActive;
            await Task.Delay(TimeSpan.FromMilliseconds(25)).ConfigureAwait(false);
        }
    }

    public async Task<bool> TerminateAndConfirmEmptyAsync()
    {
        var terminationRequested = true;
        try
        {
            _jobApi.TerminateJob(_jobHandle, exitCode: 1);
        }
        catch
        {
            terminationRequested = false;
        }
        var jobState = await WaitForNoActiveProcessesAsync(CleanupTimeout).ConfigureAwait(false);
        return terminationRequested && jobState == WindowsJobEmptyState.Empty;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        // Closing the sole KILL_ON_JOB_CLOSE handle also covers GUI shutdown and
        // unconfirmed cleanup paths; explicit confirmation remains required to report success.
        _jobHandle.Dispose();
        _standardOutput.Dispose();
        _standardError.Dispose();
        _processHandle.Dispose();
    }

    private static bool TerminatePartialStart(
        IWindowsJobApi jobApi,
        SafeWindowsJobHandle? job,
        SafeWindowsKernelHandle? process,
        bool assignedToJob)
    {
        if (process is null) return true;
        if (!assignedToJob)
        {
            _ = WindowsNative.TerminateProcess(process, exitCode: 1);
            return WindowsNative.WaitForSingleObject(process, (uint)CleanupTimeout.TotalMilliseconds) == WindowsNative.WaitObject0;
        }

        var terminationRequested = true;
        try
        {
            jobApi.TerminateJob(job!, exitCode: 1);
        }
        catch
        {
            terminationRequested = false;
        }
        var emptyConfirmed = WaitForNoActiveProcesses(jobApi, job!, CleanupTimeout);
        return terminationRequested && emptyConfirmed;
    }

    private static bool WaitForNoActiveProcesses(IWindowsJobApi jobApi, SafeWindowsJobHandle job, TimeSpan timeout)
    {
        var timer = Stopwatch.StartNew();
        while (timer.Elapsed < timeout)
        {
            try
            {
                if (jobApi.QueryActiveProcessCount(job) == 0) return true;
            }
            catch
            {
                return false;
            }
            Thread.Sleep(25);
        }
        try { return jobApi.QueryActiveProcessCount(job) == 0; }
        catch { return false; }
    }

    private static (SafeFileHandle Read, SafeFileHandle Write) CreatePipePair()
    {
        var securityAttributes = new WindowsNative.SecurityAttributes
        {
            Length = (uint)Marshal.SizeOf<WindowsNative.SecurityAttributes>(),
            InheritHandle = true
        };
        if (!WindowsNative.CreatePipe(out var readHandle, out var writeHandle, ref securityAttributes, 0))
            throw new Win32Exception(Marshal.GetLastWin32Error());

        var read = new SafeFileHandle(readHandle, ownsHandle: true);
        var write = new SafeFileHandle(writeHandle, ownsHandle: true);
        if (!WindowsNative.SetHandleInformation(read, WindowsNative.HandleFlagInherit, 0))
        {
            var error = Marshal.GetLastWin32Error();
            read.Dispose();
            write.Dispose();
            throw new Win32Exception(error);
        }
        return (read, write);
    }

    private static WindowsNative.ProcessInformation CreateSuspendedProcess(
        LauncherProcessRequest request,
        SafeFileHandle stdoutWrite,
        SafeFileHandle stderrWrite)
    {
        var commandLine = BuildCommandLine(request);
        var commandLineBuffer = new StringBuilder(commandLine, commandLine.Length + 1);
        var attributeListSize = IntPtr.Zero;
        _ = WindowsNative.InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref attributeListSize);
        if (attributeListSize == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());

        var attributeList = Marshal.AllocHGlobal(attributeListSize);
        var inheritedHandles = Marshal.AllocHGlobal(IntPtr.Size * 2);
        var initialized = false;
        try
        {
            if (!WindowsNative.InitializeProcThreadAttributeList(attributeList, 1, 0, ref attributeListSize))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            initialized = true;
            Marshal.WriteIntPtr(inheritedHandles, 0, stdoutWrite.DangerousGetHandle());
            Marshal.WriteIntPtr(inheritedHandles, IntPtr.Size, stderrWrite.DangerousGetHandle());
            if (!WindowsNative.UpdateProcThreadAttribute(
                    attributeList,
                    0,
                    WindowsNative.ProcThreadAttributeHandleList,
                    inheritedHandles,
                    (UIntPtr)(uint)(IntPtr.Size * 2),
                    IntPtr.Zero,
                    IntPtr.Zero))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            var startupInfo = new WindowsNative.StartupInfoEx
            {
                StartupInfo = new WindowsNative.StartupInfo
                {
                    Size = (uint)Marshal.SizeOf<WindowsNative.StartupInfoEx>(),
                    Flags = WindowsNative.StartfUseStdHandles,
                    StandardInput = IntPtr.Zero,
                    StandardOutput = stdoutWrite.DangerousGetHandle(),
                    StandardError = stderrWrite.DangerousGetHandle()
                },
                AttributeList = attributeList
            };
            if (!WindowsNative.CreateProcess(
                    request.FileName,
                    commandLineBuffer,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    inheritHandles: true,
                    WindowsNative.CreateSuspended | WindowsNative.CreateNoWindow | WindowsNative.ExtendedStartupInfoPresent,
                    IntPtr.Zero,
                    request.WorkingDirectory,
                    ref startupInfo,
                    out var processInformation))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            return processInformation;
        }
        finally
        {
            if (initialized) WindowsNative.DeleteProcThreadAttributeList(attributeList);
            Marshal.FreeHGlobal(inheritedHandles);
            Marshal.FreeHGlobal(attributeList);
        }
    }

    internal static string BuildCommandLine(LauncherProcessRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.FileName) || string.IsNullOrWhiteSpace(request.WorkingDirectory))
            throw new ArgumentException("A fixed executable and working directory are required.", nameof(request));
        return string.Join(" ", new[] { request.FileName }.Concat(request.Arguments).Select(QuoteWindowsArgument));
    }

    private static string QuoteWindowsArgument(string argument)
    {
        ArgumentNullException.ThrowIfNull(argument);
        if (argument.IndexOf('\0') >= 0) throw new ArgumentException("Process arguments cannot contain NUL characters.", nameof(argument));
        if (argument.Length > 0 && argument.All(character => !char.IsWhiteSpace(character) && character != '"')) return argument;

        var quoted = new StringBuilder(argument.Length + 2).Append('"');
        var backslashes = 0;
        foreach (var character in argument)
        {
            if (character == '\\')
            {
                backslashes++;
                continue;
            }
            if (character == '"')
            {
                quoted.Append('\\', backslashes * 2 + 1).Append('"');
                backslashes = 0;
                continue;
            }
            quoted.Append('\\', backslashes).Append(character);
            backslashes = 0;
        }
        quoted.Append('\\', backslashes * 2).Append('"');
        return quoted.ToString();
    }

    private static void DisposeQuietly(IDisposable? disposable)
    {
        try { disposable?.Dispose(); }
        catch { }
    }
}

internal sealed class SafeWindowsKernelHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    internal SafeWindowsKernelHandle(IntPtr handle) : base(ownsHandle: true) => SetHandle(handle);

    protected override bool ReleaseHandle() => WindowsNative.CloseHandle(handle);
}

internal static class WindowsNative
{
    internal const uint WaitObject0 = 0;
    internal const uint WaitTimeout = 258;
    internal const uint StillActive = 259;
    internal const uint HandleFlagInherit = 1;
    internal const uint StartfUseStdHandles = 0x00000100;
    internal const uint CreateSuspended = 0x00000004;
    internal const uint CreateNoWindow = 0x08000000;
    internal const uint ExtendedStartupInfoPresent = 0x00080000;
    internal static readonly UIntPtr ProcThreadAttributeHandleList = (UIntPtr)0x00020002;

    [StructLayout(LayoutKind.Sequential)]
    internal struct SecurityAttributes
    {
        public uint Length;
        public IntPtr SecurityDescriptor;
        [MarshalAs(UnmanagedType.Bool)] public bool InheritHandle;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct StartupInfo
    {
        public uint Size;
        public IntPtr Reserved;
        public IntPtr Desktop;
        public IntPtr Title;
        public uint X;
        public uint Y;
        public uint XSize;
        public uint YSize;
        public uint XCountChars;
        public uint YCountChars;
        public uint FillAttribute;
        public uint Flags;
        public ushort ShowWindow;
        public ushort Reserved2Size;
        public IntPtr Reserved2;
        public IntPtr StandardInput;
        public IntPtr StandardOutput;
        public IntPtr StandardError;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct StartupInfoEx
    {
        public StartupInfo StartupInfo;
        public IntPtr AttributeList;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ProcessInformation
    {
        public IntPtr ProcessHandle;
        public IntPtr ThreadHandle;
        public uint ProcessId;
        public uint ThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IoCounters
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct JobObjectBasicLimitInformation
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct JobObjectExtendedLimitInformation
    {
        public JobObjectBasicLimitInformation BasicLimitInformation;
        public IoCounters IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct JobObjectBasicAccountingInformation
    {
        public long TotalUserTime;
        public long TotalKernelTime;
        public long ThisPeriodTotalUserTime;
        public long ThisPeriodTotalKernelTime;
        public uint TotalPageFaultCount;
        public uint TotalProcesses;
        public uint ActiveProcesses;
        public uint TotalTerminatedProcesses;
    }

    [DllImport("kernel32.dll", EntryPoint = "CreatePipe", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CreatePipe(out IntPtr readPipe, out IntPtr writePipe, ref SecurityAttributes attributes, uint size);

    [DllImport("kernel32.dll", EntryPoint = "SetHandleInformation", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool SetHandleInformation(SafeFileHandle handle, uint mask, uint flags);

    [DllImport("kernel32.dll", EntryPoint = "CreateJobObjectW", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern IntPtr CreateJobObject(IntPtr attributes, string? name);

    [DllImport("kernel32.dll", EntryPoint = "SetInformationJobObject", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool SetInformationJobObject(
        SafeWindowsJobHandle job,
        int informationClass,
        ref JobObjectExtendedLimitInformation information,
        uint informationLength);

    [DllImport("kernel32.dll", EntryPoint = "QueryInformationJobObject", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool QueryInformationJobObject(
        SafeWindowsJobHandle job,
        int informationClass,
        out JobObjectBasicAccountingInformation information,
        uint informationLength,
        IntPtr returnLength);

    [DllImport("kernel32.dll", EntryPoint = "AssignProcessToJobObject", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool AssignProcessToJobObject(SafeWindowsJobHandle job, IntPtr process);

    [DllImport("kernel32.dll", EntryPoint = "TerminateJobObject", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool TerminateJobObject(SafeWindowsJobHandle job, uint exitCode);

    [DllImport("kernel32.dll", EntryPoint = "ResumeThread", SetLastError = true)]
    internal static extern uint ResumeThread(IntPtr thread);

    [DllImport("kernel32.dll", EntryPoint = "InitializeProcThreadAttributeList", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool InitializeProcThreadAttributeList(
        IntPtr attributeList,
        int attributeCount,
        int flags,
        ref IntPtr size);

    [DllImport("kernel32.dll", EntryPoint = "UpdateProcThreadAttribute", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool UpdateProcThreadAttribute(
        IntPtr attributeList,
        uint flags,
        UIntPtr attribute,
        IntPtr value,
        UIntPtr size,
        IntPtr previousValue,
        IntPtr returnSize);

    [DllImport("kernel32.dll", EntryPoint = "DeleteProcThreadAttributeList")]
    internal static extern void DeleteProcThreadAttributeList(IntPtr attributeList);

    [DllImport("kernel32.dll", EntryPoint = "CreateProcessW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CreateProcess(
        string applicationName,
        StringBuilder commandLine,
        IntPtr processAttributes,
        IntPtr threadAttributes,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandles,
        uint creationFlags,
        IntPtr environment,
        string currentDirectory,
        ref StartupInfoEx startupInfo,
        out ProcessInformation processInformation);

    [DllImport("kernel32.dll", EntryPoint = "WaitForSingleObject", SetLastError = true)]
    internal static extern uint WaitForSingleObject(SafeWindowsKernelHandle handle, uint milliseconds);

    [DllImport("kernel32.dll", EntryPoint = "GetExitCodeProcess", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetExitCodeProcess(SafeWindowsKernelHandle process, out uint exitCode);

    [DllImport("kernel32.dll", EntryPoint = "TerminateProcess", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool TerminateProcess(SafeWindowsKernelHandle process, uint exitCode);

    [DllImport("kernel32.dll", EntryPoint = "CloseHandle", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CloseHandle(IntPtr handle);
}

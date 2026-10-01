using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ScreenConnectCleanup.Gui.Services;

/// <summary>
/// Starts only the fixed, non-elevated GUI stage adapter. This portable bundle is
/// not a trust boundary: scripts beside the GUI remain user-writable unless the
/// installer supplies and verifies a separate protected installation policy.
/// </summary>
public sealed class ReadOnlyRunLauncher : IReadOnlyRunLauncher
{
    private static readonly TimeSpan DefaultTimeout = TimeSpan.FromMinutes(32);
    private static readonly string[] StageNames =
    {
        "Preflight", "Snapshot (Before)", "Detect", "Review Gate", "Contain + Remove",
        "Scanners", "Uninstall installed AV", "Procmon", "Snapshot (After)+Diff", "Report"
    };

    private readonly ILauncherPlatform _platform;
    private readonly ILauncherFileSystem _fileSystem;
    private readonly ILauncherProcessRunner _processRunner;
    private readonly TimeSpan _timeout;

    public ReadOnlyRunLauncher()
        : this(new SystemLauncherPlatform(), new SystemLauncherFileSystem(), new WindowsPowerShellProcessRunner(), DefaultTimeout)
    {
    }

    internal ReadOnlyRunLauncher(
        ILauncherPlatform platform,
        ILauncherFileSystem fileSystem,
        ILauncherProcessRunner processRunner,
        TimeSpan timeout)
    {
        _platform = platform ?? throw new ArgumentNullException(nameof(platform));
        _fileSystem = fileSystem ?? throw new ArgumentNullException(nameof(fileSystem));
        _processRunner = processRunner ?? throw new ArgumentNullException(nameof(processRunner));
        if (timeout <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(timeout));
        _timeout = timeout;
    }

    public Task<ReadOnlyRunResult> RunAsync(string operation, CancellationToken cancellationToken = default) =>
        RunAsync(operation, progress: null, cancellationToken);

    public async Task<ReadOnlyRunResult> RunAsync(
        string operation,
        Action<ReadOnlyRunProgress>? progress,
        CancellationToken cancellationToken = default)
    {
        var computerName = _platform.MachineName;
        var localApplicationData = _platform.LocalApplicationDataPath;
        if (string.IsNullOrWhiteSpace(localApplicationData) || !Path.IsPathFullyQualified(localApplicationData))
        {
            return new ReadOnlyRunResult(string.Empty, computerName, string.Empty, -1, "The per-user application data path is unavailable.");
        }
        var runsRoot = Path.GetFullPath(Path.Combine(localApplicationData, "ScreenConnectCleanup", "Runs"));
        if (!IsSupportedOperation(operation))
        {
            return new ReadOnlyRunResult(string.Empty, computerName, runsRoot, -1, "Unsupported read-only GUI operation.");
        }

        if (!IsValidComputerName(computerName))
        {
            return new ReadOnlyRunResult(string.Empty, computerName, runsRoot, -1, "The local computer name is not valid for a GUI run.");
        }

        var runId = CreateRunId(computerName);
        var runRoot = Path.Combine(runsRoot, runId);
        var requestRoot = Path.GetFullPath(Path.Combine(localApplicationData, "ScreenConnectCleanup", "Requests"));
        var requestPath = Path.Combine(requestRoot, $"request-{Guid.NewGuid():N}.json");
        string? error = null;
        var exitCode = -1;
        var hasRequest = false;
        var preserveRequest = false;
        var processRunnerInvoked = false;

        try
        {
            if (!_platform.IsWindows)
            {
                throw new InvalidOperationException("Windows is required for the read-only GUI adapter.");
            }
            if (_platform.IsProcessElevated)
            {
                throw new InvalidOperationException("The read-only GUI adapter must be launched from a non-elevated process.");
            }

            _fileSystem.EnsureDirectory(runsRoot);
            _fileSystem.EnsureDirectory(requestRoot);
            for (var attempt = 0; attempt < 5; attempt++)
            {
                runId = CreateRunId(computerName);
                runRoot = Path.Combine(runsRoot, runId);
                if (!_fileSystem.PathExists(runRoot) && !_fileSystem.PathExists(Path.Combine(runsRoot, $".gui-run-{runId}.claim")))
                {
                    break;
                }
                if (attempt == 4) throw new IOException("A unique GUI run identifier could not be reserved.");
            }

            if (!Path.IsPathFullyQualified(_platform.ApplicationBaseDirectory))
            {
                throw new InvalidOperationException("The application bundle root is unavailable.");
            }
            var appBase = Path.GetFullPath(_platform.ApplicationBaseDirectory);
            _fileSystem.ValidateNoReparsePoints(appBase, requireLeaf: true);
            var adapterPath = GetFixedBundleFile(appBase, "gui-bridge", "Invoke-GuiStage.ps1");
            var stateLibraryPath = GetFixedBundleFile(appBase, "gui-bridge", "GuiState.ps1");
            var detectorPath = GetFixedBundleFile(appBase, "detect-remote-access.ps1");
            RequireFixedScript(adapterPath);
            RequireFixedScript(stateLibraryPath);
            RequireFixedScript(detectorPath);

            var powershellPath = GetWindowsPowerShellPath();
            _fileSystem.ValidateNoReparsePoints(powershellPath, requireLeaf: true);
            if (!_fileSystem.FileExists(powershellPath))
            {
                throw new FileNotFoundException("Windows PowerShell 5.1 is unavailable.");
            }

            var requestBytes = JsonSerializer.SerializeToUtf8Bytes(new GuiRequest(1, operation, runId, computerName));
            if (requestBytes.Length == 0 || requestBytes.Length > 65536)
            {
                throw new InvalidOperationException("The GUI request exceeded its size bound.");
            }
            _fileSystem.WriteNewFile(requestPath, requestBytes);
            hasRequest = true;

            var arguments = new[]
            {
                "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                "-File", adapterPath, "-RequestPath", requestPath, "-OutRoot", runsRoot, "-ReturnExitCode"
            };
            NotifyProgress(progress, new ReadOnlyRunProgress(runId, computerName, runRoot, null, ProducerKnownActive: true));
            processRunnerInvoked = true;
            var processTask = _processRunner.RunAsync(
                new LauncherProcessRequest(powershellPath, appBase, arguments), _timeout, cancellationToken);
            PublishCurrentStateIfValid(progress, runsRoot, runRoot, runId, computerName);
            var processResult = await WaitForProcessAndPublishStateAsync(
                processTask, progress, runsRoot, runRoot, runId, computerName).ConfigureAwait(false);

            exitCode = processResult.AdapterReturnCode ?? processResult.ExitCode;
            preserveRequest = processResult.PreserveRequest;
            if (processResult.PreserveRequest)
            {
                error = "The read-only GUI process tree did not terminate or descendant exit could not be confirmed; the run is incomplete and its request was retained.";
            }
            else if (processResult.Cancelled)
            {
                error = "The read-only GUI run was cancelled; its state is incomplete.";
            }
            else if (processResult.TimedOut)
            {
                error = "The read-only GUI run timed out; its state is incomplete.";
            }
            else if (!string.IsNullOrEmpty(processResult.Error))
            {
                error = "The read-only GUI adapter could not complete safely.";
            }
            else if (processResult.AdapterReturnCode is null && processResult.ExitCode == 0)
            {
                error = "The read-only GUI adapter did not return its bounded status code.";
            }
            else if (exitCode != 0)
            {
                error = $"The read-only GUI adapter exited with code {exitCode}.";
            }
            else if (!_fileSystem.FileExists(Path.Combine(runRoot, "gui-state.json")))
            {
                error = "The read-only GUI adapter exited without publishing run state.";
            }
        }
        catch (OperationCanceledException)
        {
            preserveRequest = processRunnerInvoked;
            error = preserveRequest
                ? "The read-only GUI process tree could not be confirmed stopped; the run is incomplete and its request was retained."
                : "The read-only GUI run was cancelled before a process was started; its state is incomplete.";
        }
        catch (Exception)
        {
            // Avoid exposing environment details or raw process output in GUI state.
            preserveRequest = processRunnerInvoked;
            if (preserveRequest)
            {
                error = "The read-only GUI process tree could not be confirmed stopped; the run is incomplete and its request was retained.";
            }
            else
            {
                error = "The read-only GUI adapter could not start or complete safely.";
            }
        }
        finally
        {
            if (hasRequest && !preserveRequest)
            {
                try { _fileSystem.DeleteFileIfExists(requestPath); }
                catch { /* The request is bounded and contains no secret or authorization. */ }
            }
            if (error is not null)
            {
                try { WriteIncompleteStateIfMissing(runsRoot, runRoot, runId, computerName); }
                catch { /* The result still surfaces the fixed run path and failure to the caller. */ }
            }
        }

        return new ReadOnlyRunResult(runId, computerName, runRoot, exitCode, error);

        void RequireFixedScript(string path)
        {
            _fileSystem.ValidateNoReparsePoints(path, requireLeaf: true);
            if (!_fileSystem.FileExists(path))
            {
                throw new FileNotFoundException("A fixed GUI adapter dependency is missing.");
            }
        }
    }

    private static async Task<LauncherProcessResult> WaitForProcessAndPublishStateAsync(
        Task<LauncherProcessResult> processTask,
        Action<ReadOnlyRunProgress>? progress,
        string runsRoot,
        string runRoot,
        string runId,
        string computerName)
    {
        while (!processTask.IsCompleted)
        {
            await Task.WhenAny(processTask, Task.Delay(TimeSpan.FromMilliseconds(500))).ConfigureAwait(false);
            if (!processTask.IsCompleted)
            {
                PublishCurrentStateIfValid(progress, runsRoot, runRoot, runId, computerName);
            }
        }

        return await processTask.ConfigureAwait(false);
    }

    private static void PublishCurrentStateIfValid(
        Action<ReadOnlyRunProgress>? progress,
        string runsRoot,
        string runRoot,
        string runId,
        string computerName)
    {
        if (progress is null) return;
        var stateRead = RunStateReader.ReadForActiveProducer(runsRoot, runRoot, runId, computerName);
        if (stateRead.IsValid)
        {
            NotifyProgress(progress, new ReadOnlyRunProgress(runId, computerName, runRoot, stateRead, ProducerKnownActive: true));
        }
    }

    private static void NotifyProgress(Action<ReadOnlyRunProgress>? progress, ReadOnlyRunProgress update)
    {
        try { progress?.Invoke(update); }
        catch { /* A presentation callback must not interrupt the bounded adapter. */ }
    }


    private void WriteIncompleteStateIfMissing(string runsRoot, string runRoot, string runId, string computerName)
    {
        _fileSystem.EnsureDirectory(runsRoot);
        _fileSystem.EnsureDirectory(runRoot);
        var statePath = Path.Combine(runRoot, "gui-state.json");
        var stages = StageNames.Select((name, id) => new IncompleteStage(id, name)).ToArray();
        var state = new IncompleteRunState(
            1,
            runId,
            computerName,
            "Incomplete",
            null,
            stages,
            new[] { "The launcher did not receive a completed adapter state." },
            Array.Empty<string>(),
            new Dictionary<string, string>(StringComparer.Ordinal),
            DateTime.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture));
        var bytes = JsonSerializer.SerializeToUtf8Bytes(state);
        _fileSystem.WriteNewFileIfMissing(statePath, bytes);
    }

    private string GetWindowsPowerShellPath()
    {
        if (!Path.IsPathFullyQualified(_platform.WindowsDirectory))
        {
            throw new InvalidOperationException("The Windows system directory is unavailable.");
        }
        var systemRoot = Path.GetFullPath(_platform.WindowsDirectory);
        var systemDirectory = !_platform.Is64BitProcess && _platform.Is64BitOperatingSystem
            ? Path.Combine(systemRoot, "Sysnative")
            : Path.Combine(systemRoot, "System32");
        return Path.Combine(systemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");
    }

    private string GetFixedBundleFile(string appBase, params string[] relativeParts)
    {
        var path = Path.GetFullPath(Path.Combine(new[] { appBase }.Concat(relativeParts).ToArray()));
        var prefix = appBase.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;
        if (!path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("A fixed GUI script path escaped the application bundle.");
        }
        return path;
    }

    private static string CreateRunId(string computerName) =>
        $"{computerName}-{DateTime.UtcNow:yyyyMMdd_HHmmssfff}-{Guid.NewGuid():N}";

    private static bool IsSupportedOperation(string? operation) =>
        string.Equals(operation, "DetectOnly", StringComparison.Ordinal);

    private static bool IsValidComputerName(string? computerName) =>
        !string.IsNullOrEmpty(computerName) && computerName.Length <= 63 &&
        System.Text.RegularExpressions.Regex.IsMatch(computerName, "^[A-Za-z0-9][A-Za-z0-9._-]*$", System.Text.RegularExpressions.RegexOptions.CultureInvariant);

    private sealed record GuiRequest(
        [property: JsonPropertyName("schemaVersion")] int SchemaVersion,
        [property: JsonPropertyName("operation")] string Operation,
        [property: JsonPropertyName("runId")] string RunId,
        [property: JsonPropertyName("computerName")] string ComputerName);

    private sealed record IncompleteRunState(
        [property: JsonPropertyName("schemaVersion")] int SchemaVersion,
        [property: JsonPropertyName("runId")] string RunId,
        [property: JsonPropertyName("computerName")] string ComputerName,
        [property: JsonPropertyName("overallStatus")] string OverallStatus,
        [property: JsonPropertyName("currentStage")] int? CurrentStage,
        [property: JsonPropertyName("stages")] IReadOnlyList<IncompleteStage> Stages,
        [property: JsonPropertyName("warnings")] IReadOnlyList<string> Warnings,
        [property: JsonPropertyName("errors")] IReadOnlyList<string> Errors,
        [property: JsonPropertyName("artifacts")] IReadOnlyDictionary<string, string> Artifacts,
        [property: JsonPropertyName("updatedUtc")] string UpdatedUtc);

    private sealed record IncompleteStage(
        [property: JsonPropertyName("id")] int Id,
        [property: JsonPropertyName("name")] string Name,
        [property: JsonPropertyName("status")] string Status = "Pending",
        [property: JsonPropertyName("operation")] string Operation = "",
        [property: JsonPropertyName("startedUtc")] string? StartedUtc = null,
        [property: JsonPropertyName("endedUtc")] string? EndedUtc = null);
}

internal interface ILauncherPlatform
{
    bool IsWindows { get; }
    bool IsProcessElevated { get; }
    bool Is64BitOperatingSystem { get; }
    bool Is64BitProcess { get; }
    string MachineName { get; }
    string LocalApplicationDataPath { get; }
    string ApplicationBaseDirectory { get; }
    string WindowsDirectory { get; }
}

internal interface ILauncherFileSystem
{
    void EnsureDirectory(string path);
    void ValidateNoReparsePoints(string path, bool requireLeaf);
    bool FileExists(string path);
    bool PathExists(string path);
    void WriteNewFile(string path, byte[] bytes);
    void WriteNewFileIfMissing(string path, byte[] bytes);
    void DeleteFileIfExists(string path);
}

internal sealed record LauncherProcessRequest(string FileName, string WorkingDirectory, IReadOnlyList<string> Arguments);

internal sealed record LauncherProcessResult(
    int ExitCode,
    bool TimedOut = false,
    bool Cancelled = false,
    string? Error = null,
    int? AdapterReturnCode = null,
    bool PreserveRequest = false);

internal interface ILauncherProcessRunner
{
    Task<LauncherProcessResult> RunAsync(LauncherProcessRequest request, TimeSpan timeout, CancellationToken cancellationToken);
}

internal sealed class SystemLauncherPlatform : ILauncherPlatform
{
    public bool IsWindows => OperatingSystem.IsWindows();
    public bool Is64BitOperatingSystem => Environment.Is64BitOperatingSystem;
    public bool Is64BitProcess => Environment.Is64BitProcess;
    public string MachineName => Environment.MachineName;
    public string LocalApplicationDataPath => Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    public string ApplicationBaseDirectory => AppContext.BaseDirectory;
    public string WindowsDirectory => Environment.GetFolderPath(Environment.SpecialFolder.Windows);

    public bool IsProcessElevated
    {
        get
        {
            if (!OperatingSystem.IsWindows()) return false;
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
    }
}

internal sealed class SystemLauncherFileSystem : ILauncherFileSystem
{
    public void EnsureDirectory(string path)
    {
        ValidateNoReparsePoints(path, requireLeaf: false);
        Directory.CreateDirectory(path);
        ValidateNoReparsePoints(path, requireLeaf: true);
        if (!Directory.Exists(path)) throw new DirectoryNotFoundException("A required GUI directory could not be created.");
    }

    public void ValidateNoReparsePoints(string path, bool requireLeaf)
    {
        var fullPath = Path.GetFullPath(path);
        var root = Path.GetPathRoot(fullPath);
        if (string.IsNullOrEmpty(root)) throw new IOException("A fixed GUI path has no filesystem root.");
        var current = root;
        var relative = fullPath[root.Length..];
        foreach (var segment in relative.Split(new[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar }, StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, segment);
            FileAttributes attributes;
            try
            {
                attributes = File.GetAttributes(current);
            }
            catch (FileNotFoundException)
            {
                continue;
            }
            catch (DirectoryNotFoundException)
            {
                continue;
            }
            if ((attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new IOException("A fixed GUI path contains a reparse point.");
            }
        }

        if (requireLeaf && !File.Exists(fullPath) && !Directory.Exists(fullPath))
        {
            throw new FileNotFoundException("A required fixed GUI path is missing.");
        }
    }

    public bool FileExists(string path)
    {
        try
        {
            var attributes = File.GetAttributes(path);
            return (attributes & FileAttributes.Directory) == 0;
        }
        catch (FileNotFoundException) { return false; }
        catch (DirectoryNotFoundException) { return false; }
    }

    public bool PathExists(string path)
    {
        try
        {
            _ = File.GetAttributes(path);
            return true;
        }
        catch (FileNotFoundException) { return false; }
        catch (DirectoryNotFoundException) { return false; }
    }

    public void WriteNewFile(string path, byte[] bytes)
    {
        ValidateNoReparsePoints(Path.GetDirectoryName(path) ?? throw new IOException("Request path has no parent."), requireLeaf: true);
        var created = false;
        try
        {
            using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            created = true;
            stream.Write(bytes);
            stream.Flush(flushToDisk: true);
        }
        catch
        {
            if (created)
            {
                try { File.Delete(path); }
                catch { }
            }
            throw;
        }
    }

    public void WriteNewFileIfMissing(string path, byte[] bytes)
    {
        ValidateNoReparsePoints(Path.GetDirectoryName(path) ?? throw new IOException("State path has no parent."), requireLeaf: true);
        var created = false;
        try
        {
            using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
            created = true;
            stream.Write(bytes);
            stream.Flush(flushToDisk: true);
        }
        catch (IOException) when (!created && PathExists(path))
        {
            // Preserve any state already published by the adapter; never overwrite it.
        }
        catch
        {
            if (created)
            {
                try { File.Delete(path); }
                catch { }
            }
            throw;
        }
    }

    public void DeleteFileIfExists(string path)
    {
        if (!PathExists(path)) return;
        ValidateNoReparsePoints(path, requireLeaf: true);
        File.Delete(path);
    }
}

internal sealed class WindowsPowerShellProcessRunner : ILauncherProcessRunner
{
    private static readonly TimeSpan CleanupTimeout = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan DescendantExitGrace = TimeSpan.FromSeconds(1);
    private readonly IWindowsJobApi _jobApi;

    public WindowsPowerShellProcessRunner() : this(new NativeWindowsJobApi())
    {
    }

    internal WindowsPowerShellProcessRunner(IWindowsJobApi jobApi) =>
        _jobApi = jobApi ?? throw new ArgumentNullException(nameof(jobApi));

    public Task<LauncherProcessResult> RunAsync(LauncherProcessRequest request, TimeSpan timeout, CancellationToken cancellationToken)
    {
        if (cancellationToken.IsCancellationRequested)
        {
            return Task.FromResult(new LauncherProcessResult(-1, Cancelled: true));
        }

        return OperatingSystem.IsWindows()
            ? RunWithWindowsContainmentAsync(request, timeout, cancellationToken)
            : RunWithPortableProcessAsync(request, timeout, cancellationToken);
    }

    private async Task<LauncherProcessResult> RunWithWindowsContainmentAsync(
        LauncherProcessRequest request,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        WindowsProcessContainment process;
        try
        {
            process = WindowsProcessContainment.Start(request, _jobApi);
        }
        catch (WindowsProcessStartException error)
        {
            return new LauncherProcessResult(
                -1,
                Error: "The read-only GUI process could not be safely contained or started.",
                PreserveRequest: !error.TerminationConfirmed);
        }
        catch
        {
            return new LauncherProcessResult(-1, Error: "The read-only GUI process could not be safely contained or started.");
        }

        return await RunContainedProcessAsync(process, timeout, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<LauncherProcessResult> RunContainedProcessAsync(
        WindowsProcessContainment process,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        var returnCodeCapture = new AdapterReturnCodeCapture();
        var outputTask = ReadAdapterOutputAsync(process.StandardOutput, returnCodeCapture);
        var errorTask = DrainErrorAsync(process.StandardError);
        try
        {
            var elapsed = Stopwatch.StartNew();
            while (true)
            {
                if (process.HasExited) break;
                if (cancellationToken.IsCancellationRequested)
                {
                    var confirmed = await process.TerminateAndConfirmEmptyAsync().ConfigureAwait(false);
                    return new LauncherProcessResult(
                        -1,
                        Cancelled: true,
                        Error: confirmed
                            ? "The cancelled read-only GUI process tree was terminated and confirmed empty."
                            : "The cancelled read-only GUI process tree could not be confirmed stopped.",
                        PreserveRequest: !confirmed);
                }
                if (elapsed.Elapsed >= timeout)
                {
                    var confirmed = await process.TerminateAndConfirmEmptyAsync().ConfigureAwait(false);
                    return new LauncherProcessResult(
                        -1,
                        TimedOut: true,
                        Error: confirmed
                            ? "The timed-out read-only GUI process tree was terminated and confirmed empty."
                            : "The timed-out read-only GUI process tree could not be confirmed stopped.",
                        PreserveRequest: !confirmed);
                }
                await Task.Delay(TimeSpan.FromMilliseconds(25)).ConfigureAwait(false);
            }

            var exitCode = process.ExitCode;
            var jobState = await process.WaitForNoActiveProcessesAsync(DescendantExitGrace).ConfigureAwait(false);
            if (jobState == WindowsJobEmptyState.QueryFailed)
            {
                _ = await process.TerminateAndConfirmEmptyAsync().ConfigureAwait(false);
                return new LauncherProcessResult(
                    exitCode,
                    Error: "The read-only GUI process tree could not be queried and its termination is unconfirmed.",
                    PreserveRequest: true);
            }

            var unexpectedDescendants = jobState == WindowsJobEmptyState.StillActive;
            if (unexpectedDescendants && !await process.TerminateAndConfirmEmptyAsync().ConfigureAwait(false))
            {
                return new LauncherProcessResult(
                    exitCode,
                    Error: "Contained descendant processes remained and their termination could not be confirmed.",
                    PreserveRequest: true);
            }

            if (!await DrainOutputWithinBoundAsync(outputTask, errorTask).ConfigureAwait(false))
            {
                return new LauncherProcessResult(
                    exitCode,
                    Error: "The read-only GUI adapter output could not be drained safely.",
                    PreserveRequest: unexpectedDescendants);
            }
            if (!returnCodeCapture.TryGetCode(out var adapterReturnCode))
            {
                return new LauncherProcessResult(
                    exitCode,
                    Error: "Adapter return output was missing or ambiguous.",
                    PreserveRequest: unexpectedDescendants);
            }
            if (unexpectedDescendants)
            {
                return new LauncherProcessResult(
                    exitCode,
                    Error: "Contained descendant processes remained after adapter completion and were terminated.",
                    AdapterReturnCode: adapterReturnCode);
            }
            return new LauncherProcessResult(exitCode, AdapterReturnCode: adapterReturnCode);
        }
        catch
        {
            var confirmed = await process.TerminateAndConfirmEmptyAsync().ConfigureAwait(false);
            return new LauncherProcessResult(
                -1,
                Error: confirmed
                    ? "The read-only GUI process failed; its process tree was terminated and confirmed empty."
                    : "The read-only GUI process failed and its process tree could not be confirmed stopped.",
                PreserveRequest: !confirmed);
        }
        finally
        {
            process.Dispose();
            await ObserveOutputTasksAsync(outputTask, errorTask).ConfigureAwait(false);
        }
    }

    private static async Task<LauncherProcessResult> RunWithPortableProcessAsync(
        LauncherProcessRequest request,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        if (cancellationToken.IsCancellationRequested)
        {
            return new LauncherProcessResult(-1, Cancelled: true);
        }

        using var process = new Process();
        process.StartInfo = CreateStartInfo(request);
        // -ReturnExitCode emits the adapter result; powershell.exe -File otherwise exits 0 on normal script return.
        var returnCodeCapture = new AdapterReturnCodeCapture();

        try
        {
            process.OutputDataReceived += (_, eventArgs) => returnCodeCapture.Add(eventArgs.Data);
            process.ErrorDataReceived += (_, _) => { };
            if (!process.Start()) return new LauncherProcessResult(-1, Error: "Process start returned false.");
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();
        }
        catch
        {
            var stop = await StopAndReapAsync(process).ConfigureAwait(false);
            return new LauncherProcessResult(-1, Error: stop.ErrorMessage, PreserveRequest: true);
        }

        using var timeoutSource = new CancellationTokenSource(timeout);
        using var linkedSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutSource.Token);
        try
        {
            await process.WaitForExitAsync(linkedSource.Token).ConfigureAwait(false);
            process.WaitForExit();
            if (!returnCodeCapture.TryGetCode(out var adapterReturnCode))
            {
                return new LauncherProcessResult(process.ExitCode, Error: "Adapter return output was missing or ambiguous.");
            }
            return new LauncherProcessResult(process.ExitCode, AdapterReturnCode: adapterReturnCode);
        }
        catch (OperationCanceledException)
        {
            var wasCancelled = cancellationToken.IsCancellationRequested;
            var stop = await StopAndReapAsync(process).ConfigureAwait(false);
            return new LauncherProcessResult(-1, TimedOut: !wasCancelled, Error: stop.ErrorMessage, PreserveRequest: true);
        }
        catch
        {
            var stop = await StopAndReapAsync(process).ConfigureAwait(false);
            return new LauncherProcessResult(-1, Error: stop.ErrorMessage, PreserveRequest: true);
        }
    }

    private static async Task ReadAdapterOutputAsync(StreamReader output, AdapterReturnCodeCapture capture)
    {
        try
        {
            while (await output.ReadLineAsync().ConfigureAwait(false) is { } line) capture.Add(line);
        }
        catch
        {
            // The caller observes missing or ambiguous adapter status as an error.
        }
    }

    private static async Task DrainErrorAsync(Stream error)
    {
        try { await error.CopyToAsync(Stream.Null).ConfigureAwait(false); }
        catch { /* Native process failures are reported through the bounded result. */ }
    }

    private static async Task<bool> DrainOutputWithinBoundAsync(Task outputTask, Task errorTask)
    {
        try
        {
            await Task.WhenAll(outputTask, errorTask).WaitAsync(CleanupTimeout).ConfigureAwait(false);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static async Task ObserveOutputTasksAsync(Task outputTask, Task errorTask)
    {
        try
        {
            await Task.WhenAll(outputTask, errorTask).WaitAsync(CleanupTimeout).ConfigureAwait(false);
        }
        catch { /* The bounded result already records output-drain failure. */ }
    }

    internal static ProcessStartInfo CreateStartInfo(LauncherProcessRequest request)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = request.FileName,
            WorkingDirectory = request.WorkingDirectory,
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
            RedirectStandardInput = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        foreach (var argument in request.Arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }
        return startInfo;
    }

    private static async Task<ProcessTreeStopResult> StopAndReapAsync(Process process)
    {
        var killRequestFailed = false;
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
            else
            {
                killRequestFailed = true;
            }
        }
        catch (Exception)
        {
            killRequestFailed = true;
        }

        var waitFailed = false;
        var parentExited = false;
        try
        {
            using var waitLimit = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await process.WaitForExitAsync(waitLimit.Token).ConfigureAwait(false);
            parentExited = process.HasExited;
        }
        catch (Exception)
        {
            waitFailed = true;
        }

        return new ProcessTreeStopResult(killRequestFailed, waitFailed, parentExited);
    }

    private sealed record ProcessTreeStopResult(bool KillRequestFailed, bool WaitFailed, bool ParentExited)
    {
        public string ErrorMessage => !KillRequestFailed && !WaitFailed && ParentExited
            ? "The parent exited after a process-tree kill request, but descendant exit could not be confirmed; the run is Incomplete."
            : "The bounded process-tree termination attempt failed; descendant exit could not be confirmed and the run is Incomplete.";
    }

    internal sealed class AdapterReturnCodeCapture
    {
        private readonly object _sync = new();
        private int? _code;
        private bool _invalid;

        public void Add(string? line)
        {
            if (string.IsNullOrWhiteSpace(line)) return;
            if (line.Length > 16 || !int.TryParse(line, NumberStyles.Integer, CultureInfo.InvariantCulture, out var value) || value is < 0 or > 255)
            {
                lock (_sync) _invalid = true;
                return;
            }
            lock (_sync)
            {
                if (_code.HasValue) _invalid = true;
                else _code = value;
            }
        }

        public bool TryGetCode(out int? code)
        {
            lock (_sync)
            {
                code = _code;
                return !_invalid && _code.HasValue;
            }
        }
    }
}

using System.Diagnostics;
using System.Text;
using System.Text.Json;
using ScreenConnectCleanup.Gui.Services;
using Xunit;

namespace ScreenConnectCleanup.Gui.Prototype.Tests;

public sealed class ReadOnlyRunLauncherTests
{
    [Theory]
    [InlineData("DetectOnly", 0)]
    public async Task StartsOnlyTheFixedDirectAdapterWithAnExactBoundedRequest(string operation, int exitCode)
    {
        using var fixture = new LauncherFixture();
        fixture.ProcessRunner.Handler = request =>
        {
            var requestPath = ArgumentValue(request.Arguments, "-RequestPath");
            var outRoot = ArgumentValue(request.Arguments, "-OutRoot");
            using var document = JsonDocument.Parse(File.ReadAllBytes(requestPath));
            var runId = document.RootElement.GetProperty("runId").GetString();
            Directory.CreateDirectory(Path.Combine(outRoot, runId!));
            File.WriteAllText(Path.Combine(outRoot, runId!, "gui-state.json"), "{}");
            return Task.FromResult(new LauncherProcessResult(0, AdapterReturnCode: exitCode));
        };

        var result = await fixture.Launcher.RunAsync(operation);

        Assert.Null(result.Error);
        Assert.Equal(exitCode, result.ExitCode);
        Assert.Equal("HOST-01", result.ComputerName);
        Assert.Matches("^HOST-01-[0-9]{8}_[0-9]{9}-[a-f0-9]{32}$", result.RunId);
        Assert.Equal(Path.Combine(fixture.RunsRoot, result.RunId), result.RunRoot);
        Assert.Single(fixture.ProcessRunner.Requests);

        var process = fixture.ProcessRunner.Requests[0];
        Assert.Equal(fixture.PowerShellPath, process.FileName);
        Assert.Equal(fixture.ApplicationBase, process.WorkingDirectory);
        Assert.Equal(new[]
        {
            "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File",
            fixture.AdapterPath, "-RequestPath", ArgumentValue(process.Arguments, "-RequestPath"),
            "-OutRoot", fixture.RunsRoot, "-ReturnExitCode"
        }, process.Arguments);
        Assert.DoesNotContain("-Command", process.Arguments);
        Assert.DoesNotContain("sc-cleanup.ps1", string.Join(" ", process.Arguments), StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("remove-screenconnect.ps1", string.Join(" ", process.Arguments), StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(operation, process.Arguments);

        var requestPath = ArgumentValue(process.Arguments, "-RequestPath");
        var serializedRequest = fixture.ProcessRunner.RequestBodies[0];
        Assert.InRange(serializedRequest.Length, 1, 65536);
        Assert.False(serializedRequest.AsSpan().StartsWith(Encoding.UTF8.GetPreamble()));
        using var requestDocument = JsonDocument.Parse(serializedRequest);
        var root = requestDocument.RootElement;
        Assert.Equal(new[] { "schemaVersion", "operation", "runId", "computerName" },
            root.EnumerateObject().Select(property => property.Name));
        Assert.Equal(1, root.GetProperty("schemaVersion").GetInt32());
        Assert.Equal(operation, root.GetProperty("operation").GetString());
        Assert.Equal(result.RunId, root.GetProperty("runId").GetString());
        Assert.Equal(result.ComputerName, root.GetProperty("computerName").GetString());
        Assert.False(File.Exists(requestPath));
    }

    [Fact]
    public async Task RunIdentifiersAreUniqueAcrossInvocations()
    {
        using var fixture = new LauncherFixture();
        fixture.ProcessRunner.Handler = request =>
        {
            var requestPath = ArgumentValue(request.Arguments, "-RequestPath");
            var outRoot = ArgumentValue(request.Arguments, "-OutRoot");
            using var document = JsonDocument.Parse(File.ReadAllBytes(requestPath));
            var runId = document.RootElement.GetProperty("runId").GetString()!;
            Directory.CreateDirectory(Path.Combine(outRoot, runId));
            File.WriteAllText(Path.Combine(outRoot, runId, "gui-state.json"), "{}");
            return Task.FromResult(new LauncherProcessResult(0, AdapterReturnCode: 0));
        };

        var first = await fixture.Launcher.RunAsync("DetectOnly");
        var second = await fixture.Launcher.RunAsync("DetectOnly");

        Assert.NotEqual(first.RunId, second.RunId);
        Assert.Equal(2, fixture.ProcessRunner.Requests.Count);
    }

    [Theory]
    [InlineData("detectonly")]
    [InlineData("Remove")]
    [InlineData("")]
    public async Task UnsupportedOperationsNeverStartAProcess(string operation)
    {
        using var fixture = new LauncherFixture();

        var result = await fixture.Launcher.RunAsync(operation);

        Assert.Equal(-1, result.ExitCode);
        Assert.NotNull(result.Error);
        Assert.Empty(fixture.ProcessRunner.Requests);
        Assert.False(Directory.Exists(fixture.RunsRoot));
    }

    [Fact]
    public async Task MissingFixedDependencyFailsClosedAndPublishesValidIncompleteState()
    {
        using var fixture = new LauncherFixture();
        File.Delete(fixture.DetectorPath);

        var result = await fixture.Launcher.RunAsync("DetectOnly");

        Assert.NotNull(result.Error);
        Assert.Empty(fixture.ProcessRunner.Requests);
        AssertValidIncompleteState(fixture, result);
    }

    [Fact]
    public async Task ReparsePointAdapterPathIsRejected()
    {
        if (!OperatingSystem.IsLinux()) return;

        using var fixture = new LauncherFixture();
        var externalScript = Path.Combine(fixture.Root, "external-adapter.ps1");
        File.WriteAllText(externalScript, "synthetic inert external script; never executed");
        File.Delete(fixture.AdapterPath);
        File.CreateSymbolicLink(fixture.AdapterPath, externalScript);

        var result = await fixture.Launcher.RunAsync("DetectOnly");

        Assert.NotNull(result.Error);
        Assert.Empty(fixture.ProcessRunner.Requests);
        AssertValidIncompleteState(fixture, result);
    }

    [Theory]
    [InlineData("not-windows")]
    [InlineData("elevated")]
    public async Task NonWindowsOrElevatedCallerIsRefusedAndVisible(string condition)
    {
        using var fixture = new LauncherFixture();
        fixture.Platform.IsWindows = condition != "not-windows";
        fixture.Platform.IsProcessElevated = condition == "elevated";

        var result = await fixture.Launcher.RunAsync("DetectOnly");

        Assert.NotNull(result.Error);
        Assert.Empty(fixture.ProcessRunner.Requests);
        AssertValidIncompleteState(fixture, result);
    }

    [Theory]
    [InlineData("timeout")]
    [InlineData("cancel")]
    [InlineData("start-error")]
    [InlineData("nonzero-exit")]
    public async Task ProcessFailuresLeaveAValidIncompleteRun(string failure)
    {
        using var fixture = new LauncherFixture();
        fixture.ProcessRunner.Handler = _ => Task.FromResult(failure switch
        {
            "timeout" => new LauncherProcessResult(-1, TimedOut: true),
            "cancel" => new LauncherProcessResult(-1, Cancelled: true),
            "start-error" => new LauncherProcessResult(-1, Error: "synthetic process start failure"),
            _ => new LauncherProcessResult(2)
        });

        var result = await fixture.Launcher.RunAsync("DetectOnly");

        Assert.NotNull(result.Error);
        AssertValidIncompleteState(fixture, result);
    }

    [Fact]
    public async Task UnconfirmedProcessTreeTerminationKeepsTheRequestAndReportsIncomplete()
    {
        using var fixture = new LauncherFixture();
        var resultConstructor = typeof(LauncherProcessResult).GetConstructors()
            .SingleOrDefault(constructor => constructor.GetParameters().Length == 6);
        Assert.NotNull(resultConstructor);
        fixture.ProcessRunner.Handler = _ => Task.FromResult((LauncherProcessResult)resultConstructor.Invoke(
            new object?[] { -1, false, false, "synthetic unconfirmed process-tree termination", null, true }));

        var result = await fixture.Launcher.RunAsync("DetectOnly");

        Assert.Contains("process tree", result.Error, StringComparison.OrdinalIgnoreCase);
        var requestPath = ArgumentValue(fixture.ProcessRunner.Requests.Single().Arguments, "-RequestPath");
        Assert.True(File.Exists(requestPath), "The request must remain when descendant termination is unconfirmed.");
        var state = RunStateReader.Read(fixture.RunsRoot, result.RunRoot, result.RunId, result.ComputerName);
        Assert.True(state.IsValid, string.Join("; ", state.Issues));
        Assert.Equal("Incomplete", state.State.OverallStatus);
    }

    [Fact]
    public async Task SuccessfulExitWithoutPublishedStateIsNotReportedAsACompletedRun()
    {
        using var fixture = new LauncherFixture();
        fixture.ProcessRunner.Handler = _ => Task.FromResult(new LauncherProcessResult(0));

        var result = await fixture.Launcher.RunAsync("DetectOnly");

        Assert.NotNull(result.Error);
        AssertValidIncompleteState(fixture, result);
    }

    [Fact]
    public async Task AdapterReturnValueIsUsedInsteadOfPowerShellHostExitCode()
    {
        using var fixture = new LauncherFixture();
        fixture.ProcessRunner.Handler = _ => Task.FromResult(new LauncherProcessResult(0, AdapterReturnCode: 1));

        var result = await fixture.Launcher.RunAsync("DetectOnly");

        Assert.Equal(1, result.ExitCode);
        Assert.NotNull(result.Error);
        AssertValidIncompleteState(fixture, result);
    }

    [Fact]
    public async Task FullInvestigationIsRejectedBeforeAnyRequestProcessOrCollectorAccess()
    {
        using var fixture = new LauncherFixture();

        var result = await fixture.Launcher.RunAsync("FullInvestigation");

        Assert.Equal(-1, result.ExitCode);
        Assert.Equal("Unsupported read-only GUI operation.", result.Error);
        Assert.Empty(fixture.ProcessRunner.Requests);
        Assert.Empty(fixture.ProcessRunner.RequestBodies);
        Assert.Empty(fixture.FileSystem.AccessedPaths);
        Assert.False(Directory.Exists(fixture.RunsRoot));
        Assert.False(Directory.Exists(Path.Combine(fixture.LocalApplicationData, "ScreenConnectCleanup", "Requests")));
        Assert.DoesNotContain(fixture.FileSystem.AccessedPaths,
            path => string.Equals(Path.GetFileName(path), "collect-snapshot.ps1", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void PowerShellStartInfoUsesSeparateArgumentsWithoutShellOrElevation()
    {
        var arguments = new[] { "-File", @"C:\Program Files\GUI\gui-bridge\Invoke-GuiStage.ps1", "-OutRoot", @"C:\Users\Tech\AppData\Local\Runs" };
        var request = new LauncherProcessRequest(
            @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            @"C:\Program Files\GUI",
            arguments);

        var startInfo = WindowsPowerShellProcessRunner.CreateStartInfo(request);

        Assert.Equal(request.FileName, startInfo.FileName);
        Assert.Equal(request.WorkingDirectory, startInfo.WorkingDirectory);
        Assert.False(startInfo.UseShellExecute);
        Assert.True(startInfo.CreateNoWindow);
        Assert.Equal(ProcessWindowStyle.Hidden, startInfo.WindowStyle);
        Assert.False(startInfo.RedirectStandardInput);
        Assert.True(startInfo.RedirectStandardOutput);
        Assert.True(startInfo.RedirectStandardError);
        Assert.True(string.IsNullOrEmpty(startInfo.Verb));
        Assert.Equal(arguments, startInfo.ArgumentList);
        Assert.DoesNotContain("-Command", startInfo.ArgumentList);
    }

    [Fact]
    public void AdapterStatusCaptureAcceptsOnlyOneBoundedIntegerLine()
    {
        var capture = new WindowsPowerShellProcessRunner.AdapterReturnCodeCapture();
        capture.Add(string.Empty);
        capture.Add("10");

        Assert.True(capture.TryGetCode(out var value));
        Assert.Equal(10, value);

        var ambiguousCapture = new WindowsPowerShellProcessRunner.AdapterReturnCodeCapture();
        ambiguousCapture.Add("0");
        ambiguousCapture.Add("10");
        Assert.False(ambiguousCapture.TryGetCode(out _));

        var untrustedOutputCapture = new WindowsPowerShellProcessRunner.AdapterReturnCodeCapture();
        untrustedOutputCapture.Add("unexpected output");
        Assert.False(untrustedOutputCapture.TryGetCode(out _));
    }

    [Fact]
    public async Task CancellationTerminatesSyntheticParentAndChildWithoutClaimingTreeExit()
    {
        if (!OperatingSystem.IsLinux()) return;

        var result = await RunSyntheticParentChildAsync(cancel: true);

        Assert.False(result.Cancelled);
        Assert.NotNull(result.Error);
        var preserveRequest = typeof(LauncherProcessResult).GetProperty("PreserveRequest");
        Assert.NotNull(preserveRequest);
        Assert.True((bool)preserveRequest.GetValue(result)!);
    }

    [Fact]
    public async Task TimeoutTerminatesSyntheticParentAndChildWithoutClaimingTreeExit()
    {
        if (!OperatingSystem.IsLinux()) return;

        var result = await RunSyntheticParentChildAsync(cancel: false);

        Assert.True(result.TimedOut);
        Assert.NotNull(result.Error);
        var preserveRequest = typeof(LauncherProcessResult).GetProperty("PreserveRequest");
        Assert.NotNull(preserveRequest);
        Assert.True((bool)preserveRequest.GetValue(result)!);
    }

    private static async Task<LauncherProcessResult> RunSyntheticParentChildAsync(bool cancel)
    {
        var root = Path.Combine(Path.GetTempPath(), $"gui synthetic process tree {Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        var childPidPath = Path.Combine(root, "child.pid");
        var quotedPidPath = $"'{childPidPath.Replace("'", "'\\''", StringComparison.Ordinal)}'";
        var script = $"sleep 30 & child=$!; printf '%s' \"$child\" > {quotedPidPath}; wait";
        using var cancellation = new CancellationTokenSource();
        var runner = new WindowsPowerShellProcessRunner();
        var request = new LauncherProcessRequest("/bin/sh", root, new[] { "-c", script });
        var run = runner.RunAsync(request, cancel ? TimeSpan.FromSeconds(10) : TimeSpan.FromMilliseconds(800), cancellation.Token);
        try
        {
            var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(4);
            while (!File.Exists(childPidPath) && !run.IsCompleted && DateTime.UtcNow < deadline)
            {
                await Task.Delay(20);
            }

            Assert.True(File.Exists(childPidPath), "The synthetic child process did not start.");
            if (cancel) cancellation.Cancel();
            var result = await run.WaitAsync(TimeSpan.FromSeconds(8));
            var childPid = int.Parse(File.ReadAllText(childPidPath));
            Assert.True(await WaitForLinuxProcessStopAsync(childPid, TimeSpan.FromSeconds(5)),
                "The synthetic child remained alive after parent-tree termination was requested.");
            return result;
        }
        finally
        {
            if (!run.IsCompleted) cancellation.Cancel();
            try { await run.WaitAsync(TimeSpan.FromSeconds(8)); }
            catch (TimeoutException) { }
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    private static async Task<bool> WaitForLinuxProcessStopAsync(int processId, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            var statPath = $"/proc/{processId}/stat";
            if (!File.Exists(statPath)) return true;
            var stat = await File.ReadAllTextAsync(statPath);
            var stateStart = stat.LastIndexOf(')') + 2;
            if (stateStart < stat.Length && stat[stateStart] is 'Z' or 'X') return true;
            await Task.Delay(25);
        }

        return !File.Exists($"/proc/{processId}/stat");
    }

    private static string ArgumentValue(IReadOnlyList<string> arguments, string name)
    {
        var index = arguments.ToList().FindIndex(argument => string.Equals(argument, name, StringComparison.Ordinal));
        Assert.True(index >= 0 && index + 1 < arguments.Count, $"Missing value for {name}.");
        return arguments[index + 1];
    }

    private static void AssertValidIncompleteState(LauncherFixture fixture, ReadOnlyRunResult result)
    {
        Assert.NotEmpty(result.RunId);
        Assert.True(File.Exists(Path.Combine(result.RunRoot, "gui-state.json")));
        var state = RunStateReader.Read(fixture.RunsRoot, result.RunRoot, result.RunId, result.ComputerName);
        Assert.True(state.IsValid, string.Join("; ", state.Issues));
        Assert.False(state.IsComplete);
        Assert.Equal("Incomplete", state.State.OverallStatus);
        Assert.Equal(10, state.State.Stages.Count);
        Assert.All(state.State.Stages, stage => Assert.Equal("Pending", stage.Status));
        var requestRoot = Path.Combine(fixture.LocalApplicationData, "ScreenConnectCleanup", "Requests");
        if (Directory.Exists(requestRoot)) Assert.Empty(Directory.EnumerateFiles(requestRoot));
    }

    private sealed class LauncherFixture : IDisposable
    {
        public LauncherFixture()
        {
            Root = Path.Combine(Path.GetTempPath(), $"readonly gui launcher tests {Guid.NewGuid():N}");
            ApplicationBase = Path.Combine(Root, "application bundle");
            LocalApplicationData = Path.Combine(Root, "local app data");
            WindowsDirectory = Path.Combine(Root, "windows root");
            Directory.CreateDirectory(ApplicationBase);
            Directory.CreateDirectory(LocalApplicationData);
            Directory.CreateDirectory(WindowsDirectory);

            AdapterPath = CreateBundleFile("gui-bridge", "Invoke-GuiStage.ps1");
            _ = CreateBundleFile("gui-bridge", "GuiState.ps1");
            DetectorPath = CreateBundleFile("detect-remote-access.ps1");
            PowerShellPath = Path.Combine(WindowsDirectory, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
            Directory.CreateDirectory(Path.GetDirectoryName(PowerShellPath)!);
            File.WriteAllText(PowerShellPath, "synthetic inert fixture; never executed");

            RunsRoot = Path.Combine(LocalApplicationData, "ScreenConnectCleanup", "Runs");
            Platform = new FakeLauncherPlatform
            {
                MachineName = "HOST-01",
                LocalApplicationDataPath = LocalApplicationData,
                ApplicationBaseDirectory = ApplicationBase,
                WindowsDirectory = WindowsDirectory
            };
            FileSystem = new TrackingLauncherFileSystem();
            ProcessRunner = new FakeLauncherProcessRunner();
            Launcher = new ReadOnlyRunLauncher(Platform, FileSystem, ProcessRunner, TimeSpan.FromSeconds(5));
        }

        public string Root { get; }
        public string ApplicationBase { get; }
        public string LocalApplicationData { get; }
        public string WindowsDirectory { get; }
        public string AdapterPath { get; }
        public string DetectorPath { get; }
        public string PowerShellPath { get; }
        public string RunsRoot { get; }
        public FakeLauncherPlatform Platform { get; }
        public TrackingLauncherFileSystem FileSystem { get; }
        public FakeLauncherProcessRunner ProcessRunner { get; }
        public ReadOnlyRunLauncher Launcher { get; }

        private string CreateBundleFile(params string[] parts)
        {
            var path = Path.Combine(new[] { ApplicationBase }.Concat(parts).ToArray());
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, "synthetic inert script fixture; never executed");
            return path;
        }

        public void Dispose()
        {
            if (Directory.Exists(Root)) Directory.Delete(Root, recursive: true);
        }
    }

    private sealed class FakeLauncherPlatform : ILauncherPlatform
    {
        public bool IsWindows { get; set; } = true;
        public bool IsProcessElevated { get; set; }
        public bool Is64BitOperatingSystem => true;
        public bool Is64BitProcess => true;
        public string MachineName { get; set; } = string.Empty;
        public string LocalApplicationDataPath { get; set; } = string.Empty;
        public string ApplicationBaseDirectory { get; set; } = string.Empty;
        public string WindowsDirectory { get; set; } = string.Empty;
    }

    private sealed class TrackingLauncherFileSystem : ILauncherFileSystem
    {
        private readonly SystemLauncherFileSystem _inner = new();
        public List<string> AccessedPaths { get; } = new();

        public void EnsureDirectory(string path)
        {
            AccessedPaths.Add(Path.GetFullPath(path));
            _inner.EnsureDirectory(path);
        }

        public void ValidateNoReparsePoints(string path, bool requireLeaf)
        {
            AccessedPaths.Add(Path.GetFullPath(path));
            _inner.ValidateNoReparsePoints(path, requireLeaf);
        }

        public bool FileExists(string path)
        {
            AccessedPaths.Add(Path.GetFullPath(path));
            return _inner.FileExists(path);
        }

        public bool PathExists(string path)
        {
            AccessedPaths.Add(Path.GetFullPath(path));
            return _inner.PathExists(path);
        }

        public void WriteNewFile(string path, byte[] bytes)
        {
            AccessedPaths.Add(Path.GetFullPath(path));
            _inner.WriteNewFile(path, bytes);
        }

        public void WriteNewFileIfMissing(string path, byte[] bytes)
        {
            AccessedPaths.Add(Path.GetFullPath(path));
            _inner.WriteNewFileIfMissing(path, bytes);
        }

        public void DeleteFileIfExists(string path)
        {
            AccessedPaths.Add(Path.GetFullPath(path));
            _inner.DeleteFileIfExists(path);
        }
    }

    private sealed class FakeLauncherProcessRunner : ILauncherProcessRunner
    {
        public List<LauncherProcessRequest> Requests { get; } = new();
        public List<byte[]> RequestBodies { get; } = new();
        public Func<LauncherProcessRequest, Task<LauncherProcessResult>>? Handler { get; set; }

        public Task<LauncherProcessResult> RunAsync(
            LauncherProcessRequest request,
            TimeSpan timeout,
            CancellationToken cancellationToken)
        {
            Requests.Add(request);
            var requestPath = ArgumentValue(request.Arguments, "-RequestPath");
            RequestBodies.Add(File.ReadAllBytes(requestPath));
            return Handler?.Invoke(request) ?? Task.FromResult(new LauncherProcessResult(0));
        }
    }
}

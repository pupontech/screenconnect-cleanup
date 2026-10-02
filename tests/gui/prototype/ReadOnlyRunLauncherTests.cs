using System.ComponentModel;
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
    public void WindowsProcessCommandLinePreservesPathsWithSpacesAndApostrophesWithoutShellParsing()
    {
        var request = new LauncherProcessRequest(
            @"C:\Program Files\Windows PowerShell\v1.0\powershell.exe",
            @"C:\Program Files\GUI",
            new[]
            {
                "-File", @"C:\Users\O'Brien\App Data\Invoke-GuiStage.ps1",
                "-RequestPath", @"C:\Users\O'Brien\App Data\request.json", "-ReturnExitCode"
            });

        var commandLine = WindowsProcessContainment.BuildCommandLine(request);

        Assert.Equal(
            "\"C:\\Program Files\\Windows PowerShell\\v1.0\\powershell.exe\" -File \"C:\\Users\\O'Brien\\App Data\\Invoke-GuiStage.ps1\" -RequestPath \"C:\\Users\\O'Brien\\App Data\\request.json\" -ReturnExitCode",
            commandLine);
        Assert.DoesNotContain("-Command", commandLine);
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
    public void ProcessStartFailureDiagnosticsExposeOnlyFailureKindAndNativeCode()
    {
        var cause = new Win32Exception(87, "synthetic path and argv must not be exposed");
        var error = new WindowsProcessStartException(terminationConfirmed: true, cause: cause);

        Assert.Equal("Win32Exception", error.FailureKind);
        Assert.Equal(87, error.NativeErrorCode);
        Assert.Contains("failure kind: Win32Exception", error.Message, StringComparison.Ordinal);
        Assert.Contains("native error 87", error.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("synthetic path", error.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("argv", error.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Null(error.InnerException);
    }

    [Fact]
    public void WindowsAnonymousPipeStreamsUseSynchronousFileStreamHandles()
    {
        if (!OperatingSystem.IsWindows()) return;

        using var fixture = new WindowsProcessFixture();
        using var process = WindowsProcessContainment.Start(fixture.Request, new NativeWindowsJobApi());

        var outputFile = Assert.IsType<FileStream>(process.StandardOutput.BaseStream);
        var errorFile = Assert.IsType<FileStream>(process.StandardError);
        Assert.False(outputFile.IsAsync);
        Assert.False(errorFile.IsAsync);
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

    [Fact]
    public async Task WindowsJobContainmentConfirmsParentAndChildAreStoppedOnCancellation()
    {
        if (!OperatingSystem.IsWindows()) return;

        var run = await RunSyntheticWindowsParentChildAsync(
            cancellation: true,
            timeout: TimeSpan.FromSeconds(15));

        Assert.True(run.Result.Cancelled);
        Assert.False(run.Result.PreserveRequest);
        Assert.NotNull(run.Result.Error);
        Assert.Equal(0u, run.JobActiveProcessCounts[^1]);
        await AssertWindowsProcessesStoppedAsync(run.ParentProcessId, run.ChildProcessId);
    }

    [Fact]
    public async Task WindowsJobContainmentConfirmsParentAndChildAreStoppedOnTimeout()
    {
        if (!OperatingSystem.IsWindows()) return;

        var run = await RunSyntheticWindowsParentChildAsync(
            cancellation: false,
            timeout: TimeSpan.FromSeconds(2));

        Assert.True(run.Result.TimedOut);
        Assert.False(run.Result.PreserveRequest);
        Assert.NotNull(run.Result.Error);
        Assert.Equal(0u, run.JobActiveProcessCounts[^1]);
        await AssertWindowsProcessesStoppedAsync(run.ParentProcessId, run.ChildProcessId);
    }

    [Fact]
    public async Task WindowsNormalCompletionDoesNotReportSuccessWhileAContainedChildRemains()
    {
        if (!OperatingSystem.IsWindows()) return;

        var run = await RunSyntheticWindowsParentChildAsync(
            cancellation: false,
            timeout: TimeSpan.FromSeconds(15),
            parentExitsAfterStartingChild: true);

        Assert.Equal(0, run.Result.AdapterReturnCode);
        Assert.NotNull(run.Result.Error);
        Assert.False(run.Result.PreserveRequest);
        // Console-host helpers may also belong to the job; the safety contract is
        // nonempty after parent exit, then zero after confirmed cleanup.
        Assert.Contains(run.JobActiveProcessCounts, count => count > 0u);
        Assert.Equal(0u, run.JobActiveProcessCounts[^1]);
        await AssertWindowsProcessesStoppedAsync(run.ParentProcessId, run.ChildProcessId);
    }

    [Fact]
    public async Task WindowsJobEmptyAccountingDoesNotConfirmTerminationWhileTheHostHandleIsLive()
    {
        if (!OperatingSystem.IsWindows()) return;

        using var fixture = new WindowsProcessFixture();
        var process = WindowsProcessContainment.Start(fixture.Request, new EmptyReportingWindowsJobApi());
        try
        {
            var processes = await fixture.WaitForChildAsync();

            Assert.False(await process.TerminateAndConfirmEmptyAsync(),
                "A zero job count must not confirm termination while the host process handle remains live.");
            Assert.False(process.HasExited, "The synthetic job API intentionally leaves the host running.");
            Assert.False(IsWindowsProcessStopped(processes.ChildProcessId),
                "The synthetic job API intentionally leaves the child running.");
        }
        finally
        {
            process.Dispose();
        }

        await AssertTrackedWindowsProcessesStoppedAsync(fixture);
    }

    [Fact]
    public async Task WindowsNormalCompletionCapturesTheAdapterCodeAfterTheJobBecomesEmpty()
    {
        if (!OperatingSystem.IsWindows()) return;

        var root = Path.Combine(Path.GetTempPath(), $"ScreenConnect GUI's normal completion {Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        try
        {
            var scriptPath = Path.Combine(root, "adapter's status.ps1");
            File.WriteAllText(scriptPath, "[Console]::Out.WriteLine('0')");
            var powershell = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
            var request = new LauncherProcessRequest(powershell, root, new[]
            {
                "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", scriptPath
            });

            var result = await new WindowsPowerShellProcessRunner().RunAsync(
                request, TimeSpan.FromSeconds(10), CancellationToken.None);

            Assert.Null(result.Error);
            Assert.Equal(0, result.AdapterReturnCode);
            Assert.False(result.PreserveRequest);
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    [Theory]
    [InlineData("assign")]
    [InlineData("resume")]
    public async Task WindowsContainmentSetupFailureNeverRunsTheSuspendedScript(string failurePoint)
    {
        if (!OperatingSystem.IsWindows()) return;

        using var fixture = new WindowsProcessFixture();
        var jobApi = new FaultingWindowsJobApi(failurePoint);
        var runner = new WindowsPowerShellProcessRunner(jobApi);
        var result = await runner.RunAsync(fixture.Request, TimeSpan.FromSeconds(10), CancellationToken.None);

        Assert.NotNull(result.Error);
        Assert.Contains("failure kind: InvalidOperationException", result.Error, StringComparison.Ordinal);
        Assert.False(result.PreserveRequest);
        Assert.False(File.Exists(fixture.MarkerPath));
        var assignIndex = jobApi.Calls.IndexOf("assign");
        var resumeIndex = jobApi.Calls.IndexOf("resume");
        Assert.True(assignIndex >= 0);
        if (failurePoint == "assign") Assert.Equal(-1, resumeIndex);
        else Assert.True(resumeIndex > assignIndex, "The process must be assigned before its primary thread resumes.");
    }

    [Theory]
    [InlineData("query")]
    [InlineData("kill")]
    public async Task WindowsContainmentQueryOrKillFailurePreservesRequestAndKillsOnHandleClose(string failurePoint)
    {
        if (!OperatingSystem.IsWindows()) return;

        var fixture = new WindowsProcessFixture();
        using var cancellation = new CancellationTokenSource();
        var runner = new WindowsPowerShellProcessRunner(new FaultingWindowsJobApi(failurePoint));
        var runTask = runner.RunAsync(fixture.Request, TimeSpan.FromSeconds(15), cancellation.Token);
        try
        {
            var processes = await fixture.WaitForChildAsync(runTask);
            cancellation.Cancel();
            var result = await runTask.WaitAsync(TimeSpan.FromSeconds(12));

            Assert.True(result.Cancelled);
            Assert.True(result.PreserveRequest);
            Assert.NotNull(result.Error);
            await AssertWindowsProcessesStoppedAsync(processes.ParentProcessId, processes.ChildProcessId);
        }
        finally
        {
            cancellation.Cancel();
            try { await runTask.WaitAsync(TimeSpan.FromSeconds(12)); }
            catch (TimeoutException) { }
            try { await AssertTrackedWindowsProcessesStoppedAsync(fixture); }
            finally { fixture.Dispose(); }
        }
    }

    [Fact]
    public async Task ClosingTheOwnedWindowsJobHandleKillsTheRunningParentAndChild()
    {
        if (!OperatingSystem.IsWindows()) return;

        using var fixture = new WindowsProcessFixture();
        var jobApi = new RecordingWindowsJobApi();
        var process = WindowsProcessContainment.Start(fixture.Request, jobApi);
        WindowsProcessIds processes;
        try
        {
            processes = await fixture.WaitForChildAsync();
            Assert.False(process.HasExited, "The Windows PowerShell host must still be running before job close.");
            Assert.Equal(WindowsJobEmptyState.StillActive,
                await process.WaitForNoActiveProcessesAsync(TimeSpan.Zero));
            Assert.False(IsWindowsProcessStopped(processes.ChildProcessId),
                "The synthetic child must still be running before job close.");
            // Windows may attach console-host helpers; require the live parent
            // and child, not an environment-specific exact total.
            Assert.True(jobApi.ActiveProcessCounts.Single() >= 2u);
        }
        finally
        {
            process.Dispose();
        }

        await AssertWindowsProcessesStoppedAsync(processes.ParentProcessId, processes.ChildProcessId);
    }

    private static async Task<WindowsProcessRun> RunSyntheticWindowsParentChildAsync(
        bool cancellation,
        TimeSpan timeout,
        bool parentExitsAfterStartingChild = false)
    {
        var fixture = new WindowsProcessFixture(parentExitsAfterStartingChild);
        using var cancellationSource = new CancellationTokenSource();
        var jobApi = new RecordingWindowsJobApi();
        var runner = new WindowsPowerShellProcessRunner(jobApi);
        var runTask = runner.RunAsync(fixture.Request, timeout, cancellationSource.Token);
        try
        {
            var processes = await fixture.WaitForChildAsync(runTask);
            if (cancellation) cancellationSource.Cancel();
            var result = await runTask.WaitAsync(TimeSpan.FromSeconds(12));
            return new WindowsProcessRun(
                result,
                processes.ParentProcessId,
                processes.ChildProcessId,
                jobApi.ActiveProcessCounts.ToArray());
        }
        finally
        {
            cancellationSource.Cancel();
            try { await runTask.WaitAsync(TimeSpan.FromSeconds(12)); }
            catch (TimeoutException) { }
            try { await AssertTrackedWindowsProcessesStoppedAsync(fixture); }
            finally { fixture.Dispose(); }
        }
    }

    private static async Task AssertTrackedWindowsProcessesStoppedAsync(WindowsProcessFixture fixture)
    {
        var parentStopped = true;
        if (fixture.ParentProcessId is int parentProcessId)
            parentStopped = await WaitForWindowsProcessStopAsync(parentProcessId, TimeSpan.FromSeconds(5));
        var childStopped = true;
        if (fixture.ChildProcessId is int childProcessId)
            childStopped = await WaitForWindowsProcessStopAsync(childProcessId, TimeSpan.FromSeconds(5));
        Assert.True(parentStopped,
            $"The Windows PowerShell host process {fixture.ParentProcessId} was not confirmed stopped before fixture cleanup.");
        Assert.True(childStopped,
            $"The synthetic child process {fixture.ChildProcessId} was not confirmed stopped before fixture cleanup.");
    }

    private static async Task AssertWindowsProcessesStoppedAsync(int parentProcessId, int childProcessId)
    {
        var parentStopped = await WaitForWindowsProcessStopAsync(parentProcessId, TimeSpan.FromSeconds(5));
        var childStopped = await WaitForWindowsProcessStopAsync(childProcessId, TimeSpan.FromSeconds(5));
        Assert.True(parentStopped, $"The Windows PowerShell host process {parentProcessId} was not confirmed stopped.");
        Assert.True(childStopped, $"The synthetic child process {childProcessId} was not confirmed stopped.");
    }

    private static async Task<bool> WaitForWindowsProcessStopAsync(int processId, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            try
            {
                using var process = Process.GetProcessById(processId);
                if (process.HasExited) return true;
            }
            catch (ArgumentException)
            {
                return true;
            }
            await Task.Delay(25);
        }

        return false;
    }

    private sealed record WindowsProcessRun(
        LauncherProcessResult Result,
        int ParentProcessId,
        int ChildProcessId,
        IReadOnlyList<uint> JobActiveProcessCounts);

    private sealed record WindowsProcessIds(int ParentProcessId, int ChildProcessId);

    private sealed class WindowsProcessFixture : IDisposable
    {
        public WindowsProcessFixture(bool parentExitsAfterStartingChild = false)
        {
            Root = Path.Combine(Path.GetTempPath(), $"ScreenConnect GUI's containment {Guid.NewGuid():N}");
            Directory.CreateDirectory(Root);
            var childScript = Path.Combine(Root, "child's sleeper.ps1");
            var parentScript = Path.Combine(Root, "parent's launcher.ps1");
            MarkerPath = Path.Combine(Root, "child process id.txt");
            ParentProcessIdPath = Path.Combine(Root, "parent process id.txt");
            ChildProcessIdPath = Path.Combine(Root, "launched child process id.txt");
            var childCode = "param([string]$MarkerPath) $temporaryPath = $MarkerPath + '.tmp'; [IO.File]::WriteAllText($temporaryPath, [string]$PID); [IO.File]::Move($temporaryPath, $MarkerPath); Start-Sleep -Seconds 60";
            File.WriteAllText(childScript, childCode);
            var parentCode = @"
param([string]$ChildScript, [string]$MarkerPath, [string]$ParentPidPath, [string]$ChildPidPath, [string]$ExitAfterStart)
$parentPidTemporaryPath = $ParentPidPath + '.tmp'
[IO.File]::WriteAllText($parentPidTemporaryPath, [string]$PID)
[IO.File]::Move($parentPidTemporaryPath, $ParentPidPath)
$child = Join-Path $PSHOME 'powershell.exe'
$arguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File ""' + $ChildScript + '"" -MarkerPath ""' + $MarkerPath + '""'
$process = [Diagnostics.Process]::Start($child, $arguments)
$childPidTemporaryPath = $ChildPidPath + '.tmp'
[IO.File]::WriteAllText($childPidTemporaryPath, [string]$process.Id)
[IO.File]::Move($childPidTemporaryPath, $ChildPidPath)
$deadline = [DateTime]::UtcNow.AddSeconds(5)
while (-not [IO.File]::Exists($MarkerPath) -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 10 }
if (-not [IO.File]::Exists($MarkerPath)) { throw 'The synthetic child did not publish its startup marker before the bounded handshake expired.' }
if ($ExitAfterStart -eq 'true') { [Console]::Out.WriteLine('0'); exit 0 }
Start-Sleep -Seconds 60
";
            File.WriteAllText(parentScript, parentCode);
            var powershell = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
            Request = new LauncherProcessRequest(powershell, Root, new[]
            {
                "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                "-File", parentScript, "-ChildScript", childScript, "-MarkerPath", MarkerPath,
                "-ParentPidPath", ParentProcessIdPath, "-ChildPidPath", ChildProcessIdPath,
                "-ExitAfterStart", parentExitsAfterStartingChild ? "true" : "false"
            });
        }

        public string Root { get; }
        public string MarkerPath { get; }
        public string ParentProcessIdPath { get; }
        public string ChildProcessIdPath { get; }
        public LauncherProcessRequest Request { get; }
        public int? ParentProcessId { get; private set; }
        public int? ChildProcessId { get; private set; }

        public async Task<WindowsProcessIds> WaitForChildAsync(Task<LauncherProcessResult>? runTask = null)
        {
            var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(8);
            while (!File.Exists(MarkerPath) && runTask?.IsCompleted != true && DateTime.UtcNow < deadline)
            {
                await Task.Delay(20);
            }
            if (File.Exists(ParentProcessIdPath))
                ParentProcessId = int.Parse(await File.ReadAllTextAsync(ParentProcessIdPath));
            if (File.Exists(ChildProcessIdPath))
                ChildProcessId = int.Parse(await File.ReadAllTextAsync(ChildProcessIdPath));
            Assert.True(ParentProcessId.HasValue, "The synthetic Windows PowerShell host did not publish its process ID.");
            Assert.True(ChildProcessId.HasValue,
                $"The synthetic Windows PowerShell host {ParentProcessId} did not publish the launched child process ID.");
            Assert.True(File.Exists(MarkerPath),
                $"The synthetic Windows child {ChildProcessId} did not complete its startup handshake (host PID {ParentProcessId}).");
            Assert.Equal(ChildProcessId.Value, int.Parse(await File.ReadAllTextAsync(MarkerPath)));
            return new WindowsProcessIds(ParentProcessId.Value, ChildProcessId.Value);
        }

        public void Dispose()
        {
            if (!Directory.Exists(Root)) return;
            if (ParentProcessId is int parentProcessId && !IsWindowsProcessStopped(parentProcessId)) return;
            if (ChildProcessId is int childProcessId && !IsWindowsProcessStopped(childProcessId)) return;
            // Process/job assertions run before disposal. Windows can briefly keep
            // directory handles during terminated console-helper teardown; retry
            // that filesystem boundary only, and still fail if it stays locked.
            var cleanup = Stopwatch.StartNew();
            while (true)
            {
                try
                {
                    Directory.Delete(Root, recursive: true);
                    return;
                }
                catch (DirectoryNotFoundException)
                {
                    return;
                }
                catch (IOException) when (cleanup.Elapsed < TimeSpan.FromSeconds(5))
                {
                    Thread.Sleep(25);
                }
            }
        }
    }

    private sealed class RecordingWindowsJobApi : IWindowsJobApi
    {
        private readonly NativeWindowsJobApi _inner = new();
        public List<uint> ActiveProcessCounts { get; } = new();

        public SafeWindowsJobHandle CreateConfiguredJob() => _inner.CreateConfiguredJob();

        public void AssignToJob(SafeWindowsJobHandle job, IntPtr processHandle) => _inner.AssignToJob(job, processHandle);

        public uint ResumePrimaryThread(IntPtr threadHandle) => _inner.ResumePrimaryThread(threadHandle);

        public uint QueryActiveProcessCount(SafeWindowsJobHandle job)
        {
            var activeProcessCount = _inner.QueryActiveProcessCount(job);
            ActiveProcessCounts.Add(activeProcessCount);
            return activeProcessCount;
        }

        public void TerminateJob(SafeWindowsJobHandle job, uint exitCode) => _inner.TerminateJob(job, exitCode);
    }

    private sealed class EmptyReportingWindowsJobApi : IWindowsJobApi
    {
        private readonly NativeWindowsJobApi _inner = new();

        public SafeWindowsJobHandle CreateConfiguredJob() => _inner.CreateConfiguredJob();

        public void AssignToJob(SafeWindowsJobHandle job, IntPtr processHandle) => _inner.AssignToJob(job, processHandle);

        public uint ResumePrimaryThread(IntPtr threadHandle) => _inner.ResumePrimaryThread(threadHandle);

        public uint QueryActiveProcessCount(SafeWindowsJobHandle job) => 0;

        public void TerminateJob(SafeWindowsJobHandle job, uint exitCode)
        {
            // Deliberately do not terminate; this test isolates the process-handle confirmation.
        }
    }

    private static bool IsWindowsProcessStopped(int processId)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            return process.HasExited;
        }
        catch (ArgumentException)
        {
            return true;
        }
    }

    private sealed class FaultingWindowsJobApi : IWindowsJobApi
    {
        private readonly string _failurePoint;
        private readonly NativeWindowsJobApi _inner = new();
        private bool _terminationRequested;
        public List<string> Calls { get; } = new();

        public FaultingWindowsJobApi(string failurePoint) => _failurePoint = failurePoint;

        public SafeWindowsJobHandle CreateConfiguredJob()
        {
            Calls.Add("create");
            return _inner.CreateConfiguredJob();
        }

        public void AssignToJob(SafeWindowsJobHandle job, IntPtr processHandle)
        {
            Calls.Add("assign");
            if (_failurePoint == "assign") throw new InvalidOperationException("synthetic assignment failure");
            _inner.AssignToJob(job, processHandle);
        }

        public uint ResumePrimaryThread(IntPtr threadHandle)
        {
            Calls.Add("resume");
            if (_failurePoint == "resume") throw new InvalidOperationException("synthetic resume failure");
            return _inner.ResumePrimaryThread(threadHandle);
        }

        public uint QueryActiveProcessCount(SafeWindowsJobHandle job)
        {
            Calls.Add("query");
            if (_failurePoint == "query" && _terminationRequested)
                throw new InvalidOperationException("synthetic query failure");
            return _inner.QueryActiveProcessCount(job);
        }

        public void TerminateJob(SafeWindowsJobHandle job, uint exitCode)
        {
            Calls.Add("terminate");
            _terminationRequested = true;
            if (_failurePoint == "kill") throw new InvalidOperationException("synthetic job termination failure");
            _inner.TerminateJob(job, exitCode);
        }
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

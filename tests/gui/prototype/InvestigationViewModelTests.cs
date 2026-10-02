using System.Reflection;
using System.Text.Json;
using ScreenConnectCleanup.Gui.Models;
using ScreenConnectCleanup.Gui.Services;
using ScreenConnectCleanup.Gui.ViewModels;
using Xunit;

namespace ScreenConnectCleanup.Gui.Prototype.Tests;

public sealed class InvestigationViewModelTests
{
    [Fact]
    public async Task FullInvestigationCommandIsDisabledAndExecutionNeverCallsLauncher()
    {
        var launcher = DispatchProxy.Create<IReadOnlyRunLauncher, ProgressLauncherProxy>();
        var proxy = (ProgressLauncherProxy)(object)launcher;
        var viewModel = new InvestigationViewModel(launcher, Path.GetTempPath());

        Assert.False(viewModel.StartFullInvestigationCommand.CanExecute(null));
        await viewModel.StartFullInvestigationCommand.ExecuteAsync(null);

        Assert.Equal(0, proxy.InvocationCount);
    }

    [Fact]
    public void LoadingRunWithoutArtifactsClearsSyntheticInstancesAndDisablesDecisions()
    {
        var viewModel = new ReviewViewModel();
        Assert.NotEmpty(viewModel.ScreenConnectInstances);
        Assert.NotEmpty(viewModel.OtherTargets);

        viewModel.LoadCurrentRun(new InvestigationRunSnapshot(null, null, null, "Incomplete"));

        Assert.Empty(viewModel.ScreenConnectInstances);
        Assert.Empty(viewModel.OtherTargets);
        Assert.False(viewModel.ApproveAllInstancesCommand.CanExecute(null));
        Assert.False(viewModel.DeclineAllInstancesCommand.CanExecute(null));
        Assert.False(viewModel.ResetDecisionCommand.CanExecute(null));
        Assert.Equal(ReviewDecision.NotReviewed, viewModel.SelectionForAllInstances);
    }

    [Fact]
    public async Task DetectOnlyPublishesCurrentIdentityAndValidatedLiveStageWhileLauncherIsActive()
    {
        const string runId = "HOST-LIVE-001";
        const string computerName = "HOST";
        var trustedRoot = Path.Combine(Path.GetTempPath(), $"gui vm progress {Guid.NewGuid():N}");
        var runRoot = Path.Combine(trustedRoot, runId);
        Directory.CreateDirectory(runRoot);
        var launcher = DispatchProxy.Create<IReadOnlyRunLauncher, ProgressLauncherProxy>();
        var proxy = (ProgressLauncherProxy)(object)launcher;
        proxy.RunId = runId;
        proxy.ComputerName = computerName;
        proxy.RunRoot = runRoot;
        proxy.StateRead = WriteAndReadActiveState(trustedRoot, runRoot, runId, computerName);
        var viewModel = new InvestigationViewModel(launcher, trustedRoot);

        try
        {
            var execution = viewModel.StartDetectOnlyCommand.ExecuteAsync(null);

            Assert.Equal(runId, viewModel.RunState.RunId);
            Assert.Equal(computerName, viewModel.RunState.ComputerName);
            Assert.Equal(StatusValues.Running, viewModel.RunState.OverallStatus);
            Assert.Equal(StatusValues.Running, viewModel.Stages[2].Status);
            Assert.Same(viewModel.Stages[2], viewModel.CurrentStage);
            Assert.True(viewModel.IsRunInProgress);

            proxy.Complete(new ReadOnlyRunResult(runId, computerName, runRoot, -1, "synthetic test completion"));
            await execution;
        }
        finally
        {
            proxy.Complete(new ReadOnlyRunResult(runId, computerName, runRoot, -1, "synthetic test cleanup"));
            if (Directory.Exists(trustedRoot)) Directory.Delete(trustedRoot, recursive: true);
        }
    }

    [Fact]
    public async Task DetectOnlyCancellationAfterRunningProgressDowngradesToIncomplete()
    {
        const string runId = "HOST-CANCELLED-001";
        const string computerName = "HOST";
        var trustedRoot = Path.Combine(Path.GetTempPath(), $"gui vm cancelled {Guid.NewGuid():N}");
        var runRoot = Path.Combine(trustedRoot, runId);
        Directory.CreateDirectory(runRoot);
        var launcher = DispatchProxy.Create<IReadOnlyRunLauncher, ProgressLauncherProxy>();
        var proxy = (ProgressLauncherProxy)(object)launcher;
        proxy.RunId = runId;
        proxy.ComputerName = computerName;
        proxy.RunRoot = runRoot;
        proxy.StateRead = WriteAndReadActiveState(trustedRoot, runRoot, runId, computerName);
        var viewModel = new InvestigationViewModel(launcher, trustedRoot);

        try
        {
            var execution = viewModel.StartDetectOnlyCommand.ExecuteAsync(null);
            Assert.Equal(StatusValues.Running, viewModel.RunState.OverallStatus);
            Assert.Equal(StatusValues.Running, viewModel.Stages[2].Status);
            Assert.Same(viewModel.Stages[2], viewModel.CurrentStage);

            proxy.Cancel();
            await execution;

            AssertIncompleteAfterUnvalidatedExit(viewModel, runId, runRoot,
                "cancelled before its result could be validated");
        }
        finally
        {
            proxy.Cancel();
            if (Directory.Exists(trustedRoot)) Directory.Delete(trustedRoot, recursive: true);
        }
    }

    [Fact]
    public async Task ReturnedCancellationAfterRunningProgressShowsTerminalIncompleteState()
    {
        const string runId = "HOST-RETURNED-CANCEL-001";
        const string computerName = "HOST";
        const string error = "The read-only GUI run was cancelled; its state is incomplete.";
        var trustedRoot = Path.Combine(Path.GetTempPath(), $"gui vm returned cancel {Guid.NewGuid():N}");
        var runRoot = Path.Combine(trustedRoot, runId);
        Directory.CreateDirectory(runRoot);
        var launcher = DispatchProxy.Create<IReadOnlyRunLauncher, ProgressLauncherProxy>();
        var proxy = (ProgressLauncherProxy)(object)launcher;
        proxy.RunId = runId;
        proxy.ComputerName = computerName;
        proxy.RunRoot = runRoot;
        proxy.StateRead = WriteAndReadActiveState(trustedRoot, runRoot, runId, computerName);
        var viewModel = new InvestigationViewModel(launcher, trustedRoot);

        try
        {
            var execution = viewModel.StartDetectOnlyCommand.ExecuteAsync(null);
            Assert.Equal(StatusValues.Running, viewModel.RunState.OverallStatus);
            Assert.Equal(StatusValues.Running, viewModel.Stages[2].Status);

            proxy.Complete(new ReadOnlyRunResult(runId, computerName, runRoot, -1, error));
            await execution;

            Assert.Equal(StatusValues.Incomplete, viewModel.RunState.OverallStatus);
            Assert.Equal(StatusValues.Completed, viewModel.Stages[0].Status);
            Assert.Equal(StatusValues.Completed, viewModel.Stages[1].Status);
            Assert.Equal(StatusValues.Incomplete, viewModel.Stages[2].Status);
            Assert.NotNull(viewModel.Stages[2].EndedUtc);
            Assert.Null(viewModel.CurrentStage);
            Assert.Null(viewModel.RunState.CurrentStage);
            Assert.Equal(error, viewModel.OperationStatus);
            Assert.StartsWith("Ended at ", viewModel.ElapsedTime, StringComparison.Ordinal);
            Assert.Contains(viewModel.Errors, message => message == error);
            Assert.Empty(viewModel.Warnings);
            Assert.False(viewModel.IsProcessActive);
            Assert.False(viewModel.IsRunInProgress);
        }
        finally
        {
            proxy.Complete(new ReadOnlyRunResult(runId, computerName, runRoot, -1, "synthetic test cleanup"));
            if (Directory.Exists(trustedRoot)) Directory.Delete(trustedRoot, recursive: true);
        }
    }

    [Fact]
    public async Task ZeroExitWithStoppedRunningStateShowsTerminalIncompleteNotSuccess()
    {
        const string runId = "HOST-ZERO-EXIT-RUNNING-001";
        const string computerName = "HOST";
        var trustedRoot = Path.Combine(Path.GetTempPath(), $"gui vm zero exit running {Guid.NewGuid():N}");
        var runRoot = Path.Combine(trustedRoot, runId);
        Directory.CreateDirectory(runRoot);
        var launcher = DispatchProxy.Create<IReadOnlyRunLauncher, ProgressLauncherProxy>();
        var proxy = (ProgressLauncherProxy)(object)launcher;
        proxy.RunId = runId;
        proxy.ComputerName = computerName;
        proxy.RunRoot = runRoot;
        proxy.StateRead = WriteAndReadActiveState(trustedRoot, runRoot, runId, computerName);
        var viewModel = new InvestigationViewModel(launcher, trustedRoot);
        InvestigationRunSnapshot? loaded = null;
        viewModel.RunLoaded += snapshot => loaded = snapshot;

        try
        {
            var execution = viewModel.StartDetectOnlyCommand.ExecuteAsync(null);
            var completedStageStartedUtc = viewModel.Stages[0].StartedUtc;
            var completedStageEndedUtc = viewModel.Stages[0].EndedUtc;
            var runningStageStartedUtc = viewModel.Stages[2].StartedUtc;

            proxy.Complete(new ReadOnlyRunResult(runId, computerName, runRoot, 0, null));
            await execution;

            Assert.NotNull(loaded?.StateRead);
            Assert.True(loaded.StateRead.IsValid);
            Assert.True(loaded.StateRead.IsTerminal);
            Assert.Equal(StatusValues.Incomplete, loaded.StateRead.State.OverallStatus);
            Assert.Equal(StatusValues.Incomplete, viewModel.RunState.OverallStatus);
            Assert.Equal(StatusValues.Completed, viewModel.Stages[0].Status);
            Assert.Equal(completedStageStartedUtc, viewModel.Stages[0].StartedUtc);
            Assert.Equal(completedStageEndedUtc, viewModel.Stages[0].EndedUtc);
            Assert.Equal(StatusValues.Incomplete, viewModel.Stages[2].Status);
            Assert.Equal(runningStageStartedUtc, viewModel.Stages[2].StartedUtc);
            Assert.NotNull(viewModel.Stages[2].EndedUtc);
            Assert.Null(viewModel.RunState.CurrentStage);
            Assert.Null(viewModel.CurrentStage);
            Assert.True(viewModel.RunState.UpdatedUtc >= viewModel.Stages[2].EndedUtc);
            Assert.StartsWith("Ended at ", viewModel.ElapsedTime, StringComparison.Ordinal);
            Assert.DoesNotContain("completed with exit code 0", viewModel.OperationStatus, StringComparison.OrdinalIgnoreCase);
            Assert.False(viewModel.FindingsStatus.Contains("Complete — no findings", StringComparison.Ordinal));
        }
        finally
        {
            proxy.Complete(new ReadOnlyRunResult(runId, computerName, runRoot, -1, "synthetic test cleanup"));
            if (Directory.Exists(trustedRoot)) Directory.Delete(trustedRoot, recursive: true);
        }
    }

    [Fact]
    public async Task ZeroExitWithInvalidFinalStateShowsIncompleteAndPreservesValidatedProgress()
    {
        const string runId = "HOST-ZERO-EXIT-INVALID-001";
        const string computerName = "HOST";
        var trustedRoot = Path.Combine(Path.GetTempPath(), $"gui vm zero exit invalid {Guid.NewGuid():N}");
        var runRoot = Path.Combine(trustedRoot, runId);
        Directory.CreateDirectory(runRoot);
        var launcher = DispatchProxy.Create<IReadOnlyRunLauncher, ProgressLauncherProxy>();
        var proxy = (ProgressLauncherProxy)(object)launcher;
        proxy.RunId = runId;
        proxy.ComputerName = computerName;
        proxy.RunRoot = runRoot;
        proxy.StateRead = WriteAndReadActiveState(trustedRoot, runRoot, runId, computerName);
        var viewModel = new InvestigationViewModel(launcher, trustedRoot);
        InvestigationRunSnapshot? loaded = null;
        viewModel.RunLoaded += snapshot => loaded = snapshot;

        try
        {
            var execution = viewModel.StartDetectOnlyCommand.ExecuteAsync(null);
            var completedStageStartedUtc = viewModel.Stages[0].StartedUtc;
            var completedStageEndedUtc = viewModel.Stages[0].EndedUtc;
            var runningStageStartedUtc = viewModel.Stages[2].StartedUtc;
            File.WriteAllText(Path.Combine(runRoot, "gui-state.json"), "{ invalid final state");

            proxy.Complete(new ReadOnlyRunResult(runId, computerName, runRoot, 0, null));
            await execution;

            Assert.NotNull(loaded?.StateRead);
            Assert.False(loaded.StateRead.IsValid);
            Assert.Equal(StatusValues.Incomplete, viewModel.RunState.OverallStatus);
            Assert.Null(viewModel.RunState.CurrentStage);
            Assert.Null(viewModel.CurrentStage);
            Assert.DoesNotContain("completed with exit code 0", viewModel.OperationStatus, StringComparison.OrdinalIgnoreCase);
            Assert.StartsWith("Ended at ", viewModel.ElapsedTime, StringComparison.Ordinal);
            Assert.NotEmpty(viewModel.Stages);
            Assert.Equal(runId, viewModel.RunState.RunId);
            Assert.Equal(computerName, viewModel.RunState.ComputerName);
            Assert.Equal(StatusValues.Completed, viewModel.Stages[0].Status);
            Assert.Equal(completedStageStartedUtc, viewModel.Stages[0].StartedUtc);
            Assert.Equal(completedStageEndedUtc, viewModel.Stages[0].EndedUtc);
            Assert.Equal(StatusValues.Completed, viewModel.Stages[1].Status);
            Assert.Equal(StatusValues.Incomplete, viewModel.Stages[2].Status);
            Assert.Equal(runningStageStartedUtc, viewModel.Stages[2].StartedUtc);
            Assert.NotNull(viewModel.Stages[2].EndedUtc);
            Assert.True(viewModel.RunState.UpdatedUtc >= viewModel.Stages[2].EndedUtc);
            Assert.Contains(viewModel.Errors, error => error.Contains("malformed or truncated JSON", StringComparison.Ordinal));
        }
        finally
        {
            proxy.Complete(new ReadOnlyRunResult(runId, computerName, runRoot, -1, "synthetic test cleanup"));
            if (Directory.Exists(trustedRoot)) Directory.Delete(trustedRoot, recursive: true);
        }
    }

    [Theory]
    [InlineData(-1, "The read-only GUI run timed out; its state is incomplete.", "The read-only GUI run timed out; its state is incomplete.")]
    [InlineData(7, null, "Adapter exit code 7; inspect the validated run state.")]
    public async Task ReturnedTimeoutOrNonzeroExitAfterRunningProgressShowsTerminalState(
        int exitCode,
        string? error,
        string expectedOperationStatus)
    {
        const string runId = "HOST-RETURNED-FAILURE-001";
        const string computerName = "HOST";
        var trustedRoot = Path.Combine(Path.GetTempPath(), $"gui vm returned failure {Guid.NewGuid():N}");
        var runRoot = Path.Combine(trustedRoot, runId);
        Directory.CreateDirectory(runRoot);
        var launcher = DispatchProxy.Create<IReadOnlyRunLauncher, ProgressLauncherProxy>();
        var proxy = (ProgressLauncherProxy)(object)launcher;
        proxy.RunId = runId;
        proxy.ComputerName = computerName;
        proxy.RunRoot = runRoot;
        proxy.StateRead = WriteAndReadActiveState(trustedRoot, runRoot, runId, computerName);
        var viewModel = new InvestigationViewModel(launcher, trustedRoot);

        try
        {
            var execution = viewModel.StartDetectOnlyCommand.ExecuteAsync(null);
            proxy.Complete(new ReadOnlyRunResult(runId, computerName, runRoot, exitCode, error));
            await execution;

            Assert.Equal(StatusValues.Incomplete, viewModel.RunState.OverallStatus);
            Assert.Equal(StatusValues.Completed, viewModel.Stages[0].Status);
            Assert.Equal(StatusValues.Incomplete, viewModel.Stages[2].Status);
            Assert.NotNull(viewModel.Stages[2].EndedUtc);
            Assert.Null(viewModel.CurrentStage);
            Assert.Equal(expectedOperationStatus, viewModel.OperationStatus);
            Assert.StartsWith("Ended at ", viewModel.ElapsedTime, StringComparison.Ordinal);
            Assert.False(viewModel.IsProcessActive);
        }
        finally
        {
            proxy.Complete(new ReadOnlyRunResult(runId, computerName, runRoot, -1, "synthetic test cleanup"));
            if (Directory.Exists(trustedRoot)) Directory.Delete(trustedRoot, recursive: true);
        }
    }

    [Fact]
    public async Task ReturnedPreservedRequestWarnsThatProcessTreeTerminationIsUnconfirmed()
    {
        const string runId = "HOST-PRESERVED-REQUEST-001";
        const string computerName = "HOST";
        const string error = "The read-only GUI process tree did not terminate or descendant exit could not be confirmed; the run is incomplete and its request was retained.";
        var trustedRoot = Path.Combine(Path.GetTempPath(), $"gui vm preserved request {Guid.NewGuid():N}");
        var runRoot = Path.Combine(trustedRoot, runId);
        Directory.CreateDirectory(runRoot);
        var launcher = DispatchProxy.Create<IReadOnlyRunLauncher, ProgressLauncherProxy>();
        var proxy = (ProgressLauncherProxy)(object)launcher;
        proxy.RunId = runId;
        proxy.ComputerName = computerName;
        proxy.RunRoot = runRoot;
        proxy.StateRead = WriteAndReadActiveState(trustedRoot, runRoot, runId, computerName);
        var viewModel = new InvestigationViewModel(launcher, trustedRoot);

        try
        {
            var execution = viewModel.StartDetectOnlyCommand.ExecuteAsync(null);
            proxy.Complete(new ReadOnlyRunResult(runId, computerName, runRoot, -1, error));
            await execution;

            Assert.Equal(StatusValues.Incomplete, viewModel.RunState.OverallStatus);
            Assert.Null(viewModel.CurrentStage);
            Assert.Equal(error, viewModel.OperationStatus);
            Assert.Contains(viewModel.Warnings, warning =>
                warning.Contains("Process-tree termination is unconfirmed", StringComparison.Ordinal));
            Assert.Contains(viewModel.Warnings, warning =>
                warning.Contains("may still be running", StringComparison.Ordinal));
            Assert.DoesNotContain(viewModel.Warnings, warning =>
                warning.Contains("tree exited", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            proxy.Complete(new ReadOnlyRunResult(runId, computerName, runRoot, -1, "synthetic test cleanup"));
            if (Directory.Exists(trustedRoot)) Directory.Delete(trustedRoot, recursive: true);
        }
    }

    [Fact]
    public async Task DetectOnlyExceptionAfterRunningProgressDowngradesToIncomplete()
    {
        const string runId = "HOST-FAILED-001";
        const string computerName = "HOST";
        const string failure = "synthetic launcher failure";
        var trustedRoot = Path.Combine(Path.GetTempPath(), $"gui vm failed {Guid.NewGuid():N}");
        var runRoot = Path.Combine(trustedRoot, runId);
        Directory.CreateDirectory(runRoot);
        var launcher = DispatchProxy.Create<IReadOnlyRunLauncher, ProgressLauncherProxy>();
        var proxy = (ProgressLauncherProxy)(object)launcher;
        proxy.RunId = runId;
        proxy.ComputerName = computerName;
        proxy.RunRoot = runRoot;
        proxy.StateRead = WriteAndReadActiveState(trustedRoot, runRoot, runId, computerName);
        var viewModel = new InvestigationViewModel(launcher, trustedRoot);

        try
        {
            var execution = viewModel.StartDetectOnlyCommand.ExecuteAsync(null);
            Assert.Equal(StatusValues.Running, viewModel.RunState.OverallStatus);
            Assert.Equal(StatusValues.Running, viewModel.Stages[2].Status);
            Assert.Same(viewModel.Stages[2], viewModel.CurrentStage);

            proxy.Fail(new InvalidOperationException(failure));
            await execution;

            AssertIncompleteAfterUnvalidatedExit(viewModel, runId, runRoot, failure);
        }
        finally
        {
            proxy.Cancel();
            if (Directory.Exists(trustedRoot)) Directory.Delete(trustedRoot, recursive: true);
        }
    }

    [Fact]
    public async Task SecondDetectOnlyRunResetsElapsedTimeBeforeDeferredLaunchCompletes()
    {
        const string computerName = "HOST";
        const string firstRunId = "HOST-ELAPSED-001";
        const string secondRunId = "HOST-ELAPSED-002";
        var trustedRoot = Path.Combine(Path.GetTempPath(), $"gui vm elapsed {Guid.NewGuid():N}");
        var firstRunRoot = Path.Combine(trustedRoot, firstRunId);
        var secondRunRoot = Path.Combine(trustedRoot, secondRunId);
        Directory.CreateDirectory(firstRunRoot);
        Directory.CreateDirectory(secondRunRoot);
        var launcher = new SequencedLauncher();
        var firstCompletion = launcher.Enqueue(firstRunId, computerName, firstRunRoot,
            WriteAndReadActiveState(trustedRoot, firstRunRoot, firstRunId, computerName));
        var secondCompletion = launcher.Enqueue(secondRunId, computerName, secondRunRoot,
            WriteAndReadActiveState(trustedRoot, secondRunRoot, secondRunId, computerName), publishProgress: false);
        var viewModel = new InvestigationViewModel(launcher, trustedRoot);

        try
        {
            var firstExecution = viewModel.StartDetectOnlyCommand.ExecuteAsync(null);
            firstCompletion.SetResult(new ReadOnlyRunResult(firstRunId, computerName, firstRunRoot, -1,
                "synthetic first-run completion"));
            await firstExecution;
            Assert.StartsWith("Ended at ", viewModel.ElapsedTime);
            Assert.Equal(StatusValues.Incomplete, viewModel.RunState.OverallStatus);

            var secondExecution = viewModel.StartDetectOnlyCommand.ExecuteAsync(null);
            Assert.Equal("Waiting for validated run state…", viewModel.ElapsedTime);
            Assert.False(secondCompletion.Task.IsCompleted);

            secondCompletion.SetResult(new ReadOnlyRunResult(secondRunId, computerName, secondRunRoot, -1,
                "synthetic second-run completion"));
            await secondExecution;
        }
        finally
        {
            firstCompletion.TrySetCanceled();
            secondCompletion.TrySetCanceled();
            if (Directory.Exists(trustedRoot)) Directory.Delete(trustedRoot, recursive: true);
        }
    }

    [Fact]
    public async Task CancelIsDisabledAfterProcessExitWhileValidatedResultIsHandedOff()
    {
        const string runId = "HOST-HANDOFF-001";
        const string computerName = "HOST";
        var trustedRoot = Path.Combine(Path.GetTempPath(), $"gui vm handoff {Guid.NewGuid():N}");
        var runRoot = Path.Combine(trustedRoot, runId);
        Directory.CreateDirectory(runRoot);
        var launcher = DispatchProxy.Create<IReadOnlyRunLauncher, ProgressLauncherProxy>();
        var proxy = (ProgressLauncherProxy)(object)launcher;
        proxy.RunId = runId;
        proxy.ComputerName = computerName;
        proxy.RunRoot = runRoot;
        proxy.StateRead = WriteAndReadActiveState(trustedRoot, runRoot, runId, computerName);
        var dispatcher = new QueuedSynchronizationContext();
        var previousContext = SynchronizationContext.Current;
        Task? execution = null;
        InvestigationViewModel viewModel;

        SynchronizationContext.SetSynchronizationContext(dispatcher);
        try
        {
            viewModel = new InvestigationViewModel(launcher, trustedRoot);
            execution = viewModel.StartDetectOnlyCommand.ExecuteAsync(null);
        }
        finally
        {
            SynchronizationContext.SetSynchronizationContext(previousContext);
        }

        try
        {
            proxy.Complete(new ReadOnlyRunResult(runId, computerName, runRoot, 0, null));
            await dispatcher.WaitForCallbackAsync(TimeSpan.FromSeconds(3));
            Assert.True(dispatcher.RunNext());
            await dispatcher.WaitForCallbackAsync(TimeSpan.FromSeconds(3));

            Assert.True(viewModel.IsRunInProgress);
            Assert.False(viewModel.CancelRunCommand.CanExecute(null));

            Assert.True(dispatcher.RunNext());
            await execution!;
        }
        finally
        {
            proxy.Complete(new ReadOnlyRunResult(runId, computerName, runRoot, -1, "synthetic test cleanup"));
            while (dispatcher.RunNext()) await Task.Yield();
            if (execution is not null && !execution.IsCompleted)
            {
                await execution.WaitAsync(TimeSpan.FromSeconds(3));
            }
            if (Directory.Exists(trustedRoot)) Directory.Delete(trustedRoot, recursive: true);
        }
    }

    private static void AssertIncompleteAfterUnvalidatedExit(
        InvestigationViewModel viewModel,
        string runId,
        string runRoot,
        string expectedError)
    {
        Assert.Equal(runId, viewModel.RunState.RunId);
        Assert.Equal("HOST", viewModel.RunState.ComputerName);
        Assert.Equal(runRoot, viewModel.RunRoot);
        Assert.Equal(StatusValues.Incomplete, viewModel.RunState.OverallStatus);
        Assert.All(viewModel.RunState.Stages, stage => Assert.NotEqual(StatusValues.Running, stage.Status));
        Assert.Equal(StatusValues.Incomplete, viewModel.Stages[2].Status);
        Assert.Null(viewModel.CurrentStage);
        Assert.Null(viewModel.RunState.CurrentStage);
        Assert.Contains(viewModel.Errors, error => error.Contains(expectedError, StringComparison.Ordinal));
        Assert.Contains(viewModel.RunState.Errors, error => error.Contains(expectedError, StringComparison.Ordinal));
        Assert.StartsWith("Incomplete", viewModel.FindingsStatus);
        Assert.False(viewModel.FindingsStatus.Contains("Complete — no findings", StringComparison.Ordinal));
    }

    private static RunStateReadResult WriteAndReadActiveState(
        string trustedRoot,
        string runRoot,
        string runId,
        string computerName)
    {
        var stageNames = new[]
        {
            "Preflight", "Snapshot (Before)", "Detect", "Review Gate", "Contain + Remove",
            "Scanners", "Uninstall installed AV", "Procmon", "Snapshot (After)+Diff", "Report"
        };
        var updated = DateTimeOffset.UtcNow;
        var stages = stageNames.Select((name, id) => new
        {
            id,
            name,
            status = id < 2 ? StatusValues.Completed : id == 2 ? StatusValues.Running : StatusValues.Pending,
            operation = id == 2 ? "Synthetic detector stage" : string.Empty,
            startedUtc = id <= 2 ? updated : (DateTimeOffset?)null,
            endedUtc = id < 2 ? updated : (DateTimeOffset?)null
        }).ToArray();
        var document = new
        {
            schemaVersion = 1,
            runId,
            computerName,
            overallStatus = StatusValues.Running,
            currentStage = 2,
            stages,
            warnings = Array.Empty<string>(),
            errors = Array.Empty<string>(),
            artifacts = new Dictionary<string, string>(),
            updatedUtc = updated
        };
        File.WriteAllText(Path.Combine(runRoot, "gui-state.json"), JsonSerializer.Serialize(document));
        var activeRead = typeof(RunStateReader).GetMethod(
            "ReadForActiveProducer",
            BindingFlags.NonPublic | BindingFlags.Static,
            binder: null,
            types: new[] { typeof(string), typeof(string), typeof(string), typeof(string) },
            modifiers: null);
        Assert.NotNull(activeRead);
        var result = (RunStateReadResult)activeRead.Invoke(null,
            new object[] { trustedRoot, runRoot, runId, computerName })!;
        Assert.True(result.IsValid, string.Join("; ", result.Issues));
        return result;
    }

    public class ProgressLauncherProxy : DispatchProxy
    {
        private readonly TaskCompletionSource<ReadOnlyRunResult> _completion =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public string RunId { get; set; } = string.Empty;
        public string ComputerName { get; set; } = string.Empty;
        public string RunRoot { get; set; } = string.Empty;
        public RunStateReadResult? StateRead { get; set; }
        public int InvocationCount { get; private set; }

        public void Complete(ReadOnlyRunResult result) => _completion.TrySetResult(result);

        public void Fail(Exception exception) => _completion.TrySetException(exception);

        public void Cancel() => _completion.TrySetCanceled();

        protected override object? Invoke(MethodInfo? targetMethod, object?[]? args)
        {
            InvocationCount++;
            Assert.NotNull(targetMethod);
            Assert.Equal(nameof(IReadOnlyRunLauncher.RunAsync), targetMethod.Name);
            var progress = args?.OfType<Delegate>().FirstOrDefault();
            if (progress is not null)
            {
                var progressType = progress.GetType().GetGenericArguments().Single();
                var value = Activator.CreateInstance(progressType, RunId, ComputerName, RunRoot, StateRead, true);
                progress.DynamicInvoke(value);
            }

            return _completion.Task;
        }
    }

    private sealed class SequencedLauncher : IReadOnlyRunLauncher
    {
        private readonly Queue<(string RunId, string ComputerName, string RunRoot,
            RunStateReadResult StateRead, bool PublishProgress,
            TaskCompletionSource<ReadOnlyRunResult> Completion)> _runs = new();

        public TaskCompletionSource<ReadOnlyRunResult> Enqueue(
            string runId,
            string computerName,
            string runRoot,
            RunStateReadResult stateRead,
            bool publishProgress = true)
        {
            var completion = new TaskCompletionSource<ReadOnlyRunResult>(TaskCreationOptions.RunContinuationsAsynchronously);
            _runs.Enqueue((runId, computerName, runRoot, stateRead, publishProgress, completion));
            return completion;
        }

        public Task<ReadOnlyRunResult> RunAsync(string operation, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException("The test launcher requires the progress callback overload.");

        public Task<ReadOnlyRunResult> RunAsync(
            string operation,
            Action<ReadOnlyRunProgress>? progress,
            CancellationToken cancellationToken = default)
        {
            var run = _runs.Dequeue();
            if (run.PublishProgress)
            {
                progress?.Invoke(new ReadOnlyRunProgress(run.RunId, run.ComputerName, run.RunRoot,
                    run.StateRead, ProducerKnownActive: true));
            }
            return run.Completion.Task;
        }
    }

    private sealed class QueuedSynchronizationContext : SynchronizationContext
    {
        private readonly System.Collections.Concurrent.ConcurrentQueue<(SendOrPostCallback Callback, object? State)> _queue = new();
        private readonly SemaphoreSlim _posted = new(0);

        public override void Post(SendOrPostCallback callback, object? state)
        {
            _queue.Enqueue((callback, state));
            _posted.Release();
        }

        public async Task WaitForCallbackAsync(TimeSpan timeout) =>
            await _posted.WaitAsync(timeout).ConfigureAwait(false);

        public bool RunNext()
        {
            if (!_queue.TryDequeue(out var item)) return false;
            var previous = Current;
            SetSynchronizationContext(this);
            try { item.Callback(item.State); }
            finally { SetSynchronizationContext(previous); }
            return true;
        }
    }
}

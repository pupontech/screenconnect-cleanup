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

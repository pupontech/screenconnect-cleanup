using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ScreenConnectCleanup.Gui.Models;
using ScreenConnectCleanup.Gui.Services;
using System.IO;
using System.Text.Json;

namespace ScreenConnectCleanup.Gui.ViewModels;

public partial class ViewModelBase : ObservableObject
{
    [ObservableProperty]
    private string _title = string.Empty;

    [ObservableProperty]
    private bool _isLoading;

    public virtual Task InitializeAsync() => Task.CompletedTask;
}

public partial class HomeViewModel : ViewModelBase
{
    [ObservableProperty]
    private string _computerName = "SYNTHETIC-WORKSTATION";

    [ObservableProperty]
    private string _operatingSystem = "Windows 11 (synthetic preview)";

    [ObservableProperty]
    private bool _isAdministrator;

    [ObservableProperty]
    private string _freeSpace = "Not queried in Phase 1";

    [ObservableProperty]
    private string _toolVersion = "0.1.0";

    [ObservableProperty]
    private DateTime? _incidentDate;

    [ObservableProperty]
    private List<RunHistoryEntry> _recentRuns = SyntheticFixtures.CreateRunHistory();

    [ObservableProperty]
    private RunHistoryEntry? _selectedRun;

    public HomeViewModel() => Title = "ScreenConnect Cleanup";

    [RelayCommand]
    private void OpenRun(RunHistoryEntry? run)
    {
        if (run is null)
        {
            return;
        }
    }

    [RelayCommand]
    private void StartNewInvestigation()
    {
        // Phase 1 has no engine integration; shell navigation is available in the main toolbar.
    }
}

public sealed class RunHistoryEntry
{
    public string RunId { get; set; } = string.Empty;
    public string ComputerName { get; set; } = string.Empty;
    public string OverallStatus { get; set; } = string.Empty;
    public DateTime StartedUtc { get; set; }
    public DateTime? CompletedUtc { get; set; }
    public bool IsInterrupted => CompletedUtc == null && OverallStatus != StatusValues.Completed;
}

#if WINDOWS
public sealed record InvestigationRunSnapshot(
    RunStateReadResult? StateRead,
    FindingsReadResult? Findings,
    ReadOnlyRunResult? LauncherResult,
    string FindingsStatus);

public partial class InvestigationViewModel : ViewModelBase
{
    private readonly IReadOnlyRunLauncher? _launcher;
    private readonly string _trustedRunsRoot;
    private readonly SynchronizationContext? _uiContext;
    private CancellationTokenSource? _activeRunCancellation;
    private int _runGate;
    private long _runGeneration;
    private string? _activeRunId;

    [ObservableProperty]
    private RunState _runState = SyntheticFixtures.CreateTypicalRunState();

    [ObservableProperty]
    private List<StageState> _stages = SyntheticFixtures.CreateTypicalRunState().Stages;

    [ObservableProperty]
    private StageState? _currentStage;

    [ObservableProperty]
    private string _elapsedTime = "Synthetic preview";

    [ObservableProperty]
    private List<string> _warnings = new() { "Synthetic fixture only; no detection was run." };

    [ObservableProperty]
    private List<string> _errors = new();

    [ObservableProperty]
    private string _logContent = "No process or log file was opened in Phase 1.";

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(StartDetectOnlyCommand))]
    private bool _canStartDetectOnly;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(StartFullInvestigationCommand))]
    private bool _canStartFullInvestigation;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(StartDetectOnlyCommand))]
    [NotifyCanExecuteChangedFor(nameof(StartFullInvestigationCommand))]
    [NotifyCanExecuteChangedFor(nameof(CancelRunCommand))]
    private bool _isRunInProgress;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(CancelRunCommand))]
    private bool _isProcessActive;

    [ObservableProperty]
    private bool _hasRealRun;

    [ObservableProperty]
    private string _operationStatus = "No real run has been started.";

    [ObservableProperty]
    private string _findingsStatus = "Incomplete — no real findings have been read.";

    [ObservableProperty]
    private string _runRoot = "Not available";

    public event Action<InvestigationRunSnapshot>? RunLoaded;

    public InvestigationViewModel(
        IReadOnlyRunLauncher? launcher = null,
        string? trustedRunsRoot = null,
        SynchronizationContext? uiContext = null)
    {
        _launcher = launcher;
        _trustedRunsRoot = trustedRunsRoot ?? string.Empty;
        _uiContext = uiContext ?? SynchronizationContext.Current;
        Title = "Investigation";
        Stages = RunState.Stages;
        CurrentStage = Stages.FirstOrDefault(stage => stage.Status == StatusValues.Running);
        CanStartDetectOnly = launcher is not null && !string.IsNullOrWhiteSpace(_trustedRunsRoot);
    }

    [RelayCommand(CanExecute = nameof(CanExecuteDetectOnly))]
    private Task StartDetectOnly(CancellationToken cancellationToken) =>
        RunDetectOnlyInspectionAsync(cancellationToken);

    private bool CanExecuteDetectOnly() => CanStartDetectOnly && !IsRunInProgress;

    [RelayCommand(CanExecute = nameof(CanExecuteFullInvestigation))]
    private Task StartFullInvestigation(CancellationToken cancellationToken) => Task.CompletedTask;

    private bool CanExecuteFullInvestigation() => false;

    [RelayCommand(CanExecute = nameof(CanCancelRun))]
    private void CancelRun()
    {
        if (IsProcessActive) _activeRunCancellation?.Cancel();
    }

    private bool CanCancelRun() => IsRunInProgress && IsProcessActive;

    private async Task RunDetectOnlyInspectionAsync(CancellationToken commandToken)
    {
        if (_launcher is null || string.IsNullOrWhiteSpace(_trustedRunsRoot) ||
            Interlocked.CompareExchange(ref _runGate, 1, 0) != 0)
        {
            return;
        }

        var runGeneration = Interlocked.Increment(ref _runGeneration);
        _activeRunId = null;
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(commandToken);
        _activeRunCancellation = cancellation;
        IsRunInProgress = true;
        IsProcessActive = true;
        HasRealRun = true;
        OperationStatus = "Starting Detect Only inspection…";
        ElapsedTime = "Waiting for validated run state…";
        FindingsStatus = "Incomplete — the run has not produced a validated findings artifact.";
        RunRoot = "Not available";
        Warnings = new List<string>();
        Errors = new List<string>();
        RunState = CreateIncompleteRunState();
        Stages = RunState.Stages;
        CurrentStage = null;
        RunLoaded?.Invoke(new InvestigationRunSnapshot(null, null, null, FindingsStatus));

        try
        {
            var launchResult = await _launcher.RunAsync(
                "DetectOnly",
                progress => QueueRunProgress(progress, runGeneration),
                cancellation.Token);
            IsProcessActive = false;
            var currentRun = await Task.Run(
                () => ReadCurrentRun(launchResult), CancellationToken.None);
            if (runGeneration == Interlocked.Read(ref _runGeneration) &&
                (_activeRunId is null || string.Equals(_activeRunId, launchResult.RunId, StringComparison.Ordinal)))
            {
                _activeRunId ??= launchResult.RunId;
                ApplyCurrentRun(currentRun);
            }
        }
        catch (OperationCanceledException)
        {
            IsProcessActive = false;
            OperationStatus = "Cancelled — no validated run result was returned.";
            FindingsStatus = "Incomplete — cancellation did not produce a validated findings artifact.";
            SetIncompleteAfterUnvalidatedExit(
                "The Detect Only inspection was cancelled before its result could be validated.");
            RunLoaded?.Invoke(new InvestigationRunSnapshot(null, null, null, FindingsStatus));
        }
        catch (Exception exception)
        {
            IsProcessActive = false;
            var message = string.IsNullOrWhiteSpace(exception.Message)
                ? "The Detect Only inspection failed before a result could be validated."
                : $"The Detect Only inspection failed before a result could be validated: {exception.Message}";
            OperationStatus = "Incomplete — no run state was validated.";
            FindingsStatus = "Incomplete — no findings artifact was validated.";
            SetIncompleteAfterUnvalidatedExit(message.Length <= 2048 ? message : message[..2048]);
            RunLoaded?.Invoke(new InvestigationRunSnapshot(null, null, null, FindingsStatus));
        }
        finally
        {
            if (runGeneration == Interlocked.Read(ref _runGeneration))
            {
                IsProcessActive = false;
                _activeRunId = null;
                Interlocked.Increment(ref _runGeneration);
                _activeRunCancellation = null;
                IsRunInProgress = false;
                Interlocked.Exchange(ref _runGate, 0);
            }
        }
    }

    private void QueueRunProgress(ReadOnlyRunProgress progress, long runGeneration)
    {
        void Apply() => ApplyRunProgress(progress, runGeneration);
        if (_uiContext is null || ReferenceEquals(SynchronizationContext.Current, _uiContext))
        {
            Apply();
            return;
        }

        _uiContext.Post(_ => Apply(), null);
    }

    private void ApplyRunProgress(ReadOnlyRunProgress progress, long runGeneration)
    {
        if (runGeneration != Interlocked.Read(ref _runGeneration) ||
            string.IsNullOrWhiteSpace(progress.RunId) ||
            string.IsNullOrWhiteSpace(progress.ComputerName) ||
            string.IsNullOrWhiteSpace(progress.RunRoot))
        {
            return;
        }

        if (_activeRunId is null)
        {
            _activeRunId = progress.RunId;
            RunRoot = progress.RunRoot;
            RunState = new RunState
            {
                RunId = progress.RunId,
                ComputerName = progress.ComputerName,
                OverallStatus = StatusValues.Incomplete,
                Stages = new List<StageState>()
            };
            Stages = RunState.Stages;
            CurrentStage = null;
            OperationStatus = "Detect Only inspection is running; waiting for validated stage state.";
        }
        else if (!string.Equals(_activeRunId, progress.RunId, StringComparison.Ordinal))
        {
            return;
        }

        if (progress.StateRead is not { IsValid: true } stateRead ||
            !string.Equals(stateRead.State.RunId, progress.RunId, StringComparison.Ordinal) ||
            !string.Equals(stateRead.State.ComputerName, progress.ComputerName, StringComparison.Ordinal))
        {
            return;
        }

        var report = stateRead.State;
        RunState = new RunState
        {
            RunId = report.RunId,
            ComputerName = report.ComputerName,
            OverallStatus = report.OverallStatus,
            CurrentStage = report.CurrentStage,
            Stages = report.Stages.Select(stage => new StageState
            {
                Id = stage.Id,
                Name = stage.Name,
                Status = stage.Status,
                Operation = stage.Operation,
                StartedUtc = stage.StartedUtc?.UtcDateTime,
                EndedUtc = stage.EndedUtc?.UtcDateTime
            }).ToList(),
            Warnings = report.Warnings.ToList(),
            Errors = report.Errors.ToList(),
            Artifacts = new Dictionary<string, string>(report.Artifacts, StringComparer.Ordinal),
            UpdatedUtc = report.UpdatedUtc.UtcDateTime
        };
        Stages = RunState.Stages;
        CurrentStage = RunState.CurrentStage is int currentStage && currentStage >= 0 && currentStage < Stages.Count
            ? Stages[currentStage]
            : null;
        ElapsedTime = $"Last updated {report.UpdatedUtc:yyyy-MM-dd HH:mm:ss 'UTC'}";
        Warnings = report.Warnings.Distinct(StringComparer.Ordinal).ToList();
        Errors = report.Errors.Concat(stateRead.Issues).Distinct(StringComparer.Ordinal).ToList();
        RunRoot = progress.RunRoot;
        OperationStatus = progress.ProducerKnownActive
            ? "Detect Only inspection is running; stage state was validated."
            : "Detect Only inspection stage state was validated.";
    }

    private CurrentRunRead ReadCurrentRun(ReadOnlyRunResult launchResult)
    {
        var stateRead = RunStateReader.Read(
            _trustedRunsRoot,
            launchResult.RunRoot,
            launchResult.RunId,
            launchResult.ComputerName);

        FindingsReadResult? findings = null;
        if (stateRead.IsValid && stateRead.State.Artifacts.TryGetValue("findings", out var findingsRelativePath))
        {
            findings = FindingsReader.Read(
                _trustedRunsRoot,
                launchResult.RunRoot,
                launchResult.RunId,
                launchResult.ComputerName,
                findingsRelativePath);
        }

        var expectedExit = launchResult.ExitCode == 0;

        string findingsStatus;
        if (!stateRead.IsValid)
        {
            findingsStatus = "Incomplete — the current run state failed validation.";
        }
        else if (findings is null)
        {
            findingsStatus = "Incomplete — the validated run state has no findings artifact pointer.";
        }
        else if (!findings.IsComplete)
        {
            findingsStatus = "Incomplete — the findings artifact has validation issues.";
        }
        else if (findings.HasFindings)
        {
            findingsStatus = "Findings present — this view does not approve or perform cleanup.";
        }
        else if (stateRead.IsComplete && expectedExit && launchResult.Error is null)
        {
            findingsStatus = "Complete — no findings detected.";
        }
        else
        {
            findingsStatus = $"No findings in the findings artifact; run status is {stateRead.State.OverallStatus}, not a clean completion.";
        }

        return new CurrentRunRead(launchResult, stateRead, findings, findingsStatus, expectedExit);
    }

    private void ApplyCurrentRun(CurrentRunRead currentRun)
    {
        var stateRead = currentRun.StateRead;
        var report = stateRead.State;
        RunState = new RunState
        {
            RunId = report.RunId,
            ComputerName = report.ComputerName,
            OverallStatus = stateRead.IsValid ? report.OverallStatus : StatusValues.Incomplete,
            CurrentStage = report.CurrentStage,
            Stages = report.Stages.Select(stage => new StageState
            {
                Id = stage.Id,
                Name = stage.Name,
                Status = stage.Status,
                Operation = stage.Operation,
                StartedUtc = stage.StartedUtc?.UtcDateTime,
                EndedUtc = stage.EndedUtc?.UtcDateTime
            }).ToList(),
            Warnings = report.Warnings.ToList(),
            Errors = report.Errors.ToList(),
            Artifacts = new Dictionary<string, string>(report.Artifacts, StringComparer.Ordinal),
            UpdatedUtc = report.UpdatedUtc.UtcDateTime
        };
        Stages = RunState.Stages;
        CurrentStage = RunState.CurrentStage is int currentStage && currentStage >= 0 && currentStage < Stages.Count
            ? Stages[currentStage]
            : null;
        ElapsedTime = $"Last updated {report.UpdatedUtc:yyyy-MM-dd HH:mm:ss 'UTC'}";
        RunRoot = currentRun.LaunchResult.RunRoot;
        FindingsStatus = currentRun.FindingsStatus;

        var warningMessages = report.Warnings.ToList();
        Warnings = warningMessages.Distinct(StringComparer.Ordinal).ToList();

        var errorMessages = report.Errors.ToList();
        errorMessages.AddRange(stateRead.Issues);
        if (currentRun.Findings is not null)
        {
            errorMessages.AddRange(currentRun.Findings.Issues.Select(issue => $"Findings: {issue}"));
        }
        if (!string.IsNullOrWhiteSpace(currentRun.LaunchResult.Error))
        {
            errorMessages.Add(currentRun.LaunchResult.Error);
        }
        else if (!currentRun.ExpectedExit)
        {
            errorMessages.Add($"The Detect Only adapter exited with code {currentRun.LaunchResult.ExitCode}; no success is inferred.");
        }
        Errors = errorMessages.Distinct(StringComparer.Ordinal).ToList();

        OperationStatus = currentRun.LaunchResult.Error ?? (currentRun.ExpectedExit
            ? "Detect Only completed with exit code 0."
            : $"Adapter exit code {currentRun.LaunchResult.ExitCode}; inspect the validated run state.");

        RunLoaded?.Invoke(new InvestigationRunSnapshot(
            stateRead, currentRun.Findings, currentRun.LaunchResult, currentRun.FindingsStatus));
    }

    private static RunState CreateIncompleteRunState() => new()
    {
        OverallStatus = StatusValues.Incomplete,
        Stages = new List<StageState>()
    };

    private void SetIncompleteAfterUnvalidatedExit(string terminalError)
    {
        RunStateReadResult? stateRead = null;
        var runId = _activeRunId;
        var computerName = RunState.ComputerName;
        if (!string.IsNullOrWhiteSpace(runId) && !string.IsNullOrWhiteSpace(computerName) &&
            Path.IsPathFullyQualified(RunRoot))
        {
            stateRead = RunStateReader.Read(_trustedRunsRoot, RunRoot, runId, computerName);
        }

        var validationIssues = stateRead?.Issues ?? Array.Empty<string>();
        var errors = (stateRead is { IsValid: true }
                ? stateRead.State.Errors
                : RunState.Errors)
            .Concat(validationIssues)
            .Append(terminalError)
            .Distinct(StringComparer.Ordinal)
            .ToList();

        if (stateRead is { IsValid: true } &&
            string.Equals(stateRead.State.RunId, runId, StringComparison.Ordinal) &&
            string.Equals(stateRead.State.ComputerName, computerName, StringComparison.Ordinal))
        {
            var report = stateRead.State;
            RunState = new RunState
            {
                RunId = report.RunId,
                ComputerName = report.ComputerName,
                OverallStatus = StatusValues.Incomplete,
                CurrentStage = null,
                Stages = report.Stages.Select(stage => new StageState
                {
                    Id = stage.Id,
                    Name = stage.Name,
                    Status = stage.Status == StatusValues.Running ? StatusValues.Incomplete : stage.Status,
                    Operation = stage.Operation,
                    StartedUtc = stage.StartedUtc?.UtcDateTime,
                    EndedUtc = stage.EndedUtc?.UtcDateTime
                }).ToList(),
                Warnings = report.Warnings.ToList(),
                Errors = errors,
                Artifacts = new Dictionary<string, string>(report.Artifacts, StringComparer.Ordinal),
                UpdatedUtc = report.UpdatedUtc.UtcDateTime
            };
            ElapsedTime = $"Last updated {report.UpdatedUtc:yyyy-MM-dd HH:mm:ss 'UTC'}";
        }
        else
        {
            RunState = new RunState
            {
                RunId = RunState.RunId,
                ComputerName = RunState.ComputerName,
                OverallStatus = StatusValues.Incomplete,
                CurrentStage = null,
                Stages = RunState.Stages.Select(stage => new StageState
                {
                    Id = stage.Id,
                    Name = stage.Name,
                    Status = stage.Status == StatusValues.Running ? StatusValues.Incomplete : stage.Status,
                    Operation = stage.Operation,
                    StartedUtc = stage.StartedUtc,
                    EndedUtc = stage.EndedUtc
                }).ToList(),
                Warnings = RunState.Warnings.ToList(),
                Errors = errors,
                Artifacts = new Dictionary<string, string>(RunState.Artifacts, StringComparer.Ordinal),
                UpdatedUtc = RunState.UpdatedUtc
            };
        }

        Stages = RunState.Stages;
        CurrentStage = null;
        Errors = RunState.Errors.ToList();
    }

    public void UpdateProgress(int completedCount)
    {
        // Progress is represented only by validated current-run stage state.
    }

    private sealed record CurrentRunRead(
        ReadOnlyRunResult LaunchResult,
        RunStateReadResult StateRead,
        FindingsReadResult? Findings,
        string FindingsStatus,
        bool ExpectedExit);
}
#else
public partial class InvestigationViewModel : ViewModelBase
{
    [ObservableProperty]
    private RunState _runState = SyntheticFixtures.CreateTypicalRunState();

    [ObservableProperty]
    private List<StageState> _stages = SyntheticFixtures.CreateTypicalRunState().Stages;

    [ObservableProperty]
    private StageState? _currentStage;

    [ObservableProperty]
    private string _elapsedTime = "Synthetic preview";

    [ObservableProperty]
    private List<string> _warnings = new() { "Synthetic fixture only; no detection was run." };

    [ObservableProperty]
    private List<string> _errors = new();

    [ObservableProperty]
    private string _logContent = "No process or log file was opened in Phase 1.";

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(StartDetectOnlyCommand))]
    private bool _canStartDetectOnly;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(StartFullInvestigationCommand))]
    private bool _canStartFullInvestigation;

    public InvestigationViewModel()
    {
        Title = "Investigation";
        Stages = RunState.Stages;
        CurrentStage = Stages.FirstOrDefault(stage => stage.Status == StatusValues.Running);
    }

    [RelayCommand(CanExecute = nameof(CanExecuteDetectOnly))]
    private void StartDetectOnly()
    {
        // The non-Windows test shell remains a synthetic preview.
    }

    private bool CanExecuteDetectOnly() => CanStartDetectOnly;

    [RelayCommand(CanExecute = nameof(CanExecuteFullInvestigation))]
    private void StartFullInvestigation()
    {
        // The non-Windows test shell remains a synthetic preview.
    }

    private bool CanExecuteFullInvestigation() => CanStartFullInvestigation;

    public void UpdateProgress(int completedCount)
    {
        // The non-Windows test shell has no process or progress source.
    }
}
#endif

#if WINDOWS
public sealed record OtherTargetPreview(string ProductName, IReadOnlyList<string> Hits);
#endif

public partial class ReviewViewModel : ViewModelBase
{
    [ObservableProperty]
    private InvestigationData _investigationData = SyntheticFixtures.CreateInvestigationWithMultipleInstances();

    [ObservableProperty]
    private List<ScreenConnectInstance> _screenConnectInstances = SyntheticFixtures.CreateInvestigationWithMultipleInstances().ScreenConnectInstances;

    [ObservableProperty]
    private List<OtherTarget> _otherTargets = SyntheticFixtures.CreateInvestigationWithMultipleInstances().OtherTargets;

    [ObservableProperty]
    private ScreenConnectInstance? _selectedInstance;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(ResetDecisionCommand))]
    private ReviewDecision _selectionForAllInstances = ReviewDecision.NotReviewed;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(ApproveAllInstancesCommand))]
    private bool _canApproveAll;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(DeclineAllInstancesCommand))]
    private bool _canDecline;

    [ObservableProperty]
    private string _approvalStatus = "Synthetic preview; no decision has been recorded.";

#if WINDOWS
    [ObservableProperty]
    private bool _isSyntheticPreview = true;

    [ObservableProperty]
    private IReadOnlyList<string> _currentRunInstances = Array.Empty<string>();

    [ObservableProperty]
    private IReadOnlyList<OtherTargetPreview> _currentRunOtherTargets = Array.Empty<OtherTargetPreview>();

    [ObservableProperty]
    private IReadOnlyList<string> _currentRunFindingsIssues = Array.Empty<string>();

    [ObservableProperty]
    private string _currentRunFindingsStatus = "Incomplete — no real findings have been read.";

    [ObservableProperty]
    private string _currentRunDisplayNote = "";
#endif

    public ReviewViewModel() => Title = "Review";

    [RelayCommand(CanExecute = nameof(CanExecuteApproveAllInstances))]
    private void ApproveAllInstances()
    {
#if WINDOWS
        if (!IsSyntheticPreview)
        {
            return;
        }
#endif
        SelectionForAllInstances = ReviewDecision.ApproveRemoval;
        ApprovalStatus = $"Synthetic preview: approval selected for {ScreenConnectInstances.Count} instance(s); nothing was changed.";
    }

    private bool CanExecuteApproveAllInstances() => CanApproveAll
#if WINDOWS
        && IsSyntheticPreview
#endif
        ;

    [RelayCommand(CanExecute = nameof(CanExecuteDeclineAllInstances))]
    private void DeclineAllInstances()
    {
#if WINDOWS
        if (!IsSyntheticPreview)
        {
            return;
        }
#endif
        SelectionForAllInstances = ReviewDecision.DeclineRemoval;
        ApprovalStatus = "Synthetic preview: removal declined; nothing was changed.";
    }

    private bool CanExecuteDeclineAllInstances() => CanDecline
#if WINDOWS
        && IsSyntheticPreview
#endif
        ;

    [RelayCommand(CanExecute = nameof(CanExecuteResetDecision))]
    private void ResetDecision()
    {
#if WINDOWS
        if (!IsSyntheticPreview)
        {
            return;
        }
#endif
        SelectionForAllInstances = ReviewDecision.NotReviewed;
        ApprovalStatus = "Synthetic preview; no decision has been recorded.";
    }

    private bool CanExecuteResetDecision() => SelectionForAllInstances != ReviewDecision.NotReviewed
#if WINDOWS
        && IsSyntheticPreview
#endif
        ;

#if WINDOWS
    public void LoadCurrentRun(InvestigationRunSnapshot snapshot)
    {
        const int maximumVisibleFindings = 200;
        const int maximumRenderedCharacters = 8192;
        const int maximumVisibleHitsPerTarget = 100;
        const int maximumRenderedHitCharacters = 2048;

        IsSyntheticPreview = false;
        CurrentRunInstances = snapshot.Findings?.Instances
            .Take(maximumVisibleFindings)
            .Select(finding => RenderBoundedJson(finding.Data, maximumRenderedCharacters))
            .ToArray() ?? Array.Empty<string>();
        CurrentRunOtherTargets = snapshot.Findings?.OtherTargets
            .Take(maximumVisibleFindings)
            .Select(target => new OtherTargetPreview(
                target.ProductName,
                target.Hits.Take(maximumVisibleHitsPerTarget)
                    .Select(hit => RenderBoundedJson(hit, maximumRenderedHitCharacters))
                    .ToArray()))
            .ToArray() ?? Array.Empty<OtherTargetPreview>();
        CurrentRunFindingsIssues = snapshot.Findings?.Issues ?? Array.Empty<string>();
        CurrentRunFindingsStatus = snapshot.FindingsStatus;

        var instanceCount = snapshot.Findings?.Instances.Count ?? 0;
        var targetCount = snapshot.Findings?.OtherTargets.Count ?? 0;
        var displayLimitsReached = instanceCount > maximumVisibleFindings || targetCount > maximumVisibleFindings ||
            (snapshot.Findings?.OtherTargets.Any(target => target.Hits.Count > maximumVisibleHitsPerTarget) ?? false);
        CurrentRunDisplayNote = snapshot.Findings is null
            ? "No validated findings artifact is available. Empty lists are not a clean result."
            : displayLimitsReached
                ? $"The read-only preview is bounded: showing up to {maximumVisibleFindings} instances and targets, {maximumVisibleHitsPerTarget} hits per target, and {maximumRenderedCharacters:N0} characters per finding. The validated artifact is unchanged."
                : "Finding data is shown from the validated read-only artifact; no source data is modified.";

        ScreenConnectInstances = new List<ScreenConnectInstance>();
        OtherTargets = new List<OtherTarget>();
        CanApproveAll = false;
        CanDecline = false;
        SelectionForAllInstances = ReviewDecision.NotReviewed;
        ApprovalStatus = "Read-only run data. Approval and decline controls are unavailable for real runs.";
    }

    private static string RenderBoundedJson(JsonElement value, int maximumCharacters)
    {
        var json = value.GetRawText();
        return json.Length <= maximumCharacters
            ? json
            : $"{json[..maximumCharacters]}… [preview truncated; validated artifact unchanged]";
    }
#endif
}

public partial class ResultsViewModel : ViewModelBase
{
    [ObservableProperty]
    private ResultsSummary _results = SyntheticFixtures.CreateIncompleteResults();

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(OpenReportCommand))]
    private bool _canOpenReport;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(OpenRunFolderCommand))]
    private bool _canOpenRunFolder;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(CopyShareLinkCommand))]
    private string _shareLink = string.Empty;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(CopyShareLinkCommand))]
    private bool _canCopyShareLink;

    public ResultsViewModel() => Title = "Results";

    [RelayCommand(CanExecute = nameof(CanExecuteOpenReport))]
    private void OpenReport()
    {
        // No artifact exists in the static Phase 1 shell.
    }

    private bool CanExecuteOpenReport() => CanOpenReport;

    [RelayCommand(CanExecute = nameof(CanExecuteOpenRunFolder))]
    private void OpenRunFolder()
    {
        // No run folder exists in the static Phase 1 shell.
    }

    private bool CanExecuteOpenRunFolder() => CanOpenRunFolder;

    [RelayCommand(CanExecute = nameof(CanExecuteCopyShareLink))]
    private void CopyShareLink()
    {
        // Clipboard access is intentionally not implemented in the static Phase 1 shell.
    }

    private bool CanExecuteCopyShareLink() => CanCopyShareLink && !string.IsNullOrWhiteSpace(ShareLink);
}

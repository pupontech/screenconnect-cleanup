using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ScreenConnectCleanup.Gui.Models;
using ScreenConnectCleanup.Gui.Services;

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
        // Deliberately inert in the static Phase 1 shell.
    }

    private bool CanExecuteDetectOnly() => CanStartDetectOnly;

    [RelayCommand(CanExecute = nameof(CanExecuteFullInvestigation))]
    private void StartFullInvestigation()
    {
        // Deliberately inert in the static Phase 1 shell.
    }

    private bool CanExecuteFullInvestigation() => CanStartFullInvestigation;

    public void UpdateProgress(int completedCount)
    {
        // Phase 1 contains no measured work or progress source.
    }
}

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

    public ReviewViewModel() => Title = "Review";

    [RelayCommand(CanExecute = nameof(CanExecuteApproveAllInstances))]
    private void ApproveAllInstances()
    {
        SelectionForAllInstances = ReviewDecision.ApproveRemoval;
        ApprovalStatus = $"Synthetic preview: approval selected for {ScreenConnectInstances.Count} instance(s); nothing was changed.";
    }

    private bool CanExecuteApproveAllInstances() => CanApproveAll;

    [RelayCommand(CanExecute = nameof(CanExecuteDeclineAllInstances))]
    private void DeclineAllInstances()
    {
        SelectionForAllInstances = ReviewDecision.DeclineRemoval;
        ApprovalStatus = "Synthetic preview: removal declined; nothing was changed.";
    }

    private bool CanExecuteDeclineAllInstances() => CanDecline;

    [RelayCommand(CanExecute = nameof(CanExecuteResetDecision))]
    private void ResetDecision()
    {
        SelectionForAllInstances = ReviewDecision.NotReviewed;
        ApprovalStatus = "Synthetic preview; no decision has been recorded.";
    }

    private bool CanExecuteResetDecision() => SelectionForAllInstances != ReviewDecision.NotReviewed;
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

using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using ScreenConnectCleanup.Gui.Services;
using System.IO;

namespace ScreenConnectCleanup.Gui.ViewModels;

public partial class MainWindowViewModel : ObservableObject
{
    private readonly INavigationService _navigation;

#if WINDOWS
    public static string DefaultTrustedRunsRoot => Path.GetFullPath(Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "ScreenConnectCleanup",
        "Runs"));
#endif

    [ObservableProperty]
    private ViewModelBase _currentViewModel = null!;

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(NavigateBackCommand))]
    private bool _canNavigateBack;

    public HomeViewModel Home { get; }
    public InvestigationViewModel Investigation { get; }
    public ReviewViewModel Review { get; }
    public ResultsViewModel Results { get; }

#if WINDOWS
    public MainWindowViewModel() : this(
        new NavigationService(),
        new ReadOnlyRunLauncher(),
        DefaultTrustedRunsRoot)
    {
    }

    public MainWindowViewModel(INavigationService navigation) : this(
        navigation,
        new ReadOnlyRunLauncher(),
        DefaultTrustedRunsRoot)
    {
    }

    public MainWindowViewModel(
        INavigationService navigation,
        IReadOnlyRunLauncher? runLauncher,
        string trustedRunsRoot)
#else
    public MainWindowViewModel() : this(new NavigationService())
    {
    }

    public MainWindowViewModel(INavigationService navigation)
#endif
    {
        _navigation = navigation ?? throw new ArgumentNullException(nameof(navigation));

        Home = new HomeViewModel();
#if WINDOWS
        Investigation = new InvestigationViewModel(runLauncher, trustedRunsRoot);
        Review = new ReviewViewModel();
        Investigation.RunLoaded += Review.LoadCurrentRun;
#else
        Investigation = new InvestigationViewModel();
        Review = new ReviewViewModel();
#endif
        Review.CanApproveAll = Review.ScreenConnectInstances.Count > 0;
        Review.CanDecline = Review.ScreenConnectInstances.Count > 0;
        Results = new ResultsViewModel();

        _navigation.NavigationRequested += OnNavigationRequested;
        CurrentViewModel = ViewModelFor(_navigation.CurrentView ?? "Home");
        CanNavigateBack = _navigation.CanNavigateBack;
    }

    [RelayCommand]
    private void NavigateHome() => _navigation.NavigateTo("Home");

    [RelayCommand]
    private void NavigateInvestigation() => _navigation.NavigateTo("Investigation");

    [RelayCommand]
    private void NavigateReview() => _navigation.NavigateTo("Review");

    [RelayCommand]
    private void NavigateResults() => _navigation.NavigateTo("Results");

    [RelayCommand(CanExecute = nameof(CanExecuteNavigateBack))]
    private void NavigateBack() => _navigation.NavigateBack();

    private bool CanExecuteNavigateBack() => CanNavigateBack;

    private void OnNavigationRequested(object? sender, NavigationDestination destination)
    {
        CurrentViewModel = ViewModelFor(destination.ViewName);
        CanNavigateBack = _navigation.CanNavigateBack;
    }

    private ViewModelBase ViewModelFor(string viewName) => viewName switch
    {
        "Home" => Home,
        "Investigation" => Investigation,
        "Review" => Review,
        "Results" => Results,
        _ => throw new ArgumentOutOfRangeException(nameof(viewName), viewName, "Only the four Phase 1 views are supported.")
    };
}

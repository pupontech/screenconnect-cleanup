using ScreenConnectCleanup.Gui.Models;
using ScreenConnectCleanup.Gui.Services;
using ScreenConnectCleanup.Gui.ViewModels;
using Xunit;

namespace ScreenConnectCleanup.Gui.Phase1.Tests;

public sealed class NavigationServiceTests
{
    [Fact]
    public void StartsAtHomeWithoutBackNavigation()
    {
        var navigation = new NavigationService();

        Assert.Equal("Home", navigation.CurrentView);
        Assert.False(navigation.CanNavigateBack);
    }

    [Fact]
    public void UnknownViewIsRejectedWithoutChangingCurrentView()
    {
        var navigation = new NavigationService();

        Assert.Throws<ArgumentOutOfRangeException>(() => navigation.NavigateTo("Settings"));
        Assert.Equal("Home", navigation.CurrentView);
        Assert.False(navigation.CanNavigateBack);
    }

    [Fact]
    public void NavigatesBetweenViewsAndBackReturnsToHome()
    {
        var navigation = new NavigationService();

        navigation.NavigateTo("Investigation");
        navigation.NavigateTo("Review");

        Assert.Equal("Review", navigation.CurrentView);
        Assert.True(navigation.CanNavigateBack);

        navigation.NavigateBack();
        Assert.Equal("Investigation", navigation.CurrentView);

        navigation.NavigateBack();
        Assert.Equal("Home", navigation.CurrentView);
        Assert.False(navigation.CanNavigateBack);
    }
}

public sealed class CommandStateTests
{
    [Fact]
    public void InvestigationCommandsTrackTheirEnabledState()
    {
        var viewModel = new InvestigationViewModel();

        Assert.False(viewModel.StartDetectOnlyCommand.CanExecute(null));
        Assert.False(viewModel.StartFullInvestigationCommand.CanExecute(null));

        viewModel.CanStartDetectOnly = true;
        Assert.True(viewModel.StartDetectOnlyCommand.CanExecute(null));
        Assert.False(viewModel.StartFullInvestigationCommand.CanExecute(null));

        viewModel.CanStartFullInvestigation = true;
        Assert.True(viewModel.StartFullInvestigationCommand.CanExecute(null));

        viewModel.CanStartDetectOnly = false;
        Assert.False(viewModel.StartDetectOnlyCommand.CanExecute(null));
    }

    [Fact]
    public void ReviewCommandsTrackAvailabilityAndDecisionState()
    {
        var viewModel = new ReviewViewModel();

        Assert.False(viewModel.ApproveAllInstancesCommand.CanExecute(null));
        Assert.False(viewModel.DeclineAllInstancesCommand.CanExecute(null));
        Assert.False(viewModel.ResetDecisionCommand.CanExecute(null));

        viewModel.CanApproveAll = true;
        viewModel.CanDecline = true;
        Assert.True(viewModel.ApproveAllInstancesCommand.CanExecute(null));
        Assert.True(viewModel.DeclineAllInstancesCommand.CanExecute(null));

        viewModel.ApproveAllInstancesCommand.Execute(null);
        Assert.Equal(ReviewDecision.ApproveRemoval, viewModel.SelectionForAllInstances);
        Assert.True(viewModel.ResetDecisionCommand.CanExecute(null));

        viewModel.ResetDecisionCommand.Execute(null);
        Assert.Equal(ReviewDecision.NotReviewed, viewModel.SelectionForAllInstances);
        Assert.False(viewModel.ResetDecisionCommand.CanExecute(null));
    }

    [Fact]
    public void ResultsCommandsTrackArtifactAvailability()
    {
        var viewModel = new ResultsViewModel();

        Assert.False(viewModel.OpenReportCommand.CanExecute(null));
        Assert.False(viewModel.OpenRunFolderCommand.CanExecute(null));
        Assert.False(viewModel.CopyShareLinkCommand.CanExecute(null));

        viewModel.CanOpenReport = true;
        viewModel.CanOpenRunFolder = true;
        viewModel.ShareLink = "https://example.invalid/share/fixture";
        viewModel.CanCopyShareLink = true;

        Assert.True(viewModel.OpenReportCommand.CanExecute(null));
        Assert.True(viewModel.OpenRunFolderCommand.CanExecute(null));
        Assert.True(viewModel.CopyShareLinkCommand.CanExecute(null));

        viewModel.CanCopyShareLink = false;
        Assert.False(viewModel.CopyShareLinkCommand.CanExecute(null));
    }
}

public sealed class ShellNavigationCommandTests
{
    [Fact]
    public void SyntheticReviewControlsOnlyUpdateTheInMemoryPreview()
    {
        var shell = new MainWindowViewModel();

        Assert.True(shell.Review.ApproveAllInstancesCommand.CanExecute(null));
        shell.Review.ApproveAllInstancesCommand.Execute(null);

        Assert.Equal(ReviewDecision.ApproveRemoval, shell.Review.SelectionForAllInstances);
        Assert.Contains("nothing was changed", shell.Review.ApprovalStatus, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void NavigationCommandsSwitchViewsAndBackCommandTracksHistory()
    {
        var shell = new MainWindowViewModel();

        Assert.Equal("ScreenConnect Cleanup", shell.CurrentViewModel.Title);
        Assert.False(shell.NavigateBackCommand.CanExecute(null));

        shell.NavigateInvestigationCommand.Execute(null);
        Assert.Equal("Investigation", shell.CurrentViewModel.Title);
        Assert.True(shell.NavigateBackCommand.CanExecute(null));

        shell.NavigateReviewCommand.Execute(null);
        Assert.Equal("Review", shell.CurrentViewModel.Title);

        shell.NavigateResultsCommand.Execute(null);
        Assert.Equal("Results", shell.CurrentViewModel.Title);

        shell.NavigateBackCommand.Execute(null);
        Assert.Equal("Review", shell.CurrentViewModel.Title);
        shell.NavigateBackCommand.Execute(null);
        Assert.Equal("Investigation", shell.CurrentViewModel.Title);
        shell.NavigateBackCommand.Execute(null);
        Assert.Equal("ScreenConnect Cleanup", shell.CurrentViewModel.Title);
        Assert.False(shell.NavigateBackCommand.CanExecute(null));
    }
}

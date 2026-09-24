using System.Xml.Linq;
using Xunit;

namespace ScreenConnectCleanup.Gui.Phase1.Tests;

public sealed class StaticShellContractTests
{
    private static readonly XNamespace Presentation = "http://schemas.microsoft.com/winfx/2006/xaml/presentation";

    [Fact]
    public void ContainsExactlyTheFourNamedStaticViews()
    {
        var viewsDirectory = Path.Combine(AppContext.BaseDirectory, "Ui", "Views");
        Assert.True(Directory.Exists(viewsDirectory), "The compiled test output must include the WPF view source files.");

        var names = Directory.GetFiles(viewsDirectory, "*.xaml")
            .Select(Path.GetFileNameWithoutExtension)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(new[] { "HomeView", "InvestigationView", "ResultsView", "ReviewView" }, names);
        foreach (var path in Directory.GetFiles(viewsDirectory, "*.xaml"))
        {
            var document = XDocument.Load(path);
            Assert.Equal(Presentation + "UserControl", document.Root?.Name);
        }
    }

    [Fact]
    public void MainWindowExposesAccessibleKeyboardAndSystemThemeNavigation()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "Ui", "MainWindow.xaml");
        var document = XDocument.Load(path);
        var keys = document.Descendants(Presentation + "KeyBinding")
            .Select(element => ((string?)element.Attribute("Key"),
                (string?)element.Attribute("Modifiers"),
                (string?)element.Attribute("Command")))
            .ToArray();

        Assert.Contains(("D1", "Alt", "{Binding NavigateHomeCommand}"), keys);
        Assert.Contains(("D2", "Alt", "{Binding NavigateInvestigationCommand}"), keys);
        Assert.Contains(("D3", "Alt", "{Binding NavigateReviewCommand}"), keys);
        Assert.Contains(("D4", "Alt", "{Binding NavigateResultsCommand}"), keys);

        var source = File.ReadAllText(path);
        Assert.Contains("AutomationProperties.Name", source, StringComparison.Ordinal);
        Assert.Contains("SystemColors.WindowBrushKey", source, StringComparison.Ordinal);
        Assert.Contains("UseLayoutRounding=\"True\"", source, StringComparison.Ordinal);
        Assert.Contains("SnapsToDevicePixels=\"True\"", source, StringComparison.Ordinal);
    }

    [Fact]
    public void SyntheticRunStateUsesTenContractStagesAndOnlyContractStatuses()
    {
        var run = ScreenConnectCleanup.Gui.Services.SyntheticFixtures.CreateTypicalRunState();

        Assert.Equal(Enumerable.Range(0, 10), run.Stages.Select(stage => stage.Id));
        Assert.Equal(new[]
        {
            "Preflight", "Snapshot (Before)", "Detect", "Review Gate", "Contain + Remove",
            "Scanners", "Uninstall installed AV", "Procmon", "Snapshot (After)+Diff", "Report"
        }, run.Stages.Select(stage => stage.Name));
        Assert.Contains(run.OverallStatus, ScreenConnectCleanup.Gui.Models.StatusValues.All);
        Assert.All(run.Stages, stage => Assert.Contains(stage.Status, ScreenConnectCleanup.Gui.Models.StatusValues.All));
    }
}

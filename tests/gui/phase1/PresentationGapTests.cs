using System.Xml.Linq;
using Xunit;

namespace ScreenConnectCleanup.Gui.Phase1.Tests;

public sealed class PresentationGapTests
{
    private static readonly XNamespace Presentation = "http://schemas.microsoft.com/winfx/2006/xaml/presentation";

    [Fact]
    public void HomeShowsAllSyntheticStatusFieldsAndShellNavigationActions()
    {
        var document = LoadView("HomeView");
        var textValues = document.Descendants(Presentation + "TextBlock")
            .Select(element => (string?)element.Attribute("Text"))
            .ToArray();

        Assert.Contains("Administrator status", textValues);
        Assert.Contains("Disk space", textValues);
        Assert.Contains("Version", textValues);
        Assert.Contains("Incident date", textValues);
        Assert.Contains(textValues, value => value == "{Binding IsAdministrator}");
        Assert.Contains(textValues, value => value == "{Binding FreeSpace}");
        Assert.Contains(textValues, value => value == "{Binding ToolVersion}");
        Assert.Contains(textValues, value => value?.StartsWith("{Binding IncidentDate,", StringComparison.Ordinal) == true);

        AssertHomeAction(document, "Full Investigation", "NavigateInvestigationCommand");
        AssertHomeAction(document, "Detect Only", "NavigateInvestigationCommand");
        AssertHomeAction(document, "Previous Runs", "NavigateResultsCommand");
    }

    [Fact]
    public void ReviewShowsInstallDateEvidenceFileCustomPropertiesAndParsingWarnings()
    {
        var document = LoadView("ReviewView");
        var textValues = document.Descendants(Presentation + "TextBlock")
            .Select(element => (string?)element.Attribute("Text"))
            .ToArray();
        var itemSources = document.Descendants(Presentation + "ItemsControl")
            .Select(element => (string?)element.Attribute("ItemsSource"))
            .ToArray();

        Assert.Contains("Install date (UTC)", textValues);
        Assert.Contains(textValues, value => value?.StartsWith("{Binding InstallDirCreatedUtc,", StringComparison.Ordinal) == true);
        Assert.Contains("Evidence basis", textValues);
        Assert.Contains("Executable file", textValues);
        Assert.Contains(textValues, value => value == "{Binding File}");
        Assert.Contains("Custom properties", textValues);
        Assert.Contains(textValues, value => value == "{Binding Key}");
        Assert.Contains(textValues, value => value == "{Binding Value}");
        Assert.Contains("Parsing warnings", textValues);
        Assert.Contains(itemSources, value => value == "{Binding Sources}");
        Assert.Contains(itemSources, value => value == "{Binding CustomProperties}");
        Assert.Contains(itemSources, value => value == "{Binding ParseIssues}");
    }

    private static XDocument LoadView(string name) => XDocument.Load(
        Path.Combine(AppContext.BaseDirectory, "Ui", "Views", $"{name}.xaml"));

    private static void AssertHomeAction(XDocument document, string content, string commandName)
    {
        var button = Assert.Single(document.Descendants(Presentation + "Button"), element =>
            (string?)element.Attribute("Content") == content);

        Assert.Equal("False", (string?)button.Attribute("IsEnabled"));
        Assert.Equal(
            $"{{Binding DataContext.{commandName}, RelativeSource={{RelativeSource AncestorType={{x:Type Window}}}}}}",
            (string?)button.Attribute("Command"));
    }
}

using System.Xml.Linq;
using Xunit;

namespace ScreenConnectCleanup.Gui.Phase1.Tests;

public sealed class FocusNavigationTests
{
    private static readonly XNamespace Presentation = "http://schemas.microsoft.com/winfx/2006/xaml/presentation";

    [Theory]
    [InlineData("HomeView")]
    [InlineData("InvestigationView")]
    [InlineData("ReviewView")]
    [InlineData("ResultsView")]
    public void RootScrollViewerUsesContinuingTabNavigation(string viewName)
    {
        var document = XDocument.Load(
            Path.Combine(AppContext.BaseDirectory, "Ui", "Views", $"{viewName}.xaml"));
        var root = Assert.IsType<XElement>(document.Root);
        var scrollViewer = Assert.Single(root.Elements(Presentation + "ScrollViewer"));
        var tabNavigation = (string?)scrollViewer.Attribute("KeyboardNavigation.TabNavigation");

        Assert.True(
            tabNavigation is null || string.Equals(tabNavigation, "Continue", StringComparison.Ordinal),
            $"{viewName}'s root ScrollViewer must use WPF's continuing Tab navigation, not trap focus in a cycle.");
    }
}

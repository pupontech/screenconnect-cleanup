namespace ScreenConnectCleanup.Gui.Services;

/// <summary>
/// Navigation direction for view transitions.
/// </summary>
public enum NavigationDirection
{
    Forward,
    Back
}

/// <summary>
/// Represents a navigation destination.
/// </summary>
public record NavigationDestination(string ViewName, string? Parameter = null);

/// <summary>
/// Service interface for navigation between views.
/// </summary>
public interface INavigationService
{
    string? CurrentView { get; }
    IReadOnlyList<string> NavigationHistory { get; }
    event EventHandler<NavigationDestination>? NavigationRequested;
    void NavigateTo(string viewName, string? parameter = null);
    void NavigateBack();
    bool CanNavigateBack { get; }
}

/// <summary>
/// Simple navigation service implementation.
/// </summary>
public sealed class NavigationService : INavigationService
{
    private static readonly HashSet<string> KnownViews = new(StringComparer.Ordinal)
    {
        "Home", "Investigation", "Review", "Results"
    };

    private readonly List<string> _history = new();

    public NavigationService() => CurrentView = "Home";

    public string? CurrentView { get; private set; }
    public IReadOnlyList<string> NavigationHistory => _history.AsReadOnly();
    public bool CanNavigateBack => _history.Count > 0;

    public event EventHandler<NavigationDestination>? NavigationRequested;

    public void NavigateTo(string viewName, string? parameter = null)
    {
        if (!KnownViews.Contains(viewName))
        {
            throw new ArgumentOutOfRangeException(nameof(viewName), viewName, "Only the four Phase 1 views are supported.");
        }

        if (string.Equals(CurrentView, viewName, StringComparison.Ordinal))
        {
            return;
        }

        if (CurrentView is not null)
        {
            _history.Add(CurrentView);
        }

        CurrentView = viewName;
        NavigationRequested?.Invoke(this, new NavigationDestination(viewName, parameter));
    }

    public void NavigateBack()
    {
        if (!CanNavigateBack)
        {
            return;
        }

        CurrentView = _history[^1];
        _history.RemoveAt(_history.Count - 1);
        NavigationRequested?.Invoke(this, new NavigationDestination(CurrentView, null));
    }
}

/// <summary>
/// System information service (reads from environment for display).
/// </summary>
public interface ISystemInfoService
{
    string ComputerName { get; }
    string OperatingSystem { get; }
    bool IsAdministrator { get; }
    string FreeSpace { get; }
    string ToolVersion { get; }
}

/// <summary>
/// Read-only system info from environment (synthetic on non-Windows).
/// </summary>
public class SystemInfoService : ISystemInfoService
{
    public string ComputerName => Environment.MachineName;
    public string OperatingSystem => Environment.OSVersion.ToString();
    public bool IsAdministrator => false; // Requires Windows P/Invoke
    public string FreeSpace => "Not available on this platform";
    public string ToolVersion => "0.1.0";
}

/// <summary>
/// Platform detection for Windows-only features.
/// </summary>
public static class PlatformInfo
{
    public const string OperatingSystem = "Windows";
    public const string MinimumVersion = "10.0.17763.0";

    /// <summary>
    /// Whether the current platform supports the full WPF UI.
    /// </summary>
    public static bool IsWindowsRuntime => false; // False on Linux build/test

    /// <summary>
    /// Windows-only features that require runtime on Windows.
    /// </summary>
    public static IReadOnlyList<string> WindowsOnlyFeatures { get; } = new List<string>
    {
        "Native clipboard access",
        "Native file/folder dialogs",
        "Administrator detection via Windows API",
        "Disk space query via Windows API",
        "System theme detection (light/dark)",
        "DPI awareness configuration",
        "Windows 10+ common item dialogs"
    };
}

using ScreenConnectCleanup.Gui.Models;
using ScreenConnectCleanup.Gui.ViewModels;

namespace ScreenConnectCleanup.Gui.Services;

/// <summary>
/// Provides synthetic test fixtures for Phase 1.
/// </summary>
public static class SyntheticFixtures
{
    /// <summary>
    /// Creates a synthetic run state with typical investigation progress.
    /// </summary>
    public static RunState CreateTypicalRunState()
    {
        return new RunState
        {
            RunId = "HOST-20260923_120000",
            ComputerName = "HOST",
            OverallStatus = StatusValues.Running,
            CurrentStage = 2,
            Stages = new List<StageState>
            {
                new() { Id = 0, Name = "Preflight", Status = StatusValues.Completed,
                    Operation = "System checks", StartedUtc = DateTime.UtcNow.AddMinutes(-30),
                    EndedUtc = DateTime.UtcNow.AddMinutes(-25) },
                new() { Id = 1, Name = "Snapshot (Before)", Status = StatusValues.Completed,
                    Operation = "Before snapshot", StartedUtc = DateTime.UtcNow.AddMinutes(-25),
                    EndedUtc = DateTime.UtcNow.AddMinutes(-20) },
                new() { Id = 2, Name = "Detect", Status = StatusValues.Running,
                    Operation = "Remote-access detection", StartedUtc = DateTime.UtcNow.AddMinutes(-20) },
                new() { Id = 3, Name = "Review Gate", Status = StatusValues.Pending },
                new() { Id = 4, Name = "Contain + Remove", Status = StatusValues.Pending },
                new() { Id = 5, Name = "Scanners", Status = StatusValues.Pending },
                new() { Id = 6, Name = "Uninstall installed AV", Status = StatusValues.Pending },
                new() { Id = 7, Name = "Procmon", Status = StatusValues.Pending },
                new() { Id = 8, Name = "Snapshot (After)+Diff", Status = StatusValues.Pending },
                new() { Id = 9, Name = "Report", Status = StatusValues.Pending }
            },
            Warnings = new List<string> { "Detection provider unavailable" },
            Errors = new List<string>(),
            Artifacts = new Dictionary<string, string>
            {
                { "findings", "detect/HOST_2026-09-23_120000/findings.json" },
                { "log", "master.log" }
            },
            UpdatedUtc = DateTime.UtcNow
        };
    }

    /// <summary>
    /// Creates a synthetic investigation with multiple ScreenConnect instances.
    /// </summary>
    public static InvestigationData CreateInvestigationWithMultipleInstances()
    {
        return new InvestigationData
        {
            RunId = "HOST-20260923_120000",
            ComputerName = "HOST",
            InvestigationStartedUtc = DateTime.UtcNow.AddHours(-1),
            ScreenConnectInstances = new List<ScreenConnectInstance>
            {
                new()
                {
                    Identifier = "SC-V optive-2026",
                    RelayHost = "relay1.screenconnect.example.com:443",
                    SessionType = "Remote Assistance",
                    ServerKeyFingerprint = "SHA256:A1B2C3D4E5F6...",
                    InstallDirCreatedUtc = DateTime.UtcNow.AddDays(-90),
                    InstallDir = @"C:\Program Files\ScreenConnect",
                    CustomProperties = new Dictionary<string, string>
                    {
                        { "CustomerName", "Acme Corp" },
                        { "TechnicianId", "T12345" }
                    },
                    Sources = new List<string> { "Registry", "File Scan", "Service" },
                    File = @"C:\Program Files\ScreenConnect\ScreenConnectService.exe",
                    ParseIssues = new List<string>()
                },
                new()
                {
                    Identifier = "SC-Prod-2025",
                    RelayHost = "relay2.screenconnect.example.com:443",
                    SessionType = "Active Session",
                    ServerKeyFingerprint = "SHA256:F6E5D4C3B2A1...",
                    InstallDirCreatedUtc = DateTime.UtcNow.AddDays(-365),
                    InstallDir = @"C:\Program Files\ScreenConnect",
                    CustomProperties = new Dictionary<string, string>
                    {
                        { "Department", "IT Support" }
                    },
                    Sources = new List<string> { "Registry", "Event Log" },
                    File = @"C:\Program Files\ScreenConnect\ScreenConnectClient.exe",
                    ParseIssues = new List<string> { "Missing custom property: Location" }
                }
            },
            OtherTargets = new List<OtherTarget>
            {
                new()
                {
                    ProductName = "TeamViewer",
                    Hits = new List<string> { @"C:\Program Files\TeamViewer\TeamViewer.exe" },
                    File = @"C:\Program Files\TeamViewer\TeamViewer.exe"
                }
            },
            Warnings = new List<string>(),
            Errors = new List<string>()
        };
    }

    /// <summary>
    /// Creates a synthetic investigation with zero findings.
    /// </summary>
    public static InvestigationData CreateInvestigationWithNoFindings()
    {
        return new InvestigationData
        {
            RunId = "HOST-20260923_120000",
            ComputerName = "HOST",
            InvestigationStartedUtc = DateTime.UtcNow.AddHours(-1),
            ScreenConnectInstances = new List<ScreenConnectInstance>(),
            OtherTargets = new List<OtherTarget>(),
            Warnings = new List<string> { "Detection provider unavailable" },
            Errors = new List<string>()
        };
    }

    /// <summary>
    /// Creates a synthetic investigation with provider errors.
    /// </summary>
    public static InvestigationData CreateInvestigationWithProviderErrors()
    {
        return new InvestigationData
        {
            RunId = "HOST-20260923_120000",
            ComputerName = "HOST",
            InvestigationStartedUtc = DateTime.UtcNow.AddHours(-1),
            ScreenConnectInstances = new List<ScreenConnectInstance>(),
            OtherTargets = new List<OtherTarget>(),
            Warnings = new List<string>(),
            Errors = new List<string> { "Detection provider unavailable" },
            // ProviderError flag on instances would be set per-instance
        };
    }

    /// <summary>
    /// Creates a synthetic investigation with malformed data (missing fields).
    /// </summary>
    public static InvestigationData CreateInvestigationWithMalformedData()
    {
        return new InvestigationData
        {
            RunId = "",  // Missing run ID
            ComputerName = "",
            InvestigationStartedUtc = DateTime.MinValue,
            ScreenConnectInstances = new List<ScreenConnectInstance>
            {
                new()
                {
                    // Many fields intentionally empty
                    Identifier = "UNKNOWN",
                    RelayHost = "",
                    SessionType = "",
                    ServerKeyFingerprint = "",
                    InstallDirCreatedUtc = null,
                    InstallDir = "",
                    CustomProperties = new Dictionary<string, string>(),
                    Sources = new List<string>(),
                    File = "",
                    ParseIssues = new List<string> { "Incomplete detection data" }
                }
            },
            OtherTargets = new List<OtherTarget>()
        };
    }

    /// <summary>
    /// Creates synthetic run history entries.
    /// </summary>
    public static List<RunHistoryEntry> CreateRunHistory()
    {
        return new List<RunHistoryEntry>
        {
            new()
            {
                RunId = "HOST-20260923_120000",
                ComputerName = "HOST",
                OverallStatus = "Completed",
                StartedUtc = DateTime.UtcNow.AddDays(-1),
                CompletedUtc = DateTime.UtcNow.AddDays(-1).AddHours(1)
            },
            new()
            {
                RunId = "WORKSTATION-20260922_090000",
                ComputerName = "WORKSTATION",
                OverallStatus = "Incomplete",
                StartedUtc = DateTime.UtcNow.AddDays(-2),
                CompletedUtc = null
            },
            new()
            {
                RunId = "SERVER-20260920_140000",
                ComputerName = "SERVER",
                OverallStatus = "Warning",
                StartedUtc = DateTime.UtcNow.AddDays(-5),
                CompletedUtc = DateTime.UtcNow.AddDays(-5).AddHours(2)
            }
        };
    }

    /// <summary>
    /// Creates synthetic results summary.
    /// </summary>
    public static ResultsSummary CreateCompletedResults()
    {
        return new ResultsSummary
        {
            RunId = "HOST-20260923_120000",
            ComputerName = "HOST",
            StartedUtc = DateTime.UtcNow.AddHours(-2),
            CompletedUtc = DateTime.UtcNow.AddMinutes(-10),
            Detection = new DetectionOutcome
            {
                Status = StatusValues.Completed,
                InstanceCount = 2,
                FindingsPath = "detect/HOST_2026-09-23_120000/findings.json",
                LogPath = "logs/detect.log"
            },
            Removal = new RemovalOutcome
            {
                Status = StatusValues.Completed,
                AllApproved = true,
                ManifestPath = "removal/manifest.json",
                LogPath = "logs/removal.log"
            },
            Scanner = new ScannerOutcome
            {
                Status = StatusValues.Completed,
                ScannerType = "KVRT",
                ResultsPath = "scans/kvrt-result.json",
                LogPath = "logs/scanner.log"
            },
            Verification = new VerificationOutcome
            {
                Status = StatusValues.Completed,
                BeforeSnapshotPath = "snapshots/before.json",
                AfterSnapshotPath = "snapshots/after.json",
                DiffPath = "snapshots/diff.json",
                LogPath = "logs/verify.log"
            },
            Reboot = new RebootOutcome
            {
                Status = StatusValues.Completed,
                RebootRequired = true,
                LogPath = "logs/reboot.log"
            },
            Report = new ReportOutcome
            {
                Status = StatusValues.Completed,
                ReportPath = "reports/report.html"
            },
            SanitizedShare = new SanitizedShareOutcome
            {
                Status = StatusValues.Completed,
                Destination = "https://microbin.example.com",
                ShareLink = "https://microbin.example.com/s/abc123"
            }
        };
    }

    /// <summary>
    /// Creates synthetic results with incomplete detection.
    /// </summary>
    public static ResultsSummary CreateIncompleteResults()
    {
        return new ResultsSummary
        {
            RunId = "HOST-20260923_120000",
            ComputerName = "HOST",
            StartedUtc = DateTime.UtcNow.AddHours(-2),
            CompletedUtc = null,
            Detection = new DetectionOutcome
            {
                Status = StatusValues.Incomplete,
                InstanceCount = 0,
                FindingsPath = "",
                LogPath = "logs/detect.log"
            },
            Removal = new RemovalOutcome
            {
                Status = StatusValues.Incomplete,
                AllApproved = false,
                ManifestPath = "",
                LogPath = ""
            },
            Scanner = new ScannerOutcome
            {
                Status = StatusValues.Incomplete,
                ScannerType = "",
                ResultsPath = "",
                LogPath = ""
            },
            Verification = new VerificationOutcome
            {
                Status = StatusValues.Incomplete,
                BeforeSnapshotPath = "",
                AfterSnapshotPath = "",
                DiffPath = "",
                LogPath = ""
            },
            Reboot = new RebootOutcome
            {
                Status = StatusValues.Incomplete,
                RebootRequired = false,
                LogPath = ""
            },
            Report = new ReportOutcome
            {
                Status = StatusValues.Incomplete,
                ReportPath = ""
            },
            SanitizedShare = new SanitizedShareOutcome
            {
                Status = StatusValues.Incomplete,
                Destination = "",
                ShareLink = ""
            }
        };
    }
}

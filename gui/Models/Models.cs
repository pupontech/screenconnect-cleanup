namespace ScreenConnectCleanup.Gui.Models;

/// <summary>
/// Represents the overall state of a cleanup run.
/// </summary>
public class RunState
{
    public string RunId { get; set; } = string.Empty;
    public string ComputerName { get; set; } = string.Empty;
    public string OverallStatus { get; set; } = "Pending";
    public int? CurrentStage { get; set; }
    public List<StageState> Stages { get; set; } = new();
    public List<string> Warnings { get; set; } = new();
    public List<string> Errors { get; set; } = new();
    public Dictionary<string, string> Artifacts { get; set; } = new();
    public DateTime UpdatedUtc { get; set; }
}

/// <summary>
/// Status values for stages and overall run.
/// </summary>
public static class StatusValues
{
    public const string Pending = "Pending";
    public const string Running = "Running";
    public const string NeedsAction = "NeedsAction";
    public const string Completed = "Completed";
    public const string Warning = "Warning";
    public const string Failed = "Failed";
    public const string Skipped = "Skipped";
    public const string RebootPending = "RebootPending";
    public const string Incomplete = "Incomplete";

    public static readonly string[] All = new[]
    {
        Pending, Running, NeedsAction, Completed, Warning, Failed,
        Skipped, RebootPending, Incomplete
    };
}

/// <summary>
/// Represents a single stage in the investigation pipeline.
/// </summary>
public class StageState
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Status { get; set; } = StatusValues.Pending;
    public string Operation { get; set; } = string.Empty;
    public DateTime? StartedUtc { get; set; }
    public DateTime? EndedUtc { get; set; }
}

/// <summary>
/// Represents a detected ScreenConnect instance.
/// </summary>
public class ScreenConnectInstance
{
    public string Identifier { get; set; } = string.Empty;
    public string RelayHost { get; set; } = string.Empty;
    public string SessionType { get; set; } = string.Empty;
    public string ServerKeyFingerprint { get; set; } = string.Empty;
    public DateTime? InstallDirCreatedUtc { get; set; }
    public string InstallDir { get; set; } = string.Empty;
    public Dictionary<string, string> CustomProperties { get; set; } = new();
    public List<string> Sources { get; set; } = new();
    public Dictionary<string, string> UnknownParams { get; set; } = new();
    public string File { get; set; } = string.Empty;
    public List<string> ParseIssues { get; set; } = new();
    public bool EventLogError { get; set; }
    public bool ProviderError { get; set; }
}

/// <summary>
/// Represents other detected remote access products (detect-only).
/// </summary>
public class OtherTarget
{
    public string ProductName { get; set; } = string.Empty;
    public List<string> Hits { get; set; } = new();
    public string File { get; set; } = string.Empty;
}

/// <summary>
/// Investigation data containing findings.
/// </summary>
public class InvestigationData
{
    public string RunId { get; set; } = string.Empty;
    public string ComputerName { get; set; } = string.Empty;
    public DateTime InvestigationStartedUtc { get; set; }
    public DateTime? InvestigationEndedUtc { get; set; }
    public List<ScreenConnectInstance> ScreenConnectInstances { get; set; } = new();
    public List<OtherTarget> OtherTargets { get; set; } = new();
    public List<string> Warnings { get; set; } = new();
    public List<string> Errors { get; set; } = new();
    public bool HasFindings => ScreenConnectInstances.Count > 0 || OtherTargets.Count > 0;
}

/// <summary>
/// Review decision for ScreenConnect instances.
/// </summary>
public enum ReviewDecision
{
    NotReviewed,
    ApproveRemoval,
    DeclineRemoval
}

/// <summary>
/// Results summary for a completed run.
/// </summary>
public class ResultsSummary
{
    public string RunId { get; set; } = string.Empty;
    public string ComputerName { get; set; } = string.Empty;
    public DateTime StartedUtc { get; set; }
    public DateTime? CompletedUtc { get; set; }
    public DetectionOutcome Detection { get; set; } = new();
    public RemovalOutcome Removal { get; set; } = new();
    public ScannerOutcome Scanner { get; set; } = new();
    public VerificationOutcome Verification { get; set; } = new();
    public RebootOutcome Reboot { get; set; } = new();
    public ReportOutcome Report { get; set; } = new();
    public SanitizedShareOutcome SanitizedShare { get; set; } = new();
}

public class DetectionOutcome
{
    public string Status { get; set; } = StatusValues.Incomplete;
    public int InstanceCount { get; set; }
    public string FindingsPath { get; set; } = string.Empty;
    public string LogPath { get; set; } = string.Empty;
}

public class RemovalOutcome
{
    public string Status { get; set; } = StatusValues.Incomplete;
    public bool AllApproved { get; set; }
    public string ManifestPath { get; set; } = string.Empty;
    public string LogPath { get; set; } = string.Empty;
}

public class ScannerOutcome
{
    public string Status { get; set; } = StatusValues.Incomplete;
    public string ScannerType { get; set; } = string.Empty;
    public string ResultsPath { get; set; } = string.Empty;
    public string LogPath { get; set; } = string.Empty;
}

public class VerificationOutcome
{
    public string Status { get; set; } = StatusValues.Incomplete;
    public string BeforeSnapshotPath { get; set; } = string.Empty;
    public string AfterSnapshotPath { get; set; } = string.Empty;
    public string DiffPath { get; set; } = string.Empty;
    public string LogPath { get; set; } = string.Empty;
}

public class RebootOutcome
{
    public string Status { get; set; } = StatusValues.Incomplete;
    public bool RebootRequired { get; set; }
    public string LogPath { get; set; } = string.Empty;
}

public class ReportOutcome
{
    public string Status { get; set; } = StatusValues.Incomplete;
    public string ReportPath { get; set; } = string.Empty;
}

public class SanitizedShareOutcome
{
    public string Status { get; set; } = StatusValues.Incomplete;
    public string Destination { get; set; } = string.Empty;
    public string ShareLink { get; set; } = string.Empty;
}

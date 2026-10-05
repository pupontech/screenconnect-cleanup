namespace ScreenConnectCleanup.Gui.Services;

/// <summary>Bounded, non-elevated GUI investigation entry point. Never authorizes removal.</summary>
public interface IReadOnlyRunLauncher
{
    Task<ReadOnlyRunResult> RunAsync(string operation, CancellationToken cancellationToken = default);

    Task<ReadOnlyRunResult> RunAsync(
        string operation,
        Action<ReadOnlyRunProgress>? progress,
        CancellationToken cancellationToken = default);
}

/// <summary>A run identity and optional validated state snapshot from a known active producer.</summary>
public sealed record ReadOnlyRunProgress(
    string RunId,
    string ComputerName,
    string RunRoot,
    RunStateReadResult? StateRead,
    bool ProducerKnownActive);

/// <summary>A process outcome and pointers for fail-closed readers, not evidence of success.</summary>
public sealed record ReadOnlyRunResult(
    string RunId,
    string ComputerName,
    string RunRoot,
    int ExitCode,
    string? Error);

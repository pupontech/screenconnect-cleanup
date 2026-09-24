using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Collections.ObjectModel;
using Microsoft.Win32.SafeHandles;

namespace ScreenConnectCleanup.Gui.Services;

/// <summary>A validated, read-only snapshot of the GUI run state.</summary>
public sealed class RunStateReport
{
    internal RunStateReport(
        string runId,
        string computerName,
        string overallStatus,
        int? currentStage,
        IReadOnlyList<RunStageState> stages,
        IReadOnlyList<string> warnings,
        IReadOnlyList<string> errors,
        IReadOnlyDictionary<string, string> artifacts,
        DateTimeOffset updatedUtc)
    {
        RunId = runId;
        ComputerName = computerName;
        OverallStatus = overallStatus;
        CurrentStage = currentStage;
        Stages = Array.AsReadOnly(stages.ToArray());
        Warnings = Array.AsReadOnly(warnings.ToArray());
        Errors = Array.AsReadOnly(errors.ToArray());
        Artifacts = new ReadOnlyDictionary<string, string>(new Dictionary<string, string>(artifacts, StringComparer.Ordinal));
        UpdatedUtc = updatedUtc;
    }

    public string RunId { get; }
    public string ComputerName { get; }
    public string OverallStatus { get; }
    public int? CurrentStage { get; }
    public IReadOnlyList<RunStageState> Stages { get; }
    public IReadOnlyList<string> Warnings { get; }
    public IReadOnlyList<string> Errors { get; }
    public IReadOnlyDictionary<string, string> Artifacts { get; }
    public DateTimeOffset UpdatedUtc { get; }
}

/// <summary>A validated entry from the engine's ten-stage pipeline.</summary>
public sealed class RunStageState
{
    internal RunStageState(
        int id,
        string name,
        string status,
        string operation,
        DateTimeOffset? startedUtc,
        DateTimeOffset? endedUtc)
    {
        Id = id;
        Name = name;
        Status = status;
        Operation = operation;
        StartedUtc = startedUtc;
        EndedUtc = endedUtc;
    }

    public int Id { get; }
    public string Name { get; }
    public string Status { get; }
    public string Operation { get; }
    public DateTimeOffset? StartedUtc { get; }
    public DateTimeOffset? EndedUtc { get; }
}

/// <summary>Result of reading and validating one gui-state.json file.</summary>
public sealed class RunStateReadResult
{
    internal RunStateReadResult(RunStateReport state, IReadOnlyList<string> issues, bool isValid)
    {
        State = state;
        Issues = Array.AsReadOnly(issues.ToArray());
        IsValid = isValid;
    }

    public RunStateReport State { get; }
    public IReadOnlyList<string> Issues { get; }
    public bool IsValid { get; }
    /// <summary>True when the reported overall run status is final, whether successful or not.</summary>
    public bool IsTerminal => IsValid &&
        State.OverallStatus is "Completed" or "Warning" or "Failed" or "Skipped" or "Incomplete";
    /// <summary>True only when the overall run and every stage completed successfully or was skipped.</summary>
    public bool IsComplete => IsValid && State.OverallStatus == "Completed" &&
        State.Stages.All(stage => stage.Status is "Completed" or "Skipped");
}

/// <summary>
/// Reads gui-state.json beneath a caller-supplied trusted runs root. This reader
/// never launches stages and never treats artifact pointers as proof of execution.
/// </summary>
public static class RunStateReader
{
    private const int SchemaVersion = 1;
    private const int MaximumStateBytes = 1024 * 1024;
    private const int MaximumMessages = 100;
    private const int MaximumMessageLength = 4096;
    private const int MaximumMessageCharacters = 65536;
    private const int MaximumOperationLength = 4096;
    private const int MaximumArtifactPathLength = 2048;
    private const int LinuxOpenReadOnly = 0;
    private const int LinuxOpenNonBlocking = 0x800;
    private const int LinuxOpenNoFollow = 0x20000;
    private const int LinuxOpenDirectory = 0x10000;
    private const int LinuxOpenCloseOnExec = 0x80000;

    private static readonly string[] StageNames =
    {
        "Preflight",
        "Snapshot (Before)",
        "Detect",
        "Review Gate",
        "Contain + Remove",
        "Scanners",
        "Uninstall installed AV",
        "Procmon",
        "Snapshot (After)+Diff",
        "Report"
    };

    private static readonly HashSet<string> AllowedStatuses = new(StringComparer.Ordinal)
    {
        "Pending", "Running", "NeedsAction", "Completed", "Warning",
        "Failed", "Skipped", "RebootPending", "Incomplete"
    };

    private static readonly HashSet<string> AllowedArtifactRoles = new(StringComparer.Ordinal)
    {
        "findings", "beforeSnapshot", "plan", "removalManifest", "scannerResults",
        "avUninstallResults", "procmon", "afterSnapshot", "diff", "results", "report",
        "sanitizedPackage", "log"
    };

    /// <summary>
    /// Reads &lt;runRoot&gt;/gui-state.json, requiring the run directory leaf to
    /// equal expectedRunId and both paths to remain physically beneath trustedRunsRoot.
    /// </summary>
    public static RunStateReadResult Read(
        string trustedRunsRoot,
        string runRoot,
        string expectedRunId,
        string expectedComputerName)
    {
        var issues = new List<string>();
        try
        {
            if (!TryResolveStatePath(trustedRunsRoot, runRoot, expectedRunId, expectedComputerName, issues, out var paths))
            {
                return InvalidResult(issues);
            }

            var resolvedPaths = paths!;
            using (resolvedPaths)
            using (var stateHandle = OpenStateHandle(resolvedPaths.StatePath))
            {
                var openedStatePath = GetFinalPath(stateHandle);
                if (!PathsMatch(openedStatePath, resolvedPaths.ExpectedStatePhysicalPath) ||
                    !IsPathWithin(openedStatePath, resolvedPaths.TrustedRootPhysicalPath))
                {
                    AddIssue(issues, "The opened GUI state file is outside the current run's physical path boundary.");
                    return InvalidResult(issues);
                }

                using var stream = new FileStream(stateHandle, FileAccess.Read);
                if (stream.Length <= 0 || stream.Length > MaximumStateBytes)
                {
                    AddIssue(issues, "The GUI state file is empty or exceeds the size limit.");
                    return InvalidResult(issues);
                }

                var bytes = new byte[checked((int)stream.Length)];
                stream.ReadExactly(bytes);
                if (!PathsMatch(GetFinalPath(resolvedPaths.TrustedRootHandle), resolvedPaths.TrustedRootPhysicalPath) ||
                    !PathsMatch(GetFinalPath(resolvedPaths.RunRootHandle), resolvedPaths.RunRootPhysicalPath) ||
                    !PathsMatch(GetFinalPath(stateHandle), resolvedPaths.ExpectedStatePhysicalPath))
                {
                    AddIssue(issues, "The GUI state file or run root changed physical paths while being read.");
                    return InvalidResult(issues);
                }

                using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 32 });
                if (!TryParseDocument(document.RootElement, expectedRunId, expectedComputerName,
                        resolvedPaths.RunRootPhysicalPath, issues, out var report))
                {
                    return InvalidResult(issues);
                }

                return new RunStateReadResult(report!, issues.ToArray(), isValid: true);
            }
        }
        catch (JsonException)
        {
            AddIssue(issues, "The GUI state file contains malformed or truncated JSON.");
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or
                                           ArgumentException or NotSupportedException or System.Security.SecurityException)
        {
            AddIssue(issues, "The GUI state file could not be read safely.");
        }

        return InvalidResult(issues);
    }

    private static bool TryParseDocument(
        JsonElement root,
        string expectedRunId,
        string expectedComputerName,
        string runRootPhysicalPath,
        List<string> issues,
        out RunStateReport? report)
    {
        report = null;
        if (root.ValueKind != JsonValueKind.Object || ContainsDuplicateProperties(root) ||
            !HasOnlyProperties(root, "schemaVersion", "runId", "computerName", "overallStatus", "currentStage",
                "stages", "warnings", "errors", "artifacts", "updatedUtc"))
        {
            AddIssue(issues, "The GUI state document root is malformed, has duplicate properties, or has unknown fields.");
            return false;
        }

        if (!TryGetUniqueProperty(root, "schemaVersion", out var schemaVersion) ||
            schemaVersion.ValueKind != JsonValueKind.Number || !schemaVersion.TryGetInt32(out var version))
        {
            AddIssue(issues, "The GUI state schemaVersion is missing or malformed.");
            return false;
        }

        if (version != SchemaVersion)
        {
            AddIssue(issues, "The GUI state schema version is unsupported.");
            return false;
        }

        if (!TryReadString(root, "runId", out var runId) ||
            !string.Equals(runId, expectedRunId, StringComparison.Ordinal) ||
            !TryReadString(root, "computerName", out var computerName) ||
            !string.Equals(computerName, expectedComputerName, StringComparison.Ordinal))
        {
            AddIssue(issues, "The GUI state run identity does not match the selected run and computer.");
            return false;
        }

        if (!TryReadStatus(root, "overallStatus", out var overallStatus))
        {
            AddIssue(issues, "The GUI state overallStatus is missing or unrecognized.");
            return false;
        }

        if (!TryReadCurrentStage(root, out var currentStage))
        {
            AddIssue(issues, "The GUI state currentStage must be null or an integer from 0 through 9.");
            return false;
        }

        if (!TryReadStages(root, issues, out var stages))
        {
            return false;
        }

        if (string.Equals(overallStatus, "Completed", StringComparison.Ordinal) &&
            stages.Any(stage => stage.Status is not ("Completed" or "Skipped")))
        {
            AddIssue(issues, "overallStatus cannot be Completed while a stage is not Completed or Skipped.");
            return false;
        }

        if (!TryReadMessages(root, "warnings", issues, out var warnings) ||
            !TryReadMessages(root, "errors", issues, out var errors) ||
            !TryReadArtifacts(root, runRootPhysicalPath, issues, out var artifacts) ||
            !TryReadUtc(root, "updatedUtc", required: true, out var updatedUtc))
        {
            return false;
        }

        var interrupted = string.Equals(overallStatus, "Running", StringComparison.Ordinal) ||
                          stages.Any(stage => string.Equals(stage.Status, "Running", StringComparison.Ordinal));
        if (interrupted)
        {
            overallStatus = "Incomplete";
            stages = stages.Select(stage => stage.Status is "Running"
                ? new RunStageState(stage.Id, stage.Name, "Incomplete", stage.Operation, stage.StartedUtc, stage.EndedUtc)
                : stage).ToArray();
            AddIssue(issues, "The producer stopped in a Running state; the report is Incomplete.");
        }

        report = new RunStateReport(runId!, computerName!, overallStatus!, currentStage, stages,
            warnings!, errors!, artifacts!, updatedUtc!.Value);
        return true;
    }

    private static bool TryReadStages(JsonElement root, List<string> issues, out IReadOnlyList<RunStageState> stages)
    {
        stages = Array.Empty<RunStageState>();
        if (!TryGetUniqueProperty(root, "stages", out var value) || value.ValueKind != JsonValueKind.Array ||
            value.GetArrayLength() != StageNames.Length)
        {
            AddIssue(issues, "The GUI state must contain exactly ten stage records.");
            return false;
        }

        var parsed = new List<RunStageState>(StageNames.Length);
        var seen = new HashSet<int>();
        foreach (var item in value.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.Object || ContainsDuplicateProperties(item) ||
                !HasOnlyProperties(item, "id", "name", "status", "operation", "startedUtc", "endedUtc") ||
                !TryGetUniqueProperty(item, "id", out var idElement) || idElement.ValueKind != JsonValueKind.Number ||
                !idElement.TryGetInt32(out var id) || id < 0 || id >= StageNames.Length || !seen.Add(id) ||
                !TryReadString(item, "name", out var name) || !string.Equals(name, StageNames[id], StringComparison.Ordinal) ||
                !TryReadStatus(item, "status", out var status) ||
                !TryReadBoundedString(item, "operation", MaximumOperationLength, out var operation) ||
                !TryReadUtc(item, "startedUtc", required: false, out var startedUtc) ||
                !TryReadUtc(item, "endedUtc", required: false, out var endedUtc))
            {
                AddIssue(issues, "A GUI stage record is malformed, duplicated, out of range, or does not match the engine stage table.");
                return false;
            }

            parsed.Add(new RunStageState(id, name!, status!, operation!, startedUtc, endedUtc));
        }

        if (seen.Count != StageNames.Length || parsed.Where((stage, index) => stage.Id != index).Any())
        {
            AddIssue(issues, "The ten GUI stage records must be in engine order with unique IDs 0 through 9.");
            return false;
        }

        stages = parsed.ToArray();
        return true;
    }

    private static bool TryReadMessages(JsonElement root, string propertyName, List<string> issues, out IReadOnlyList<string>? messages)
    {
        messages = null;
        if (!TryGetUniqueProperty(root, propertyName, out var value) || value.ValueKind != JsonValueKind.Array ||
            value.GetArrayLength() > MaximumMessages)
        {
            AddIssue(issues, $"The GUI state {propertyName} must be a bounded string array.");
            return false;
        }

        var result = new List<string>(value.GetArrayLength());
        var totalCharacters = 0;
        foreach (var item in value.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.String || item.GetString() is not { } message ||
                message.Length > MaximumMessageLength || totalCharacters + message.Length > MaximumMessageCharacters)
            {
                AddIssue(issues, $"The GUI state {propertyName} contains an invalid or oversized message.");
                return false;
            }

            totalCharacters += message.Length;
            result.Add(message);
        }

        messages = result.ToArray();
        return true;
    }

    private static bool TryReadArtifacts(
        JsonElement root,
        string runRootPhysicalPath,
        List<string> issues,
        out IReadOnlyDictionary<string, string>? artifacts)
    {
        artifacts = null;
        if (!TryGetUniqueProperty(root, "artifacts", out var value) || value.ValueKind != JsonValueKind.Object ||
            ContainsDuplicateProperties(value))
        {
            AddIssue(issues, "The GUI state artifacts map is missing or malformed.");
            return false;
        }

        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var property in value.EnumerateObject())
        {
            if (!AllowedArtifactRoles.Contains(property.Name) || property.Value.ValueKind != JsonValueKind.String ||
                property.Value.GetString() is not { } relativePath ||
                !IsSafeRelativeArtifactPath(relativePath) ||
                !TryValidateArtifactPath(runRootPhysicalPath, relativePath) || result.ContainsKey(property.Name))
            {
                AddIssue(issues, "The GUI state artifacts map contains an unknown role or unsafe path.");
                return false;
            }

            result.Add(property.Name, relativePath);
        }

        artifacts = result;
        return true;
    }

    private static bool TryValidateArtifactPath(string runRootPhysicalPath, string relativePath)
    {
        try
        {
            var segments = relativePath.Split('/');
            var candidate = Path.GetFullPath(Path.Combine(runRootPhysicalPath, Path.Combine(segments)));
            if (!IsPathWithin(candidate, runRootPhysicalPath))
            {
                return false;
            }

            var currentPath = runRootPhysicalPath;
            for (var index = 0; index < segments.Length; index++)
            {
                currentPath = Path.Combine(currentPath, segments[index]);
                FileAttributes attributes;
                try
                {
                    attributes = File.GetAttributes(currentPath);
                }
                catch (FileNotFoundException)
                {
                    return true;
                }
                catch (DirectoryNotFoundException)
                {
                    return true;
                }

                if ((attributes & FileAttributes.ReparsePoint) != 0)
                {
                    return false;
                }

                var isDirectory = (attributes & FileAttributes.Directory) != 0;
                if (index < segments.Length - 1 && !isDirectory)
                {
                    return false;
                }

                if (index == segments.Length - 1 && isDirectory)
                {
                    return false;
                }

                using var handle = isDirectory
                    ? OpenDirectoryHandle(currentPath)
                    : OpenArtifactHandle(currentPath);
                var physicalPath = GetFinalPath(handle);
                if (!PathsMatch(physicalPath, currentPath) || !IsPathWithin(physicalPath, runRootPhysicalPath))
                {
                    return false;
                }
            }

            return true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or
                                           ArgumentException or NotSupportedException or System.Security.SecurityException)
        {
            return false;
        }
    }

    private static bool IsSafeRelativeArtifactPath(string relativePath)
    {
        if (string.IsNullOrWhiteSpace(relativePath) || relativePath.Length > MaximumArtifactPathLength ||
            relativePath.StartsWith("/", StringComparison.Ordinal) || relativePath.StartsWith('\\') ||
            Path.IsPathRooted(relativePath) || relativePath.Contains('\\') || relativePath.Contains(':') ||
            relativePath.Contains('\0') || relativePath.Any(char.IsControl))
        {
            return false;
        }

        var segments = relativePath.Split('/');
        return segments.All(segment => segment.Length > 0 && segment is not ("." or "..") &&
            !segment.EndsWith(' ') && !segment.EndsWith('.') &&
            segment.IndexOfAny(Path.GetInvalidFileNameChars()) < 0 &&
            segment.IndexOfAny(new[] { '<', '>', '"', '|', '?', '*' }) < 0 &&
            !IsReservedWindowsDeviceName(segment));
    }

    private static bool IsReservedWindowsDeviceName(string segment)
    {
        var baseName = segment.Split('.')[0].TrimEnd(' ').ToUpperInvariant();
        return baseName is "CON" or "PRN" or "AUX" or "NUL" or "CONIN$" or "CONOUT$" ||
               (baseName.Length == 4 &&
                (baseName.StartsWith("COM", StringComparison.Ordinal) || baseName.StartsWith("LPT", StringComparison.Ordinal)) &&
                baseName[3] is >= '1' and <= '9');
    }

    private static bool TryReadStatus(JsonElement element, string propertyName, out string? status)
    {
        status = null;
        return TryReadString(element, propertyName, out status) && AllowedStatuses.Contains(status!);
    }

    private static bool TryReadCurrentStage(JsonElement root, out int? currentStage)
    {
        currentStage = null;
        if (!TryGetUniqueProperty(root, "currentStage", out var value))
        {
            return false;
        }

        if (value.ValueKind == JsonValueKind.Null)
        {
            return true;
        }

        if (value.ValueKind != JsonValueKind.Number || !value.TryGetInt32(out var stage) || stage < 0 || stage > 9)
        {
            return false;
        }

        currentStage = stage;
        return true;
    }

    private static bool TryReadString(JsonElement element, string propertyName, out string? result) =>
        TryReadBoundedString(element, propertyName, MaximumMessageLength, out result) &&
        !string.IsNullOrWhiteSpace(result);

    private static bool TryReadBoundedString(JsonElement element, string propertyName, int maxLength, out string? result)
    {
        result = null;
        if (!TryGetUniqueProperty(element, propertyName, out var value) || value.ValueKind != JsonValueKind.String ||
            value.GetString() is not { } text || text.Length > maxLength)
        {
            return false;
        }

        result = text;
        return true;
    }

    private static bool TryReadUtc(JsonElement element, string propertyName, bool required, out DateTimeOffset? result)
    {
        result = null;
        if (!TryGetUniqueProperty(element, propertyName, out var value))
        {
            return false;
        }

        if (value.ValueKind == JsonValueKind.Null)
        {
            return !required;
        }

        if (value.ValueKind != JsonValueKind.String)
        {
            return false;
        }

        var timestamp = value.GetString();
        if (timestamp is null ||
            !(timestamp.EndsWith("Z", StringComparison.OrdinalIgnoreCase) ||
              timestamp.EndsWith("+00:00", StringComparison.Ordinal)) ||
            !DateTimeOffset.TryParse(timestamp, CultureInfo.InvariantCulture,
                DateTimeStyles.RoundtripKind, out var parsed) || parsed.Offset != TimeSpan.Zero)
        {
            return false;
        }

        result = parsed;
        return true;
    }

    private static bool TryResolveStatePath(
        string trustedRunsRoot,
        string runRoot,
        string expectedRunId,
        string expectedComputerName,
        List<string> issues,
        out StatePaths? paths)
    {
        paths = null;
        if (string.IsNullOrWhiteSpace(trustedRunsRoot) || string.IsNullOrWhiteSpace(runRoot) ||
            string.IsNullOrWhiteSpace(expectedRunId) || string.IsNullOrWhiteSpace(expectedComputerName))
        {
            AddIssue(issues, "The trusted run identity is incomplete.");
            return false;
        }

        SafeFileHandle? trustedRootHandle = null;
        SafeFileHandle? runRootHandle = null;
        try
        {
            if (!OperatingSystem.IsWindows() && !OperatingSystem.IsLinux())
            {
                AddIssue(issues, "Physical GUI state path verification is unsupported on this platform.");
                return false;
            }

            var trustedRootPath = Path.GetFullPath(trustedRunsRoot);
            var runRootPath = Path.GetFullPath(runRoot);
            if (IsUncOrDevicePath(trustedRunsRoot) || IsUncOrDevicePath(runRoot) ||
                !Directory.Exists(trustedRootPath) || !Directory.Exists(runRootPath))
            {
                AddIssue(issues, "The trusted runs root or current run root is missing or is not a local directory.");
                return false;
            }

            if (HasReparsePointInPath(trustedRootPath) || HasReparsePointInPath(runRootPath))
            {
                AddIssue(issues, "The trusted runs root, current run root, or an ancestor is a reparse point.");
                return false;
            }

            if (!IsPathWithin(runRootPath, trustedRootPath) ||
                !string.Equals(Path.GetFileName(Path.TrimEndingDirectorySeparator(runRootPath)), expectedRunId,
                    OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
            {
                AddIssue(issues, "The current run root is outside the trusted root or its leaf does not match runId.");
                return false;
            }

            trustedRootHandle = OpenDirectoryHandle(trustedRootPath);
            runRootHandle = OpenDirectoryHandle(runRootPath);
            var trustedRootPhysicalPath = GetFinalPath(trustedRootHandle);
            var runRootPhysicalPath = GetFinalPath(runRootHandle);
            if (!PathsMatch(trustedRootPhysicalPath, NormalizePhysicalPath(trustedRootPath)) ||
                !PathsMatch(runRootPhysicalPath, NormalizePhysicalPath(runRootPath)) ||
                !IsPathWithin(runRootPhysicalPath, trustedRootPhysicalPath))
            {
                AddIssue(issues, "The current run root resolves outside the trusted physical runs-root boundary.");
                return false;
            }

            var statePath = Path.GetFullPath(Path.Combine(runRootPath, "gui-state.json"));
            var expectedStatePhysicalPath = Path.GetFullPath(Path.Combine(runRootPhysicalPath, "gui-state.json"));
            if (!IsPathWithin(statePath, runRootPath) || !File.Exists(statePath) || IsReparsePoint(statePath))
            {
                AddIssue(issues, "The GUI state file is missing or is a reparse point.");
                return false;
            }

            paths = new StatePaths(trustedRootPhysicalPath, runRootPhysicalPath, expectedStatePhysicalPath,
                statePath, trustedRootHandle, runRootHandle);
            trustedRootHandle = null;
            runRootHandle = null;
            return true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or
                                           ArgumentException or NotSupportedException or System.Security.SecurityException)
        {
            AddIssue(issues, "The GUI state path could not be resolved safely.");
            return false;
        }
        finally
        {
            trustedRootHandle?.Dispose();
            runRootHandle?.Dispose();
        }
    }

    private static bool IsUncOrDevicePath(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            return path.StartsWith("\\\\", StringComparison.Ordinal) ||
                   path.StartsWith("//", StringComparison.Ordinal) ||
                   path.StartsWith("\\\\?\\", StringComparison.Ordinal) ||
                   path.StartsWith("\\\\.\\", StringComparison.Ordinal);
        }

        return path.StartsWith("//", StringComparison.Ordinal);
    }

    private static bool HasOnlyProperties(JsonElement element, params string[] allowed)
    {
        var names = new HashSet<string>(allowed, StringComparer.Ordinal);
        return element.EnumerateObject().All(property => names.Contains(property.Name));
    }

    private static bool TryGetUniqueProperty(JsonElement element, string name, out JsonElement value)
    {
        value = default;
        if (element.ValueKind != JsonValueKind.Object)
        {
            return false;
        }

        var found = false;
        foreach (var property in element.EnumerateObject())
        {
            if (!string.Equals(property.Name, name, StringComparison.Ordinal))
            {
                continue;
            }

            if (found)
            {
                return false;
            }

            value = property.Value;
            found = true;
        }

        return found;
    }

    private static bool ContainsDuplicateProperties(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name) || ContainsDuplicateProperties(property.Value))
                {
                    return true;
                }
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray())
            {
                if (ContainsDuplicateProperties(item))
                {
                    return true;
                }
            }
        }

        return false;
    }

    private static bool IsReparsePoint(string path) =>
        (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0;

    private static bool HasReparsePointInPath(string fullPath)
    {
        var pathRoot = Path.GetPathRoot(fullPath);
        if (string.IsNullOrEmpty(pathRoot) || IsReparsePoint(pathRoot))
        {
            return true;
        }

        var currentPath = pathRoot;
        foreach (var component in fullPath[pathRoot.Length..].Split(
                     new[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar },
                     StringSplitOptions.RemoveEmptyEntries))
        {
            currentPath = Path.Combine(currentPath, component);
            if (IsReparsePoint(currentPath))
            {
                return true;
            }
        }

        return false;
    }

    private static SafeFileHandle OpenDirectoryHandle(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            var handle = CreateFileW(path, FileReadAttributes,
                FileShare.Read | FileShare.Write | FileShare.Delete, IntPtr.Zero, OpenExisting,
                FileFlagBackupSemantics, IntPtr.Zero);
            if (handle.IsInvalid)
            {
                handle.Dispose();
                throw new IOException("A GUI state directory could not be opened safely.");
            }

            return handle;
        }

        return OpenLinuxHandle(path, LinuxOpenReadOnly | LinuxOpenDirectory | LinuxOpenCloseOnExec | LinuxOpenNoFollow);
    }

    private static SafeFileHandle OpenStateHandle(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            return File.OpenHandle(path, FileMode.Open, FileAccess.Read,
                FileShare.Read | FileShare.Delete, FileOptions.SequentialScan);
        }

        return OpenLinuxHandle(path, LinuxOpenReadOnly | LinuxOpenNonBlocking | LinuxOpenCloseOnExec | LinuxOpenNoFollow);
    }

    private static SafeFileHandle OpenArtifactHandle(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            return File.OpenHandle(path, FileMode.Open, FileAccess.Read,
                FileShare.Read | FileShare.Write | FileShare.Delete, FileOptions.SequentialScan);
        }

        return OpenLinuxHandle(path, LinuxOpenReadOnly | LinuxOpenNonBlocking | LinuxOpenCloseOnExec | LinuxOpenNoFollow);
    }

    private static SafeFileHandle OpenLinuxHandle(string path, int flags)
    {
        var descriptor = OpenLinux(path, flags);
        if (descriptor < 0)
        {
            throw new IOException($"A GUI state path could not be opened safely (errno {Marshal.GetLastPInvokeError()}).");
        }

        return new SafeFileHandle(new IntPtr(descriptor), ownsHandle: true);
    }

    private static string GetFinalPath(SafeFileHandle handle)
    {
        if (OperatingSystem.IsWindows())
        {
            var capacity = 512;
            while (capacity <= 32768)
            {
                var buffer = new StringBuilder(capacity);
                var length = GetFinalPathNameByHandleW(handle, buffer, (uint)capacity, 0);
                if (length == 0)
                {
                    throw new IOException("A physical path could not be obtained from an opened GUI state handle.");
                }

                if (length < capacity)
                {
                    return NormalizePhysicalPath(buffer.ToString());
                }

                capacity = checked((int)length + 1);
            }

            throw new IOException("The opened GUI state path exceeds the supported physical-path length.");
        }

        var procPath = $"/proc/self/fd/{handle.DangerousGetHandle().ToInt32()}";
        var size = 512;
        while (size <= 32768)
        {
            var buffer = new byte[size];
            var length = ReadLinkLinux(procPath, buffer, (nuint)buffer.Length).ToInt64();
            if (length < 0)
            {
                throw new IOException($"A physical GUI state path could not be obtained (errno {Marshal.GetLastPInvokeError()}).");
            }

            if (length < buffer.Length)
            {
                return NormalizePhysicalPath(Encoding.UTF8.GetString(buffer, 0, checked((int)length)));
            }

            size *= 2;
        }

        throw new IOException("The opened GUI state path exceeds the supported physical-path length.");
    }

    private static string NormalizePhysicalPath(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            if (path.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
            {
                path = @"\\" + path[8..];
            }
            else if (path.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase))
            {
                path = path[4..];
            }
        }

        return Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
    }

    private static bool PathsMatch(string first, string second) =>
        string.Equals(NormalizePhysicalPath(first), NormalizePhysicalPath(second),
            OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);

    private static bool IsPathWithin(string candidatePath, string boundaryPath)
    {
        var candidate = NormalizePhysicalPath(candidatePath);
        var boundary = NormalizePhysicalPath(boundaryPath);
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        var prefix = Path.EndsInDirectorySeparator(boundary) ? boundary : boundary + Path.DirectorySeparatorChar;
        return candidate.StartsWith(prefix, comparison);
    }

    private static RunStateReadResult InvalidResult(List<string> issues) =>
        new(new RunStateReport(string.Empty, string.Empty, "Incomplete", null,
                Array.Empty<RunStageState>(), Array.Empty<string>(), Array.Empty<string>(),
                new Dictionary<string, string>(), DateTimeOffset.UnixEpoch), issues.ToArray(), isValid: false);

    private static void AddIssue(List<string> issues, string issue)
    {
        if (!issues.Contains(issue, StringComparer.Ordinal))
        {
            issues.Add(issue);
        }
    }

    private sealed record StatePaths(
        string TrustedRootPhysicalPath,
        string RunRootPhysicalPath,
        string ExpectedStatePhysicalPath,
        string StatePath,
        SafeFileHandle TrustedRootHandle,
        SafeFileHandle RunRootHandle) : IDisposable
    {
        public void Dispose()
        {
            RunRootHandle.Dispose();
            TrustedRootHandle.Dispose();
        }
    }

    private const uint FileReadAttributes = 0x80;
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string fileName, uint desiredAccess, FileShare shareMode,
        IntPtr securityAttributes, uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(SafeFileHandle file, StringBuilder filePath,
        uint filePathLength, uint flags);

    [DllImport("libc", EntryPoint = "open", SetLastError = true)]
    private static extern int OpenLinux([MarshalAs(UnmanagedType.LPUTF8Str)] string path, int flags);

    [DllImport("libc", EntryPoint = "readlink", SetLastError = true)]
    private static extern nint ReadLinkLinux([MarshalAs(UnmanagedType.LPUTF8Str)] string path,
        [Out] byte[] buffer, nuint bufferSize);
}

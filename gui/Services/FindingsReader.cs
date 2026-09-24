using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace ScreenConnectCleanup.Gui.Services;

/// <summary>
/// A read-only view of one detector instance. Data retains the complete source
/// object so fields not yet represented by the GUI are not discarded.
/// </summary>
public sealed class ScreenConnectFinding
{
    internal ScreenConnectFinding(JsonElement data) => Data = data;

    public JsonElement Data { get; }

    public string DisplayValue(string propertyName)
    {
        if (Data.ValueKind == JsonValueKind.Object && Data.TryGetProperty(propertyName, out var value))
        {
            return DisplayScalar(value);
        }

        return FindingsReader.NotAvailable;
    }

    internal static string DisplayScalar(JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.String when !string.IsNullOrWhiteSpace(value.GetString()) => value.GetString()!,
        JsonValueKind.Number or JsonValueKind.True or JsonValueKind.False => value.ToString(),
        _ => FindingsReader.NotAvailable
    };
}

/// <summary>
/// A detect-only result for a non-ScreenConnect remote-access target.
/// </summary>
public sealed class OtherTargetFinding
{
    internal OtherTargetFinding(JsonElement data, string productName, IReadOnlyList<JsonElement> hits)
    {
        Data = data;
        ProductName = productName;
        Hits = hits;
    }

    public JsonElement Data { get; }
    public string ProductName { get; }
    public IReadOnlyList<JsonElement> Hits { get; }
}

/// <summary>
/// Detector findings and validation status. Findings are retained when the
/// result is incomplete; only a valid complete document can report IsClean.
/// </summary>
public sealed class FindingsReadResult
{
    internal FindingsReadResult(
        string? runId,
        string? computerName,
        IReadOnlyList<ScreenConnectFinding> instances,
        IReadOnlyList<OtherTargetFinding> otherTargets,
        IReadOnlyList<string> issues)
    {
        RunId = runId;
        ComputerName = computerName;
        Instances = instances;
        OtherTargets = otherTargets;
        Issues = issues;
    }

    public string? RunId { get; }
    public string? ComputerName { get; }
    public IReadOnlyList<ScreenConnectFinding> Instances { get; }
    public IReadOnlyList<OtherTargetFinding> OtherTargets { get; }
    public IReadOnlyList<string> Issues { get; }
    public bool IsComplete => Issues.Count == 0;
    public bool HasFindings => Instances.Count > 0 || OtherTargets.Any(target => target.Hits.Count > 0);
    public bool IsClean => IsComplete && !HasFindings;
}

/// <summary>
/// Reads the current detector artifact without modifying it. Callers must
/// supply the trusted runs root, selected outer run root, and relative findings pointer.
/// </summary>
public static class FindingsReader
{
    public const string NotAvailable = "Not available";
    private const int MaximumArtifactBytes = 16 * 1024 * 1024;
    private const int LinuxOpenReadOnly = 0;
    private const int LinuxOpenNonBlocking = 0x800;
    private const int LinuxOpenNoFollow = 0x20000;
    private const int LinuxOpenDirectory = 0x10000;
    private const int LinuxOpenCloseOnExec = 0x80000;

    /// <summary>
    /// Reads &lt;runRoot&gt;/detect/&lt;nestedRunId&gt;/findings.json beneath the
    /// trusted runs root. The outer directory leaf must match expectedOuterRunId,
    /// and the nested directory leaf must match findings.json.RunId.
    /// </summary>
    public static FindingsReadResult Read(
        string trustedRunsRoot,
        string runRoot,
        string expectedOuterRunId,
        string expectedComputerName,
        string findingsRelativePath)
    {
        var issues = new List<string>();
        if (!TryResolveArtifactPath(
                trustedRunsRoot,
                runRoot,
                expectedOuterRunId,
                expectedComputerName,
                findingsRelativePath,
                issues,
                out var paths))
        {
            return EmptyResult(issues);
        }

        using var resolvedPaths = paths!;

        try
        {
            CheckForAmbiguousArtifacts(resolvedPaths, findingsRelativePath, issues);

            using var artifactHandle = OpenArtifactHandle(resolvedPaths.ArtifactPath);
            if (!PathsMatch(GetFinalPath(artifactHandle), resolvedPaths.ExpectedArtifactPhysicalPath))
            {
                AddIssue(issues, "The opened findings artifact is outside the current run's physical path boundary.");
                return EmptyResult(issues);
            }

            using var stream = new FileStream(artifactHandle, FileAccess.Read);
            if (stream.Length <= 0 || stream.Length > MaximumArtifactBytes)
            {
                AddIssue(issues, "The findings artifact is empty or exceeds the size limit.");
                return EmptyResult(issues);
            }

            var bytes = new byte[checked((int)stream.Length)];
            stream.ReadExactly(bytes);
            if (!PathsMatch(GetFinalPath(resolvedPaths.TrustedRunsRootHandle), resolvedPaths.TrustedRunsRootPhysicalPath) ||
                !PathsMatch(GetFinalPath(resolvedPaths.RootHandle), resolvedPaths.RootPhysicalPath) ||
                !PathsMatch(GetFinalPath(artifactHandle), resolvedPaths.ExpectedArtifactPhysicalPath))
            {
                AddIssue(issues, "The findings artifact or run root changed physical paths while being read.");
            }

            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 64 });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                AddIssue(issues, "The findings document root must be an object.");
                return EmptyResult(issues);
            }

            if (ContainsDuplicateProperties(root))
            {
                AddIssue(issues, "The findings artifact contains duplicate JSON properties.");
            }

            var runId = ReadRequiredString(root, "RunId", "The findings RunId is missing or malformed.", issues);
            var computerName = ReadRequiredString(root, "ComputerName", "The findings computer name is missing or malformed.", issues);
            if (runId is not null && !string.Equals(runId, resolvedPaths.NestedRunId, StringComparison.OrdinalIgnoreCase))
            {
                AddIssue(issues, "The findings RunId does not match its nested detector directory.");
            }

            if (computerName is not null &&
                !string.Equals(computerName, expectedComputerName, StringComparison.OrdinalIgnoreCase))
            {
                AddIssue(issues, "The findings computer name does not match the current run.");
            }

            var instances = ReadInstances(root, issues);
            var otherTargets = ReadOtherTargets(root, issues);
            ValidateCollectionStatus(root, issues);

            return new FindingsReadResult(runId, computerName, instances, otherTargets, issues.ToArray());
        }
        catch (JsonException)
        {
            AddIssue(issues, "The findings artifact contains malformed JSON.");
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException or System.Security.SecurityException)
        {
            AddIssue(issues, "The findings artifact could not be read safely.");
        }

        return EmptyResult(issues);
    }

    private static bool TryResolveArtifactPath(
        string trustedRunsRoot,
        string runRoot,
        string expectedOuterRunId,
        string expectedComputerName,
        string findingsRelativePath,
        List<string> issues,
        out ArtifactPaths? paths)
    {
        paths = null;
        SafeFileHandle? trustedRunsRootHandle = null;
        SafeFileHandle? rootHandle = null;
        if (string.IsNullOrWhiteSpace(trustedRunsRoot) ||
            string.IsNullOrWhiteSpace(runRoot) ||
            string.IsNullOrWhiteSpace(expectedOuterRunId) ||
            string.IsNullOrWhiteSpace(expectedComputerName))
        {
            AddIssue(issues, "The current run identity is incomplete.");
            return false;
        }

        if (string.IsNullOrWhiteSpace(findingsRelativePath) || Path.IsPathRooted(findingsRelativePath))
        {
            AddIssue(issues, "The findings artifact path must be relative to the current run root.");
            return false;
        }

        var segments = findingsRelativePath.Replace('\\', '/').Split('/');
        if (segments.Length != 3 ||
            !string.Equals(segments[0], "detect", StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(segments[2], "findings.json", StringComparison.OrdinalIgnoreCase) ||
            !IsSafePathSegment(segments[1]))
        {
            AddIssue(issues, "The findings artifact path is malformed or escapes the detector directory.");
            return false;
        }

        try
        {
            if (!OperatingSystem.IsWindows() && !OperatingSystem.IsLinux())
            {
                AddIssue(issues, "Physical findings-path verification is unsupported on this platform.");
                return false;
            }

            var trustedRunsRootPath = Path.GetFullPath(trustedRunsRoot);
            if (!Directory.Exists(trustedRunsRootPath))
            {
                AddIssue(issues, "The trusted runs root is missing.");
                return false;
            }

            if (HasReparsePointInPath(trustedRunsRootPath))
            {
                AddIssue(issues, "The trusted runs root or one of its ancestors is a reparse point.");
                return false;
            }

            var rootPath = Path.GetFullPath(runRoot);
            if (!Directory.Exists(rootPath))
            {
                AddIssue(issues, "The current run root is missing.");
                return false;
            }

            if (!IsPathWithin(rootPath, trustedRunsRootPath))
            {
                AddIssue(issues, "The current run root is outside the trusted runs root.");
                return false;
            }

            if (HasReparsePointInPath(rootPath))
            {
                AddIssue(issues, "The current run root or one of its ancestors is a reparse point.");
                return false;
            }

            trustedRunsRootHandle = OpenDirectoryHandle(trustedRunsRootPath);
            var trustedRunsRootPhysicalPath = GetFinalPath(trustedRunsRootHandle);
            if (!PathsMatch(trustedRunsRootPhysicalPath, NormalizePhysicalPath(trustedRunsRootPath)))
            {
                AddIssue(issues, "The trusted runs root resolves through a reparse point or changed physical paths.");
                return false;
            }

            if (!string.Equals(Path.GetFileName(Path.TrimEndingDirectorySeparator(rootPath)), expectedOuterRunId, StringComparison.OrdinalIgnoreCase))
            {
                AddIssue(issues, "The outer run directory does not match the current run identity.");
                return false;
            }

            rootHandle = OpenDirectoryHandle(rootPath);
            var rootPhysicalPath = GetFinalPath(rootHandle);
            if (!PathsMatch(rootPhysicalPath, NormalizePhysicalPath(rootPath)) ||
                !IsPathWithin(rootPhysicalPath, trustedRunsRootPhysicalPath))
            {
                AddIssue(issues, "The current run root resolves outside the trusted physical runs-root boundary.");
                return false;
            }

            var detectPath = Path.GetFullPath(Path.Combine(rootPath, "detect"));
            var nestedPath = Path.GetFullPath(Path.Combine(detectPath, segments[1]));
            var artifactPath = Path.GetFullPath(Path.Combine(nestedPath, "findings.json"));
            var expectedArtifactPhysicalPath = Path.GetFullPath(Path.Combine(rootPhysicalPath, "detect", segments[1], "findings.json"));
            var rootPrefix = Path.TrimEndingDirectorySeparator(rootPath) + Path.DirectorySeparatorChar;
            var pathComparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
            if (!artifactPath.StartsWith(rootPrefix, pathComparison))
            {
                AddIssue(issues, "The findings artifact resolves outside the current run root.");
                return false;
            }

            if (!Directory.Exists(detectPath) || IsReparsePoint(detectPath) ||
                !Directory.Exists(nestedPath) || IsReparsePoint(nestedPath) ||
                !File.Exists(artifactPath) || IsReparsePoint(artifactPath))
            {
                AddIssue(issues, "The findings artifact or one of its directories is missing or is a reparse point.");
                return false;
            }

            paths = new ArtifactPaths(
                rootPath,
                trustedRunsRootPhysicalPath,
                rootPhysicalPath,
                expectedArtifactPhysicalPath,
                detectPath,
                nestedPath,
                artifactPath,
                segments[1],
                trustedRunsRootHandle,
                rootHandle);
            trustedRunsRootHandle = null;
            rootHandle = null;
            return true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException or System.Security.SecurityException)
        {
            AddIssue(issues, "The findings artifact path could not be resolved safely.");
            return false;
        }
        finally
        {
            trustedRunsRootHandle?.Dispose();
            rootHandle?.Dispose();
        }
    }

    private static void CheckForAmbiguousArtifacts(ArtifactPaths paths, string requestedRelativePath, List<string> issues)
    {
        try
        {
            var findingsFiles = new List<string>();
            foreach (var directory in Directory.EnumerateDirectories(paths.DetectPath))
            {
                if (IsReparsePoint(directory))
                {
                    AddIssue(issues, "The detector directory contains a reparse point.");
                    continue;
                }

                var candidate = Path.Combine(directory, "findings.json");
                if (File.Exists(candidate))
                {
                    findingsFiles.Add(Path.GetFullPath(candidate));
                }
            }

            var requestedPath = Path.GetFullPath(paths.ArtifactPath);
            var pathComparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
            if (findingsFiles.Count != 1 || !findingsFiles.Any(path => string.Equals(path, requestedPath, pathComparison)))
            {
                AddIssue(issues, "The current detector findings artifact is missing or ambiguous.");
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            AddIssue(issues, "The detector directory could not be checked for ambiguous artifacts.");
        }
    }

    private static IReadOnlyList<ScreenConnectFinding> ReadInstances(JsonElement root, List<string> issues)
    {
        var results = new List<ScreenConnectFinding>();
        if (!TryGetUniqueProperty(root, "ScreenConnect", out var screenConnect) || screenConnect.ValueKind != JsonValueKind.Object)
        {
            AddIssue(issues, "ScreenConnect findings are missing or malformed.");
            return results;
        }

        if (!TryGetUniqueProperty(screenConnect, "Instances", out var instances))
        {
            AddIssue(issues, "ScreenConnect.Instances is missing.");
            return results;
        }

        if (instances.ValueKind == JsonValueKind.Array)
        {
            foreach (var instance in instances.EnumerateArray())
            {
                if (instance.ValueKind != JsonValueKind.Object)
                {
                    AddIssue(issues, "ScreenConnect.Instances contains a malformed item.");
                    continue;
                }

                results.Add(new ScreenConnectFinding(instance.Clone()));
            }

            return results;
        }

        // Preserve an object-shaped positive finding for display, but never
        // treat a scalar or object in place of the required array as complete.
        if (instances.ValueKind == JsonValueKind.Object && instances.EnumerateObject().Any())
        {
            results.Add(new ScreenConnectFinding(instances.Clone()));
        }

        AddIssue(issues, "ScreenConnect.Instances must be a JSON array.");
        return results;
    }

    private static IReadOnlyList<OtherTargetFinding> ReadOtherTargets(JsonElement root, List<string> issues)
    {
        var results = new List<OtherTargetFinding>();
        if (!TryGetUniqueProperty(root, "OtherTargets", out var targets))
        {
            AddIssue(issues, "OtherTargets is missing.");
            return results;
        }

        if (targets.ValueKind == JsonValueKind.Array)
        {
            foreach (var target in targets.EnumerateArray())
            {
                ReadOtherTarget(target, results, issues);
            }

            return results;
        }

        // Windows PowerShell 5.1 can serialize an empty nested array as {}.
        // Accept only that unambiguous empty shape; a nonempty object is kept
        // visible as a singleton but remains an incomplete artifact.
        if (IsEmptyObject(targets))
        {
            return results;
        }

        if (targets.ValueKind == JsonValueKind.Object)
        {
            ReadOtherTarget(targets, results, issues);
        }

        AddIssue(issues, "OtherTargets must be a JSON array.");
        return results;
    }

    private static void ReadOtherTarget(JsonElement target, List<OtherTargetFinding> results, List<string> issues)
    {
        if (target.ValueKind != JsonValueKind.Object)
        {
            AddIssue(issues, "OtherTargets contains a malformed item.");
            return;
        }

        var productName = "Not available";
        if (TryGetUniqueProperty(target, "Name", out var name) || TryGetUniqueProperty(target, "ProductName", out name))
        {
            productName = ScreenConnectFinding.DisplayScalar(name);
        }

        if (!TryGetUniqueProperty(target, "Hits", out var hits))
        {
            AddIssue(issues, "An OtherTargets entry has no Hits collection.");
            return;
        }

        IReadOnlyList<JsonElement> hitList;
        if (hits.ValueKind == JsonValueKind.Array)
        {
            hitList = hits.EnumerateArray().Select(hit => hit.Clone()).ToArray();
        }
        else if (IsEmptyObject(hits))
        {
            hitList = Array.Empty<JsonElement>();
        }
        else if (hits.ValueKind == JsonValueKind.Object)
        {
            hitList = new[] { hits.Clone() };
            AddIssue(issues, "An OtherTargets Hits collection is not an array.");
        }
        else
        {
            hitList = Array.Empty<JsonElement>();
            AddIssue(issues, "An OtherTargets Hits collection is malformed.");
        }

        results.Add(new OtherTargetFinding(target.Clone(), productName, hitList));
    }

    private static void ValidateCollectionStatus(JsonElement root, List<string> issues)
    {
        if (!TryGetUniqueProperty(root, "CollectionComplete", out var complete) ||
            complete.ValueKind != JsonValueKind.True)
        {
            AddIssue(issues, "CollectionComplete is missing or is not true.");
        }

        if (!TryGetUniqueProperty(root, "CollectionErrors", out var collectionErrors))
        {
            AddIssue(issues, "CollectionErrors is missing.");
        }
        else if (collectionErrors.ValueKind == JsonValueKind.Array)
        {
            if (collectionErrors.GetArrayLength() > 0)
            {
                AddIssue(issues, "The detector reported collection errors.");
            }

            foreach (var item in collectionErrors.EnumerateArray())
            {
                if (item.ValueKind != JsonValueKind.Object ||
                    !HasNonEmptyString(item, "Source") ||
                    !HasNonEmptyString(item, "Error"))
                {
                    AddIssue(issues, "CollectionErrors contains a malformed item.");
                    break;
                }
            }
        }
        else
        {
            AddIssue(issues, "CollectionErrors is malformed or nonempty.");
        }

        if (!TryGetUniqueProperty(root, "ScreenConnect", out var screenConnect) ||
            screenConnect.ValueKind != JsonValueKind.Object ||
            !TryGetUniqueProperty(screenConnect, "ParseIssues", out var parseIssues))
        {
            AddIssue(issues, "ScreenConnect.ParseIssues is missing or malformed.");
        }
        else if (parseIssues.ValueKind == JsonValueKind.Array)
        {
            if (parseIssues.GetArrayLength() > 0)
            {
                AddIssue(issues, "ScreenConnect contains parse issues.");
            }
        }
        else
        {
            AddIssue(issues, "ScreenConnect.ParseIssues is malformed or nonempty.");
        }

        if (!TryGetUniqueProperty(root, "EventLogError", out var eventLogError))
        {
            AddIssue(issues, "EventLogError is missing.");
        }
        else if (eventLogError.ValueKind == JsonValueKind.String)
        {
            if (!string.IsNullOrWhiteSpace(eventLogError.GetString()))
            {
                AddIssue(issues, "The detector could not read the System event log.");
            }
        }
        else if (eventLogError.ValueKind == JsonValueKind.True)
        {
            AddIssue(issues, "The detector could not read the System event log.");
        }
        else if (eventLogError.ValueKind is not (JsonValueKind.Null or JsonValueKind.False))
        {
            AddIssue(issues, "EventLogError is malformed.");
        }
    }

    private static bool TryGetUniqueProperty(JsonElement element, string propertyName, out JsonElement value)
    {
        value = default;
        if (element.ValueKind != JsonValueKind.Object)
        {
            return false;
        }

        var found = false;
        foreach (var property in element.EnumerateObject())
        {
            if (!string.Equals(property.Name, propertyName, StringComparison.Ordinal))
            {
                continue;
            }

            value = property.Value;
            found = true;
        }

        return found;
    }

    private static string? ReadRequiredString(JsonElement element, string propertyName, string issue, List<string> issues)
    {
        if (TryGetUniqueProperty(element, propertyName, out var value) &&
            value.ValueKind == JsonValueKind.String &&
            !string.IsNullOrWhiteSpace(value.GetString()))
        {
            return value.GetString();
        }

        AddIssue(issues, issue);
        return null;
    }

    private static bool HasNonEmptyString(JsonElement element, string propertyName) =>
        TryGetUniqueProperty(element, propertyName, out var value) &&
        value.ValueKind == JsonValueKind.String &&
        !string.IsNullOrWhiteSpace(value.GetString());

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

    private static bool IsEmptyObject(JsonElement element) =>
        element.ValueKind == JsonValueKind.Object && !element.EnumerateObject().Any();

    private static bool IsSafePathSegment(string segment)
    {
        if (string.IsNullOrWhiteSpace(segment) || segment is "." or ".." ||
            segment.IndexOfAny(new[] { '/', '\\', ':', '\0' }) >= 0 ||
            segment.EndsWith(' ') || segment.EndsWith('.'))
        {
            return false;
        }

        return !segment.Any(char.IsControl) &&
               segment.IndexOfAny(Path.GetInvalidFileNameChars()) < 0;
    }

    private static bool IsReparsePoint(string path)
    {
        var attributes = File.GetAttributes(path);
        return (attributes & FileAttributes.ReparsePoint) != 0;
    }

    private static bool HasReparsePointInPath(string fullPath)
    {
        var pathRoot = Path.GetPathRoot(fullPath);
        if (string.IsNullOrEmpty(pathRoot))
        {
            throw new IOException("The run root has no filesystem root.");
        }

        var currentPath = pathRoot;
        if (IsReparsePoint(currentPath))
        {
            return true;
        }

        var components = fullPath[pathRoot.Length..].Split(
            new[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar },
            StringSplitOptions.RemoveEmptyEntries);
        foreach (var component in components)
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
            var handle = CreateFileW(
                path,
                FileReadAttributes,
                FileShare.Read | FileShare.Write | FileShare.Delete,
                IntPtr.Zero,
                OpenExisting,
                FileFlagBackupSemantics,
                IntPtr.Zero);
            if (handle.IsInvalid)
            {
                handle.Dispose();
                throw new IOException("The current run root could not be opened safely.");
            }

            return handle;
        }

        return OpenLinuxHandle(path, LinuxOpenReadOnly | LinuxOpenDirectory | LinuxOpenCloseOnExec | LinuxOpenNoFollow);
    }

    private static SafeFileHandle OpenArtifactHandle(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            return File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.Read, FileOptions.SequentialScan);
        }

        return OpenLinuxHandle(path, LinuxOpenReadOnly | LinuxOpenNonBlocking | LinuxOpenCloseOnExec | LinuxOpenNoFollow);
    }

    private static SafeFileHandle OpenLinuxHandle(string path, int flags)
    {
        var descriptor = OpenLinux(path, flags);
        if (descriptor < 0)
        {
            throw new IOException($"A findings path could not be opened safely (errno {Marshal.GetLastPInvokeError()}).");
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
                    throw new IOException("A physical path could not be obtained from the opened handle.");
                }

                if (length < capacity)
                {
                    return NormalizePhysicalPath(buffer.ToString());
                }

                capacity = checked((int)length + 1);
            }

            throw new IOException("The opened path exceeds the supported physical-path length.");
        }

        if (OperatingSystem.IsLinux())
        {
            var procPath = $"/proc/self/fd/{handle.DangerousGetHandle().ToInt32()}";
            var capacity = 512;
            while (capacity <= 32768)
            {
                var buffer = new byte[capacity];
                var length = ReadLinkLinux(procPath, buffer, (nuint)buffer.Length).ToInt64();
                if (length < 0)
                {
                    throw new IOException($"A physical path could not be obtained from the opened handle (errno {Marshal.GetLastPInvokeError()}).");
                }

                if (length < buffer.Length)
                {
                    return NormalizePhysicalPath(Encoding.UTF8.GetString(buffer, 0, checked((int)length)));
                }

                capacity *= 2;
            }

            throw new IOException("The opened path exceeds the supported physical-path length.");
        }

        throw new PlatformNotSupportedException("Physical path verification is supported only on Windows and Linux.");
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

    private static bool PathsMatch(string first, string second)
    {
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        return string.Equals(NormalizePhysicalPath(first), NormalizePhysicalPath(second), comparison);
    }

    private static bool IsPathWithin(string candidatePath, string boundaryPath)
    {
        var candidate = NormalizePhysicalPath(candidatePath);
        var boundary = NormalizePhysicalPath(boundaryPath);
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        var boundaryPrefix = Path.EndsInDirectorySeparator(boundary) ? boundary : boundary + Path.DirectorySeparatorChar;
        return candidate.StartsWith(boundaryPrefix, comparison);
    }

    private const uint FileReadAttributes = 0x80;
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(
        string fileName,
        uint desiredAccess,
        FileShare shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(
        SafeFileHandle file,
        StringBuilder filePath,
        uint filePathLength,
        uint flags);

    [DllImport("libc", EntryPoint = "open", SetLastError = true)]
    private static extern int OpenLinux(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string path,
        int flags);

    [DllImport("libc", EntryPoint = "readlink", SetLastError = true)]
    private static extern nint ReadLinkLinux(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string path,
        [Out] byte[] buffer,
        nuint bufferSize);

    private static void AddIssue(List<string> issues, string issue)
    {
        if (!issues.Contains(issue, StringComparer.Ordinal))
        {
            issues.Add(issue);
        }
    }

    private static FindingsReadResult EmptyResult(List<string> issues) =>
        new(null, null, Array.Empty<ScreenConnectFinding>(), Array.Empty<OtherTargetFinding>(), issues.ToArray());

    private sealed record ArtifactPaths(
        string RootPath,
        string TrustedRunsRootPhysicalPath,
        string RootPhysicalPath,
        string ExpectedArtifactPhysicalPath,
        string DetectPath,
        string NestedPath,
        string ArtifactPath,
        string NestedRunId,
        SafeFileHandle TrustedRunsRootHandle,
        SafeFileHandle RootHandle) : IDisposable
    {
        public void Dispose()
        {
            RootHandle.Dispose();
            TrustedRunsRootHandle.Dispose();
        }
    }
}

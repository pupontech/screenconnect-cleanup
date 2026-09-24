using ScreenConnectCleanup.Gui.Services;
using Xunit;

namespace ScreenConnectCleanup.Gui.Phase2.Tests;

public sealed class FindingsReaderTests
{
    private const string OuterRunId = "HOST-20260923_120000";
    private const string DetectorRunId = "HOST_2026-09-23_120000";
    private const string ComputerName = "HOST";

    [Fact]
    public void ValidCompleteZeroFindingsIsClean()
    {
        using var fixture = new ReaderFixture();
        fixture.WriteFindings();

        var result = fixture.Read();

        Assert.True(result.IsComplete);
        Assert.True(result.IsClean);
        Assert.False(result.HasFindings);
        Assert.Empty(result.Instances);
        Assert.Empty(result.OtherTargets);
    }

    [Fact]
    public void MultipleInstancesArePreservedAsPositiveFindings()
    {
        using var fixture = new ReaderFixture();
        fixture.WriteFindings(instances: """
            [
              { "Identifier": "alpha", "RelayHost": "relay-a.example" },
              { "Identifier": "beta", "SessionType": "Support" }
            ]
            """);

        var result = fixture.Read();

        Assert.True(result.IsComplete);
        Assert.False(result.IsClean);
        Assert.Equal(2, result.Instances.Count);
        Assert.Equal("alpha", result.Instances[0].DisplayValue("Identifier"));
        Assert.Equal("Not available", result.Instances[1].DisplayValue("RelayHost"));
    }

    [Fact]
    public void PartialCollectionKeepsInstancesAndOtherTargetHitsVisible()
    {
        using var fixture = new ReaderFixture();
        fixture.WriteFindings(
            instances: "[{ \"Identifier\": \"seen-instance\" }]",
            collectionComplete: "false",
            collectionErrors: "[{ \"Source\": \"Services\", \"Error\": \"provider unavailable\" }]",
            otherTargets: "[{ \"Name\": \"RemoteTool\", \"Hits\": [{ \"Kind\": \"process\", \"Name\": \"remote.exe\" }] }]");

        var result = fixture.Read();

        Assert.False(result.IsComplete);
        Assert.False(result.IsClean);
        Assert.Single(result.Instances);
        var target = Assert.Single(result.OtherTargets);
        Assert.Equal("RemoteTool", target.ProductName);
        Assert.Single(target.Hits);
        Assert.Contains("seen-instance", result.Instances[0].DisplayValue("Identifier"));
        Assert.Contains(result.Issues, issue => issue.Contains("collection", StringComparison.OrdinalIgnoreCase));
    }

    [Theory]
    [InlineData("[{ \"Key\": \"bad-config\", \"Issue\": \"missing relay\" }]", "null")]
    [InlineData("[]", "\"event provider unavailable\"")]
    public void ParseIssuesOrEventLogErrorPreventsCleanResult(string parseIssues, string eventLogError)
    {
        using var fixture = new ReaderFixture();
        fixture.WriteFindings(
            instances: "[{ \"Identifier\": \"positive\" }]",
            parseIssues: parseIssues,
            eventLogError: eventLogError);

        var result = fixture.Read();

        Assert.False(result.IsComplete);
        Assert.False(result.IsClean);
        Assert.Single(result.Instances);
    }

    [Fact]
    public void LegacyArtifactWithoutCollectionCompleteIsIncompleteButKeepsPositiveEvidence()
    {
        using var fixture = new ReaderFixture();
        fixture.WriteFindings(
            instances: "[{ \"Identifier\": \"legacy-positive\" }]",
            includeCollectionComplete: false);

        var result = fixture.Read();

        Assert.False(result.IsComplete);
        Assert.False(result.IsClean);
        Assert.Single(result.Instances);
        Assert.Equal("legacy-positive", result.Instances[0].DisplayValue("Identifier"));
    }

    [Fact]
    public void MalformedInstancesObjectIsVisibleButNeverAcceptedAsComplete()
    {
        using var fixture = new ReaderFixture();
        fixture.WriteFindings(instances: "{ \"Identifier\": \"singleton\" }");

        var result = fixture.Read();

        Assert.False(result.IsComplete);
        Assert.Single(result.Instances);
        Assert.Equal("singleton", result.Instances[0].DisplayValue("Identifier"));
    }

    [Fact]
    public void EmptyObjectCollectionErrorsCannotReportClean()
    {
        using var fixture = new ReaderFixture();
        fixture.WriteFindings(collectionErrors: "{}");

        var result = fixture.Read();

        Assert.False(result.IsComplete);
        Assert.False(result.IsClean);
        Assert.Contains(result.Issues, issue => issue.Contains("CollectionErrors", StringComparison.Ordinal));
    }

    [Fact]
    public void EmptyObjectParseIssuesCannotReportClean()
    {
        using var fixture = new ReaderFixture();
        fixture.WriteFindings(parseIssues: "{}");

        var result = fixture.Read();

        Assert.False(result.IsComplete);
        Assert.False(result.IsClean);
        Assert.Contains(result.Issues, issue => issue.Contains("ParseIssues", StringComparison.Ordinal));
    }

    [Fact]
    public void MalformedCollectionStatusKeepsPositiveInstancesVisible()
    {
        using var fixture = new ReaderFixture();
        fixture.WriteFindings(
            instances: "[{ \"Identifier\": \"preserved-positive\" }]",
            collectionErrors: "{}");

        var result = fixture.Read();

        Assert.False(result.IsComplete);
        Assert.False(result.IsClean);
        Assert.Equal("preserved-positive", Assert.Single(result.Instances).DisplayValue("Identifier"));
    }

    [Theory]
    [InlineData("OTHER_2026-09-23_120000", "HOST")]
    [InlineData("HOST_2026-09-23_120000", "OTHER")]
    public void NestedRunOrComputerMismatchPreventsCompleteResult(string findingsRunId, string findingsComputer)
    {
        using var fixture = new ReaderFixture();
        fixture.WriteFindings(
            runId: findingsRunId,
            computerName: findingsComputer,
            instances: "[{ \"Identifier\": \"positive\" }]");

        var result = fixture.Read();

        Assert.False(result.IsComplete);
        Assert.False(result.IsClean);
        Assert.Single(result.Instances);
    }

    [Fact]
    public void TraversalPathIsRejectedBeforeReadingOutsideTheCurrentRun()
    {
        using var fixture = new ReaderFixture();
        fixture.WriteFindings(instances: "[{ \"Identifier\": \"must-not-be-read\" }]");

        var result = fixture.Read("detect/../../outside/findings.json");

        Assert.False(result.IsComplete);
        Assert.Empty(result.Instances);
        Assert.Contains(result.Issues, issue => issue.Contains("path", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void MultipleNestedFindingsArtifactsAreAmbiguousButSelectedEvidenceRemainsVisible()
    {
        using var fixture = new ReaderFixture();
        fixture.WriteFindings(instances: "[{ \"Identifier\": \"current\" }]");
        fixture.WriteAdditionalArtifact("HOST_2026-09-22_120000");

        var result = fixture.Read();

        Assert.False(result.IsComplete);
        Assert.Single(result.Instances);
        Assert.Equal("current", result.Instances[0].DisplayValue("Identifier"));
        Assert.Contains(result.Issues, issue => issue.Contains("ambiguous", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void ReparsePointInsideDetectorPathIsRejected()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using var fixture = new ReaderFixture();
        var externalDirectory = Path.Combine(Path.GetTempPath(), $"findings-reader-external-{Guid.NewGuid():N}");
        Directory.CreateDirectory(externalDirectory);
        try
        {
            File.WriteAllText(Path.Combine(externalDirectory, "findings.json"), fixture.CreateDocument());
            Directory.Delete(fixture.NestedDirectory, recursive: true);
            Directory.CreateSymbolicLink(fixture.NestedDirectory, externalDirectory);

            var result = fixture.Read();

            Assert.False(result.IsComplete);
            Assert.Empty(result.Instances);
            Assert.Contains(result.Issues, issue => issue.Contains("reparse", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            Directory.Delete(fixture.RootParent, recursive: true);
            Directory.Delete(externalDirectory, recursive: true);
        }
    }

    [Fact]
    public void SymlinkedAncestorOfRunRootIsRejected()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using var fixture = new ReaderFixture();
        fixture.WriteFindings();
        var linkedParent = Path.Combine(Path.GetTempPath(), $"findings-reader-parent-link-{Guid.NewGuid():N}");
        try
        {
            Directory.CreateSymbolicLink(linkedParent, fixture.RootParent);

            var result = fixture.ReadFrom(linkedParent, Path.Combine(linkedParent, OuterRunId));

            Assert.False(result.IsComplete);
            Assert.False(result.IsClean);
            Assert.Contains(result.Issues, issue => issue.Contains("reparse", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            if (Directory.Exists(linkedParent))
            {
                Directory.Delete(linkedParent);
            }
        }
    }

    [Fact]
    public void RunRootOutsideTrustedRunsRootIsRejected()
    {
        using var fixture = new ReaderFixture();
        var outsideRootParent = Path.Combine(Path.GetTempPath(), $"findings-reader-outside-{Guid.NewGuid():N}");
        var outsideRoot = Path.Combine(outsideRootParent, OuterRunId);
        var nestedDirectory = Path.Combine(outsideRoot, "detect", DetectorRunId);
        Directory.CreateDirectory(nestedDirectory);
        File.WriteAllText(Path.Combine(nestedDirectory, "findings.json"), fixture.CreateDocument());

        try
        {
            var result = fixture.ReadFrom(fixture.RootParent, outsideRoot);

            Assert.False(result.IsComplete);
            Assert.False(result.IsClean);
            Assert.Contains(result.Issues, issue => issue.Contains("trusted runs root", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            Directory.Delete(outsideRootParent, recursive: true);
        }
    }

    [Fact]
    public async Task ArtifactReplacementRaceCannotReadOutsideRunRoot()
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        using var fixture = new ReaderFixture();
        fixture.WriteFindings(instances: "[{ \"Identifier\": \"inside-run\" }]");
        var detectDirectory = Path.Combine(fixture.Root, "detect");
        for (var index = 0; index < 1200; index++)
        {
            Directory.CreateDirectory(Path.Combine(detectDirectory, $"unrelated-{index:D4}"));
        }

        var artifactPath = Path.Combine(fixture.NestedDirectory, "findings.json");
        var backupPath = artifactPath + ".original";
        var externalDirectory = Path.Combine(Path.GetTempPath(), $"findings-reader-race-external-{Guid.NewGuid():N}");
        Directory.CreateDirectory(externalDirectory);
        var externalArtifact = Path.Combine(externalDirectory, "findings.json");
        File.WriteAllText(externalArtifact, fixture.CreateDocument());

        var substitutions = 0;
        var stop = 0;
        var swapper = Task.Run(() =>
        {
            while (Volatile.Read(ref stop) == 0)
            {
                File.Move(artifactPath, backupPath);
                File.CreateSymbolicLink(artifactPath, externalArtifact);
                Interlocked.Increment(ref substitutions);
                Thread.Sleep(1);
                File.Delete(artifactPath);
                File.Move(backupPath, artifactPath);
            }
        });

        var results = new List<FindingsReadResult>();
        try
        {
            while (!swapper.IsCompleted && results.Count < 100)
            {
                results.Add(fixture.Read());
            }
        }
        finally
        {
            Volatile.Write(ref stop, 1);
            await swapper;
            if (File.Exists(backupPath))
            {
                if (File.Exists(artifactPath) || File.ResolveLinkTarget(artifactPath, returnFinalTarget: false) is not null)
                {
                    File.Delete(artifactPath);
                }

                File.Move(backupPath, artifactPath);
            }

            Directory.Delete(externalDirectory, recursive: true);
        }

        Assert.True(substitutions > 0);
        Assert.NotEmpty(results);
        Assert.All(results, result => Assert.False(result.IsClean));
    }

    [Fact]
    public void MalformedJsonFailsClosed()
    {
        using var fixture = new ReaderFixture();
        fixture.WriteRaw("{ not-json");

        var result = fixture.Read();

        Assert.False(result.IsComplete);
        Assert.False(result.IsClean);
        Assert.Empty(result.Instances);
        Assert.Contains(result.Issues, issue => issue.Contains("malformed JSON", StringComparison.Ordinal));
    }

    [Fact]
    public void OtherTargetHitAlonePreventsCleanResult()
    {
        using var fixture = new ReaderFixture();
        fixture.WriteFindings(
            otherTargets: "[{ \"Name\": \"RemoteTool\", \"Hits\": [{ \"Kind\": \"service\" }] }]");

        var result = fixture.Read();

        Assert.True(result.IsComplete);
        Assert.True(result.HasFindings);
        Assert.False(result.IsClean);
        Assert.Single(Assert.Single(result.OtherTargets).Hits);
    }

    private sealed class ReaderFixture : IDisposable
    {
        public ReaderFixture()
        {
            RootParent = Path.Combine(Path.GetTempPath(), $"findings-reader-{Guid.NewGuid():N}");
            Root = Path.Combine(RootParent, OuterRunId);
            NestedDirectory = Path.Combine(Root, "detect", DetectorRunId);
            Directory.CreateDirectory(NestedDirectory);
        }

        public string RootParent { get; }
        public string Root { get; }
        public string NestedDirectory { get; }
        private string ArtifactPath => Path.Combine(NestedDirectory, "findings.json");

        public FindingsReadResult Read(string? relativePath = null) => FindingsReader.Read(
            RootParent,
            Root,
            OuterRunId,
            ComputerName,
            relativePath ?? $"detect/{DetectorRunId}/findings.json");

        public FindingsReadResult ReadFrom(string trustedRunsRoot, string runRoot) => FindingsReader.Read(
            trustedRunsRoot,
            runRoot,
            OuterRunId,
            ComputerName,
            $"detect/{DetectorRunId}/findings.json");

        public void WriteFindings(
            string instances = "[]",
            string parseIssues = "[]",
            string eventLogError = "null",
            string collectionComplete = "true",
            string collectionErrors = "[]",
            string otherTargets = "[]",
            bool includeCollectionComplete = true,
            string runId = DetectorRunId,
            string computerName = ComputerName)
        {
            WriteRaw(CreateDocument(
                instances,
                parseIssues,
                eventLogError,
                collectionComplete,
                collectionErrors,
                otherTargets,
                includeCollectionComplete,
                runId,
                computerName));
        }

        public string CreateDocument(
            string instances = "[]",
            string parseIssues = "[]",
            string eventLogError = "null",
            string collectionComplete = "true",
            string collectionErrors = "[]",
            string otherTargets = "[]",
            bool includeCollectionComplete = true,
            string runId = DetectorRunId,
            string computerName = ComputerName)
        {
            var completionProperty = includeCollectionComplete
                ? $"\"CollectionComplete\": {collectionComplete},"
                : string.Empty;
            return $$"""
                {
                  "RunId": "{{runId}}",
                  "ComputerName": "{{computerName}}",
                  "ScreenConnect": { "Instances": {{instances}}, "ParseIssues": {{parseIssues}} },
                  "OtherTargets": {{otherTargets}},
                  {{completionProperty}}
                  "CollectionErrors": {{collectionErrors}},
                  "EventLogError": {{eventLogError}}
                }
                """;
        }

        public void WriteRaw(string json) => File.WriteAllText(ArtifactPath, json);

        public void WriteAdditionalArtifact(string nestedRunId)
        {
            var directory = Path.Combine(Root, "detect", nestedRunId);
            Directory.CreateDirectory(directory);
            File.WriteAllText(Path.Combine(directory, "findings.json"), CreateDocument());
        }

        public void Dispose()
        {
            if (Directory.Exists(RootParent))
            {
                Directory.Delete(RootParent, recursive: true);
            }
        }
    }
}

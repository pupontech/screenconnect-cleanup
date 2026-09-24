using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Win32.SafeHandles;
using ScreenConnectCleanup.Gui.Services;
using Xunit;

namespace ScreenConnectCleanup.Gui.Phase3.Tests;

public sealed class RunStateReaderTests
{
    private const string RunId = "HOST-20260923_120000";
    private const string ComputerName = "HOST";

    [Fact]
    public void ValidTenStageReportIsReadWithAllFields()
    {
        using var fixture = new ReaderFixture();
        fixture.Write();

        var result = fixture.Read();

        Assert.True(result.IsValid);
        Assert.True(result.IsComplete);
        Assert.Empty(result.Issues);
        Assert.Equal(RunId, result.State.RunId);
        Assert.Equal(ComputerName, result.State.ComputerName);
        Assert.Equal(10, result.State.Stages.Count);
        Assert.Equal("Snapshot (Before)", result.State.Stages[1].Name);
        Assert.Equal(9, result.State.CurrentStage);
        Assert.Equal("detect/HOST_2026-09-23_120000/findings.json", result.State.Artifacts["findings"]);
        Assert.Single(result.State.Warnings);
        Assert.Empty(result.State.Errors);
    }

    [Fact]
    public void MissingStateFileReturnsIncomplete()
    {
        using var fixture = new ReaderFixture();
        var result = fixture.Read();

        Assert.False(result.IsValid);
        Assert.Equal("Incomplete", result.State.OverallStatus);
        Assert.Contains(result.Issues, issue => issue.Contains("missing", StringComparison.OrdinalIgnoreCase));
    }

    [Theory]
    [InlineData("{")]
    [InlineData("{ \"schemaVersion\": 1,")]
    public void PartialOrMalformedJsonReturnsIncomplete(string json)
    {
        using var fixture = new ReaderFixture();
        fixture.WriteRaw(json);
        var result = fixture.Read();

        Assert.False(result.IsValid);
        Assert.Equal("Incomplete", result.State.OverallStatus);
        Assert.Empty(result.State.Stages);
    }

    [Fact]
    public void FutureSchemaVersionIsRejected()
    {
        using var fixture = new ReaderFixture();
        var document = fixture.CreateDocument();
        document["schemaVersion"] = 2;
        fixture.Write(document);

        var result = fixture.Read();

        Assert.False(result.IsValid);
        Assert.Contains(result.Issues, issue => issue.Contains("unsupported", StringComparison.OrdinalIgnoreCase));
    }

    [Theory]
    [InlineData("Bogus")]
    [InlineData("complete")]
    public void InvalidOverallStatusIsRejected(string status)
    {
        using var fixture = new ReaderFixture();
        var document = fixture.CreateDocument();
        document["overallStatus"] = status;
        fixture.Write(document);

        var result = fixture.Read();

        Assert.False(result.IsValid);
        Assert.Contains(result.Issues, issue => issue.Contains("overallStatus", StringComparison.Ordinal));
    }

    [Fact]
    public void InvalidStageStatusIdNameAndDuplicateIdsAreRejected()
    {
        using var fixture = new ReaderFixture();
        var document = fixture.CreateDocument();
        document["stages"]![4]!["status"] = "Success";
        fixture.Write(document);
        Assert.False(fixture.Read().IsValid);

        document = fixture.CreateDocument();
        document["stages"]![2]!["id"] = 10;
        fixture.Write(document);
        Assert.False(fixture.Read().IsValid);

        document = fixture.CreateDocument();
        document["stages"]![2]!["name"] = "made up";
        fixture.Write(document);
        Assert.False(fixture.Read().IsValid);

        document = fixture.CreateDocument();
        document["stages"]![3]!["id"] = 2;
        fixture.Write(document);
        Assert.False(fixture.Read().IsValid);
    }

    [Fact]
    public void MissingStageIsRejected()
    {
        using var fixture = new ReaderFixture();
        var document = fixture.CreateDocument();
        ((JsonArray)document["stages"]!).RemoveAt(9);
        fixture.Write(document);

        var result = fixture.Read();

        Assert.False(result.IsValid);
        Assert.Contains(result.Issues, issue => issue.Contains("exactly ten", StringComparison.OrdinalIgnoreCase));
    }

    [Theory]
    [InlineData("OTHER-20260923_120000", "HOST")]
    [InlineData("HOST-20260923_120000", "OTHER")]
    public void RunOrComputerIdentityMismatchIsRejected(string runId, string computerName)
    {
        using var fixture = new ReaderFixture();
        var document = fixture.CreateDocument();
        document["runId"] = runId;
        document["computerName"] = computerName;
        fixture.Write(document);

        var result = fixture.Read();

        Assert.False(result.IsValid);
        Assert.Contains(result.Issues, issue => issue.Contains("identity", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void RunDirectoryLeafMustMatchExpectedIdentity()
    {
        using var fixture = new ReaderFixture(runDirectoryName: "OTHER-20260923_120000");
        fixture.Write();

        var result = fixture.Read();

        Assert.False(result.IsValid);
        Assert.Contains(result.Issues, issue => issue.Contains("leaf", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void RunRootOutsideTrustedRunsRootIsRejected()
    {
        using var fixture = new ReaderFixture();
        var externalRoot = Path.Combine(Path.GetTempPath(), $"gui-state-outside-{Guid.NewGuid():N}");
        var externalRun = Path.Combine(externalRoot, RunId);
        Directory.CreateDirectory(externalRun);
        File.WriteAllText(Path.Combine(externalRun, "gui-state.json"), fixture.CreateDocument().ToJsonString());
        try
        {
            var result = RunStateReader.Read(fixture.TrustedRoot, externalRun, RunId, ComputerName);

            Assert.False(result.IsValid);
            Assert.Contains(result.Issues, issue => issue.Contains("outside the trusted", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            Directory.Delete(externalRoot, recursive: true);
        }
    }

    [Fact]
    public void InvalidCurrentStageIsRejected()
    {
        using var fixture = new ReaderFixture();
        var document = fixture.CreateDocument();
        document["currentStage"] = 10;
        fixture.Write(document);

        Assert.False(fixture.Read().IsValid);
    }

    [Fact]
    public void RunningOverallAndStageStatesAreDowngradedToIncomplete()
    {
        using var fixture = new ReaderFixture();
        var document = fixture.CreateDocument();
        document["overallStatus"] = "Running";
        document["stages"]![2]!["status"] = "Running";
        fixture.Write(document);

        var result = fixture.Read();

        Assert.True(result.IsValid);
        Assert.False(result.IsComplete);
        Assert.Equal("Incomplete", result.State.OverallStatus);
        Assert.Equal("Incomplete", result.State.Stages[2].Status);
        Assert.Contains(result.Issues, issue => issue.Contains("producer stopped", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void NeedsActionRemainsNonterminalAndIsNotReportedComplete()
    {
        using var fixture = new ReaderFixture();
        var document = fixture.CreateDocument();
        document["overallStatus"] = "NeedsAction";
        fixture.Write(document);

        var result = fixture.Read();

        Assert.True(result.IsValid);
        Assert.False(result.IsComplete);
        Assert.Equal("NeedsAction", result.State.OverallStatus);
    }

    [Theory]
    [InlineData("Failed")]
    [InlineData("Warning")]
    [InlineData("Incomplete")]
    [InlineData("Running")]
    [InlineData("NeedsAction")]
    public void CompletedOverallStatusRejectsNonSuccessfulStage(string stageStatus)
    {
        using var fixture = new ReaderFixture();
        var document = fixture.CreateDocument();
        document["stages"]![4]!["status"] = stageStatus;
        fixture.Write(document);

        var result = fixture.Read();

        Assert.False(result.IsValid);
        Assert.False(result.IsComplete);
        Assert.Contains(result.Issues, issue => issue.Contains("overallStatus", StringComparison.Ordinal));
    }

    [Fact]
    public void FailedRunIsTerminalButNotSuccessfullyComplete()
    {
        using var fixture = new ReaderFixture();
        var document = fixture.CreateDocument();
        document["overallStatus"] = "Failed";
        document["stages"]![4]!["status"] = "Failed";
        fixture.Write(document);

        var result = fixture.Read();

        Assert.True(result.IsValid);
        Assert.True(result.IsTerminal);
        Assert.False(result.IsComplete);
    }

    [Fact]
    public void ReaderHandleAllowsAtomicReplacementWhileOpenOnWindows()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        using var fixture = new ReaderFixture();
        fixture.Write();
        var replacement = fixture.CreateDocument();
        replacement["overallStatus"] = "Warning";
        var replacementPath = Path.Combine(fixture.RunRoot, $"replacement-{Guid.NewGuid():N}.json");
        File.WriteAllText(replacementPath, replacement.ToJsonString());

        using (var readerHandle = OpenReaderHandleForTest(fixture.StatePath))
        {
            File.Replace(replacementPath, fixture.StatePath, destinationBackupFileName: null);
            Assert.False(readerHandle.IsClosed);
            Assert.Equal("Warning", fixture.Read().State.OverallStatus);
        }
    }

    private static SafeFileHandle OpenReaderHandleForTest(string path)
    {
        var method = typeof(RunStateReader).GetMethod("OpenStateHandle", BindingFlags.Static | BindingFlags.NonPublic);
        Assert.NotNull(method);
        return Assert.IsType<SafeFileHandle>(method!.Invoke(null, new object[] { path }));
    }

    [Theory]
    [InlineData("../outside.json")]
    [InlineData("/outside.json")]
    [InlineData("\\\\server\\share\\file")]
    [InlineData("logs:stream.txt")]
    [InlineData("NUL.txt")]
    [InlineData("detect/../../outside/findings.json")]
    public void TraversalRootedUncAndAlternateStreamArtifactPathsAreRejected(string path)
    {
        using var fixture = new ReaderFixture();
        var document = fixture.CreateDocument();
        document["artifacts"]!["findings"] = path;
        fixture.Write(document);

        var result = fixture.Read();

        Assert.False(result.IsValid);
        Assert.Contains(result.Issues, issue => issue.Contains("artifacts", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void UnknownArtifactRoleAndUnknownFieldsAreRejected()
    {
        using var fixture = new ReaderFixture();
        var document = fixture.CreateDocument();
        document["artifacts"]!["custom"] = "custom.json";
        fixture.Write(document);
        Assert.False(fixture.Read().IsValid);

        document = fixture.CreateDocument();
        document["approved"] = true;
        fixture.Write(document);
        var result = fixture.Read();
        Assert.False(result.IsValid);
        Assert.Contains(result.Issues, issue => issue.Contains("unknown fields", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void DuplicateJsonPropertiesAreRejected()
    {
        using var fixture = new ReaderFixture();
        var json = JsonSerializer.Serialize(fixture.CreateDocument());
        json = json.Replace("\"overallStatus\":\"Completed\"", "\"overallStatus\":\"Completed\",\"overallStatus\":\"Completed\"", StringComparison.Ordinal);
        fixture.WriteRaw(json);

        var result = fixture.Read();

        Assert.False(result.IsValid);
        Assert.Contains(result.Issues, issue => issue.Contains("duplicate", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void OversizedWarningIsRejected()
    {
        using var fixture = new ReaderFixture();
        var document = fixture.CreateDocument();
        document["warnings"] = new JsonArray(new string('x', 4097));
        fixture.Write(document);

        var result = fixture.Read();

        Assert.False(result.IsValid);
        Assert.Contains(result.Issues, issue => issue.Contains("warnings", StringComparison.Ordinal));
    }

    [Fact]
    public void NonUtcOrMalformedTimestampIsRejectedWithoutThrowing()
    {
        using var fixture = new ReaderFixture();
        var document = fixture.CreateDocument();
        document["updatedUtc"] = 123;
        fixture.Write(document);

        var result = fixture.Read();

        Assert.False(result.IsValid);
        Assert.Equal("Incomplete", result.State.OverallStatus);
    }

    [Fact]
    public void ReparsePointArtifactAncestorIsRejected()
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        using var fixture = new ReaderFixture();
        var external = Path.Combine(Path.GetTempPath(), $"gui-state-external-{Guid.NewGuid():N}");
        Directory.CreateDirectory(external);
        try
        {
            Directory.CreateSymbolicLink(Path.Combine(fixture.RunRoot, "logs"), external);
            var document = fixture.CreateDocument();
            document["artifacts"]!["log"] = "logs/master.log";
            fixture.Write(document);
            var result = fixture.Read();

            Assert.False(result.IsValid);
            Assert.Contains(result.Issues, issue => issue.Contains("artifact", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            Directory.Delete(external, recursive: true);
        }
    }

    [Fact]
    public void StateFileReparsePointIsRejected()
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        using var fixture = new ReaderFixture();
        var external = Path.Combine(Path.GetTempPath(), $"gui-state-external-{Guid.NewGuid():N}.json");
        File.WriteAllText(external, JsonSerializer.Serialize(fixture.CreateDocument()));
        try
        {
            File.CreateSymbolicLink(fixture.StatePath, external);
            var result = fixture.Read();

            Assert.False(result.IsValid);
            Assert.Contains(result.Issues, issue => issue.Contains("reparse", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            File.Delete(external);
        }
    }

    [Fact]
    public void ArtifactPointersDoNotOverrideReportedIncompleteStatus()
    {
        using var fixture = new ReaderFixture();
        var document = fixture.CreateDocument();
        document["overallStatus"] = "Incomplete";
        document["artifacts"]!["results"] = "results.json";
        fixture.Write(document);

        var result = fixture.Read();

        Assert.True(result.IsValid);
        Assert.False(result.IsComplete);
        Assert.Equal("Incomplete", result.State.OverallStatus);
    }

    private sealed class ReaderFixture : IDisposable
    {
        private static readonly string[] Names =
        {
            "Preflight", "Snapshot (Before)", "Detect", "Review Gate", "Contain + Remove",
            "Scanners", "Uninstall installed AV", "Procmon", "Snapshot (After)+Diff", "Report"
        };

        public ReaderFixture(string? runDirectoryName = null)
        {
            ExpectedRunId = RunId;
            TrustedRoot = Path.Combine(Path.GetTempPath(), $"gui-state-reader-{Guid.NewGuid():N}");
            RunRoot = Path.Combine(TrustedRoot, runDirectoryName ?? ExpectedRunId);
            Directory.CreateDirectory(RunRoot);
            StatePath = Path.Combine(RunRoot, "gui-state.json");
        }

        public string ExpectedRunId { get; }
        public string TrustedRoot { get; }
        public string RunRoot { get; }
        public string StatePath { get; }

        public RunStateReadResult Read() => RunStateReader.Read(TrustedRoot, RunRoot, ExpectedRunId, ComputerName);

        public JsonObject CreateDocument()
        {
            var stages = new JsonArray();
            for (var id = 0; id < Names.Length; id++)
            {
                stages.Add(new JsonObject
                {
                    ["id"] = id,
                    ["name"] = Names[id],
                    ["status"] = "Completed",
                    ["operation"] = string.Empty,
                    ["startedUtc"] = "2026-09-23T12:00:00Z",
                    ["endedUtc"] = "2026-09-23T12:01:00Z"
                });
            }

            return new JsonObject
            {
                ["schemaVersion"] = 1,
                ["runId"] = RunId,
                ["computerName"] = ComputerName,
                ["overallStatus"] = "Completed",
                ["currentStage"] = 9,
                ["stages"] = stages,
                ["warnings"] = new JsonArray("one warning"),
                ["errors"] = new JsonArray(),
                ["artifacts"] = new JsonObject
                {
                    ["findings"] = "detect/HOST_2026-09-23_120000/findings.json",
                    ["log"] = "master.log"
                },
                ["updatedUtc"] = "2026-09-23T12:01:00Z"
            };
        }

        public void Write() => Write(CreateDocument());
        public void Write(JsonObject document) => WriteRaw(document.ToJsonString());
        public void WriteRaw(string json) => File.WriteAllText(StatePath, json);

        public void Dispose()
        {
            if (Directory.Exists(TrustedRoot))
            {
                Directory.Delete(TrustedRoot, recursive: true);
            }
        }
    }
}

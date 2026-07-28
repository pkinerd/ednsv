using System.Reflection;
using Ednsv.Core.Services;

namespace Ednsv.Core.Tests;

/// <summary>
/// The build stamp: which commit a running instance was built from.
///
/// <para>It exists because a deployment question was mistaken for a code question. A
/// fix sat on an unmerged branch, pods were restarted, the symptom persisted — and
/// nothing the instance exposed could distinguish "the fix is not deployed" from "the
/// fix does not work". These pin the parse, since the value is only useful if it is
/// right.</para>
/// </summary>
public sealed class BuildInfoTests
{
    [Fact]
    public void TheVersionIsAlwaysReported()
    {
        Assert.False(string.IsNullOrWhiteSpace(BuildInfo.Version));
        Assert.DoesNotContain('+', BuildInfo.Version); // the revision half is split off
    }

    [Fact]
    public void TheShortCommitIsAPrefixOfTheFullOne()
    {
        // Never a truncation of something else, and never longer than what it abbreviates.
        Assert.StartsWith(BuildInfo.ShortCommit, BuildInfo.Commit, StringComparison.Ordinal);
        Assert.True(BuildInfo.ShortCommit.Length <= 7);
        if (BuildInfo.Commit.Length >= 7) Assert.Equal(7, BuildInfo.ShortCommit.Length);
    }

    [Fact]
    public void TheDisplayFormCarriesBothHalvesWhenThereIsARevision()
    {
        Assert.Contains(BuildInfo.Version, BuildInfo.Display, StringComparison.Ordinal);

        if (BuildInfo.ShortCommit.Length > 0)
            Assert.Contains(BuildInfo.ShortCommit, BuildInfo.Display, StringComparison.Ordinal);
        else
            Assert.Equal(BuildInfo.Version, BuildInfo.Display); // no placeholder invented
    }

    [Fact]
    public void ARevisionIsEmbeddedByThisBuild()
    {
        // The SDK derives it from the checkout; a container build has no .git, which is
        // why the Dockerfile passes SOURCE_COMMIT through to /p:SourceRevisionId. If
        // this ever fails locally, the image build is producing an unidentifiable
        // instance too — the exact gap this was added to close.
        var informational = typeof(BuildInfo).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;

        Assert.NotNull(informational);
        Assert.Contains('+', informational!);
        Assert.NotEmpty(BuildInfo.Commit);
        Assert.All(BuildInfo.Commit, c => Assert.True(Uri.IsHexDigit(c), $"'{c}' is not a hex digit"));
    }
}

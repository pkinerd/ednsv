using System.Reflection;

namespace Ednsv.Core.Services;

/// <summary>
/// Which build this process is: the informational version the SDK stamps into the
/// assembly, split into its version and source-revision halves.
///
/// <para>Worth having because "is the fix deployed?" is otherwise unanswerable from
/// outside. A pod restart pulls whatever the image tag currently points at, and a
/// running instance offers nothing to tell one build from another — so a fix that was
/// never rolled out is indistinguishable from one that did not work, and both look like
/// the original bug.</para>
///
/// <para>Read from <c>AssemblyInformationalVersion</c>, which the .NET SDK writes as
/// <c>1.0.0+&lt;commit&gt;</c> when it can determine a source revision. It resolves
/// that from the git checkout at build time, and a container build has no
/// <c>.git</c> — hence the <c>SOURCE_COMMIT</c> build argument in the Dockerfile,
/// without which every image would report a bare version and nothing else.</para>
/// </summary>
public static class BuildInfo
{
    private static readonly string Informational =
        typeof(BuildInfo).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()
            ?.InformationalVersion ?? "";

    /// <summary>The version without the source revision, e.g. <c>1.0.0</c>.</summary>
    public static string Version { get; } = Split().Version;

    /// <summary>The full source revision, or empty when the build could not determine
    /// one. Empty is reported honestly rather than as a placeholder — "unknown" is a
    /// useful thing to see, because it means the build did not carry its provenance.</summary>
    public static string Commit { get; } = Split().Commit;

    /// <summary>The first seven characters of <see cref="Commit"/>, as git abbreviates
    /// it, or empty. What the UI shows; the full value stays available for a copy.</summary>
    public static string ShortCommit { get; } =
        Commit.Length >= 7 ? Commit[..7] : Commit;

    /// <summary>
    /// <c>1.0.0 (7e859ee)</c>, or just the version when no revision is embedded.
    /// </summary>
    public static string Display { get; } =
        ShortCommit.Length > 0 ? $"{Version} ({ShortCommit})" : Version;

    /// <summary>Everything known about this build's provenance, for the startup log —
    /// e.g. <c>1.0.0, commit ab867c4…, branch claude/x, PR #30</c>. Whatever is missing
    /// is omitted rather than padded with placeholders.</summary>
    public static string Provenance
    {
        get
        {
            var parts = new List<string> { Version };
            parts.Add(Commit.Length > 0 ? $"commit {Commit}" : "commit unknown (no source revision embedded)");
            if (Branch.Length > 0) parts.Add($"branch {Branch}");
            if (PullRequest.Length > 0) parts.Add($"PR #{PullRequest}");
            return string.Join(", ", parts);
        }
    }

    /// <summary>The branch the image was built from, or empty. Assembly metadata
    /// rather than part of the informational version: the SDK has a hook for the
    /// revision and none for this.</summary>
    public static string Branch { get; } = Metadata("SourceBranch");

    /// <summary>The pull request number, or empty when the build was not a PR build.</summary>
    public static string PullRequest { get; } = Metadata("SourcePullRequest");

    private static string Metadata(string key) =>
        typeof(BuildInfo).Assembly.GetCustomAttributes<AssemblyMetadataAttribute>()
            .FirstOrDefault(a => a.Key == key)?.Value ?? "";

    private static (string Version, string Commit) Split()
    {
        if (Informational.Length == 0) return ("unknown", "");

        // The SDK uses '+' as the SemVer build-metadata separator. A version may also
        // carry a '-' prerelease label, which stays with the version half.
        var plus = Informational.IndexOf('+');
        return plus < 0
            ? (Informational, "")
            : (Informational[..plus], Informational[(plus + 1)..]);
    }
}

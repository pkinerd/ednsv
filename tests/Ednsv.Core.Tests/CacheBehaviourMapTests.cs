using Ednsv.Core.Checks;

namespace Ednsv.Core.Tests;

/// <summary>
/// The cache behaviour map claims to cover <i>every</i> check. A table that silently
/// falls behind the code is worse than no table: it is read as authoritative, and the
/// checks it omits are exactly the ones nobody thought about.
/// </summary>
public sealed class CacheBehaviourMapTests
{
    private static string Doc()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !File.Exists(Path.Combine(dir.FullName, "docs", "cache-behaviour-map.md")))
            dir = dir.Parent;
        Assert.NotNull(dir);
        return File.ReadAllText(Path.Combine(dir!.FullName, "docs", "cache-behaviour-map.md"));
    }

    private static List<ICheck> AllChecks() =>
        typeof(ICheck).Assembly.GetTypes()
            .Where(t => typeof(ICheck).IsAssignableFrom(t) && !t.IsAbstract && !t.IsInterface)
            .Where(t => t.GetConstructor(Type.EmptyTypes) != null)
            .Select(t => (ICheck)Activator.CreateInstance(t)!)
            .ToList();

    /// <summary>The names occupying a cell of the per-check table, exactly. Substring
    /// matching is not enough: it would accept a renamed or truncated row — "Open Relay
    /// TestX" contains "Open Relay Test" — which is precisely the drift this guards.</summary>
    private static HashSet<string> MappedNames(string doc) =>
        doc.Split('\n')
            .Where(l => l.StartsWith("| ", StringComparison.Ordinal))
            .SelectMany(l => l.Split('|'))
            .Select(cell => cell.Trim())
            .ToHashSet(StringComparer.Ordinal);

    [Fact]
    public void EveryCheckAppearsInTheMap()
    {
        var mapped = MappedNames(Doc());
        var missing = AllChecks().Select(c => c.Name).Distinct()
            .Where(n => !mapped.Contains(n))
            .OrderBy(n => n).ToList();

        Assert.True(missing.Count == 0,
            $"docs/cache-behaviour-map.md is missing {missing.Count} check(s): {string.Join(", ", missing)}");
    }

    [Fact]
    public void EveryCategoryAppearsInTheMap()
    {
        var doc = Doc();
        var missing = AllChecks().Select(c => c.Category.ToString()).Distinct()
            .Where(c => !doc.Contains(c, StringComparison.Ordinal))
            .OrderBy(c => c).ToList();

        Assert.True(missing.Count == 0, $"categories missing from the map: {string.Join(", ", missing)}");
    }

    /// <summary>
    /// The cache table's Redis column and transient-failure column must follow from the
    /// wrapper type, which is the thing that actually decides them. An `ExpiringMap` has
    /// no <c>shouldPersist</c> and no transient window — its callers simply do not write
    /// on a failure — so claiming a 30s L1 hold for one is wrong in a way that reads
    /// entirely plausible. The doc did claim exactly that until it was reconciled.
    /// </summary>
    [Theory]
    [InlineData("_queryCache", "ProbeCache", true)]
    [InlineData("_serverQueryCache", "ProbeCache", true)]
    [InlineData("_ptrCache", "ProbeCache", true)]
    [InlineData("_probeCache", "ProbeCache", true)]
    [InlineData("_portCache", "ProbeCacheValue", false)]
    [InlineData("_rcptCache", "ExpiringMap", false)]
    [InlineData("_relayCache", "ExpiringMap", false)]
    [InlineData("_getCache", "ProbeCache", true)]
    [InlineData("_axfrCache", "ExpiringMap", false)]
    public void TheCacheTableMatchesTheWrapperType(string cache, string type, bool redis)
    {
        var row = Doc().Split('\n')
            .FirstOrDefault(l => l.StartsWith("| `", StringComparison.Ordinal)
                                 && l.Count(ch => ch == '|') == 8
                                 && l.Split('|')[1].Contains('`' + cache + '`', StringComparison.Ordinal));
        Assert.True(row != null, $"no cache-table row for {cache}");

        var cols = row!.Split('|');
        Assert.Contains('`' + type + '`', row, StringComparison.Ordinal);
        Assert.Equal(redis ? "yes" : "**no**", cols[6].Trim());

        // The transient column must follow from the type, not be chosen freely.
        if (type == "ExpiringMap")
            Assert.Contains("not cached at all", cols[7], StringComparison.Ordinal);
        else
            Assert.Contains("30s", cols[7], StringComparison.Ordinal);
    }

    [Fact]
    public void TheStatedCheckCountMatchesReality()
    {
        // The prose says "All 87 checks" — a number that ages badly on its own.
        var doc = Doc();
        var actual = AllChecks().Select(c => c.Name).Distinct().Count();
        Assert.Contains($"All {actual} checks", doc, StringComparison.Ordinal);
    }
}

using Ednsv.Core.Services;

namespace Ednsv.Core.Tests;

/// <summary>
/// Startup recovery from a corrupt config.json runs with no distributed lock —
/// several replicas can hit the same bad file at the same moment. These tests
/// pin the property that makes that safe: every replica independently computes
/// the SAME repair, so concurrent writes are byte-identical and converge instead
/// of needing to be serialised.
/// </summary>
public sealed class ConfigRecoveryConcurrencyTests : IDisposable
{
    private readonly string _dir;
    private const string Corrupt = "{ this is not valid json";
    private const int Pods = 8;

    public ConfigRecoveryConcurrencyTests()
        => _dir = Path.Combine(Path.GetTempPath(), $"ednsv-recover-{Guid.NewGuid():N}");

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { /* best effort */ }
    }

    /// <summary>A saved config, then its config.json replaced by garbage.</summary>
    private void ArrangeCorruptedInstance()
    {
        var svc = new ConfigService(_dir);
        svc.LoadOrSeed(new AppConfig { EnableSmtpProbes = true });
        svc.Replace(new AppConfig { EnableSmtpProbes = false, EnableDnsbl = false }, "alice@contoso.com");
        File.WriteAllText(Path.Combine(_dir, "config.json"), Corrupt);
    }

    // Dedicated threads rather than the thread pool: every worker parks on the
    // barrier at once, which would starve a pool sized below `count`.
    private static AppConfig[] StartPodsConcurrently(string dir, int count)
    {
        using var gate = new Barrier(count);
        var results = new AppConfig[count];
        var failures = new Exception?[count];

        var threads = Enumerable.Range(0, count).Select(i => new Thread(() =>
        {
            try
            {
                var svc = new ConfigService(dir);
                gate.SignalAndWait();      // maximise overlap on the recovery path
                results[i] = svc.LoadOrSeed(new AppConfig { EnableSmtpProbes = true });
            }
            catch (Exception ex)
            {
                failures[i] = ex;
            }
        })).ToArray();

        foreach (var t in threads) t.Start();
        foreach (var t in threads) Assert.True(t.Join(TimeSpan.FromSeconds(30)), "pod startup deadlocked");

        var thrown = failures.FirstOrDefault(f => f != null);
        if (thrown != null) throw new Xunit.Sdk.XunitException($"a pod failed to start: {thrown}");
        return results;
    }

    [Fact]
    public void ConcurrentPods_AllRecoverTheSameConfig()
    {
        ArrangeCorruptedInstance();

        var results = StartPodsConcurrently(_dir, Pods);

        // Every pod restored the saved revision, none fell back to the seed.
        Assert.All(results, cfg => Assert.False(cfg.EnableSmtpProbes));
        Assert.All(results, cfg => Assert.False(cfg.EnableDnsbl));
    }

    [Fact]
    public void ConcurrentPods_QuarantineExactlyOneCopy()
    {
        ArrangeCorruptedInstance();

        StartPodsConcurrently(_dir, Pods);

        // Content-hash naming means all pods target one path, so the corrupt file
        // is preserved once rather than once per replica.
        var quarantined = Directory.GetFiles(
            Path.Combine(_dir, "config-history"), "config-corrupt-*.json");
        Assert.Single(quarantined);
        Assert.Equal(Corrupt, File.ReadAllText(quarantined[0]));
    }

    [Fact]
    public void ConcurrentPods_LeaveConfigJsonValidAndConverged()
    {
        ArrangeCorruptedInstance();

        StartPodsConcurrently(_dir, Pods);

        // Whichever pod's atomic rename landed last, the bytes are the same.
        var reopened = new ConfigService(_dir);
        var cfg = reopened.LoadOrSeed(new AppConfig { EnableSmtpProbes = true });
        Assert.False(cfg.EnableSmtpProbes);
    }

    // ListRevisions reads the in-memory _history, which only LoadOrSeed populates —
    // reading it off a bare `new ConfigService(dir)` yields an empty list and makes
    // any assertion over it vacuous.
    private List<ConfigRevisionInfo> ReadHistoryFresh()
    {
        var svc = new ConfigService(_dir);
        svc.LoadOrSeed(new AppConfig { EnableSmtpProbes = true });
        return svc.ListRevisions().Where(r => !r.IsCorrupt).ToList();
    }

    [Fact]
    public void ConcurrentPods_DoNotDuplicateOrLoseRevisionHistory()
    {
        ArrangeCorruptedInstance();
        var before = ReadHistoryFresh();
        Assert.NotEmpty(before); // guard: the assertions below must not be vacuous

        // Re-corrupt: reading the history above repaired config.json.
        File.WriteAllText(Path.Combine(_dir, "config.json"), Corrupt);
        StartPodsConcurrently(_dir, Pods);

        var after = ReadHistoryFresh();

        // Recovery writes no revision at all, so history is exactly as it was:
        // no per-replica duplicates, nothing dropped, no orphaned bodies.
        Assert.Equal(before.Select(r => r.Id), after.Select(r => r.Id));

        var bodies = Directory.GetFiles(Path.Combine(_dir, "config-history"), "config-rev-*.json");
        Assert.Equal(after.Count, bodies.Length);
    }

    [Fact]
    public void ConcurrentPods_WithNoHistoryAllSeedIdentically()
    {
        Directory.CreateDirectory(_dir);
        File.WriteAllText(Path.Combine(_dir, "config.json"), Corrupt);

        var results = StartPodsConcurrently(_dir, Pods);

        Assert.All(results, cfg => Assert.True(cfg.EnableSmtpProbes)); // the seed
        Assert.Single(Directory.GetFiles(Path.Combine(_dir, "config-history"), "config-corrupt-*.json"));
    }
}

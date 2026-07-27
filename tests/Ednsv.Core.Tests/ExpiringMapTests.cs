using Ednsv.Core.Services;

namespace Ednsv.Core.Tests;

/// <summary>
/// <see cref="ExpiringMap{TKey,TValue}"/> is what gives the caches that are not a
/// <c>ProbeCache</c> — RCPT probes, relay tests, AXFR verdicts and responses,
/// unreachable-server counts, domain summaries, the per-server client pool — the same
/// TTL every other cache has. Before it they were plain dictionaries that held every
/// key for the life of the process.
/// </summary>
public sealed class ExpiringMapTests
{
    private static ExpiringMap<string, string> Map(int ms = 60_000)
        => new(TimeSpan.FromMilliseconds(ms));

    // ── Reading ──────────────────────────────────────────────────────────

    [Fact]
    public void AValueIsReadableUntilItExpires()
    {
        var map = Map(50);
        map.Set("k", "v");

        Assert.True(map.TryGetValue("k", out var got));
        Assert.Equal("v", got);

        Thread.Sleep(120);

        Assert.False(map.TryGetValue("k", out _));
    }

    [Fact]
    public void ExpiryIsEnforcedOnReadRatherThanWaitingForAPrune()
    {
        // The load-bearing property: no timer sweeps this map, so a stale entry must be
        // refused by the read itself or the TTL would be advisory. MemoryCache checks
        // expiry inside TryGetValue, which is exactly what this leans on.
        var map = Map(50);
        map.Set("k", "v");
        Thread.Sleep(120);

        Assert.False(map.TryGetValue("k", out _));
    }

    [Fact]
    public void AMissingKeyIsSimplyAMiss()
    {
        Assert.False(Map().TryGetValue("nope", out var got));
        Assert.Null(got);
    }

    // ── Adding ───────────────────────────────────────────────────────────

    [Fact]
    public void ALiveValueIsNotOverwrittenByTryAdd()
    {
        var map = Map();
        Assert.True(map.TryAdd("k", "first"));
        Assert.False(map.TryAdd("k", "second"));

        Assert.True(map.TryGetValue("k", out var got));
        Assert.Equal("first", got);
    }

    [Fact]
    public void AnExpiredValueCountsAsAbsentSoARefetchIsStored()
    {
        // The bug this closes: a bare TryAdd against a map with expiry would report
        // "already present" for a dead entry, so the freshly fetched value would be
        // returned to the caller and then thrown away — every call refetching.
        var map = Map(50);
        map.Set("k", "stale");
        Thread.Sleep(120);

        Assert.True(map.TryAdd("k", "fresh"));
        Assert.True(map.TryGetValue("k", out var got));
        Assert.Equal("fresh", got);
    }

    [Fact]
    public void AnAlreadyExpiredEntryIsRefusedOutright()
    {
        // The import path: a record whose expiry has passed must not be resurrected.
        var map = Map();

        Assert.False(map.TryAdd("k", "v", DateTime.UtcNow.AddSeconds(-1)));
        Assert.False(map.TryGetValue("k", out _));
    }

    [Fact]
    public void AnImportKeepsItsOwnExpiryRatherThanAFreshFullTtl()
    {
        var map = Map(60_000);
        Assert.True(map.TryAdd("k", "v", DateTime.UtcNow.AddMilliseconds(80)));

        Assert.True(map.TryGetValue("k", out _));
        Thread.Sleep(150);
        Assert.False(map.TryGetValue("k", out _)); // not the map's minute
    }

    [Fact]
    public void SetReplacesWhateverIsThere()
    {
        var map = Map();
        map.Set("k", "first");
        map.Set("k", "second");

        Assert.True(map.TryGetValue("k", out var got));
        Assert.Equal("second", got);
    }

    // ── AddOrUpdate ──────────────────────────────────────────────────────

    [Fact]
    public void AddOrUpdateAddsThenUpdates()
    {
        var map = new ExpiringMap<string, int>(TimeSpan.FromMinutes(1));

        Assert.Equal(1, map.AddOrUpdate("s", 1, prev => prev + 1));
        Assert.Equal(2, map.AddOrUpdate("s", 1, prev => prev + 1));
        Assert.Equal(3, map.AddOrUpdate("s", 1, prev => prev + 1));
    }

    [Fact]
    public void AddOrUpdateStartsOverWhenTheEntryHasExpired()
    {
        // An unreachable-server count that has aged out must restart at one, not carry
        // on from a value nobody would have been allowed to read.
        var map = new ExpiringMap<string, int>(TimeSpan.FromMilliseconds(50));
        map.AddOrUpdate("s", 1, prev => prev + 1);
        map.AddOrUpdate("s", 1, prev => prev + 1);
        Thread.Sleep(120);

        Assert.Equal(1, map.AddOrUpdate("s", 1, prev => prev + 1));
    }

    [Fact]
    public void AWriteRefreshesTheExpiry()
    {
        var map = new ExpiringMap<string, int>(TimeSpan.FromMilliseconds(150));
        map.AddOrUpdate("s", 1, prev => prev + 1);
        Thread.Sleep(100);
        map.AddOrUpdate("s", 1, prev => prev + 1); // it has just failed again
        Thread.Sleep(100);

        Assert.True(map.TryGetValue("s", out var count));
        Assert.Equal(2, count);
    }

    // ── GetOrAdd ─────────────────────────────────────────────────────────

    [Fact]
    public void GetOrAddBuildsOnceAndThenServesTheCachedValue()
    {
        var map = Map();
        var built = 0;

        Assert.Equal("v", map.GetOrAdd("k", _ => { built++; return "v"; }));
        Assert.Equal("v", map.GetOrAdd("k", _ => { built++; return "other"; }));
        Assert.Equal(1, built);
    }

    [Fact]
    public void GetOrAddRebuildsAfterTheTtl()
    {
        // The per-server LookupClient pool: a client unused for a whole TTL is dropped
        // and rebuilt rather than held for the life of the process.
        var map = Map(50);
        var built = 0;
        map.GetOrAdd("k", _ => { built++; return "v"; });
        Thread.Sleep(120);
        map.GetOrAdd("k", _ => { built++; return "v"; });

        Assert.Equal(2, built);
    }

    // ── Bounded growth ───────────────────────────────────────────────────

    [Fact]
    public async Task ExpiredEntriesStopBeingServedAndAreEventuallyReleased()
    {
        // Two separate guarantees, and only the first is instant. Expiry on read is
        // exact; releasing the memory is MemoryCache's sweep, which it triggers from a
        // cache operation, rate-limits by ExpirationScanFrequency and runs on the thread
        // pool. This asserts the contract, not the schedule.
        var map = new ExpiringMap<string, string>(TimeSpan.FromMilliseconds(50));
        for (var i = 0; i < 200; i++) map.Set($"k{i}", "v");

        await Task.Delay(120);

        for (var i = 0; i < 200; i++)
            Assert.False(map.TryGetValue($"k{i}", out _), $"k{i} was still readable");
    }

    [Fact]
    public void CountIsWhatIsHeldRatherThanWhatIsReadable()
    {
        // Worth pinning because it is a trap for anyone reading the diagnostics counters
        // built on it: Count is what MemoryCache is holding, and an expired entry is
        // still held until something touches it. The read is what releases this one —
        // which is why the count assertions here bracket the read rather than follow it.
        var map = new ExpiringMap<string, string>(TimeSpan.FromMilliseconds(50));
        map.Set("k", "v");
        Thread.Sleep(120);

        Assert.Equal(1, map.Count);                 // expired, still held
        Assert.False(map.TryGetValue("k", out _));  // not readable, and now released
        Assert.Equal(0, map.Count);
    }

    // ── No TTL configured ────────────────────────────────────────────────

    [Fact]
    public void WithoutATtlNothingExpires()
    {
        // CacheTtlHours=0 means the same thing here as everywhere else: entries live
        // for the process, bounded by the number of distinct keys.
        var map = new ExpiringMap<string, string>(null);
        map.Set("k", "v");
        Thread.Sleep(60);

        Assert.True(map.TryGetValue("k", out _));
        Assert.Equal(1, map.Count);
    }

    // ── Non-string keys ──────────────────────────────────────────────────

    [Fact]
    public void TupleKeysWorkAsThemselves()
    {
        // The AXFR caches are keyed by (ip, domain) — one of the reasons this is not a
        // MemoryCache.
        var map = new ExpiringMap<(string ip, string domain), bool>(TimeSpan.FromMinutes(1));
        map.Set(("192.0.2.1", "example.com"), true);

        Assert.True(map.TryGetValue(("192.0.2.1", "example.com"), out var vulnerable));
        Assert.True(vulnerable);
        Assert.False(map.TryGetValue(("192.0.2.2", "example.com"), out _));
    }

    // ── Concurrency ──────────────────────────────────────────────────────

    [Fact]
    public void ConcurrentWritersAgreeOnOneWinnerPerKey()
    {
        var map = Map();
        var winners = 0;

        Parallel.For(0, 64, i =>
        {
            if (map.TryAdd("contested", $"v{i}")) Interlocked.Increment(ref winners);
        });

        Assert.Equal(1, winners);
        Assert.True(map.TryGetValue("contested", out _));
    }

    [Fact]
    public void ConcurrentIncrementsAreNotLost()
    {
        var map = new ExpiringMap<string, int>(TimeSpan.FromMinutes(1));

        Parallel.For(0, 500, _ => map.AddOrUpdate("s", 1, prev => prev + 1));

        Assert.True(map.TryGetValue("s", out var count));
        Assert.Equal(500, count);
    }
}

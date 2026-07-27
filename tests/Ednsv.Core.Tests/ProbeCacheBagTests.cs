using Ednsv.Core.Services;

namespace Ednsv.Core.Tests;

/// <summary>
/// The bag holds only what this process fetched fresh and has yet to write out.
/// The point of the change is what it <i>excludes</i>: entries imported from disk
/// used to go straight back into the export log, so every flush re-serialised and
/// rewrote the entire cache — including everything read from disk at startup — for
/// the life of the process.
/// </summary>
public sealed class ProbeCacheBagTests
{
    private static Task<string> Fresh(string v) => Task.FromResult(v);

    [Fact]
    public async Task AFreshFetchIsQueuedForPersistence()
    {
        var cache = new ProbeCache<string>(TimeSpan.FromMinutes(10));

        await cache.GetOrCreateAsync("k", () => Fresh("value"));

        Assert.Equal(new[] { "k" }, cache.Export().Keys);
    }

    [Fact]
    public void AnImportedEntryIsReadableButNotQueued()
    {
        var cache = new ProbeCache<string>(TimeSpan.FromMinutes(10));

        cache.Import("k", "from-disk");

        Assert.True(cache.TryGet("k", out var got));
        Assert.Equal("from-disk", got);
        Assert.Empty(cache.Export()); // already on disk — never write it back
    }

    [Fact]
    public void ImportWithAnExpiryIsAlsoMemoryOnly()
    {
        var cache = new ProbeCache<string>(TimeSpan.FromMinutes(10));

        cache.Import("k", "from-disk", DateTime.UtcNow.AddMinutes(5));

        Assert.True(cache.TryGet("k", out _));
        Assert.Empty(cache.Export());
    }

    [Fact]
    public void ImportRefusesAnEntryAlreadyPastItsExpiry()
    {
        var cache = new ProbeCache<string>(TimeSpan.FromHours(10));

        Assert.False(cache.Import("expired", "stale", DateTime.UtcNow.AddSeconds(-1)));
        Assert.False(cache.TryGet("expired", out _));
    }

    [Fact]
    public async Task ImportExpiresAtTheEntrysOwnTimeNotAFreshTtl()
    {
        // An entry with a moment left must be cached for that moment, not handed a
        // whole new TTL — otherwise every restart resurrects a nearly-dead value for
        // another full period, indefinitely.
        var cache = new ProbeCache<string>(TimeSpan.FromHours(10));

        Assert.True(cache.Import("brief", "v", DateTime.UtcNow.AddMilliseconds(200)));
        Assert.True(cache.TryGet("brief", out _), "it should be cached until its own expiry");

        await Task.Delay(500);

        Assert.False(cache.TryGet("brief", out _),
            "the entry outlived its record expiry — it was given the cache's TTL instead");
    }

    [Fact]
    public async Task ImportDoesNotClobberAValueAlreadyFetched()
    {
        // The load runs in the background while the instance serves, so a validation
        // can cache a key before the loader reaches it. That value came off the
        // network just now; the disk copy did not.
        var cache = new ProbeCache<string>(TimeSpan.FromMinutes(10));
        await cache.GetOrCreateAsync("k", () => Fresh("from-network"));

        Assert.False(cache.Import("k", "from-disk"));

        Assert.True(cache.TryGet("k", out var got));
        Assert.Equal("from-network", got);
    }

    [Fact]
    public async Task ImportDoesNotClobberAFetchStillInFlight()
    {
        // A fetch that has not returned yet will cache its result on completion, so
        // it counts as present — otherwise the import would land first and be
        // immediately overwritten, which is harmless, or land second, which is not.
        var cache = new ProbeCache<string>(TimeSpan.FromMinutes(10));
        var release = new TaskCompletionSource<string>();
        var inflight = cache.GetOrCreateAsync("k", () => release.Task);

        Assert.False(cache.Import("k", "from-disk"));

        release.SetResult("from-network");
        Assert.Equal("from-network", await inflight);
        Assert.True(cache.TryGet("k", out var got));
        Assert.Equal("from-network", got);
    }

    [Fact]
    public async Task ValueCache_ImportDoesNotClobberOrResurrect()
    {
        var cache = new ProbeCacheValue<bool>(TimeSpan.FromHours(10));

        Assert.True(cache.Import("k", true, DateTime.UtcNow.AddMinutes(5)));
        Assert.False(cache.Import("k", false, DateTime.UtcNow.AddMinutes(5)));
        Assert.True(cache.TryGet("k", out var v));
        Assert.True(v);

        Assert.False(cache.Import("dead", true, DateTime.UtcNow.AddSeconds(-1)));
        Assert.False(cache.TryGet("dead", out _));

        Assert.True(cache.Import("brief", true, DateTime.UtcNow.AddMilliseconds(200)));
        await Task.Delay(500);
        Assert.False(cache.TryGet("brief", out _));
    }

    [Fact]
    public async Task ReadingAnImportedEntryDoesNotQueueIt()
    {
        // A cache hit must not resurrect a disk entry into the write path — that
        // would reintroduce the rewrite-everything behaviour one key at a time.
        var cache = new ProbeCache<string>(TimeSpan.FromMinutes(10));
        cache.Import("k", "from-disk");

        var got = await cache.GetOrCreateAsync("k", () => Fresh("should-not-run"));

        Assert.Equal("from-disk", got);
        Assert.Empty(cache.Export());
    }

    [Fact]
    public async Task TransientResultsAreStillExcludedByShouldPersist()
    {
        var cache = new ProbeCache<string>(TimeSpan.FromMinutes(10));

        await cache.GetOrCreateAsync("bad", () => Fresh("transient"),
            shouldPersist: v => v != "transient");

        Assert.True(cache.TryGet("bad", out _)); // cached in memory
        Assert.Empty(cache.Export());            // but never persisted
    }

    [Fact]
    public async Task CollectedRecordsCarryTheFetchTimeAndTheEntrysExpiry()
    {
        // The fetch time is what orders entries across instances when their files are
        // merged, so it has to be the moment of the fetch and not of the flush.
        var cache = new ProbeCache<string>(TimeSpan.FromMinutes(10));
        var before = DateTime.UtcNow;

        await cache.GetOrCreateAsync("k", () => Fresh("v"));

        var record = Assert.Single(
            cache.CollectPending("test", v => System.Text.Json.JsonSerializer.SerializeToNode(v)).Records);
        Assert.Equal("k", record.Key);
        Assert.Equal("v", record.Value?.GetValue<string>());
        Assert.InRange(record.WrittenUtc, before.AddSeconds(-1), DateTime.UtcNow.AddSeconds(1));
        Assert.InRange(record.ExpiresUtc,
            before.AddMinutes(10).AddSeconds(-1), DateTime.UtcNow.AddMinutes(10).AddSeconds(1));
    }

    [Fact]
    public async Task CountTracksWhatIsCachedNotWhatIsQueued()
    {
        var cache = new ProbeCache<string>(TimeSpan.FromMinutes(10));
        cache.Import("imported", "a");
        await cache.GetOrCreateAsync("fetched", () => Fresh("b"));

        // Both are cached; only the fetched one is queued for writing.
        Assert.Equal(2, cache.Count);
        Assert.Single(cache.Export());
    }

    [Fact]
    public async Task RemoveClearsBothTheCacheAndTheQueue()
    {
        var cache = new ProbeCache<string>(TimeSpan.FromMinutes(10));
        await cache.GetOrCreateAsync("drop:1", () => Fresh("a"));
        await cache.GetOrCreateAsync("keep:1", () => Fresh("b"));

        cache.Remove(k => k.StartsWith("drop:"));

        Assert.False(cache.TryGet("drop:1", out _));
        Assert.Equal(new[] { "keep:1" }, cache.Export().Keys);
    }

    // ── Per-entry TTL ────────────────────────────────────────────────────

    [Fact]
    public async Task APerEntryTtlBoundsBothTheCacheAndTheDiskRecord()
    {
        // A DNS answer whose records say thirty seconds must not be served — or
        // written out as live — for the cache's full two hours. The two must agree,
        // or the disk copy resurrects the value the memory copy just expired.
        var cache = new ProbeCache<string>(TimeSpan.FromHours(2));
        var before = DateTime.UtcNow;

        await cache.GetOrCreateAsync("k", () => Fresh("v"),
            entryTtl: _ => TimeSpan.FromSeconds(30));

        var record = Assert.Single(
            cache.CollectPending("test", v => System.Text.Json.JsonSerializer.SerializeToNode(v)).Records);
        Assert.InRange(record.ExpiresUtc,
            before.AddSeconds(29), DateTime.UtcNow.AddSeconds(31));
    }

    [Fact]
    public async Task NoPerEntryTtlLeavesTheCacheWideOneGoverning()
    {
        var cache = new ProbeCache<string>(TimeSpan.FromHours(2));
        var before = DateTime.UtcNow;

        await cache.GetOrCreateAsync("null-ttl", () => Fresh("v"), entryTtl: _ => null);
        await cache.GetOrCreateAsync("no-delegate", () => Fresh("v"));

        foreach (var record in cache.CollectPending("test",
                     v => System.Text.Json.JsonSerializer.SerializeToNode(v)).Records)
        {
            Assert.InRange(record.ExpiresUtc,
                before.AddHours(2).AddSeconds(-1), DateTime.UtcNow.AddHours(2).AddSeconds(1));
        }
    }

    [Fact]
    public async Task ATtlDelegateThatThrowsFallsBackToTheCacheTtl()
    {
        // A malformed response must cost its own TTL derivation, not the entry.
        var cache = new ProbeCache<string>(TimeSpan.FromHours(2));
        var before = DateTime.UtcNow;

        await cache.GetOrCreateAsync("k", () => Fresh("v"),
            entryTtl: _ => throw new InvalidOperationException("no TTL here"));

        Assert.True(cache.TryGet("k", out _));
        var record = Assert.Single(
            cache.CollectPending("test", v => System.Text.Json.JsonSerializer.SerializeToNode(v)).Records);
        Assert.InRange(record.ExpiresUtc,
            before.AddHours(2).AddSeconds(-1), DateTime.UtcNow.AddHours(2).AddSeconds(1));
    }

    [Fact]
    public async Task APerEntryTtlAlsoExpiresTheMemoryCopy()
    {
        var cache = new ProbeCache<string>(TimeSpan.FromHours(2));

        await cache.GetOrCreateAsync("brief", () => Fresh("v"),
            entryTtl: _ => TimeSpan.FromMilliseconds(200));

        Assert.True(cache.TryGet("brief", out _));
        await Task.Delay(500);
        Assert.False(cache.TryGet("brief", out _), "the entry outlived its per-entry TTL");
    }

    // ── Value-type variant ───────────────────────────────────────────────

    [Fact]
    public async Task ValueCache_FreshFetchQueuedAndImportIsNot()
    {
        var cache = new ProbeCacheValue<bool>(TimeSpan.FromMinutes(10));

        await cache.GetOrCreateAsync("fetched", () => Task.FromResult(true));
        cache.Import("imported", false);

        Assert.Equal(new[] { "fetched" }, cache.Export().Keys);
        Assert.True(cache.TryGet("imported", out var v));
        Assert.False(v);
    }

    // ── BagEntry equality ────────────────────────────────────────────────

    [Fact]
    public void BagEntryEqualityIsReferenceIdentity()
    {
        // A flush removes written entries with TryRemove(KeyValuePair), which
        // compares values via EqualityComparer<T>.Default. If BagEntry ever gained
        // value equality — by becoming a record, say — a flush could delete a newer
        // entry that replaced the one it persisted, silently.
        var value = "same";
        var written = new BagEntry<string>(value, DateTime.UtcNow, DateTime.MaxValue);
        var newer = new BagEntry<string>(value, written.WrittenUtc, written.ExpiresUtc);

        Assert.False(written.Equals(newer), "BagEntry must not use value equality");
        Assert.True(written.Equals(written));
        Assert.NotEqual(written.GetHashCode(), newer.GetHashCode());
    }

    [Fact]
    public void AStaleBagEntryCannotEvictANewerOne()
    {
        var bag = new System.Collections.Concurrent.ConcurrentDictionary<string, BagEntry<string>>();
        var written = new BagEntry<string>("v", DateTime.UtcNow, DateTime.MaxValue);
        bag["k"] = written;

        // A newer fetch lands for the same key while the flush is writing.
        var newer = new BagEntry<string>("v", DateTime.UtcNow, DateTime.MaxValue);
        bag["k"] = newer;

        // The flush removes exactly what it persisted, and misses.
        Assert.False(bag.TryRemove(new KeyValuePair<string, BagEntry<string>>("k", written)));
        Assert.True(bag.ContainsKey("k"));
        Assert.Same(newer, bag["k"]);
    }
}

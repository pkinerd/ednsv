using Ednsv.Core.Services;

namespace Ednsv.Core.Tests;

/// <summary>
/// Republishing L1 into the shared cache after Redis has been emptied.
///
/// <para>Memory is the source rather than disk: it is fresher, needs no file I/O, and
/// is a superset of what this instance would find on disk anyway, since the startup
/// load imports every instance's live records into L1. It is also the <i>only</i>
/// source that exists when the disk tier is switched off — which is what lets a
/// Redis-backed deployment run <c>CacheDir=none</c> and still recover.</para>
///
/// <para>Needs a real Redis; self-skips without one.</para>
/// </summary>
public sealed class SharedCacheWarmTests
{
    private const string Endpoint = "127.0.0.1:6380";
    private const string ConnString = Endpoint + ",abortConnect=false,connectTimeout=300,syncTimeout=500";

    // Lazy<Task<bool>> rather than Lazy<bool>, and awaited rather than blocked on.
    // A GetAwaiter().GetResult() here occupies a thread-pool thread while its own
    // continuation waits for one, and Lazy's ExecutionAndPublication mode then blocks
    // every other class calling .Value behind it — enough classes doing that at once
    // starves the pool and the whole run stops dead.
    private static readonly Lazy<Task<bool>> Available = new(async () =>
    {
        try
        {
            using var redis = new RedisConnection(ConnString);
            return await redis.IsHealthyAsync();
        }
        catch { return false; }
    });

    private static async Task<bool> ReadyAsync()
    {
        if (await Available.Value) return true;
        Console.WriteLine($"SKIPPED: no Redis on {Endpoint}");
        return false;
    }

    private static RedisConnection Fresh() => new(ConnString, "warm" + Guid.NewGuid().ToString("N")[..10]);

    private static ProbeCacheL2<string> L2(RedisConnection redis, TimeSpan ttl) =>
        new(redis, "test", ttl, v => v, s => s);

    /// <summary>Empties the shared cache the way a Redis restart would.</summary>
    private static async Task EmptyAsync(RedisConnection redis)
    {
        var db = redis.GetDatabase();
        Assert.NotNull(db);
        foreach (var k in new[] { "a", "b", "c" })
            await db!.KeyDeleteAsync(redis.Key("cache:test:" + k));
    }

    private static async Task<int> PresentAsync(ProbeCacheL2<string> l2)
    {
        var n = 0;
        foreach (var k in new[] { "a", "b", "c" })
            if (await l2.TryGetAsync(k) != null) n++;
        return n;
    }

    [Fact]
    public async Task AWarmRepublishesEverythingHeldInMemory()
    {
        if (!await ReadyAsync()) return;
        using var redis = Fresh();
        var l2 = L2(redis, TimeSpan.FromMinutes(5));
        var cache = new ProbeCache<string>(TimeSpan.FromMinutes(5), l2);

        await cache.GetOrCreateAsync("a", () => Task.FromResult("va"));
        await cache.GetOrCreateAsync("b", () => Task.FromResult("vb"));
        cache.Import("c", "vc", DateTime.UtcNow.AddMinutes(4)); // as the startup load would
        await Task.Delay(200);
        Assert.Equal(3, await PresentAsync(l2));

        await EmptyAsync(redis);
        Assert.Equal(0, await PresentAsync(l2));

        var warmed = cache.WarmSharedCache();
        await Task.Delay(300); // the writes are fire-and-forget

        Assert.Equal(3, warmed);
        Assert.Equal(3, await PresentAsync(l2));
        Assert.Equal("va", (await l2.TryGetAsync("a"))?.Value);
        Assert.Equal("vc", (await l2.TryGetAsync("c"))?.Value);
    }

    [Fact]
    public async Task AWarmWorksWithNoDiskTierAtAll()
    {
        // The configuration this exists for: a multi-pod deployment with a managed
        // Redis and CacheDir=none, where L1 is the only copy of these results anywhere.
        if (!await ReadyAsync()) return;
        using var redis = Fresh();
        var l2 = L2(redis, TimeSpan.FromMinutes(5));
        var cache = new ProbeCache<string>(TimeSpan.FromMinutes(5), l2, persist: false);

        await cache.GetOrCreateAsync("a", () => Task.FromResult("va"));
        await Task.Delay(200);
        Assert.Empty(cache.Export()); // nothing queued for disk, by construction

        await EmptyAsync(redis);
        Assert.Equal(1, cache.WarmSharedCache());
        await Task.Delay(300);

        Assert.Equal("va", (await l2.TryGetAsync("a"))?.Value);
    }

    [Fact]
    public async Task AWarmDoesNotOverwriteWhatIsAlreadyThere()
    {
        // Instances warm concurrently, so this must be idempotent and must not undo a
        // fresher value another instance has already published.
        if (!await ReadyAsync()) return;
        using var redis = Fresh();
        var l2 = L2(redis, TimeSpan.FromMinutes(5));
        var cache = new ProbeCache<string>(TimeSpan.FromMinutes(5), l2);
        await cache.GetOrCreateAsync("a", () => Task.FromResult("mine"));
        await Task.Delay(200);

        await EmptyAsync(redis);
        l2.Set("a", "published-by-a-peer");
        await Task.Delay(200);

        cache.WarmSharedCache();
        await Task.Delay(300);

        Assert.Equal("published-by-a-peer", (await l2.TryGetAsync("a"))?.Value);
    }

    [Fact]
    public async Task AWarmDoesNotPublishWhatShouldPersistRejected()
    {
        // The predicate keeps transient errors out of the disk bag and the L2
        // write-through alike. The re-warm is the third way into the shared cache and
        // it reads the key index, which cannot tell a timeout from a real answer — so
        // the index has to be gated too, or a value deliberately withheld from peers
        // reaches them anyway the first time Redis is emptied.
        if (!await ReadyAsync()) return;
        using var redis = Fresh();
        var l2 = L2(redis, TimeSpan.FromMinutes(5));
        var cache = new ProbeCache<string>(TimeSpan.FromMinutes(5), l2);

        await cache.GetOrCreateAsync("a", () => Task.FromResult("timed-out"),
            shouldPersist: _ => false);
        await cache.GetOrCreateAsync("b", () => Task.FromResult("vb"));
        await Task.Delay(200);

        // Cached locally either way — the predicate never gated in-process dedup.
        Assert.True(cache.TryGet("a", out var held) && held == "timed-out");
        Assert.Equal(1, cache.SharedCacheIndexCount);

        await EmptyAsync(redis);
        Assert.Equal(1, cache.WarmSharedCache());
        await Task.Delay(300);

        Assert.Null(await l2.TryGetAsync("a"));
        Assert.Equal("vb", (await l2.TryGetAsync("b"))?.Value);
    }

    [Fact]
    public async Task AWarmUsesRemainingLifeSoNothingIsResurrected()
    {
        if (!await ReadyAsync()) return;
        using var redis = Fresh();
        var l2 = L2(redis, TimeSpan.FromHours(5));
        var cache = new ProbeCache<string>(TimeSpan.FromHours(5), l2);
        cache.Import("a", "va", DateTime.UtcNow.AddMinutes(2));
        await Task.Delay(200);

        await EmptyAsync(redis);
        cache.WarmSharedCache();
        await Task.Delay(300);

        var db = redis.GetDatabase();
        var ttl = await db!.KeyTimeToLiveAsync(redis.Key("cache:test:a"));
        Assert.NotNull(ttl);
        Assert.InRange(ttl!.Value, TimeSpan.FromSeconds(30), TimeSpan.FromMinutes(3));
    }

    [Fact]
    public async Task AnEntryGoneFromMemoryIsNotRepublished()
    {
        // The index is a hint, checked against MemoryCache at use. An entry that has
        // expired locally must not be pushed back into the shared cache.
        if (!await ReadyAsync()) return;
        using var redis = Fresh();
        var l2 = L2(redis, TimeSpan.FromMinutes(5));
        var cache = new ProbeCache<string>(TimeSpan.FromMinutes(5), l2);

        cache.Import("a", "va", DateTime.UtcNow.AddMilliseconds(200));
        Assert.Equal(1, cache.SharedCacheIndexCount);
        await Task.Delay(500);
        await EmptyAsync(redis);

        Assert.Equal(0, cache.WarmSharedCache());
        Assert.Equal(0, cache.SharedCacheIndexCount); // and the hint was cleaned up
        await Task.Delay(200);
        Assert.Null(await l2.TryGetAsync("a"));
    }

    [Fact]
    public async Task PruningDropsExpiredKeysSoTheIndexTracksTheLiveSet()
    {
        // Without this the index would grow to every key the process had ever cached,
        // because MemoryCache expires lazily and never says so.
        if (!await ReadyAsync()) return;
        using var redis = Fresh();
        var cache = new ProbeCache<string>(TimeSpan.FromMinutes(5), L2(redis, TimeSpan.FromMinutes(5)));

        cache.Import("brief", "v", DateTime.UtcNow.AddMilliseconds(200));
        cache.Import("lasting", "v", DateTime.UtcNow.AddMinutes(5));
        Assert.Equal(2, cache.SharedCacheIndexCount);

        await Task.Delay(500);
        cache.PruneSharedCacheIndex();

        Assert.Equal(1, cache.SharedCacheIndexCount);
    }

    [Fact]
    public void WithoutRedisThereIsNoIndexAtAll()
    {
        // A single-instance deployment must pay nothing for machinery it cannot use.
        var cache = new ProbeCache<string>(TimeSpan.FromMinutes(5));

        cache.Set("a", "va");
        cache.Import("b", "vb", DateTime.UtcNow.AddMinutes(5));

        Assert.Equal(0, cache.SharedCacheIndexCount);
        Assert.Equal(0, cache.WarmSharedCache());
    }

    [Fact]
    public void WithTheWatchDisabledThereIsNoIndexEither()
    {
        // The index is pruned only by the watch tick, so keeping it when the watch is
        // off would leak: it would accumulate every distinct key the process ever
        // cached, expired ones included, and nothing would ever read it. Configured
        // Redis is enough to reach this — no server needs to answer, since
        // RedisConnection.Enabled reflects configuration rather than reachability.
        using var redis = new RedisConnection(
            "127.0.0.1:6399,abortConnect=false,connectTimeout=150,syncTimeout=150,connectRetry=0");
        Assert.True(redis.Enabled);

        var cache = new ProbeCache<string>(TimeSpan.FromMinutes(5), L2(redis, TimeSpan.FromMinutes(5)),
            persist: false, warmSharedCache: false);

        cache.Set("a", "va");
        cache.Import("b", "vb", DateTime.UtcNow.AddMinutes(5));

        Assert.Equal(0, cache.SharedCacheIndexCount);
        Assert.Equal(0, cache.WarmSharedCache());
        // ...while the entries themselves are still cached and served from memory.
        Assert.True(cache.TryGet("a", out var a));
        Assert.Equal("va", a);
    }

    [Fact]
    public void WithTheWatchEnabledTheIndexIsKept()
    {
        // The other half of the pair: the flag must actually be what decides, so that
        // flipping it in either direction is observable.
        using var redis = new RedisConnection(
            "127.0.0.1:6399,abortConnect=false,connectTimeout=150,syncTimeout=150,connectRetry=0");

        var cache = new ProbeCache<string>(TimeSpan.FromMinutes(5), L2(redis, TimeSpan.FromMinutes(5)),
            persist: false, warmSharedCache: true);

        cache.Set("a", "va");
        cache.Import("b", "vb", DateTime.UtcNow.AddMinutes(5));

        Assert.Equal(2, cache.SharedCacheIndexCount);
    }
}

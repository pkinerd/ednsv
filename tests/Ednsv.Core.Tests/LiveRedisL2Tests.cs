using Ednsv.Core.Services;

namespace Ednsv.Core.Tests;

/// <summary>
/// A value served from the shared Redis L2 must not be queued for persistence:
/// whichever instance fetched it has already written it out, so persisting it here
/// duplicates their work onto our disk. Needs a real Redis to produce an actual L2
/// hit, so these self-skip when nothing is listening — run
/// <c>redis-server --port 6380</c> to exercise them.
/// </summary>
public sealed class LiveRedisL2Tests
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

    private static ProbeCacheL2<string> StringL2(RedisConnection redis, TimeSpan ttl) =>
        new(redis, "test", ttl, v => v, s => s);

    [Fact]
    public async Task AnL2HitIsCachedInMemoryButNotQueuedForPersistence()
    {
        if (!await ReadyAsync()) return;
        using var redis = new RedisConnection(ConnString, "l2test" + Guid.NewGuid().ToString("N")[..8]);
        var l2 = StringL2(redis, TimeSpan.FromMinutes(5));

        // Stand in for another instance having fetched and shared this value.
        l2.Set("k", "from-peer");
        for (var i = 0; i < 50 && await l2.TryGetAsync("k") == null; i++) await Task.Delay(20);
        Assert.NotNull(await l2.TryGetAsync("k")); // the write is fire-and-forget

        var cache = new ProbeCache<string>(TimeSpan.FromMinutes(5), l2);
        var factoryRan = false;

        var got = await cache.GetOrCreateAsync("k", () =>
        {
            factoryRan = true;
            return Task.FromResult("from-network");
        });

        Assert.Equal("from-peer", got);
        Assert.False(factoryRan, "the L2 hit should have satisfied the read");
        Assert.True(cache.TryGet("k", out _), "an L2 hit should populate the local cache");
        Assert.Empty(cache.Export());
    }

    [Fact]
    public async Task ImportingFromDiskWarmsTheSharedL2()
    {
        // The disk tier is what turns a coordinated restart from "every instance
        // cold" into "warm after one load" — but only if the values it holds reach
        // the shared cache too.
        if (!await ReadyAsync()) return;
        using var redis = new RedisConnection(ConnString, "l2test" + Guid.NewGuid().ToString("N")[..8]);
        var l2 = StringL2(redis, TimeSpan.FromMinutes(5));
        var cache = new ProbeCache<string>(TimeSpan.FromMinutes(5), l2);

        cache.Import("k", "from-disk", DateTime.UtcNow.AddMinutes(4));

        for (var i = 0; i < 50 && await l2.TryGetAsync("k") == null; i++) await Task.Delay(20);
        Assert.Equal("from-disk", await l2.TryGetAsync("k"));
        Assert.Empty(cache.Export()); // still never queued back to our own disk
    }

    [Fact]
    public async Task AnImportWarmsTheL2EvenWhenL1AlreadyHasTheKey()
    {
        // This is what makes re-warming an emptied Redis work at all. A re-warm
        // re-runs the disk load on a process that has been serving for a while, so L1
        // already holds nearly every key; a warm placed after the "do we have it
        // locally?" check would therefore publish nothing. Holding a key locally says
        // nothing about whether the shared cache holds it.
        if (!await ReadyAsync()) return;
        using var redis = new RedisConnection(ConnString, "l2test" + Guid.NewGuid().ToString("N")[..8]);
        var l2 = StringL2(redis, TimeSpan.FromMinutes(5));
        var cache = new ProbeCache<string>(TimeSpan.FromMinutes(5), l2);

        // Stand in for a process that has been running: the key is in L1 already.
        cache.Import("k", "from-disk", DateTime.UtcNow.AddMinutes(4));
        for (var i = 0; i < 50 && await l2.TryGetAsync("k") == null; i++) await Task.Delay(20);
        Assert.NotNull(await l2.TryGetAsync("k"));

        // Redis is emptied underneath it.
        var db = redis.GetDatabase();
        Assert.NotNull(db);
        await db!.KeyDeleteAsync(redis.Key("cache:test:k"));
        Assert.Null(await l2.TryGetAsync("k"));

        // The re-warm: the same import again, with L1 unchanged.
        Assert.False(cache.Import("k", "from-disk", DateTime.UtcNow.AddMinutes(4)),
            "L1 already holds it, so the import itself is a no-op");

        for (var i = 0; i < 50 && await l2.TryGetAsync("k") == null; i++) await Task.Delay(20);
        Assert.Equal("from-disk", await l2.TryGetAsync("k"));
    }

    [Fact]
    public async Task WarmingTheL2DoesNotOverwriteAFresherValue()
    {
        // Every instance holds an overlapping view of the same files, so without
        // When.NotExists a rolling restart has them all racing to publish their own
        // copy over each other's.
        if (!await ReadyAsync()) return;
        using var redis = new RedisConnection(ConnString, "l2test" + Guid.NewGuid().ToString("N")[..8]);
        var l2 = StringL2(redis, TimeSpan.FromMinutes(5));

        l2.Set("k", "published-by-a-peer");
        for (var i = 0; i < 50 && await l2.TryGetAsync("k") == null; i++) await Task.Delay(20);
        Assert.NotNull(await l2.TryGetAsync("k"));

        new ProbeCache<string>(TimeSpan.FromMinutes(5), l2)
            .Import("k", "older-copy-from-our-disk", DateTime.UtcNow.AddMinutes(4));
        await Task.Delay(200); // the write is fire-and-forget; give it every chance

        Assert.Equal("published-by-a-peer", await l2.TryGetAsync("k"));
    }

    [Fact]
    public async Task WarmingTheL2UsesTheEntrysRemainingLifeNotAFullTtl()
    {
        // A full TTL would resurrect a nearly-dead entry for another whole period,
        // every time any instance restarted.
        if (!await ReadyAsync()) return;
        using var redis = new RedisConnection(ConnString, "l2test" + Guid.NewGuid().ToString("N")[..8]);
        var l2 = StringL2(redis, TimeSpan.FromHours(5));
        var cache = new ProbeCache<string>(TimeSpan.FromHours(5), l2);

        cache.Import("k", "nearly-dead", DateTime.UtcNow.AddMinutes(2));

        for (var i = 0; i < 50 && await l2.TryGetAsync("k") == null; i++) await Task.Delay(20);
        var db = redis.GetDatabase();
        Assert.NotNull(db);
        var ttl = await db!.KeyTimeToLiveAsync(redis.Key("cache:test:k"));
        Assert.NotNull(ttl);
        Assert.InRange(ttl!.Value, TimeSpan.FromSeconds(30), TimeSpan.FromMinutes(3));
    }

    [Fact]
    public async Task AnL2MissStillQueuesTheNetworkResult()
    {
        if (!await ReadyAsync()) return;
        using var redis = new RedisConnection(ConnString, "l2test" + Guid.NewGuid().ToString("N")[..8]);
        var cache = new ProbeCache<string>(TimeSpan.FromMinutes(5), StringL2(redis, TimeSpan.FromMinutes(5)));

        var got = await cache.GetOrCreateAsync("absent", () => Task.FromResult("from-network"));

        Assert.Equal("from-network", got);
        Assert.Equal(new[] { "absent" }, cache.Export().Keys);
    }
}

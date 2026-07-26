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

    private static readonly Lazy<bool> Available = new(() =>
    {
        try
        {
            using var redis = new RedisConnection(ConnString);
            return redis.IsHealthyAsync().GetAwaiter().GetResult();
        }
        catch { return false; }
    });

    private static bool Ready()
    {
        if (Available.Value) return true;
        Console.WriteLine($"SKIPPED: no Redis on {Endpoint}");
        return false;
    }

    private static ProbeCacheL2<string> StringL2(RedisConnection redis, TimeSpan ttl) =>
        new(redis, "test", ttl, v => v, s => s);

    [Fact]
    public async Task AnL2HitIsCachedInMemoryButNotQueuedForPersistence()
    {
        if (!Ready()) return;
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
        if (!Ready()) return;
        using var redis = new RedisConnection(ConnString, "l2test" + Guid.NewGuid().ToString("N")[..8]);
        var l2 = StringL2(redis, TimeSpan.FromMinutes(5));
        var cache = new ProbeCache<string>(TimeSpan.FromMinutes(5), l2);

        cache.Import("k", "from-disk", DateTime.UtcNow.AddMinutes(4));

        for (var i = 0; i < 50 && await l2.TryGetAsync("k") == null; i++) await Task.Delay(20);
        Assert.Equal("from-disk", await l2.TryGetAsync("k"));
        Assert.Empty(cache.Export()); // still never queued back to our own disk
    }

    [Fact]
    public async Task WarmingTheL2DoesNotOverwriteAFresherValue()
    {
        // Every instance holds an overlapping view of the same files, so without
        // When.NotExists a rolling restart has them all racing to publish their own
        // copy over each other's.
        if (!Ready()) return;
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
        if (!Ready()) return;
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
        if (!Ready()) return;
        using var redis = new RedisConnection(ConnString, "l2test" + Guid.NewGuid().ToString("N")[..8]);
        var cache = new ProbeCache<string>(TimeSpan.FromMinutes(5), StringL2(redis, TimeSpan.FromMinutes(5)));

        var got = await cache.GetOrCreateAsync("absent", () => Task.FromResult("from-network"));

        Assert.Equal("from-network", got);
        Assert.Equal(new[] { "absent" }, cache.Export().Keys);
    }
}

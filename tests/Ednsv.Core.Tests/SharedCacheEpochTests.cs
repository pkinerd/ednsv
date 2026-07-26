using Ednsv.Core.Services;

namespace Ednsv.Core.Tests;

/// <summary>
/// Detecting that the shared cache has been emptied under a running instance. Needs a
/// real Redis to be worth anything — the whole behaviour is about what a flush looks
/// like from the outside — so these self-skip when nothing is listening. Run
/// <c>redis-server --port 6380</c> to exercise them.
/// </summary>
public sealed class SharedCacheEpochTests
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

    /// <summary>A namespace of its own per test, so a flush can be simulated by
    /// deleting just this test's keys rather than the whole server.</summary>
    private static RedisConnection Fresh() =>
        new(ConnString, "epoch" + Guid.NewGuid().ToString("N")[..10]);

    private static async Task SimulateFlushAsync(RedisConnection redis)
    {
        var db = redis.GetDatabase();
        Assert.NotNull(db);
        await db!.KeyDeleteAsync(redis.Key("cache-epoch"));
    }

    [Fact]
    public async Task TheFirstCheckNeverAsksForARewarm()
    {
        // Startup has just loaded from disk, which warms the L2 already.
        if (!await ReadyAsync()) return;
        using var redis = Fresh();

        Assert.False(await new SharedCacheEpoch(redis).ShouldRewarmAsync());
    }

    [Fact]
    public async Task AnUnchangedEpochAsksForNothing()
    {
        if (!await ReadyAsync()) return;
        using var redis = Fresh();
        var epoch = new SharedCacheEpoch(redis);

        await epoch.ShouldRewarmAsync();
        for (var i = 0; i < 5; i++)
            Assert.False(await epoch.ShouldRewarmAsync());
    }

    [Fact]
    public async Task AFlushAsksForARewarm()
    {
        if (!await ReadyAsync()) return;
        using var redis = Fresh();
        var epoch = new SharedCacheEpoch(redis);
        await epoch.ShouldRewarmAsync();
        var before = epoch.Known;

        await SimulateFlushAsync(redis);

        Assert.True(await epoch.ShouldRewarmAsync());
        Assert.NotNull(epoch.Known);
        Assert.NotEqual(before, epoch.Known);
    }

    [Fact]
    public async Task AFlushIsReportedOnceNotOnEveryTickAfterwards()
    {
        if (!await ReadyAsync()) return;
        using var redis = Fresh();
        var epoch = new SharedCacheEpoch(redis);
        await epoch.ShouldRewarmAsync();

        await SimulateFlushAsync(redis);
        Assert.True(await epoch.ShouldRewarmAsync());

        Assert.False(await epoch.ShouldRewarmAsync());
        Assert.False(await epoch.ShouldRewarmAsync());
    }

    [Fact]
    public async Task AnInstanceRewarmsWhenAnotherOneNoticedTheFlushFirst()
    {
        // Both must re-warm, not just the one that spotted it. With a pod-local cache
        // directory each instance holds only its own share, so a single warmer would
        // republish a fraction of what is on disk across the fleet.
        if (!await ReadyAsync()) return;
        using var redis = Fresh();
        var a = new SharedCacheEpoch(redis);
        var b = new SharedCacheEpoch(redis);
        await a.ShouldRewarmAsync();
        await b.ShouldRewarmAsync();
        Assert.Equal(a.Known, b.Known);

        await SimulateFlushAsync(redis);

        Assert.True(await a.ShouldRewarmAsync());   // A notices and re-establishes
        Assert.True(await b.ShouldRewarmAsync());   // B sees A's new epoch and follows
        Assert.Equal(a.Known, b.Known);

        Assert.False(await a.ShouldRewarmAsync());  // and then both settle
        Assert.False(await b.ShouldRewarmAsync());
    }

    [Fact]
    public async Task AnInstanceStartingAfterOthersAdoptsTheirEpochWithoutRewarming()
    {
        if (!await ReadyAsync()) return;
        using var redis = Fresh();
        var established = new SharedCacheEpoch(redis);
        await established.ShouldRewarmAsync();

        var joiner = new SharedCacheEpoch(redis);

        Assert.False(await joiner.ShouldRewarmAsync());
        Assert.Equal(established.Known, joiner.Known);
    }

    [Fact]
    public async Task AnUnreachableRedisIsNotMistakenForAFlush()
    {
        // Otherwise an outage would trigger a full disk re-read on every tick for as
        // long as it lasted.
        using var redis = new RedisConnection(
            "127.0.0.1:6399,abortConnect=false,connectTimeout=150,syncTimeout=150,connectRetry=0",
            "epochdown");
        var epoch = new SharedCacheEpoch(redis);

        for (var i = 0; i < 3; i++)
            Assert.False(await epoch.ShouldRewarmAsync());
    }

    [Fact]
    public async Task AnUnconfiguredRedisIsInert()
    {
        using var redis = new RedisConnection(null);

        Assert.False(await new SharedCacheEpoch(redis).ShouldRewarmAsync());
    }
}

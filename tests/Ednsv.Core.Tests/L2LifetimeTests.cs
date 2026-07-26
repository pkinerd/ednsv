using Ednsv.Core.Services;

namespace Ednsv.Core.Tests;

/// <summary>
/// What the shared cache does with "no expiry".
///
/// <para><c>CacheTtlHours=0</c> means the memory tier does not expire, which is safe
/// because it is keyed and therefore bounded by distinct keys. Redis is a fixed
/// allocation shared by every pod, so the same setting there meant keys that never
/// aged out — and, because a <c>volatile-*</c> eviction policy may only evict keys
/// carrying a TTL, a full server with none of them rejected writes rather than shedding
/// a cache entry. The disk tier already had a floor for exactly this
/// (<see cref="DiskCacheService.UncappedRetention"/>); this is the same floor.</para>
///
/// <para>Needs a real Redis; self-skips without one.</para>
/// </summary>
public sealed class L2LifetimeTests
{
    private const string Endpoint = "127.0.0.1:6380";
    private const string ConnString = Endpoint + ",abortConnect=false,connectTimeout=300,syncTimeout=500";

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

    private static RedisConnection Fresh() => new(ConnString, "ttl" + Guid.NewGuid().ToString("N")[..10]);

    private static ProbeCacheL2<string> L2(RedisConnection redis, TimeSpan? ttl) =>
        new(redis, "test", ttl, v => v, s => s);

    /// <summary>Within a minute — the value is computed from "now" at write time.</summary>
    private static void AssertNear(TimeSpan expected, TimeSpan actual) =>
        Assert.InRange(actual, expected - TimeSpan.FromMinutes(1), expected + TimeSpan.FromMinutes(1));

    /// <summary>Present, and with no expiry — so a `volatile-*` policy cannot touch it.</summary>
    private static async Task AssertPersistentAsync(RedisConnection redis, string suffix)
    {
        var db = redis.GetDatabase();
        var key = redis.Key(suffix);
        Assert.True(await db!.KeyExistsAsync(key), $"{suffix} was never written");
        Assert.Null(await db.KeyTimeToLiveAsync(key));
    }

    private static async Task<TimeSpan?> TtlOfAsync(RedisConnection redis, string key)
    {
        var db = redis.GetDatabase();
        Assert.NotNull(db);
        return await db!.KeyTimeToLiveAsync(redis.Key("cache:test:" + key));
    }

    [Fact]
    public async Task WithoutAConfiguredTtlKeysStillExpire()
    {
        // The write path. A persistent key here is one nothing will ever remove, in the
        // one tier that cannot grow.
        if (!await ReadyAsync()) return;
        using var redis = Fresh();

        L2(redis, null).Set("k", "v");
        await Task.Delay(200);

        var ttl = await TtlOfAsync(redis, "k");
        Assert.NotNull(ttl);
        AssertNear(DiskCacheService.UncappedRetention, ttl!.Value);
    }

    [Fact]
    public async Task AConfiguredTtlIsUsedAsIs()
    {
        if (!await ReadyAsync()) return;
        using var redis = Fresh();

        L2(redis, TimeSpan.FromMinutes(30)).Set("k", "v");
        await Task.Delay(200);

        var ttl = await TtlOfAsync(redis, "k");
        Assert.NotNull(ttl);
        AssertNear(TimeSpan.FromMinutes(30), ttl!.Value);
    }

    [Fact]
    public async Task ATtlLongerThanTheFloorIsNotShortened()
    {
        // The floor is a fallback for "no expiry", not a cap: an operator asking for a
        // week gets a week.
        if (!await ReadyAsync()) return;
        using var redis = Fresh();

        L2(redis, TimeSpan.FromDays(7)).Set("k", "v");
        await Task.Delay(200);

        var ttl = await TtlOfAsync(redis, "k");
        Assert.NotNull(ttl);
        AssertNear(TimeSpan.FromDays(7), ttl!.Value);
    }

    [Fact]
    public async Task AnUnboundedRemainingLifeIsCappedAtWhatAFreshWriteWouldGet()
    {
        // The re-warm path. An L1 entry with no expiry has DateTime.MaxValue, so its
        // "remaining life" arrives here as nearly eight thousand years — and Redis
        // stores it, leaving the same entry with a different lifetime depending on
        // whether it was written normally or republished after a flush.
        if (!await ReadyAsync()) return;
        using var redis = Fresh();

        L2(redis, null).SetIfAbsent("k", "v", DateTime.MaxValue - DateTime.UtcNow);
        await Task.Delay(200);

        var ttl = await TtlOfAsync(redis, "k");
        Assert.NotNull(ttl);
        AssertNear(DiskCacheService.UncappedRetention, ttl!.Value);
    }

    [Fact]
    public async Task ARemainingLifeShorterThanTheFloorIsHonoured()
    {
        // Still the point of SetIfAbsent's contract: a nearly-dead entry is not
        // resurrected for a fresh full period.
        if (!await ReadyAsync()) return;
        using var redis = Fresh();

        L2(redis, null).SetIfAbsent("k", "v", TimeSpan.FromMinutes(5));
        await Task.Delay(200);

        var ttl = await TtlOfAsync(redis, "k");
        Assert.NotNull(ttl);
        AssertNear(TimeSpan.FromMinutes(5), ttl!.Value);
    }

    [Fact]
    public async Task TheCoordinationKeysAreLeftPersistentSoNothingCanEvictThem()
    {
        // The other half of the eviction contract, and the reason the floor above lives
        // in ProbeCacheL2 rather than anywhere shared: config:head and cache-epoch must
        // carry NO TTL, because `volatile-*` may only evict keys that have one. Give
        // them a lifetime "for consistency" and they become eviction candidates — and
        // losing config:head leaves a pod serving stale config, or missing a token
        // revocation, with nothing logged.
        if (!await ReadyAsync()) return;
        using var redis = Fresh();
        var db = redis.GetDatabase();
        Assert.NotNull(db);

        var dir = Path.Combine(Path.GetTempPath(), $"ednsv-persist-{Guid.NewGuid():N}");
        try
        {
            var cfg = new ConfigService(dir, redis, freshnessWindow: TimeSpan.Zero);

            // The beacon is published lazily on first load, not by the constructor —
            // so Snapshot() is what exercises that path, and asserting before it would
            // pass against a key that simply is not there yet.
            _ = cfg.Snapshot();
            await new SharedCacheEpoch(redis).ShouldRewarmAsync();
            L2(redis, null).Set("k", "v");
            await Task.Delay(300);

            await AssertPersistentAsync(redis, "config:head");
            await AssertPersistentAsync(redis, "cache-epoch");

            // ConfigService has a third beacon write, in InitBeaconLocked. It is not
            // covered here and cannot be: EnsureFresh runs first and publishes the key,
            // so that branch only ever sees a beacon already present and adopts it
            // instead of writing. Giving it a TTL is therefore a mutation no test kills,
            // because the line does not execute.

            // The second beacon write path: republished when EnsureFresh finds it gone.
            await db!.KeyDeleteAsync(redis.Key("config:head"));
            cfg.EnsureFresh(force: true);
            await Task.Delay(200);
            await AssertPersistentAsync(redis, "config:head");

            // ...while the cache entry beside them is evictable.
            Assert.NotNull(await db.KeyTimeToLiveAsync(redis.Key("cache:test:k")));
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { /* best effort */ }
        }
    }

    [Fact]
    public async Task EveryKeyIsEvictableSoVolatilePoliciesHaveSomethingToShed()
    {
        // The operational point of all of the above: `volatile-lru` may only evict keys
        // that carry a TTL, so a keyspace with none of them cannot shed anything.
        if (!await ReadyAsync()) return;
        using var redis = Fresh();
        var l2 = L2(redis, null);

        for (var i = 0; i < 20; i++) l2.Set($"k{i}", "v");
        await Task.Delay(300);

        var db = redis.GetDatabase();
        for (var i = 0; i < 20; i++)
        {
            var ttl = await db!.KeyTimeToLiveAsync(redis.Key($"cache:test:k{i}"));
            Assert.True(ttl.HasValue, $"k{i} was written with no TTL — volatile-lru could not evict it");
        }
    }
}

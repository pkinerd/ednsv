using Ednsv.Core.Services;
using StackExchange.Redis;

namespace Ednsv.Core.Tests;

/// <summary>
/// What the shared cache does with "no expiry".
///
/// <para><c>CacheTtlHours=0</c> means the memory tier does not expire, which is safe
/// because it is keyed and therefore bounded by distinct keys. Redis is a fixed
/// allocation shared by every pod, so the same setting there meant keys that never
/// aged out — and, because a <c>volatile-*</c> eviction policy may only evict keys
/// carrying a TTL, a full server with none of them rejected writes rather than shedding
/// a cache entry. So the L2 carries its own floor,
/// <see cref="ProbeCacheL2.UncappedLifetime"/> — the disk tier's floor is a separate
/// constant solving a separate problem, and these tests pin this one.</para>
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
        AssertNear(ProbeCacheL2.UncappedLifetime, ttl!.Value);
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
        AssertNear(ProbeCacheL2.UncappedLifetime, ttl!.Value);
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

    // ── The read path: L2 → L1 ───────────────────────────────────────────
    //
    // Everything above covers what lands in Redis. These cover the return leg, which
    // is where the two tiers drift apart if a hit is allowed to restart the clock.
    // Observed through a re-warm, because that republishes each L1 entry with its
    // remaining life — so the TTL that lands back in Redis is the expiry L1 was
    // actually holding, which nothing else exposes.

    /// <summary>Seed the shared cache the way a peer pod would, with a chosen lifetime.</summary>
    private static async Task PeerWroteAsync(RedisConnection redis, string key, TimeSpan? ttl)
    {
        var db = redis.GetDatabase();
        Assert.NotNull(db);
        // `when:` named rather than positional: StackExchange.Redis 3.x added a
        // StringSet overload taking its own Expiration type, and a bare three-argument
        // call now binds to that one, which has no conversion from TimeSpan?.
        // When.Always is what the old overload defaulted to, so behaviour is unchanged.
        await db!.StringSetAsync(redis.Key("cache:test:" + key), "from-a-peer", ttl, when: When.Always);
    }

    /// <summary>The lifetime L1 was holding, read back by emptying Redis and re-warming.</summary>
    private static async Task<TimeSpan?> L1LifetimeViaWarmAsync(
        RedisConnection redis, ProbeCache<string> cache, string key)
    {
        var db = redis.GetDatabase();
        Assert.NotNull(db);
        await db!.KeyDeleteAsync(redis.Key("cache:test:" + key));

        cache.WarmSharedCache();
        await Task.Delay(300); // the writes are fire-and-forget

        return await TtlOfAsync(redis, key);
    }

    [Fact]
    public async Task AnL2HitDoesNotRestartTheClockInL1()
    {
        // A peer wrote this with a minute left — a DNS answer bounded by its own record
        // TTL, say. Caching it locally for a fresh full period would let our copy
        // outlive the entry it was read from, and every subsequent hit would widen the
        // gap.
        if (!await ReadyAsync()) return;
        using var redis = Fresh();

        var ours = TimeSpan.FromMinutes(30);
        var cache = new ProbeCache<string>(ours, L2(redis, ours));
        await PeerWroteAsync(redis, "k", TimeSpan.FromMinutes(1));

        Assert.Equal("from-a-peer", await cache.GetOrCreateAsync("k", () => Task.FromResult("network")));

        var held = await L1LifetimeViaWarmAsync(redis, cache, "k");

        Assert.NotNull(held);
        Assert.True(held!.Value <= TimeSpan.FromMinutes(1),
            $"L1 held the hit for {held} against a minute left on the shared key");
        Assert.True(held.Value > TimeSpan.Zero, "the entry expired immediately");
    }

    [Fact]
    public async Task AnL2HitIsStillHeldToOurOwnTtl()
    {
        // The other direction: a peer running a longer CacheTtlHours must not extend
        // ours. The shared key's life bounds us; it does not license us.
        if (!await ReadyAsync()) return;
        using var redis = Fresh();

        var ours = TimeSpan.FromMinutes(5);
        var cache = new ProbeCache<string>(ours, L2(redis, ours));
        await PeerWroteAsync(redis, "k", TimeSpan.FromDays(7));

        Assert.Equal("from-a-peer", await cache.GetOrCreateAsync("k", () => Task.FromResult("network")));

        var held = await L1LifetimeViaWarmAsync(redis, cache, "k");

        Assert.NotNull(held);
        Assert.True(held!.Value <= ours, $"a peer's seven-day key stretched our own TTL to {held}");
    }

    [Fact]
    public async Task ASharedKeyWithNoExpiryLeavesOurOwnTtlGoverning()
    {
        // Nothing this class writes is ever without an expiry, so this is a key from
        // somewhere else. "No expiry" is not a licence to cache forever — our TTL
        // governs, exactly as it did before the remaining life was read at all.
        if (!await ReadyAsync()) return;
        using var redis = Fresh();

        var ours = TimeSpan.FromMinutes(5);
        var cache = new ProbeCache<string>(ours, L2(redis, ours));
        await PeerWroteAsync(redis, "k", ttl: null);

        Assert.Equal("from-a-peer", await cache.GetOrCreateAsync("k", () => Task.FromResult("network")));

        var held = await L1LifetimeViaWarmAsync(redis, cache, "k");

        Assert.NotNull(held);
        AssertNear(ours, held!.Value);
    }

    [Fact]
    public async Task WithNoConfiguredTtlAnL2HitTakesTheSharedKeysRemainingLife()
    {
        // CacheTtlHours=0 means L1 does not expire — but an entry read from a tier that
        // *does* expire is not ours to keep forever. Preferring "never" over a real
        // bound is the drift this prevents, and the shared key is the only bound there
        // is here.
        if (!await ReadyAsync()) return;
        using var redis = Fresh();

        var cache = new ProbeCache<string>(ttl: null, L2(redis, null));
        await PeerWroteAsync(redis, "k", TimeSpan.FromMinutes(10));

        Assert.Equal("from-a-peer", await cache.GetOrCreateAsync("k", () => Task.FromResult("network")));

        var held = await L1LifetimeViaWarmAsync(redis, cache, "k");

        Assert.NotNull(held);
        Assert.True(held!.Value <= TimeSpan.FromMinutes(10),
            $"L1 held the hit for {held} against ten minutes left on the shared key");
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

            // LoadOrSeed, not just the constructor: the beacon is published from
            // InitBeaconLocked once the config file exists, and asserting before that
            // would pass against a key that simply is not there yet. It also matches
            // how every real caller starts, which matters — EnsureFresh will not
            // publish a head for a config file it has not been able to read.
            _ = cfg.LoadOrSeed(new AppConfig());
            await new SharedCacheEpoch(redis).ShouldRewarmAsync();
            L2(redis, null).Set("k", "v");
            await Task.Delay(300);

            await AssertPersistentAsync(redis, "config:head");
            await AssertPersistentAsync(redis, "cache-epoch");

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

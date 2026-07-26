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
        // The load-bearing property: nothing sweeps this map on a timer, so a stale
        // entry must be refused by the read itself or the TTL would be advisory.
        var map = Map(50);
        map.Set("k", "v");
        Thread.Sleep(120);

        Assert.False(map.TryGetValue("k", out _));
        Assert.Equal(0, map.Count);
        Assert.Empty(map.Snapshot());
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
        Assert.Equal(1, map.Count);
    }

    // ── Bounded growth ───────────────────────────────────────────────────

    [Fact]
    public async Task ExpiredEntriesAreReleasedAfterALaterWrite()
    {
        // Reads alone keep the TTL honest; this is what keeps *memory* bounded for keys
        // written once and never read again — which is most of them.
        var map = new ExpiringMap<string, string>(
            TimeSpan.FromMilliseconds(50), pruneInterval: TimeSpan.FromMilliseconds(50));
        for (var i = 0; i < 200; i++) map.Set($"k{i}", "v");

        await Task.Delay(120);
        Assert.Equal(0, map.Count);              // nothing is readable...
        Assert.Equal(200, map.AllocatedCount);   // ...but the memory is still held

        map.Set("trigger", "v"); // the write that schedules the sweep

        // Asynchronous by design — the sweep runs on the thread pool, not here — so this
        // waits for it rather than asserting immediately.
        await WaitUntil(() => map.AllocatedCount <= 2, TimeSpan.FromSeconds(5));
        Assert.Equal(1, map.Count);
    }

    [Fact]
    public async Task TheSweepDoesNotRunOnTheCallersThread()
    {
        // The point of the exercise: these writes are completed by probe threads coming
        // back from the network, and walking the map is not their work. Proved with a
        // map big enough that an inline scan would be visible, and by the sweep still
        // being unfinished when the write returns.
        var map = new ExpiringMap<string, string>(
            TimeSpan.FromMilliseconds(50), pruneInterval: TimeSpan.FromMilliseconds(50));
        for (var i = 0; i < 20_000; i++) map.Set($"k{i}", "v");

        await Task.Delay(120);
        Assert.Equal(20_000, map.AllocatedCount);

        map.Set("trigger", "v");

        // If the prune were inline, the write above could not have returned with the map
        // still full. This is a race by nature, so it is one-directional: a pass is
        // proof of off-thread execution, and the wait below is what makes a fluke
        // scheduling delay fail loudly rather than silently.
        var stillFullOnReturn = map.AllocatedCount > 1_000;

        await WaitUntil(() => map.AllocatedCount <= 2, TimeSpan.FromSeconds(10));
        Assert.True(stillFullOnReturn,
            "the sweep completed before the write returned, which means it ran inline");
    }

    [Fact]
    public async Task ManyConcurrentWritersScheduleOneSweepBetweenThem()
    {
        // What this pins is the observable contract — a burst of concurrent writes costs
        // one sweep, not one per writer. It does **not** isolate the `_pruneScheduled`
        // gate: removing that leaves this green, because the interval check closes the
        // window before a second thread can get through it even with 64 released at once.
        // The gate is what turns that from a very high probability into a guarantee, and
        // it is the only thing covering a scan that outlives its own interval; neither is
        // reachable from here.
        //
        // The map's own TTL is long and the entries to be swept carry short expiries of
        // their own, so nothing the burst writes can expire while the test is still
        // watching.
        var map = new ExpiringMap<string, string>(
            TimeSpan.FromMinutes(10), pruneInterval: TimeSpan.FromMilliseconds(200));
        for (var i = 0; i < 2_000; i++)
            map.TryAdd($"brief{i}", "v", DateTime.UtcNow.AddMilliseconds(50));

        await Task.Delay(250); // past both the entries' expiry and the prune interval
        Assert.Equal(0, map.PruneRuns);

        // Dedicated threads, not Task.Run: 64 pool tasks all blocking together starve the
        // pool, which then injects threads about twice a second — the writes trickle in
        // over a minute, cross the interval repeatedly, and the test ends up measuring
        // its own starvation instead of the gate.
        const int writers = 64;
        var release = new ManualResetEventSlim(false);
        var threads = Enumerable.Range(0, writers).Select(i => new Thread(() =>
        {
            release.Wait();
            map.Set($"burst{i}", "v");
        }) { IsBackground = true }).ToList();

        foreach (var t in threads) t.Start();
        Thread.Sleep(50);   // let them all reach the wait
        release.Set();
        foreach (var t in threads) t.Join();

        await WaitUntil(() => map.PruneRuns >= 1, TimeSpan.FromSeconds(5));
        await Task.Delay(150); // give any extra sweeps time to show up

        Assert.Equal(1, map.PruneRuns);
        Assert.Equal(writers, map.Count);
    }

    [Fact]
    public async Task TheGateIsReleasedSoLaterSweepsStillRun()
    {
        // A gate that is taken and never given back would leave the first sweep as the
        // only one the process ever performs.
        var map = new ExpiringMap<string, string>(
            TimeSpan.FromMilliseconds(40), pruneInterval: TimeSpan.FromMilliseconds(40));

        map.Set("a", "v");
        await Task.Delay(100);
        map.Set("b", "v");
        await WaitUntil(() => map.PruneRuns >= 1, TimeSpan.FromSeconds(5));

        await Task.Delay(100);
        map.Set("c", "v");
        await WaitUntil(() => map.PruneRuns >= 2, TimeSpan.FromSeconds(5));

        Assert.True(map.PruneRuns >= 2, $"only {map.PruneRuns} sweep(s) ever ran");
    }

    [Fact]
    public async Task TheSweepIsRateLimitedRatherThanRunPerWrite()
    {
        var map = new ExpiringMap<string, string>(
            TimeSpan.FromMinutes(10), pruneInterval: TimeSpan.FromSeconds(30));
        for (var i = 0; i < 100; i++)
            map.TryAdd($"brief{i}", "v", DateTime.UtcNow.AddMilliseconds(30));
        await Task.Delay(80);

        // A fresh map has just "pruned" (its clock starts at construction), so with a
        // 30-second interval nothing may sweep — however many writes arrive.
        for (var i = 0; i < 1_000; i++) map.Set($"lasting{i}", "v");
        await Task.Delay(200);

        Assert.Equal(0, map.PruneRuns);            // 1,000 writes, no sweep
        Assert.Equal(1_100, map.AllocatedCount);   // the 100 dead keys are still held
        Assert.Equal(1_000, map.Count);            // and correctly unreadable
    }

    [Fact]
    public async Task AnIdleMapIsNeverSwept()
    {
        // No timer, so nothing wakes up to walk a map that nobody is writing to — which
        // is safe precisely because a map nobody writes to cannot be growing.
        var map = new ExpiringMap<string, string>(
            TimeSpan.FromMilliseconds(30), pruneInterval: TimeSpan.FromMilliseconds(30));
        map.Set("k", "v");

        await Task.Delay(300);

        Assert.Equal(1, map.AllocatedCount); // held, though expired
        Assert.Equal(0, map.Count);          // and correctly unreadable throughout
    }

    private static async Task WaitUntil(Func<bool> condition, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            if (condition()) return;
            await Task.Delay(20);
        }
        Assert.True(condition(), "condition was still false at the timeout");
    }

    [Fact]
    public void PruneDropsOnlyWhatHasExpired()
    {
        var map = new ExpiringMap<string, string>(TimeSpan.FromMinutes(1));
        map.TryAdd("brief", "v", DateTime.UtcNow.AddMilliseconds(50));
        map.Set("lasting", "v");

        Thread.Sleep(120);
        map.Prune();

        Assert.Equal(1, map.Count);
        Assert.True(map.TryGetValue("lasting", out _));
    }

    [Fact]
    public void TryRemoveTakesTheEntryOut()
    {
        var map = Map();
        map.Set("k", "v");

        Assert.True(map.TryRemove("k"));
        Assert.False(map.TryRemove("k"));
        Assert.False(map.TryGetValue("k", out _));
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

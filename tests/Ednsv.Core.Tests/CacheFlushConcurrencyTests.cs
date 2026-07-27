using System.Collections.Concurrent;
using System.Text.Json;
using Ednsv.Core.Services;

namespace Ednsv.Core.Tests;

/// <summary>
/// The flush deliberately holds no lock across its write: it snapshots the bags,
/// writes, then removes exactly what it wrote by reference. That is only safe if
/// concurrent fetches can neither be lost nor persisted twice, which is precisely
/// the kind of property that is silently wrong rather than obviously wrong.
///
/// <para>These run many writers against many flushes and check the invariant that
/// matters: <b>every value fetched is written exactly once</b>, and once the writers
/// stop, a final flush leaves the bag empty.</para>
/// </summary>
public sealed class CacheFlushConcurrencyTests
{
    private const int Writers = 8;
    private const int PerWriter = 500;

    [Fact]
    public async Task EveryFetchIsPersistedExactlyOnceAcrossConcurrentFlushes()
    {
        var cache = new ProbeCache<string>(TimeSpan.FromMinutes(10));
        var written = new ConcurrentBag<string>();
        using var stop = new CancellationTokenSource();

        var flusher = Task.Run(async () =>
        {
            while (!stop.IsCancellationRequested)
            {
                Drain(cache, written);
                await Task.Yield();
            }
        });

        var writers = Enumerable.Range(0, Writers).Select(w => Task.Run(async () =>
        {
            for (var i = 0; i < PerWriter; i++)
                await cache.GetOrCreateAsync($"w{w}:k{i}", () => Task.FromResult($"w{w}:v{i}"));
        })).ToArray();

        await Task.WhenAll(writers);
        stop.Cancel();
        await flusher;

        Drain(cache, written); // the shutdown flush

        var all = written.ToList();
        Assert.Equal(Writers * PerWriter, all.Count);              // nothing lost
        Assert.Equal(all.Count, all.Distinct().Count());           // nothing written twice
        Assert.Empty(cache.CollectPending("t", V).Records);        // and the bag drained
    }

    [Fact]
    public async Task AValueWrittenWhileAFlushIsInFlightIsNeverDroppedByItsCommit()
    {
        // Deterministic rather than racy: the writer is released only once the flush
        // has snapshotted, and the commit happens only once the writer has landed. A
        // flush that removed by key rather than by reference would delete the newer
        // value here and lose the update silently — and a probabilistic version of
        // this test catches that only some of the time.
        var cache = new ProbeCache<string>(TimeSpan.FromMinutes(10));
        var written = new ConcurrentBag<string>();

        var snapshotted = new TaskCompletionSource();
        var overwritten = new TaskCompletionSource();

        for (var i = 0; i < 20; i++) cache.Set($"shared:{i}", "old");

        var flusher = Task.Run(async () =>
        {
            var pending = cache.CollectPending("t", V);
            Assert.Equal(20, pending.Records.Count);
            foreach (var record in pending.Records)
                written.Add($"{record.Key}={record.Value!.GetValue<string>()}");

            snapshotted.SetResult();
            await overwritten.Task;   // the writer lands mid-"write"
            pending.Commit();
        });

        await snapshotted.Task;
        for (var i = 0; i < 20; i++) cache.Set($"shared:{i}", "new");
        overwritten.SetResult();
        await flusher;

        // Every replacement must still be queued — the commit removed only what it
        // actually persisted.
        var stillQueued = cache.CollectPending("t", V).Records;
        Assert.Equal(20, stillQueued.Count);
        Assert.All(stillQueued, r => Assert.Equal("new", r.Value!.GetValue<string>()));

        // And the flush recorded the values it did snapshot, not the newer ones.
        Assert.All(written, w => Assert.EndsWith("=old", w));
    }

    private static System.Text.Json.Nodes.JsonNode? V(string v) => JsonSerializer.SerializeToNode(v);

    /// <summary>
    /// One flush: collect, "write", commit — the shape of <c>SaveAsync</c>.
    ///
    /// <para>The yield between collect and commit is the point, not padding. A real
    /// flush spends milliseconds writing a file there, and that gap is exactly the
    /// window in which a fresh fetch can land on a key already snapshotted. Without
    /// it the window is a few instructions wide and a broken commit slips through
    /// most runs.</para>
    /// </summary>
    private static void Drain(ProbeCache<string> cache, ConcurrentBag<string> written)
    {
        var pending = cache.CollectPending("t", V);
        if (pending.Records.Count == 0) return;

        foreach (var record in pending.Records)
            written.Add($"{record.Key}={record.Value!.GetValue<string>()}");

        Thread.Sleep(1); // stand in for the write
        pending.Commit();
    }
}

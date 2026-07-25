using Ednsv.Core.Services;

namespace Ednsv.Core.Tests;

/// <summary>
/// Exercises the write lease against a real Redis. CI runs no Redis service, so
/// these self-skip when nothing is listening on <see cref="Endpoint"/>; run a local
/// <c>redis-server --port 6380</c> to have them execute. They cover what the
/// unreachable-Redis tests cannot: that the lease actually excludes, releases,
/// namespaces, and expires — and that layering it over the compare-and-set does
/// not weaken the lost-update protection the CAS provides.
/// </summary>
public sealed class LiveRedisLeaseTests
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

    /// <summary>True when the test body should run. Logs the skip so a silent
    /// pass is never mistaken for real coverage.</summary>
    private static bool Ready()
    {
        if (Available.Value) return true;
        Console.WriteLine($"SKIPPED: no Redis on {Endpoint}");
        return false;
    }

    private static RedisConnection Connect(string ns) => new(ConnString, ns);
    private static string FreshNamespace() => "test" + Guid.NewGuid().ToString("N")[..10];
    private static string TempDir() => Path.Combine(Path.GetTempPath(), $"ednsv-live-{Guid.NewGuid():N}");

    [Fact]
    public void Lease_ExcludesASecondHolderAndFreesOnRelease()
    {
        if (!Ready()) return;
        var ns = FreshNamespace();
        using var a = Connect(ns);
        using var b = Connect(ns);

        var first = a.TryAcquireLock("config:write", TimeSpan.FromSeconds(10), TimeSpan.FromMilliseconds(200));
        Assert.NotNull(first);

        Assert.Null(b.TryAcquireLock("config:write", TimeSpan.FromSeconds(10), TimeSpan.FromMilliseconds(300)));

        first!.Dispose();
        var second = b.TryAcquireLock("config:write", TimeSpan.FromSeconds(10), TimeSpan.FromMilliseconds(500));
        Assert.NotNull(second);
        second!.Dispose();
    }

    [Fact]
    public void Lease_IsNamespacedPerDeployment()
    {
        if (!Ready()) return;
        using var one = Connect(FreshNamespace());
        using var two = Connect(FreshNamespace());

        // Two deployments sharing a Redis must not block each other.
        var a = one.TryAcquireLock("config:write", TimeSpan.FromSeconds(10), TimeSpan.FromMilliseconds(200));
        var b = two.TryAcquireLock("config:write", TimeSpan.FromSeconds(10), TimeSpan.FromMilliseconds(200));

        Assert.NotNull(a);
        Assert.NotNull(b);
        a!.Dispose();
        b!.Dispose();
    }

    [Fact]
    public void Lease_ExpiresSoADeadHolderCannotBlockForever()
    {
        if (!Ready()) return;
        var ns = FreshNamespace();
        using var dead = Connect(ns);
        using var next = Connect(ns);

        // Taken and never released, as if the holder were killed mid-write.
        Assert.NotNull(dead.TryAcquireLock("config:write", TimeSpan.FromSeconds(1), TimeSpan.FromMilliseconds(200)));

        Thread.Sleep(TimeSpan.FromMilliseconds(1400));

        var recovered = next.TryAcquireLock("config:write", TimeSpan.FromSeconds(5), TimeSpan.FromMilliseconds(500));
        Assert.NotNull(recovered);
        recovered!.Dispose();
    }

    [Fact]
    public void ConcurrentSavesAllLandWithACoherentHistory()
    {
        if (!Ready()) return;
        var dir = TempDir();
        var ns = FreshNamespace();
        const int writers = 6;

        try
        {
            var seed = new ConfigService(dir, Connect(ns));
            seed.LoadOrSeed(new AppConfig());

            var services = Enumerable.Range(0, writers).Select(_ =>
            {
                var svc = new ConfigService(dir, Connect(ns));
                svc.LoadOrSeed(new AppConfig());
                return svc;
            }).ToArray();

            using var gate = new Barrier(writers);
            var failures = new Exception?[writers];
            var threads = Enumerable.Range(0, writers).Select(i => new Thread(() =>
            {
                gate.SignalAndWait();
                // No If-Match: the caller claims no base revision, so serialising
                // behind the lease should let every one of them land in turn.
                try { services[i].Replace(new AppConfig { EnableDoh = true }, $"editor{i}"); }
                catch (Exception ex) { failures[i] = ex; }
            })).ToArray();

            foreach (var t in threads) t.Start();
            foreach (var t in threads) Assert.True(t.Join(TimeSpan.FromSeconds(30)), "a save deadlocked");
            Assert.All(failures, f => Assert.Null(f));

            var final = new ConfigService(dir, Connect(ns));
            final.LoadOrSeed(new AppConfig());
            var revisions = final.ListRevisions().Where(r => !r.IsCorrupt).ToList();
            var bodies = Directory.GetFiles(Path.Combine(dir, "config-history"), "config-rev-*.json");

            // Baseline plus one revision per writer, each with a distinct id and
            // exactly one body — no id claimed twice, nothing orphaned.
            Assert.Equal(writers + 1, revisions.Count);
            Assert.Equal(revisions.Count, revisions.Select(r => r.Id).Distinct().Count());
            Assert.Equal(revisions.Count, bodies.Length);
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { /* best effort */ }
        }
    }

    [Fact]
    public void StaleIfMatchIsStillRejectedUnderTheLease()
    {
        if (!Ready()) return;
        var dir = TempDir();
        var ns = FreshNamespace();

        try
        {
            var alice = new ConfigService(dir, Connect(ns));
            alice.LoadOrSeed(new AppConfig());
            var bob = new ConfigService(dir, Connect(ns));
            bob.LoadOrSeed(new AppConfig());

            var bobsView = bob.Head;
            Assert.Equal(alice.Head, bobsView);

            alice.Replace(new AppConfig { EnableDoh = true }, "alice", expectedHead: alice.Head);

            // The whole point of the CAS: serialising writes must not turn a real
            // lost update into a silent overwrite.
            Assert.Throws<RevisionConflictException>(() =>
                bob.Replace(new AppConfig { EnableDnsbl = false }, "bob", expectedHead: bobsView));

            // A caller that sent no If-Match claimed no base, so it still applies.
            bob.Replace(new AppConfig { EnableSmtpProbes = false }, "bob");
            Assert.False(bob.Snapshot().EnableSmtpProbes);
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { /* best effort */ }
        }
    }
}

using System.Reflection;
using Ednsv.Core.Models;
using Ednsv.Core.Services;

namespace Ednsv.Core.Tests;

/// <summary>
/// What happens to the config and users head beacons when the beacon itself is lost —
/// evicted, flushed, or gone with a Redis restart — and when the shared file cannot be
/// read at the moment a peer advances the head.
///
/// <para>The head is an opaque GUID, which is what makes these interesting: a GUID
/// carries no information about the content it names, so a head published against
/// unverified state cannot be caught by any later check. It satisfies "has it moved?"
/// forever. Every test here is about a pod being permanently, silently stale.</para>
///
/// <para>Needs a real Redis — the whole subject is what a flush and a compare-and-set
/// look like from the outside — so these self-skip when nothing is listening. Run
/// <c>redis-server --port 6380</c> to exercise them.</para>
/// </summary>
public sealed class BeaconLossTests : IDisposable
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

    private readonly string _dir = Path.Combine(Path.GetTempPath(), "beacon-" + Guid.NewGuid().ToString("N")[..10]);
    private readonly List<RedisConnection> _conns = new();

    /// <summary>A namespace per test, so "the beacon is gone" is one key delete rather
    /// than a FLUSHALL that would take every other test's keys with it.</summary>
    private RedisConnection Fresh(string ns)
    {
        var c = new RedisConnection(ConnString, ns);
        _conns.Add(c);
        return c;
    }

    public void Dispose()
    {
        foreach (var c in _conns) c.Dispose();
        try { Directory.Delete(_dir, true); } catch { }
    }

    /// <summary>
    /// Reads a private field. Deliberately white-box: two of the guarantees here are
    /// about what a pod records rather than what it serves — that it did not adopt a
    /// head it never verified, and did not stamp a file it failed to read. Both are
    /// covered end-to-end by the scenario tests, but each is also independently and
    /// redundantly recoverable there, so a scenario alone cannot tell which mechanism
    /// did the saving. These read the field and settle it.
    /// </summary>
    private static T Field<T>(object target, string name)
        => (T)target.GetType()
            .GetField(name, BindingFlags.Instance | BindingFlags.NonPublic)!
            .GetValue(target)!;

    private static void DeleteBeacon(RedisConnection redis, string suffix)
    {
        var db = redis.GetDatabase();
        Assert.NotNull(db);
        Assert.True(db!.KeyDelete(redis.Key(suffix)), "the beacon should have existed before the test deleted it");
    }

    private ConfigService NewConfig(RedisConnection redis)
    {
        // Zero freshness window: every read checks the beacon, so the tests assert on
        // the coordination logic rather than on a timer.
        var svc = new ConfigService(_dir, redis, TimeSpan.Zero);
        svc.LoadOrSeed(new AppConfig());
        return svc;
    }

    // ── config:head ──────────────────────────────────────────────────────

    [Fact]
    public async Task ALostConfigBeaconIsRepublishedFromDiskNotFromMemory()
    {
        if (!await ReadyAsync()) return;
        var ns = "beacon" + Guid.NewGuid().ToString("N")[..10];

        var a = NewConfig(Fresh(ns));
        var b = NewConfig(Fresh(ns));
        Assert.True(a.Snapshot().EnableDnsbl);
        Assert.True(b.Snapshot().EnableDnsbl);

        // A saves. B has not read since, so B is holding the old config.
        var next = a.Snapshot();
        next.EnableDnsbl = false;
        a.Replace(next, "test");

        // The beacon vanishes before B ever notices the change.
        DeleteBeacon(_conns[0], "config:head");

        // B is now first to republish. It must read the file before claiming to speak
        // for it: publishing its own stale head would make that head the cluster's
        // truth, and B would match it forever.
        Assert.False(b.Snapshot().EnableDnsbl);
        Assert.False(a.Snapshot().EnableDnsbl);
    }

    [Fact]
    public async Task AConfigHeadIsNotAdoptedWhenTheFileCannotBeRead()
    {
        if (!await ReadyAsync()) return;
        var ns = "beacon" + Guid.NewGuid().ToString("N")[..10];

        var redis = Fresh(ns);
        var b = NewConfig(redis);
        Assert.True(b.Snapshot().EnableDnsbl);
        var before = b.Head;

        // A peer advances the head, but the shared file is momentarily unreadable —
        // a half-written mount, a permissions blip. Adopting the head here would
        // record "I hold what the beacon names" against content never loaded.
        var db = redis.GetDatabase()!;
        db.StringSet(redis.Key("config:head"), Guid.NewGuid().ToString("N"));
        var path = Path.Combine(_dir, "config.json");
        var good = File.ReadAllText(path);
        File.WriteAllText(path, "{ this is not json");

        Assert.True(b.Snapshot().EnableDnsbl); // kept the last known-good copy
        Assert.Equal(before, b.Head);          // and did not claim to be current

        // Once the file is readable again the pod converges on its own.
        File.WriteAllText(path, good.Replace("\"enableDnsbl\": true", "\"enableDnsbl\": false"));
        Assert.False(b.Snapshot().EnableDnsbl);
    }

    [Fact]
    public async Task AConfigChangeIsSeenEvenIfTheBeaconNeverMoves()
    {
        if (!await ReadyAsync()) return;
        if (!OperatingSystem.IsLinux() && !OperatingSystem.IsMacOS()) return; // mtime granularity
        var ns = "beacon" + Guid.NewGuid().ToString("N")[..10];

        var b = NewConfig(Fresh(ns));
        Assert.True(b.Snapshot().EnableDnsbl);
        var head = b.Head;

        // The backstop: config.json changes while the beacon stands still. Nothing in
        // the head can reveal this, which is exactly why it is checked separately.
        var path = Path.Combine(_dir, "config.json");
        File.WriteAllText(path, File.ReadAllText(path).Replace("\"enableDnsbl\": true", "\"enableDnsbl\": false"));

        Assert.False(b.Snapshot().EnableDnsbl);
        Assert.Equal(head, b.Head); // content re-read; the head is still the peer's to move
    }

    [Fact]
    public async Task AFailedConfigReadDoesNotRecordThatVersionAsHeld()
    {
        if (!await ReadyAsync()) return;
        var ns = "beacon" + Guid.NewGuid().ToString("N")[..10];

        var b = NewConfig(Fresh(ns));
        Assert.True(b.Snapshot().EnableDnsbl);
        var held = Field<(long, long)>(b, "_diskStamp");

        // A read that failed must leave the record of what this pod holds untouched.
        // Stamping the file it could not read would tell the drift check that this
        // version is already loaded, and the very next write to that file — the one
        // that fixes it — would then look like nothing had changed.
        var path = Path.Combine(_dir, "config.json");
        File.WriteAllText(path, "{ this is not json");
        Assert.True(b.Snapshot().EnableDnsbl);

        Assert.Equal(held, Field<(long, long)>(b, "_diskStamp"));
    }

    // ── users:head ───────────────────────────────────────────────────────

    private AuthService NewAuth(RedisConnection redis)
    {
        var svc = new AuthService(_dir, AuthService.Hash("root-token"), redis, TimeSpan.Zero);
        svc.Load();
        return svc;
    }

    [Fact]
    public async Task ALostUsersBeaconIsRepublishedFromDiskNotFromMemory()
    {
        if (!await ReadyAsync()) return;
        var ns = "beacon" + Guid.NewGuid().ToString("N")[..10];

        var a = NewAuth(Fresh(ns));
        var b = NewAuth(Fresh(ns));

        var issued = a.Issue("alice", false, "root", null);
        Assert.Equal(AuthService.IssueStatus.Success, issued.Status);
        Assert.NotNull(b.AuthenticateBearer(issued.Token!)); // B has caught up

        a.Revoke("alice", "root", elevated: true);
        DeleteBeacon(_conns[0], "users:head");

        // The stale-forever case with teeth: if B republishes the head it was holding
        // before the revocation, the revoked token authenticates indefinitely.
        Assert.Null(b.AuthenticateBearer(issued.Token!));
        Assert.Null(a.AuthenticateBearer(issued.Token!));
    }

    [Fact]
    public async Task AUsersHeadIsNotAdoptedWhenTheFileCannotBeRead()
    {
        if (!await ReadyAsync()) return;
        var ns = "beacon" + Guid.NewGuid().ToString("N")[..10];

        var redis = Fresh(ns);
        var b = NewAuth(redis);
        var before = Field<string>(b, "_headGuid");

        // A peer advances the head while the shared file is momentarily unreadable.
        // Adopting it would record "I hold what the beacon names" against content this
        // pod never loaded — and the head is a GUID, so nothing downstream can tell.
        var db = redis.GetDatabase()!;
        db.StringSet(redis.Key("users:head"), Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        File.WriteAllText(Path.Combine(_dir, "users.json"), "{ not json");
        b.AuthenticateBearer("anything-at-all"); // drives the freshness check

        Assert.Equal(before, Field<string>(b, "_headGuid"));
    }

    [Fact]
    public async Task AUserWriteRefusesRatherThanCommitOnAHeadItCouldNotVerify()
    {
        if (!await ReadyAsync()) return;
        var ns = "beacon" + Guid.NewGuid().ToString("N")[..10];

        var a = NewAuth(Fresh(ns));
        var b = NewAuth(Fresh(ns));
        Assert.Equal(AuthService.IssueStatus.Success, a.Issue("grace", false, "root", null).Status);

        // The head has moved and B cannot read the file it names. The write path has its
        // own freshness check, and it is the dangerous one: adopting the head here makes
        // B's compare-and-set succeed, so B would persist the users it happens to be
        // holding and drop grace on the floor for the whole cluster. Refusing is the
        // only safe answer — the caller retries, and by then the file usually reads.
        File.WriteAllText(Path.Combine(_dir, "users.json"), "{ not json");

        Assert.Throws<StoreUnavailableException>(() => b.Issue("heidi", false, "root", null));
    }

    [Fact]
    public async Task AFailedUsersReadDoesNotRecordThatVersionAsHeld()
    {
        if (!await ReadyAsync()) return;
        var ns = "beacon" + Guid.NewGuid().ToString("N")[..10];

        var a = NewAuth(Fresh(ns));
        var b = NewAuth(Fresh(ns));
        var issued = a.Issue("erin", false, "root", null);
        Assert.NotNull(b.AuthenticateBearer(issued.Token!)); // B has read the file once
        var held = Field<(long, long)>(b, "_diskStamp");

        File.WriteAllText(Path.Combine(_dir, "users.json"), "{ not json");
        b.AuthenticateBearer("anything-at-all");

        Assert.Equal(held, Field<(long, long)>(b, "_diskStamp"));
    }

    [Fact]
    public async Task AUserChangeIsSeenEvenIfTheBeaconNeverMoves()
    {
        if (!await ReadyAsync()) return;
        if (!OperatingSystem.IsLinux() && !OperatingSystem.IsMacOS()) return; // mtime granularity
        var ns = "beacon" + Guid.NewGuid().ToString("N")[..10];

        var a = NewAuth(Fresh(ns));
        var b = NewAuth(Fresh(ns));
        var issued = a.Issue("frank", false, "root", null);
        Assert.NotNull(b.AuthenticateBearer(issued.Token!));

        // The backstop: users.json changes while the beacon stands still. A head that
        // is only a GUID cannot reveal this, which is why the file is checked directly.
        var path = Path.Combine(_dir, "users.json");
        File.WriteAllText(path, File.ReadAllText(path)
            .Replace("\"revoked\": false", "\"revoked\": true"));

        Assert.Null(b.AuthenticateBearer(issued.Token!));
    }

    [Fact]
    public async Task AnUnreadableUsersFileNeverLetsAPodClobberAPeersRevocation()
    {
        if (!await ReadyAsync()) return;
        var ns = "beacon" + Guid.NewGuid().ToString("N")[..10];

        var a = NewAuth(Fresh(ns));
        var b = NewAuth(Fresh(ns));

        var bob = a.Issue("bob", false, "root", null);
        var carol = a.Issue("carol", false, "root", null);
        Assert.NotNull(b.AuthenticateBearer(bob.Token!)); // B has caught up
        a.Revoke("bob", "root", elevated: true);

        // The revocation is on disk and the head has moved, but B's read of the file
        // fails at exactly that moment — a half-written mount, an I/O blip. B keeps the
        // copy it has, which is the right call, but it must NOT record that it now holds
        // what the head names.
        var path = Path.Combine(_dir, "users.json");
        var good = File.ReadAllBytes(path);
        var stamp = File.GetLastWriteTimeUtc(path);
        File.WriteAllText(path, "{ not json");
        Assert.NotNull(b.AuthenticateBearer(carol.Token!)); // drives B's freshness check

        // The blip clears with the file byte-identical and its timestamp unchanged, so
        // nothing about the file or the beacon has moved since B's failed read. Only the
        // fact that B declined to adopt the head can save it from here.
        File.WriteAllBytes(path, good);
        File.SetLastWriteTimeUtc(path, stamp);

        // B now writes. If B had adopted the head, its compare-and-set would succeed and
        // persist the users it was holding — silently reviving the revoked token for the
        // whole cluster.
        Assert.Equal(AuthService.IssueStatus.Success, b.Issue("dave", false, "root", null).Status);

        var persisted = File.ReadAllText(path);
        Assert.Contains("dave", persisted);
        Assert.Contains("carol", persisted);
        Assert.Null(b.AuthenticateBearer(bob.Token!));
        Assert.Null(a.AuthenticateBearer(bob.Token!));
    }
}

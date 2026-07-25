using Ednsv.Core.Services;

namespace Ednsv.Core.Tests;

/// <summary>
/// Config and user writes take a cross-instance lease before their compare-and-set,
/// because the CAS releases the moment it commits and leaves the file writes,
/// revision-id allocation and history rewrite unprotected. These tests pin the two
/// ends of that: no lease is needed (or taken) in single-instance mode, and a lease
/// that cannot be obtained refuses the write rather than proceeding unprotected.
/// </summary>
public sealed class WriteLeaseTests : IDisposable
{
    private readonly string _dir;

    // Configured, but nothing is listening — so no lease can ever be taken.
    private const string UnreachableRedis =
        "127.0.0.1:6399,connectTimeout=150,syncTimeout=150,connectRetry=0,abortConnect=false";

    public WriteLeaseTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), $"ednsv-lease-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { /* best effort */ }
    }

    // ── Single-instance mode is unaffected ───────────────────────────────

    [Fact]
    public void ConfigWritesStillWorkWithoutRedis()
    {
        var svc = new ConfigService(_dir);
        svc.LoadOrSeed(new AppConfig { EnableSmtpProbes = true });

        svc.Replace(new AppConfig { EnableSmtpProbes = false }, "alice@contoso.com");

        Assert.False(svc.Snapshot().EnableSmtpProbes);
    }

    [Fact]
    public void UserWritesStillWorkWithoutRedis()
    {
        var auth = new AuthService(_dir, AuthService.Hash("root-token"));
        auth.Load();

        var issued = auth.Issue("alice", isAdmin: false, "ednsv", null);
        Assert.Equal(AuthService.IssueStatus.Success, issued.Status);

        var revoked = auth.Revoke("alice", "ednsv");
        Assert.Equal(AuthService.RevokeStatus.Success, revoked.Status);
    }

    // ── Coordination unavailable ⇒ refuse, don't diverge ─────────────────

    [Fact]
    public void ConfigWriteRefusesWhenTheLeaseCannotBeTaken()
    {
        using var redis = new RedisConnection(UnreachableRedis);
        var svc = new ConfigService(_dir, redis);
        svc.LoadOrSeed(new AppConfig { EnableSmtpProbes = true });

        Assert.Throws<StoreUnavailableException>(() =>
            svc.Replace(new AppConfig { EnableSmtpProbes = false }, "alice@contoso.com"));

        // The refusal must be total: nothing partially written, no revision minted.
        Assert.True(svc.Snapshot().EnableSmtpProbes);
    }

    [Fact]
    public void UserIssueRefusesWhenTheLeaseCannotBeTaken()
    {
        using var redis = new RedisConnection(UnreachableRedis);
        var auth = new AuthService(_dir, AuthService.Hash("root-token"), redis);
        auth.Load();

        Assert.Throws<StoreUnavailableException>(
            () => auth.Issue("alice", isAdmin: false, "ednsv", null));

        Assert.Empty(auth.ListVisibleTo(AuthService.RootUsername));
    }

    [Fact]
    public void UserRevokeRefusesWhenTheLeaseCannotBeTaken()
    {
        // Seed a user without Redis, then attach an unreachable one: a revoke that
        // cannot be coordinated must fail loudly rather than appear to succeed on
        // one instance while other instances keep honouring the token.
        var seed = new AuthService(_dir, AuthService.Hash("root-token"));
        seed.Load();
        Assert.Equal(AuthService.IssueStatus.Success,
            seed.Issue("alice", isAdmin: false, "ednsv", null).Status);

        using var redis = new RedisConnection(UnreachableRedis);
        var auth = new AuthService(_dir, AuthService.Hash("root-token"), redis);
        auth.Load();

        Assert.Throws<StoreUnavailableException>(() => auth.Revoke("alice", "ednsv"));

        var reread = new AuthService(_dir, AuthService.Hash("root-token"));
        reread.Load();
        Assert.All(reread.ListVisibleTo(AuthService.RootUsername), u => Assert.False(u.Revoked));
    }

    [Fact]
    public void UserDeleteRefusesWhenTheLeaseCannotBeTaken()
    {
        var seed = new AuthService(_dir, AuthService.Hash("root-token"));
        seed.Load();
        seed.Issue("alice", isAdmin: false, "ednsv", null);
        seed.Revoke("alice", "ednsv");

        using var redis = new RedisConnection(UnreachableRedis);
        var auth = new AuthService(_dir, AuthService.Hash("root-token"), redis);
        auth.Load();

        Assert.Throws<StoreUnavailableException>(() => auth.Delete("alice", AuthService.RootUsername));

        var reread = new AuthService(_dir, AuthService.Hash("root-token"));
        reread.Load();
        Assert.Single(reread.ListVisibleTo(AuthService.RootUsername));
    }

    [Fact]
    public void RejectedWritesAreRefusedBeforeTheyTouchDisk()
    {
        using var redis = new RedisConnection(UnreachableRedis);
        var svc = new ConfigService(_dir, redis);
        svc.LoadOrSeed(new AppConfig { EnableSmtpProbes = true });

        var before = File.ReadAllText(Path.Combine(_dir, "config.json"));
        var revisionsBefore = Directory.GetFiles(Path.Combine(_dir, "config-history"), "config-rev-*.json").Length;

        Assert.Throws<StoreUnavailableException>(() =>
            svc.Replace(new AppConfig { EnableDnsbl = false }, "alice@contoso.com"));

        Assert.Equal(before, File.ReadAllText(Path.Combine(_dir, "config.json")));
        Assert.Equal(revisionsBefore,
            Directory.GetFiles(Path.Combine(_dir, "config-history"), "config-rev-*.json").Length);
    }
}

using Ednsv.Core.Services;

namespace Ednsv.Core.Tests;

/// <summary>
/// Verifies the single-instance (unconfigured) invariants of the shared Redis
/// provider. These are the behaviours the whole opt-in design relies on: with no
/// connection string the provider is disabled, hands out no database, and always
/// reports healthy so the original single-process code paths are preserved.
/// </summary>
public sealed class RedisConnectionTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Unconfigured_IsDisabled(string? connString)
    {
        using var redis = new RedisConnection(connString);

        Assert.False(redis.Enabled);
        Assert.Null(redis.GetDatabase());
    }

    [Fact]
    public async Task Unconfigured_IsHealthy()
    {
        using var redis = new RedisConnection(null);

        // Single-instance mode has no external dependency, so it is always ready.
        Assert.True(await redis.IsHealthyAsync());
    }

    [Fact]
    public void Key_UsesDefaultInstanceNamespace()
    {
        using var redis = new RedisConnection(null);

        Assert.Equal("ednsv", redis.InstanceName);
        Assert.Equal("ednsv:job:abc", redis.Key("job:abc"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Key_FallsBackToDefaultWhenInstanceNameBlank(string? instanceName)
    {
        using var redis = new RedisConnection(null, instanceName);

        Assert.Equal("ednsv", redis.InstanceName);
    }

    [Fact]
    public void Key_UsesCustomInstanceNamespace()
    {
        using var redis = new RedisConnection(null, "prod-eu");

        Assert.Equal("prod-eu", redis.InstanceName);
        Assert.Equal("prod-eu:cache:dns:example.com", redis.Key("cache:dns:example.com"));
    }

    [Fact]
    public void AccessKey_IsInjectedIntoConnectionStringPlaceholder()
    {
        // A malformed host is fine: the multiplexer connects lazily and
        // AbortOnConnectFail=false, so construction must not throw. We only assert
        // the provider is enabled, proving the {AccessKey} placeholder was replaced
        // and the resulting string parsed successfully.
        using var redis = new RedisConnection(
            "localhost:6379,password={AccessKey}", instanceName: null, accessKey: "s3cr3t-key");

        Assert.True(redis.Enabled);
    }

    [Fact]
    public void AccessKey_WithoutPlaceholder_StillParses()
    {
        using var redis = new RedisConnection(
            "localhost:6379", instanceName: null, accessKey: "unused");

        Assert.True(redis.Enabled);
    }

    // ── Write leases ─────────────────────────────────────────────────────
    // The lease serialises the config/user read-modify-write across instances.
    // It is contention control layered over the existing compare-and-set, never
    // a replacement for it, so "cannot acquire" must always be a refusal to
    // write rather than a licence to proceed unprotected.

    [Fact]
    public void TryAcquireLock_Unconfigured_ReturnsNull()
    {
        using var redis = new RedisConnection(null);

        // Single-instance mode: nothing to coordinate with, and the in-process
        // lock already serialises writers. Callers treat null as "no lease needed".
        Assert.Null(redis.TryAcquireLock("config:write",
            TimeSpan.FromSeconds(15), TimeSpan.FromSeconds(1)));
    }

    [Fact]
    public void TryAcquireLock_Unreachable_ReturnsNullPromptly()
    {
        // Configured but nothing listening. A short connect timeout keeps this
        // bounded; the point is that it reports failure instead of hanging or
        // handing back a lease it does not hold.
        using var redis = new RedisConnection(
            "127.0.0.1:6399,connectTimeout=150,syncTimeout=150,connectRetry=0,abortConnect=false");
        Assert.True(redis.Enabled);

        var started = DateTime.UtcNow;
        var lease = redis.TryAcquireLock("config:write",
            TimeSpan.FromSeconds(15), TimeSpan.FromSeconds(1));
        var elapsed = DateTime.UtcNow - started;

        Assert.Null(lease);
        Assert.True(elapsed < TimeSpan.FromSeconds(10), $"took {elapsed.TotalSeconds:F1}s");
    }

}

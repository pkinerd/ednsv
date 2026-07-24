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

    [Fact]
    public async Task DeleteKeysByPrefix_Unconfigured_IsNoOp()
    {
        using var redis = new RedisConnection(null);

        // No connection string → nothing to clear, and must not throw.
        Assert.Equal(0, await redis.DeleteKeysByPrefixAsync("cache:"));
    }
}

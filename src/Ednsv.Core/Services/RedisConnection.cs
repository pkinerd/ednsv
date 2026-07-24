using StackExchange.Redis;

namespace Ednsv.Core.Services;

/// <summary>
/// Lazily-established shared Redis connection used by the distributed
/// (horizontally-scaled) code paths: the async job store, the probe-cache L2,
/// and the config/user coordination beacons.
///
/// When no connection string is configured the provider is <see cref="Enabled"/>
/// == false and callers fall back to the single-instance behaviour (in-memory
/// jobs, disk cache, in-process config lock). Redis is therefore strictly
/// opt-in: unset connection string preserves the original single-process design.
///
/// All keys are namespaced with <see cref="InstanceName"/> so multiple EDNSV
/// deployments can share one Redis instance without colliding.
/// </summary>
public sealed class RedisConnection : IDisposable
{
    private readonly string? _connectionString;
    private readonly Lazy<ConnectionMultiplexer>? _lazy;

    /// <summary>Key prefix applied to every EDNSV key (namespacing).</summary>
    public string InstanceName { get; }

    /// <summary>True when a Redis connection string was configured.</summary>
    public bool Enabled => _lazy != null;

    public RedisConnection(string? connectionString, string? instanceName = null, string? accessKey = null)
    {
        // The access key is supplied separately (e.g. from a mounted secret) and
        // injected into the connection string at startup by replacing the
        // "{AccessKey}" placeholder, so the secret never lives in appsettings.
        if (!string.IsNullOrWhiteSpace(connectionString) && !string.IsNullOrWhiteSpace(accessKey))
            connectionString = connectionString.Replace("{AccessKey}", accessKey.Trim());

        _connectionString = string.IsNullOrWhiteSpace(connectionString) ? null : connectionString.Trim();
        InstanceName = string.IsNullOrWhiteSpace(instanceName) ? "ednsv" : instanceName.Trim();

        if (_connectionString != null)
        {
            // AbortOnConnectFail=false so the multiplexer keeps retrying in the
            // background instead of throwing on first connect — cache/beacon
            // callers treat transient Redis errors as a miss and fall through.
            var options = ConfigurationOptions.Parse(_connectionString);
            options.AbortOnConnectFail = false;
            _lazy = new Lazy<ConnectionMultiplexer>(
                () => ConnectionMultiplexer.Connect(options),
                LazyThreadSafetyMode.ExecutionAndPublication);
        }
    }

    /// <summary>Namespaced key, e.g. "ednsv:job:abc123".</summary>
    public string Key(string suffix) => $"{InstanceName}:{suffix}";

    /// <summary>
    /// The Redis database, or null when Redis is unconfigured or currently
    /// unreachable. Callers use null as "fall through to source of truth".
    /// </summary>
    public IDatabase? GetDatabase()
    {
        if (_lazy == null) return null;
        try
        {
            return _lazy.Value.GetDatabase();
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Readiness check: true when Redis is either not configured (single-instance
    /// mode is always ready) or configured and currently reachable. Used by the
    /// /health/ready probe so k8s stops routing to a pod that has lost Redis in
    /// distributed mode.
    /// </summary>
    public async Task<bool> IsHealthyAsync()
    {
        if (_lazy == null) return true; // not configured => nothing to depend on
        try
        {
            var db = _lazy.Value.GetDatabase();
            await db.PingAsync();
            return true;
        }
        catch
        {
            return false;
        }
    }

    public void Dispose()
    {
        if (_lazy is { IsValueCreated: true })
        {
            try { _lazy.Value.Dispose(); } catch { /* best effort */ }
        }
    }
}

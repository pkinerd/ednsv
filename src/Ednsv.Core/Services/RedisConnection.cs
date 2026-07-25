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
    /// Deletes every key matching "{InstanceName}:{suffixPrefix}*" across all
    /// primary endpoints, returning how many were removed. Used to wipe the shared
    /// probe-cache L2 ("cache:") on an admin cache-clear so a cleared pod does not
    /// immediately refill its memory from stale L2 entries. Uses SCAN (no admin
    /// mode required) and never FLUSHDB, so jobs and coordination beacons survive.
    /// Best-effort: returns 0 when Redis is unconfigured or unreachable.
    /// </summary>
    public async Task<long> DeleteKeysByPrefixAsync(string suffixPrefix)
    {
        if (_lazy == null) return 0;
        long deleted = 0;
        try
        {
            var mux = _lazy.Value;
            var db = mux.GetDatabase();
            var pattern = new RedisValue(Key(suffixPrefix) + "*");
            foreach (var ep in mux.GetEndPoints())
            {
                IServer server;
                try { server = mux.GetServer(ep); }
                catch { continue; }
                if (!server.IsConnected || server.IsReplica) continue;

                var batch = new List<RedisKey>(512);
                await foreach (var key in server.KeysAsync(pattern: pattern, pageSize: 512))
                {
                    batch.Add(key);
                    if (batch.Count >= 512)
                    {
                        deleted += await db.KeyDeleteAsync(batch.ToArray());
                        batch.Clear();
                    }
                }
                if (batch.Count > 0)
                    deleted += await db.KeyDeleteAsync(batch.ToArray());
            }
        }
        catch { /* best effort */ }
        return deleted;
    }

    /// <summary>
    /// Takes a short-lived exclusive lease named <paramref name="suffix"/>, or
    /// returns null when it cannot be had within <paramref name="maxWait"/> (or
    /// Redis is unconfigured or unreachable). Dispose the result to release.
    ///
    /// This is contention control, <b>not</b> a correctness boundary. A TTL lease
    /// can be violated — the holder stalls past the TTL, or a failover loses the
    /// key — and a filesystem cannot validate a fencing token, so callers must
    /// keep whatever compare-and-set already decides the outcome. The lease
    /// exists to stop two writers interleaving their file I/O in the common case,
    /// not to make it impossible.
    /// </summary>
    public IDisposable? TryAcquireLock(string suffix, TimeSpan ttl, TimeSpan maxWait)
    {
        if (_lazy == null) return null;
        IDatabase db;
        try { db = _lazy.Value.GetDatabase(); }
        catch { return null; }

        var key = (RedisKey)Key("lock:" + suffix);
        var token = (RedisValue)Guid.NewGuid().ToString("N");
        var deadline = DateTime.UtcNow + maxWait;
        var backoff = TimeSpan.FromMilliseconds(25);

        while (true)
        {
            try
            {
                if (db.LockTake(key, token, ttl)) return new Lease(db, key, token);
            }
            catch
            {
                return null; // treated as "cannot coordinate" by callers
            }

            if (DateTime.UtcNow >= deadline) return null;
            Thread.Sleep(backoff);
            if (backoff < TimeSpan.FromMilliseconds(200)) backoff += TimeSpan.FromMilliseconds(25);
        }
    }

    private sealed class Lease : IDisposable
    {
        private readonly IDatabase _db;
        private readonly RedisKey _key;
        private readonly RedisValue _token;
        private bool _released;

        public Lease(IDatabase db, RedisKey key, RedisValue token)
        {
            _db = db;
            _key = key;
            _token = token;
        }

        public void Dispose()
        {
            if (_released) return;
            _released = true;
            // Token-checked release, so a lease that already expired and was
            // retaken by someone else is never deleted out from under them.
            try { _db.LockRelease(_key, _token); }
            catch { /* it expires on its own */ }
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

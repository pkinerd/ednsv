using System.Collections.Concurrent;
using Ednsv.Core.Models;

namespace Ednsv.Core.Services;

/// <summary>
/// Encapsulates the cache lifecycle: loading from disk at startup, periodic
/// background flushing, per-domain result persistence, and recheck invalidation.
/// Intended for use as a singleton in long-lived processes (web APIs) or as a
/// scoped helper in CLI runs.
/// </summary>
public sealed class CacheManager : IAsyncDisposable
{
    private readonly string _cacheDir;
    private readonly TimeSpan _ttl;
    private readonly DnsResolverService _dns;
    private readonly SmtpProbeService _smtp;
    private readonly HttpProbeService _http;
    private readonly RedisConnection? _redis;

    private BackgroundCacheFlusher? _flusher;
    private ConcurrentDictionary<string, DomainResultSummary> _previousResults = new();
    private bool _disposed;

    // Serialises direct disk access on the no-flusher path (see SaveDirectAsync).
    private readonly SemaphoreSlim _diskLock = new(1, 1);

    public CacheManager(
        string cacheDir,
        TimeSpan ttl,
        DnsResolverService dns,
        SmtpProbeService smtp,
        HttpProbeService http,
        RedisConnection? redis = null)
    {
        _cacheDir = cacheDir;
        _ttl = ttl;
        _dns = dns;
        _smtp = smtp;
        _http = http;
        _redis = redis != null && redis.Enabled ? redis : null;
    }

    /// <summary>
    /// Loads cached probe data from disk and primes the services.
    /// Returns summary info about what was loaded, or null if nothing was found.
    /// </summary>
    public async Task<DiskCacheService.CacheLoadResult?> LoadAsync(bool retryErrors = false)
    {
        var result = await DiskCacheService.LoadAsync(_cacheDir, _ttl, _smtp, _http, _dns, retryErrors);
        var loaded = await DiskCacheService.LoadDomainResultsAsync(_cacheDir);
        if (loaded != null)
            foreach (var kvp in loaded)
                _previousResults[kvp.Key] = kvp.Value;
        return result;
    }

    /// <summary>
    /// Starts a background timer that periodically flushes in-memory caches to disk.
    /// </summary>
    public void StartBackgroundFlusher(TimeSpan interval)
    {
        _flusher ??= new BackgroundCacheFlusher(_cacheDir, _smtp, _http, _dns, interval);
    }

    /// <summary>
    /// Explicitly flushes all in-memory caches to disk.
    /// Routes through the flusher's lock when available to prevent concurrent writes.
    /// </summary>
    public Task FlushAsync() => _flusher != null
        ? _flusher.FlushAsync()
        : SaveDirectAsync();

    // Without a background flusher (CLI single-shot runs) there is no shared lock
    // to route through, so serialise here instead: MergeSaveAsync is a
    // read-modify-write per cache file, and two interleaved saves drop whichever
    // entries the loser had merged in.
    private async Task SaveDirectAsync()
    {
        await _diskLock.WaitAsync();
        try { await DiskCacheService.SaveAsync(_cacheDir, _smtp, _http, _dns); }
        finally { _diskLock.Release(); }
    }

    private async Task ClearDirectAsync()
    {
        await _diskLock.WaitAsync();
        try { DiskCacheService.Clear(_cacheDir); }
        finally { _diskLock.Release(); }
    }

    /// <summary>
    /// Requests a non-blocking background flush. Safe to call frequently.
    /// </summary>
    public void RequestFlush() => _flusher?.RequestFlush();

    /// <summary>
    /// Wipes every cache — the in-memory DNS/SMTP/HTTP probe caches, the
    /// in-memory recheck summaries, all on-disk cache files, and (in distributed
    /// mode) the shared Redis probe-cache L2. Subsequent validations re-fetch
    /// everything from scratch (slower until re-warmed). In-memory is cleared
    /// first, then the disk files are deleted under the flusher's lock: clearing
    /// memory alone is not enough, because a flush that already sampled the caches
    /// would write those pre-clear entries back after the delete. Other replicas'
    /// in-memory L1 is not cleared remotely; those copies expire on their own TTL.
    /// </summary>
    public async Task ClearAllAsync()
    {
        _dns.ClearCache();
        _smtp.ClearCache();
        _http.ClearCache();
        _previousResults.Clear();
        if (_flusher != null)
            await _flusher.ClearAsync();
        else
            await ClearDirectAsync();
        // In distributed mode also wipe the shared probe-cache L2, otherwise the
        // just-cleared local memory refills from stale Redis entries immediately.
        // Jobs and coordination beacons use different prefixes and are left intact.
        if (_redis != null)
            await _redis.DeleteKeysByPrefixAsync("cache:");
    }

    /// <summary>
    /// Saves a domain's validation result summary for future recheck decisions.
    /// Updates both the in-memory map (for subsequent rechecks within this process)
    /// and the on-disk cache (for persistence across restarts).
    /// </summary>
    public Task SaveDomainResultAsync(string domain, DomainResultSummary summary)
    {
        _previousResults[domain.ToLowerInvariant()] = summary;
        return DiskCacheService.SaveDomainResultAsync(_cacheDir, domain, summary);
    }

    /// <summary>
    /// Determines which cache types need rechecking for a domain based on previous
    /// issues at or above the specified severity. Returns the CacheDep flags.
    /// Caller sets these on DomainValidator.RecheckDeps so that ProbeCache
    /// bypasses MemoryCache via AsyncLocal without affecting other concurrent users.
    /// </summary>
    public RecheckHelper.CacheDep GetRecheckDeps(string domain, CheckSeverity minSeverity)
    {
        if (!_previousResults.TryGetValue(domain.ToLowerInvariant(), out var summary))
            return RecheckHelper.CacheDep.None;

        return RecheckHelper.GetDependenciesForIssues(summary, minSeverity);
    }

    /// <summary>
    /// Previous domain results loaded from the cache (for recheck decisions).
    /// </summary>
    public ConcurrentDictionary<string, DomainResultSummary> PreviousResults => _previousResults;

    public async ValueTask DisposeAsync()
    {
        if (_disposed) return;
        _disposed = true;

        if (_flusher != null)
            await _flusher.DisposeAsync();
        else
            await FlushAsync(); // final save even without a flusher

        _diskLock.Dispose();
    }
}

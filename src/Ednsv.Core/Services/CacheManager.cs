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

    private BackgroundCacheFlusher? _flusher;
    private readonly DomainResultStore _domainResults;
    private bool _disposed;

    // Serialises direct disk access on the no-flusher path (see SaveDirectAsync).
    private readonly SemaphoreSlim _diskLock = new(1, 1);

    public CacheManager(
        string cacheDir,
        TimeSpan ttl,
        DnsResolverService dns,
        SmtpProbeService smtp,
        HttpProbeService http)
    {
        _cacheDir = cacheDir;
        _ttl = ttl;
        _dns = dns;
        _smtp = smtp;
        _http = http;
        _domainResults = new DomainResultStore(ttl > TimeSpan.Zero ? ttl : null);
    }

    /// <summary>
    /// Loads cached probe data from disk and primes the services.
    /// Returns summary info about what was loaded, or null if nothing was found.
    /// </summary>
    public Task<DiskCacheService.CacheLoadResult?> LoadAsync(bool retryErrors = false)
        => DiskCacheService.LoadAsync(_cacheDir, _ttl, _smtp, _http, _dns, retryErrors, _domainResults);

    /// <summary>
    /// Starts a background timer that periodically flushes in-memory caches to disk.
    /// </summary>
    public void StartBackgroundFlusher(TimeSpan interval)
    {
        _flusher ??= new BackgroundCacheFlusher(_cacheDir, _smtp, _http, _dns, interval, _ttl, _domainResults);
    }

    /// <summary>
    /// Explicitly flushes all in-memory caches to disk.
    /// Routes through the flusher's lock when available to prevent concurrent writes.
    /// </summary>
    public Task FlushAsync() => _flusher != null
        ? _flusher.FlushAsync()
        : SaveDirectAsync();

    // Without a background flusher (CLI single-shot runs) there is no shared lock to
    // route through, so serialise here instead. Two concurrent saves would each
    // collect the same bag entries and write them into two files — harmless on read,
    // since the merge dedupes by key, but wasteful.
    private async Task SaveDirectAsync()
    {
        await _diskLock.WaitAsync();
        try { await DiskCacheService.SaveAsync(_cacheDir, _smtp, _http, _dns, _domainResults); }
        finally { _diskLock.Release(); }
    }

    /// <summary>
    /// Records a domain's validation result for future recheck decisions. Visible
    /// to this process immediately; written out by the next flush.
    /// </summary>
    public void SaveDomainResult(string domain, DomainResultSummary summary)
        => _domainResults.Set(domain, summary);

    /// <summary>
    /// Determines which cache types need rechecking for a domain based on previous
    /// issues at or above the specified severity. Returns the CacheDep flags.
    /// Caller sets these on DomainValidator.RecheckDeps so that ProbeCache
    /// bypasses MemoryCache via AsyncLocal without affecting other concurrent users.
    /// </summary>
    public RecheckHelper.CacheDep GetRecheckDeps(string domain, CheckSeverity minSeverity)
    {
        if (!_domainResults.TryGet(domain, out var summary))
            return RecheckHelper.CacheDep.None;

        return RecheckHelper.GetDependenciesForIssues(summary, minSeverity);
    }

    /// <summary>
    /// Previous domain results loaded from the cache (for recheck decisions).
    /// </summary>
    public ConcurrentDictionary<string, DomainResultSummary> PreviousResults => _domainResults.Results;

    public async ValueTask DisposeAsync()
    {
        if (_disposed) return;
        _disposed = true;

        if (_flusher != null)
            await _flusher.DisposeAsync();
        else
            await FlushAsync(); // final save even without a flusher

        // _diskLock is deliberately not disposed. Nothing here ever touches its
        // AvailableWaitHandle, so there is no handle to release, and disposing it
        // would turn a late FlushAsync arriving during shutdown into an
        // ObjectDisposedException instead of the harmless save it used to be.
    }
}

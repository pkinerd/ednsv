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
    private Dictionary<string, DomainResultSummary>? _previousResults;
    private bool _disposed;

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
    }

    /// <summary>
    /// Loads cached probe data from disk and primes the services.
    /// Returns summary info about what was loaded, or null if nothing was found.
    /// </summary>
    public async Task<DiskCacheService.CacheLoadResult?> LoadAsync(bool retryErrors = false)
    {
        var result = await DiskCacheService.LoadAsync(_cacheDir, _ttl, _smtp, _http, _dns, retryErrors);
        _previousResults = await DiskCacheService.LoadDomainResultsAsync(_cacheDir);
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
    /// </summary>
    public Task FlushAsync() => DiskCacheService.SaveAsync(_cacheDir, _smtp, _http, _dns);

    /// <summary>
    /// Requests a non-blocking background flush. Safe to call frequently.
    /// </summary>
    public void RequestFlush() => _flusher?.RequestFlush();

    /// <summary>
    /// Saves a domain's validation result summary for future recheck decisions.
    /// </summary>
    public Task SaveDomainResultAsync(string domain, DomainResultSummary summary)
        => DiskCacheService.SaveDomainResultAsync(_cacheDir, domain, summary);

    /// <summary>
    /// Clears cached probes for a domain that previously had issues at or above
    /// the specified severity, so those checks are re-run with fresh data.
    /// Returns true if any cache entries were cleared.
    /// </summary>
    public bool ClearForRecheck(string domain, CheckSeverity minSeverity)
    {
        if (_previousResults == null ||
            !_previousResults.TryGetValue(domain.ToLowerInvariant(), out var summary))
            return false;

        var deps = RecheckHelper.GetDependenciesForIssues(summary, minSeverity);
        if (deps == RecheckHelper.CacheDep.None)
            return false;

        RecheckHelper.ClearImportedEntriesForDomain(domain, deps, _dns, _smtp, _http);
        return true;
    }

    /// <summary>
    /// Previous domain results loaded from the cache (for recheck decisions).
    /// </summary>
    public Dictionary<string, DomainResultSummary>? PreviousResults => _previousResults;

    public async ValueTask DisposeAsync()
    {
        if (_disposed) return;
        _disposed = true;

        if (_flusher != null)
            await _flusher.DisposeAsync();
        else
            await FlushAsync(); // final save even without a flusher
    }
}

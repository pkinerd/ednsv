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
    private ConcurrentDictionary<string, DomainResultSummary> _previousResults = new();
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
    /// </summary>
    public Task FlushAsync() => DiskCacheService.SaveAsync(_cacheDir, _smtp, _http, _dns);

    /// <summary>
    /// Requests a non-blocking background flush. Safe to call frequently.
    /// </summary>
    public void RequestFlush() => _flusher?.RequestFlush();

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
    /// Clears cached probes for a domain that previously had issues at or above
    /// the specified severity, so those checks are re-run with fresh data.
    /// When importedOnly is true (CLI default), only disk-loaded entries are cleared.
    /// When false (web API), all matching in-memory entries are cleared.
    /// Returns true if any cache entries were cleared.
    /// </summary>
    public bool ClearForRecheck(string domain, CheckSeverity minSeverity, bool importedOnly = false)
    {
        if (!_previousResults.TryGetValue(domain.ToLowerInvariant(), out var summary))
            return false;

        var deps = RecheckHelper.GetDependenciesForIssues(summary, minSeverity);
        if (deps == RecheckHelper.CacheDep.None)
            return false;

        RecheckHelper.ClearEntriesForDomain(domain, deps, _dns, _smtp, _http, importedOnly);
        return true;
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
    }
}

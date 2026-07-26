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
    /// <summary>
    /// The value of <c>CacheDir</c> that turns the disk tier off entirely: no load,
    /// no flusher, no sweep, and nothing queued in the caches' write bags.
    ///
    /// <para>A path-shaped switch rather than a path plus a boolean, matching the
    /// existing sentinel convention (<see cref="AuthService.DisabledMarker"/>).
    /// Deliberately <i>not</i> "unset means off", tempting as that is: the directory
    /// is derived today and nobody sets a key that does not yet exist, so
    /// unset-means-off would silently disable the disk cache on every existing
    /// deployment the moment it upgraded.</para>
    /// </summary>
    public const string DisabledMarker = "none";

    /// <summary>
    /// True when this manager has no disk tier — see <see cref="DisabledMarker"/>.
    ///
    /// <para>Only the explicit marker counts. An empty or missing value is <b>not</b>
    /// disabled, deliberately: <c>GetValue&lt;string&gt;</c> returns the empty string
    /// for a JSON <c>null</c>, so treating blank as "off" would turn the disk cache
    /// off for anyone whose settings file merely mentions the key. Callers resolve a
    /// blank value to their own default path instead.</para>
    /// </summary>
    public static bool IsDisabled(string? cacheDir)
        => string.Equals(cacheDir?.Trim(), DisabledMarker, StringComparison.OrdinalIgnoreCase);

    private readonly string _cacheDir;
    private readonly bool _enabled;
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
        _enabled = !IsDisabled(cacheDir);
        _ttl = ttl;
        _dns = dns;
        _smtp = smtp;
        _http = http;
        _domainResults = new DomainResultStore(ttl > TimeSpan.Zero ? ttl : null, _enabled);
    }

    /// <summary>
    /// Loads cached probe data from disk and primes the services.
    /// Returns summary info about what was loaded, or null if nothing was found.
    /// </summary>
    public Task<DiskCacheService.CacheLoadResult?> LoadAsync(bool retryErrors = false)
        => _enabled
            ? DiskCacheService.LoadAsync(_cacheDir, _ttl, _smtp, _http, _dns, retryErrors, _domainResults)
            : Task.FromResult<DiskCacheService.CacheLoadResult?>(null);

    /// <summary>
    /// Starts a background timer that periodically flushes in-memory caches to disk.
    /// A no-op without a disk tier, so no timer runs and nothing is swept.
    /// </summary>
    public void StartBackgroundFlusher(TimeSpan interval)
    {
        if (!_enabled) return;
        _flusher ??= new BackgroundCacheFlusher(_cacheDir, _smtp, _http, _dns, interval, _ttl, _domainResults);
    }

    /// <summary>
    /// Explicitly flushes all in-memory caches to disk.
    /// Routes through the flusher's lock when available to prevent concurrent writes.
    /// </summary>
    public Task FlushAsync() => !_enabled
        ? Task.CompletedTask
        : _flusher != null
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
    /// Republish everything held in memory into the shared Redis cache, for use when
    /// that cache has been emptied underneath a running instance.
    ///
    /// <para>Memory, not disk. L1 is a superset of what this instance would find on
    /// disk — the startup load imports every instance's live records into it, so it
    /// holds those plus everything fetched since, including the last flush interval's
    /// worth that has not reached disk yet. It needs no file I/O, and it is the only
    /// source that exists at all when <c>CacheDir=none</c>.</para>
    ///
    /// <para>Returns the number of keys published.</para>
    /// </summary>
    public int WarmSharedCache()
        => _dns.WarmSharedCache() + _smtp.WarmSharedCache() + _http.WarmSharedCache();

    /// <summary>
    /// Drop shared-cache index entries for keys that have expired. Cheap, and needed
    /// periodically: MemoryCache expires lazily and never says so, and without this the
    /// index would accumulate every key the process had ever cached.
    /// </summary>
    public void PruneSharedCacheIndex()
    {
        _dns.PruneSharedCacheIndex();
        _smtp.PruneSharedCacheIndex();
        _http.PruneSharedCacheIndex();
    }

    /// <summary>
    /// How many keys the shared-cache index is holding across every cache. Zero when
    /// no index is kept — no Redis, or the watch that would use it turned off — which
    /// is what makes "the index does not grow when nothing will ever prune it"
    /// something a test can assert rather than something the wiring merely intends.
    /// </summary>
    public int SharedCacheIndexCount =>
        _dns.SharedCacheIndexCount + _smtp.SharedCacheIndexCount + _http.SharedCacheIndexCount;

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

    /// <summary>How many domain summaries are held for recheck decisions, including any
    /// that have expired and not yet been swept — see
    /// <see cref="ExpiringMap{TKey,TValue}.Count"/>.</summary>
    public int DomainResultCount => _domainResults.Count;

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

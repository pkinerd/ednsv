using System.Collections.Concurrent;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Ednsv.Core.Services;

/// <summary>
/// Persists probe results (SMTP, HTTP, DNS, ports) to a cache directory so they
/// can be reused across runs. Each cache type is stored in its own file, and
/// every entry carries an individual timestamp for per-entry TTL expiry.
/// </summary>
public class DiskCacheService
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    // File names within the cache directory
    private const string SmtpProbesFile = "smtp-probes.json";
    private const string PortProbesFile = "port-probes.json";
    private const string RcptProbesFile = "rcpt-probes.json";
    private const string HttpGetFile = "http-get.json";
    private const string HttpGetWithHeadersFile = "http-get-headers.json";
    private const string UnreachableServersFile = "unreachable-servers.json";
    private const string PtrLookupsFile = "ptr-lookups.json";
    private const string DnsQueriesFile = "dns-queries.json";
    private const string DnsServerQueriesFile = "dns-server-queries.json";
    private const string AxfrResultsFile = "axfr-results.json";
    private const string RelayTestsFile = "relay-tests.json";
    private const string DomainResultsFile = "domain-results.json";

    private static readonly string[] AllCacheFiles =
    {
        SmtpProbesFile, PortProbesFile, RcptProbesFile, HttpGetFile, HttpGetWithHeadersFile,
        UnreachableServersFile, PtrLookupsFile, DnsQueriesFile, DnsServerQueriesFile,
        AxfrResultsFile, RelayTestsFile, DomainResultsFile
    };

    // ── Per-instance cache files ─────────────────────────────────────────
    //
    // Each process writes its OWN copy of every cache file
    // ("dns-queries.{instance}.json") and reads all of them back merged. The
    // shared DataDir is the same mount for every replica, so a single
    // "dns-queries.json" meant N pods doing a read-modify-write of one file on
    // their own flush timers, quietly dropping each other's entries — and no
    // coordination covered it, since the Redis beacon only ever guarded config
    // and user writes. Partitioning by writer removes the race outright rather
    // than serialising it, which suits a cache: nothing needs to be atomic
    // across pods, entries are independent, and the merge on load restores the
    // shared view.
    //
    // The suffix is the pod name (HOSTNAME in Kubernetes), so it is stable
    // across a pod's restarts and files don't accumulate per process. Two
    // processes that share BOTH a hostname and a DataDir — a CLI run beside the
    // web service on one machine — still share a file; that is last-write-wins
    // rather than corruption, since every write goes through AtomicFile.
    private static readonly string InstanceSuffix = ComputeInstanceSuffix();

    private static string ComputeInstanceSuffix()
    {
        var raw = Environment.GetEnvironmentVariable("HOSTNAME");
        if (string.IsNullOrWhiteSpace(raw)) raw = Environment.MachineName;
        var cleaned = new string((raw ?? string.Empty)
            .Where(char.IsAsciiLetterOrDigit).ToArray()).ToLowerInvariant();
        if (cleaned.Length > 32) cleaned = cleaned[^32..];
        return cleaned.Length > 0 ? cleaned : "local";
    }

    /// <summary>This process's file for a cache type, e.g. "dns-queries.pod7.json".</summary>
    private static string OwnPath(string cacheDir, string filename) => Path.Combine(cacheDir,
        $"{Path.GetFileNameWithoutExtension(filename)}.{InstanceSuffix}{Path.GetExtension(filename)}");

    /// <summary>
    /// Every on-disk file holding entries for a cache type: this and other
    /// instances' files, plus the legacy un-suffixed file written before the
    /// split (still read, never written, and swept once its entries have aged
    /// past the TTL).
    /// </summary>
    private static IEnumerable<string> EnumerateVariants(string cacheDir, string filename)
    {
        var stem = Path.GetFileNameWithoutExtension(filename);
        var ext = Path.GetExtension(filename);

        string[] candidates;
        try { candidates = Directory.GetFiles(cacheDir, "*" + ext); }
        catch { yield break; }

        foreach (var path in candidates)
        {
            var name = Path.GetFileName(path);
            if (name.Equals(filename, StringComparison.Ordinal))
            {
                yield return path; // legacy shared file
                continue;
            }
            // "{stem}.{suffix}{ext}" and nothing else — an explicit prefix test
            // rather than a glob so "http-get" can't swallow "http-get-headers".
            if (name.StartsWith(stem + ".", StringComparison.Ordinal)
                && name.EndsWith(ext, StringComparison.Ordinal)
                && name.Length > stem.Length + 1 + ext.Length)
            {
                yield return path;
            }
        }
    }

    /// <summary>
    /// Deletes cache files belonging to instances that are gone, and the legacy
    /// shared file, once they are older than the TTL. A file's entries were all
    /// written no later than its mtime, so once that is past the cutoff every
    /// entry in it would be discarded on load anyway. This process's own files
    /// are never swept.
    /// </summary>
    private static void SweepExpiredVariants(string cacheDir, TimeSpan ttl)
    {
        var cutoff = DateTime.UtcNow - ttl;
        foreach (var filename in AllCacheFiles)
        {
            var own = OwnPath(cacheDir, filename);
            foreach (var path in EnumerateVariants(cacheDir, filename))
            {
                if (path.Equals(own, StringComparison.Ordinal)) continue;
                try
                {
                    if (File.GetLastWriteTimeUtc(path) < cutoff) File.Delete(path);
                }
                catch { /* best effort */ }
            }
        }
    }

    /// <summary>
    /// Saves current service caches to disk, merging with any existing entries.
    /// </summary>
    public static async Task SaveAsync(string cacheDir, SmtpProbeService smtp, HttpProbeService http, DnsResolverService dns)
    {
        Directory.CreateDirectory(cacheDir);
        var now = DateTime.UtcNow;

        // Wrap simple types into ICacheEntry wrappers
        var portEntries = smtp.ExportPortCache()
            .ToDictionary(kvp => kvp.Key, kvp => new PortProbeCacheEntry { Open = kvp.Value });
        var unreachableEntries = dns.ExportUnreachableServers()
            .ToDictionary(kvp => kvp.Key, kvp => new UnreachableServerCacheEntry { FailCount = kvp.Value });
        var ptrEntries = dns.ExportPtrCache()
            .ToDictionary(kvp => kvp.Key, kvp => new PtrCacheEntry { Names = kvp.Value });
        var axfrEntries = dns.ExportAxfrCache()
            .ToDictionary(kvp => kvp.Key, kvp => new AxfrCacheEntry { Vulnerable = kvp.Value });

        await Task.WhenAll(
            MergeSaveAsync(cacheDir, SmtpProbesFile, smtp.ExportProbeCache(), now),
            MergeSaveAsync(cacheDir, PortProbesFile, portEntries, now),
            MergeSaveAsync(cacheDir, RcptProbesFile, smtp.ExportRcptCache(), now),
            MergeSaveAsync(cacheDir, RelayTestsFile, smtp.ExportRelayCache(), now),
            MergeSaveAsync(cacheDir, HttpGetFile, http.ExportGetCache(), now),
            MergeSaveAsync(cacheDir, HttpGetWithHeadersFile, http.ExportGetWithHeadersCache(), now),
            MergeSaveAsync(cacheDir, UnreachableServersFile, unreachableEntries, now),
            MergeSaveAsync(cacheDir, PtrLookupsFile, ptrEntries, now),
            MergeSaveAsync(cacheDir, DnsQueriesFile, dns.ExportQueryCache(), now),
            MergeSaveAsync(cacheDir, DnsServerQueriesFile, dns.ExportServerQueryCache(), now),
            MergeSaveAsync(cacheDir, AxfrResultsFile, axfrEntries, now)
        );
    }

    /// <summary>
    /// Loads caches from disk and primes the services. Returns null if the
    /// directory doesn't exist or contains no usable entries.
    /// </summary>
    public static async Task<CacheLoadResult?> LoadAsync(string cacheDir, TimeSpan ttl, SmtpProbeService smtp, HttpProbeService http, DnsResolverService dns, bool retryErrors = false)
    {
        if (!Directory.Exists(cacheDir))
            return null;

        // Clear out scratch files orphaned by a killed process. Age-gated, so a
        // temp belonging to a write that is in flight right now is left alone.
        foreach (var f in AllCacheFiles)
        {
            AtomicFile.SweepStaleTemps(Path.Combine(cacheDir, f));
            AtomicFile.SweepStaleTemps(OwnPath(cacheDir, f));
        }

        // Drop files left by replicas that are gone, and the pre-split shared
        // file, once everything in them would have expired anyway. Startup is
        // enough: a rolling deploy brings up new pods, and each one sweeps.
        SweepExpiredVariants(cacheDir, ttl);

        var cutoff = DateTime.UtcNow - ttl;

        var smtpProbes = await LoadFileAsync<SmtpProbeCacheEntry>(cacheDir, SmtpProbesFile, cutoff);
        var portProbes = await LoadFileAsync<PortProbeCacheEntry>(cacheDir, PortProbesFile, cutoff);
        var rcptProbes = await LoadFileAsync<RcptCacheEntry>(cacheDir, RcptProbesFile, cutoff);
        var httpGet = await LoadFileAsync<HttpGetCacheEntry>(cacheDir, HttpGetFile, cutoff);
        var httpGetHeaders = await LoadFileAsync<HttpGetWithHeadersCacheEntry>(cacheDir, HttpGetWithHeadersFile, cutoff);
        var unreachable = await LoadFileAsync<UnreachableServerCacheEntry>(cacheDir, UnreachableServersFile, cutoff);
        var ptr = await LoadFileAsync<PtrCacheEntry>(cacheDir, PtrLookupsFile, cutoff);
        var dnsQueries = await LoadFileAsync<DnsCacheEntry>(cacheDir, DnsQueriesFile, cutoff);
        var dnsServerQueries = await LoadFileAsync<DnsCacheEntry>(cacheDir, DnsServerQueriesFile, cutoff);
        var axfrResults = await LoadFileAsync<AxfrCacheEntry>(cacheDir, AxfrResultsFile, cutoff);
        var relayTests = await LoadFileAsync<RelayCacheEntry>(cacheDir, RelayTestsFile, cutoff);

        if (retryErrors)
        {
            smtpProbes = smtpProbes?.Where(kvp =>
                    kvp.Value.Error == null &&
                    kvp.Value.Connected &&
                    // Retry probes with empty banner (likely transient read timeout)
                    !string.IsNullOrEmpty(kvp.Value.Banner) &&
                    // Retry probes where TLS was expected but cert wasn't obtained (transient TLS failure)
                    !(kvp.Value.SupportsStartTls && kvp.Value.CertSubject == null) &&
                    // Retry probes with cert metadata but missing raw bytes (upgrades old cache format)
                    !(kvp.Value.CertSubject != null && kvp.Value.CertRawBase64 == null))
                .ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
            portProbes = portProbes?.Where(kvp => kvp.Value.Open)
                .ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
            rcptProbes = rcptProbes?.Where(kvp => kvp.Value.Accepted)
                .ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
            httpGet = httpGet?.Where(kvp => kvp.Value.Success)
                .ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
            httpGetHeaders = httpGetHeaders?.Where(kvp => kvp.Value.Success)
                .ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
            relayTests = relayTests?.Where(kvp => !kvp.Value.Description.StartsWith("Error:") && !kvp.Value.Description.StartsWith("Connection timed out"))
                .ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
            unreachable = null; // let unreachable servers be retried
            dnsQueries = dnsQueries?.Where(kvp => !kvp.Value.HasError)
                .ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
            dnsServerQueries = dnsServerQueries?.Where(kvp => !kvp.Value.HasError)
                .ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
        }

        // Convert new DTO types to the dictionary types the services expect
        if (smtpProbes?.Count > 0) smtp.ImportProbeCache(smtpProbes.ToDictionary(kvp => kvp.Key, kvp => (SmtpProbeCacheEntry)kvp.Value));
        if (portProbes?.Count > 0) smtp.ImportPortCache(portProbes.ToDictionary(kvp => kvp.Key, kvp => kvp.Value.Open));
        if (rcptProbes?.Count > 0) smtp.ImportRcptCache(rcptProbes.ToDictionary(kvp => kvp.Key, kvp => (RcptCacheEntry)kvp.Value));
        if (httpGet?.Count > 0) http.ImportGetCache(httpGet.ToDictionary(kvp => kvp.Key, kvp => (HttpGetCacheEntry)kvp.Value));
        if (httpGetHeaders?.Count > 0) http.ImportGetWithHeadersCache(httpGetHeaders.ToDictionary(kvp => kvp.Key, kvp => (HttpGetWithHeadersCacheEntry)kvp.Value));
        if (unreachable?.Count > 0) dns.ImportUnreachableServers(unreachable.ToDictionary(kvp => kvp.Key, kvp => kvp.Value.FailCount));
        if (ptr?.Count > 0) dns.ImportPtrCache(ptr.ToDictionary(kvp => kvp.Key, kvp => kvp.Value.Names));
        if (dnsQueries?.Count > 0) dns.ImportQueryCache(dnsQueries.ToDictionary(kvp => kvp.Key, kvp => (DnsCacheEntry)kvp.Value));
        if (dnsServerQueries?.Count > 0) dns.ImportServerQueryCache(dnsServerQueries.ToDictionary(kvp => kvp.Key, kvp => (DnsCacheEntry)kvp.Value));
        if (relayTests?.Count > 0) smtp.ImportRelayCache(relayTests.ToDictionary(kvp => kvp.Key, kvp => (RelayCacheEntry)kvp.Value));
        if (axfrResults?.Count > 0) dns.ImportAxfrCache(axfrResults.ToDictionary(kvp => kvp.Key, kvp => kvp.Value.Vulnerable));

        var result = new CacheLoadResult
        {
            SmtpProbes = smtpProbes?.Count ?? 0,
            PortProbes = portProbes?.Count ?? 0,
            RcptProbes = rcptProbes?.Count ?? 0,
            HttpRequests = (httpGet?.Count ?? 0) + (httpGetHeaders?.Count ?? 0),
            DnsQueries = (dnsQueries?.Count ?? 0) + (dnsServerQueries?.Count ?? 0),
            PtrLookups = ptr?.Count ?? 0
        };

        // Determine age from the oldest entry across all cache files
        var allTimestamps = new List<DateTime>();
        void CollectTimestamps<T>(Dictionary<string, T>? dict) where T : ICacheEntry
        {
            if (dict != null)
                foreach (var entry in dict.Values)
                    allTimestamps.Add(entry.CachedAtUtc);
        }
        CollectTimestamps(smtpProbes);
        CollectTimestamps(portProbes);
        CollectTimestamps(rcptProbes);
        CollectTimestamps(httpGet);
        CollectTimestamps(httpGetHeaders);
        CollectTimestamps(unreachable);
        CollectTimestamps(ptr);
        CollectTimestamps(dnsQueries);
        CollectTimestamps(dnsServerQueries);

        if (allTimestamps.Count > 0)
            result.Age = DateTime.UtcNow - allTimestamps.Min();

        return result.Total > 0 ? result : null;
    }

    // ── Private helpers ──────────────────────────────────────────────────

    /// <summary>
    /// Reads existing entries from a cache file, merges new entries (newer wins),
    /// stamps them, and writes back atomically.
    /// </summary>
    private static async Task MergeSaveAsync<T>(string cacheDir, string filename, Dictionary<string, T> newEntries, DateTime now) where T : ICacheEntry
    {
        if (newEntries.Count == 0) return;

        // Only ever this instance's own file, so concurrent replicas never
        // read-modify-write the same one. Merging with it preserves entries this
        // process wrote before a restart.
        var path = OwnPath(cacheDir, filename);

        // Read existing entries
        Dictionary<string, T>? existing = null;
        if (File.Exists(path))
        {
            try
            {
                var json = await File.ReadAllTextAsync(path);
                existing = JsonSerializer.Deserialize<Dictionary<string, T>>(json, JsonOptions);
            }
            catch { /* corrupt file — overwrite */ }
        }

        // Merge: new entries overwrite existing ones (they're fresher)
        var merged = existing ?? new Dictionary<string, T>();
        foreach (var kvp in newEntries)
        {
            if (kvp.Value.CachedAtUtc != default)
            {
                // The source stamped a real fetch time (e.g. DNS query caches track
                // when each response was actually fetched). Honour it so a re-fetched
                // entry's TTL ages from its latest fetch, while an untouched entry
                // loaded from disk keeps its original timestamp and expires on schedule.
            }
            else if (existing != null && existing.TryGetValue(kvp.Key, out var existingEntry))
            {
                // No fetch time supplied — preserve the on-disk timestamp so TTL
                // expiry still works across runs for caches that don't track it.
                kvp.Value.CachedAtUtc = existingEntry.CachedAtUtc;
            }
            else
            {
                kvp.Value.CachedAtUtc = now;
            }
            merged[kvp.Key] = kvp.Value;
        }

        var output = JsonSerializer.Serialize(merged, JsonOptions);
        await AtomicFile.WriteAllTextAsync(path, output);
    }

    /// <summary>
    /// Loads entries from a cache file, filtering out entries older than cutoff.
    /// </summary>
    private static async Task<Dictionary<string, T>?> LoadFileAsync<T>(string cacheDir, string filename, DateTime cutoff) where T : ICacheEntry
    {
        // Merge across every instance's file so the cache is shared on read even
        // though each writer owns its own file. Freshest entry wins per key; an
        // unreadable variant is skipped rather than failing the whole load.
        var merged = new Dictionary<string, T>();

        foreach (var path in EnumerateVariants(cacheDir, filename))
        {
            Dictionary<string, T>? entries;
            try
            {
                var json = await File.ReadAllTextAsync(path);
                entries = JsonSerializer.Deserialize<Dictionary<string, T>>(json, JsonOptions);
            }
            catch
            {
                continue; // corrupt or vanished variant
            }
            if (entries == null) continue;

            foreach (var kvp in entries)
            {
                if (kvp.Value.CachedAtUtc < cutoff) continue; // per-entry TTL
                if (merged.TryGetValue(kvp.Key, out var seen) && seen.CachedAtUtc >= kvp.Value.CachedAtUtc)
                    continue;
                merged[kvp.Key] = kvp.Value;
            }
        }

        return merged.Count > 0 ? merged : null;
    }

    // ── Public result type ───────────────────────────────────────────────

    public class CacheLoadResult
    {
        public TimeSpan Age { get; set; }
        public int SmtpProbes { get; set; }
        public int PortProbes { get; set; }
        public int RcptProbes { get; set; }
        public int HttpRequests { get; set; }
        public int DnsQueries { get; set; }
        public int PtrLookups { get; set; }
        public int Total => SmtpProbes + PortProbes + RcptProbes + HttpRequests + DnsQueries + PtrLookups;
    }

    // ── Domain results persistence ──────────────────────────────────────

    // Serializes concurrent read-modify-write to domain-results.json
    private static readonly SemaphoreSlim _domainResultsLock = new(1, 1);

    /// <summary>
    /// Saves a domain's validation result summary to the cache directory.
    /// Merges with existing results from other domains.
    /// </summary>
    public static async Task SaveDomainResultAsync(string cacheDir, string domain, DomainResultSummary summary)
    {
        Directory.CreateDirectory(cacheDir);
        var path = OwnPath(cacheDir, DomainResultsFile);

        await _domainResultsLock.WaitAsync();
        try
        {
            Dictionary<string, DomainResultSummary>? existing = null;
            if (File.Exists(path))
            {
                try
                {
                    var json = await File.ReadAllTextAsync(path);
                    existing = JsonSerializer.Deserialize<Dictionary<string, DomainResultSummary>>(json, JsonOptions);
                }
                catch { /* corrupt — overwrite */ }
            }

            var merged = existing ?? new Dictionary<string, DomainResultSummary>();
            merged[domain.ToLowerInvariant()] = summary;

            var output = JsonSerializer.Serialize(merged, JsonOptions);
            await AtomicFile.WriteAllTextAsync(path, output);
        }
        finally
        {
            _domainResultsLock.Release();
        }
    }

    /// <summary>
    /// Loads all domain result summaries from the cache directory.
    /// </summary>
    public static async Task<Dictionary<string, DomainResultSummary>?> LoadDomainResultsAsync(string cacheDir)
    {
        // Merged across instances, most recent validation per domain winning, so
        // a recheck sees prior results regardless of which replica produced them.
        var merged = new Dictionary<string, DomainResultSummary>();

        foreach (var path in EnumerateVariants(cacheDir, DomainResultsFile))
        {
            Dictionary<string, DomainResultSummary>? entries;
            try
            {
                var json = await File.ReadAllTextAsync(path);
                entries = JsonSerializer.Deserialize<Dictionary<string, DomainResultSummary>>(json, JsonOptions);
            }
            catch
            {
                continue;
            }
            if (entries == null) continue;

            foreach (var kvp in entries)
            {
                if (merged.TryGetValue(kvp.Key, out var seen) && seen.ValidatedAtUtc >= kvp.Value.ValidatedAtUtc)
                    continue;
                merged[kvp.Key] = kvp.Value;
            }
        }

        return merged.Count > 0 ? merged : null;
    }
}

// ── Cache entry interface ────────────────────────────────────────────────

/// <summary>
/// All cache entries must carry a timestamp for per-entry TTL expiry.
/// </summary>
public interface ICacheEntry
{
    DateTime CachedAtUtc { get; set; }
}

// ── Serializable DTOs for cache entries ──────────────────────────────────

public class SmtpProbeCacheEntry : ICacheEntry
{
    public DateTime CachedAtUtc { get; set; }
    public bool Connected { get; set; }
    public string Banner { get; set; } = "";
    public bool SupportsStartTls { get; set; }
    public List<string> EhloCapabilities { get; set; } = new();
    public string? CertSubject { get; set; }
    public string? CertIssuer { get; set; }
    public DateTime? CertExpiry { get; set; }
    public List<string>? CertSans { get; set; }
    public string? CertRawBase64 { get; set; }
    public List<string>? CertChainIntermediatesBase64 { get; set; }
    public string? TlsProtocol { get; set; }
    public string? TlsCipherSuite { get; set; }
    public int? SmtpMaxSize { get; set; }
    public bool SupportsRequireTls { get; set; }
    public long ConnectTimeMs { get; set; }
    public long BannerTimeMs { get; set; }
    public long EhloTimeMs { get; set; }
    public long TlsTimeMs { get; set; }
    public string? Error { get; set; }
}

public class PortProbeCacheEntry : ICacheEntry
{
    public DateTime CachedAtUtc { get; set; }
    public bool Open { get; set; }
}

public class RcptCacheEntry : ICacheEntry
{
    public DateTime CachedAtUtc { get; set; }
    public bool Accepted { get; set; }
    public string Response { get; set; } = "";
}

public class HttpGetCacheEntry : ICacheEntry
{
    public DateTime CachedAtUtc { get; set; }
    public bool Success { get; set; }
    public string Content { get; set; } = "";
    public int StatusCode { get; set; }
}

public class HttpGetWithHeadersCacheEntry : ICacheEntry
{
    public DateTime CachedAtUtc { get; set; }
    public bool Success { get; set; }
    public string Content { get; set; } = "";
    public int StatusCode { get; set; }
    public string? ContentType { get; set; }
}

public class UnreachableServerCacheEntry : ICacheEntry
{
    public DateTime CachedAtUtc { get; set; }
    public int FailCount { get; set; }
}

public class AxfrCacheEntry : ICacheEntry
{
    public DateTime CachedAtUtc { get; set; }
    public bool Vulnerable { get; set; }
}

public class RelayCacheEntry : ICacheEntry
{
    public DateTime CachedAtUtc { get; set; }
    public bool IsRelay { get; set; }
    public string Description { get; set; } = "";
}

public class PtrCacheEntry : ICacheEntry
{
    public DateTime CachedAtUtc { get; set; }
    public List<string> Names { get; set; } = new();
}

/// <summary>
/// Stores a summary of a domain's validation results for recheck decisions.
/// </summary>
public class DomainResultSummary
{
    public DateTime ValidatedAtUtc { get; set; }
    public int PassCount { get; set; }
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public int CriticalCount { get; set; }
    /// <summary>Checks that had warning or higher severity.</summary>
    public List<IssueCheckEntry> IssueChecks { get; set; } = new();
}

public class IssueCheckEntry
{
    public string Name { get; set; } = "";
    public string Category { get; set; } = "";
    public string Severity { get; set; } = "";
}

/// <summary>
/// Periodically flushes service caches to disk in the background.
/// Also exposes FlushAsync for explicit saves (e.g. after each domain).
/// Dispose to stop the background timer and perform a final save.
/// </summary>
public sealed class BackgroundCacheFlusher : IAsyncDisposable
{
    private readonly string _cacheDir;
    private readonly SmtpProbeService _smtp;
    private readonly HttpProbeService _http;
    private readonly DnsResolverService _dns;
    private readonly Timer _timer;
    private readonly SemaphoreSlim _lock = new(1, 1);
    private bool _disposed;

    public BackgroundCacheFlusher(string cacheDir, SmtpProbeService smtp, HttpProbeService http, DnsResolverService dns, TimeSpan interval)
    {
        _cacheDir = cacheDir;
        _smtp = smtp;
        _http = http;
        _dns = dns;
        _timer = new Timer(_ => _ = FlushInBackground(), null, interval, interval);
    }

    private async Task FlushInBackground()
    {
        try { await FlushAsync(); }
        catch { /* best-effort background flush */ }
    }

    public async Task FlushAsync()
    {
        if (_disposed) return;
        if (!await _lock.WaitAsync(0)) return; // skip if a flush is already in progress
        try
        {
            await DiskCacheService.SaveAsync(_cacheDir, _smtp, _http, _dns);
        }
        finally
        {
            _lock.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed) return;
        _disposed = true;
        await _timer.DisposeAsync();
        // Final flush
        await _lock.WaitAsync();
        try
        {
            await DiskCacheService.SaveAsync(_cacheDir, _smtp, _http, _dns);
        }
        finally
        {
            _lock.Release();
        }
    }
}

using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace Ednsv.Core.Services;

/// <summary>
/// Persists probe results (SMTP, HTTP, DNS, ports, domain summaries) to a cache
/// directory so they can be reused across runs and across replicas.
///
/// <para><b>Storage model: one immutable file per flush, in a per-instance folder.</b>
/// A flush serialises whatever the caches have queued since the last one into
/// <c>{cacheDir}/{instance}/cache.{utc}.{nonce}.jsonl</c>, written once via
/// <see cref="AtomicFile"/> and never touched again. There are no appends, no
/// rewrites and no compaction, so nothing is re-serialised on a later flush just
/// because it is still cached — which is what the previous model did to its entire
/// contents, on every tick, forever.</para>
///
/// <para>Consequences, all of which remove work rather than add it: no torn or
/// interleaved lines, since each file is written whole and atomically; no
/// two-writer conflict even when a CLI run shares a hostname with the web service,
/// since they write different filenames; exactly one line per key per file, since
/// the bag dedupes within a flush; and a sweep that needs no exception for "the file
/// being written right now", because there is never one.</para>
///
/// <para>Each line is a self-describing <see cref="CacheRecord"/> carrying its own
/// type tag, fetch time and expiry, so a load merges every instance's files with the
/// later fetch winning per key. Files written by the previous one-file-per-cache-type
/// model are still read, so an upgrade does not cold-start, and age out via the
/// sweep.</para>
/// </summary>
public class DiskCacheService
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    /// <summary>Record serialisation. Compact — one line per record, no indenting —
    /// and property names come from the <c>[JsonPropertyName]</c> attributes on
    /// <see cref="CacheRecord"/> rather than a naming policy.</summary>
    private static readonly JsonSerializerOptions RecordOptions = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    // ── Legacy per-type files ────────────────────────────────────────────
    //
    // Read, never written. Everything below this block exists so an upgrade finds
    // the cache it already had; the sweep deletes these once they are past the TTL.

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

    // ── Per-instance folder ──────────────────────────────────────────────
    //
    // Each process writes only into its own subfolder and reads every folder back
    // merged. The cache directory may be the same shared mount for every replica,
    // so one file per cache type meant N pods doing a read-modify-write of the same
    // file on their own flush timers, quietly dropping each other's entries — and
    // no coordination covered it, since the Redis beacon only ever guarded config
    // and user writes. Partitioning by writer removes the race outright rather than
    // serialising it, which suits a cache: nothing needs to be atomic across pods,
    // entries are independent, and the merge on load restores the shared view.
    //
    // The name is the pod name (HOSTNAME in Kubernetes), so it is stable across a
    // pod's restarts and folders don't accumulate per process. Two processes that
    // share BOTH a hostname and a cache directory — a CLI run beside the web
    // service on one machine — share a folder but never a file, since every flush
    // writes a fresh filename.
    //
    // The folder does not reduce load cost, which is driven by total file count.
    // It is there for headroom at longer retentions, and so a departed pod's files
    // are legible and removable as a unit.
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

    /// <summary>This process's folder within the cache directory.</summary>
    public static string InstanceFolder(string cacheDir) => Path.Combine(cacheDir, InstanceSuffix);

    /// <summary>
    /// Every file holding entries for a legacy cache type: the pre-split shared file
    /// and any per-instance variants of it. Read only — nothing writes these now.
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

    // ── Record files ─────────────────────────────────────────────────────

    private const string RecordFilePrefix = "cache.";
    private const string RecordFileExtension = ".jsonl";

    /// <summary>Sortable, filename-safe, and parseable back without ambiguity —
    /// the sweep reads the timestamp out of the name rather than opening the file.</summary>
    private const string FileTimeFormat = "yyyyMMdd'T'HHmmssfff'Z'";

    private static string NewRecordFileName(DateTime nowUtc) =>
        $"{RecordFilePrefix}{nowUtc.ToString(FileTimeFormat, CultureInfo.InvariantCulture)}"
        + $".{Guid.NewGuid().ToString("N")[..8]}{RecordFileExtension}";

    /// <summary>
    /// When a record file was written. Taken from its name, because every entry in
    /// it has <c>WrittenUtc &lt;= fileTime</c>, which makes the sweep's arithmetic
    /// conservative by construction and needs no parsing. Falls back to mtime for a
    /// name that doesn't parse.
    /// </summary>
    private static DateTime RecordFileTimeUtc(string path)
    {
        var parts = Path.GetFileNameWithoutExtension(path).Split('.');
        if (parts.Length >= 2 && DateTime.TryParseExact(parts[1], FileTimeFormat,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var stamp))
        {
            return stamp;
        }
        try { return File.GetLastWriteTimeUtc(path); }
        catch { return DateTime.UtcNow; }
    }

    /// <summary>
    /// Writes everything the caches have queued since the last flush into one new
    /// file, then drops exactly those entries from their bags.
    ///
    /// <para>Returns without writing when nothing is queued: the bags <i>are</i> the
    /// dirty flag, so an idle process creates no files. If the write throws, no bag
    /// is committed and the next flush retries the same entries — a failed flush
    /// loses nothing but time.</para>
    /// </summary>
    public static async Task SaveAsync(string cacheDir, SmtpProbeService smtp, HttpProbeService http,
        DnsResolverService dns, DomainResultStore? domainResults = null)
    {
        var pending = new List<PendingWrites>();
        pending.AddRange(dns.CollectPendingWrites());
        pending.AddRange(smtp.CollectPendingWrites());
        pending.AddRange(http.CollectPendingWrites());
        if (domainResults != null) pending.Add(domainResults.CollectPending());

        var body = new StringBuilder();
        var count = 0;
        foreach (var source in pending)
        {
            foreach (var record in source.Records)
            {
                body.Append(JsonSerializer.Serialize(record, RecordOptions)).Append('\n');
                count++;
            }
        }
        if (count == 0) return;

        // Idempotent and cheap. Required on every flush and not just at startup: the
        // sweep removes an empty folder belonging to an instance that has been idle
        // longer than the TTL, and that instance may be this one, still running.
        var dir = InstanceFolder(cacheDir);
        Directory.CreateDirectory(dir);

        await AtomicFile.WriteAllTextAsync(
            Path.Combine(dir, NewRecordFileName(DateTime.UtcNow)), body.ToString());

        foreach (var source in pending) source.Commit();
    }

    /// <summary>
    /// Deletes record files whose contents would all be discarded on load, the legacy
    /// per-type files once they are equally stale, and the folders of instances that
    /// are gone.
    ///
    /// <para>The rule for a record file is filename arithmetic alone — every entry in
    /// it was written no later than the file was, so once <c>fileTime + ttl</c> is
    /// past, nothing in it can still be live. It applies to this instance's files
    /// exactly as to any other's; there is no file being appended to that would need
    /// exempting.</para>
    ///
    /// <para>A folder is removed only when it is empty, is not ours, and its own
    /// mtime is past the cutoff. The age gate is what makes this safe against an
    /// instance that has just started and not yet flushed — creating the folder sets
    /// a fresh mtime, so it cannot qualify. Note the timing: removing the last file
    /// updates the parent's mtime, so the gate's clock only starts once the folder is
    /// already empty, and a dead instance's folder lingers for roughly twice the TTL.
    /// That is deliberate slack, not an oversight.</para>
    ///
    /// <para>Best-effort throughout: a file we cannot delete is left for the next
    /// sweep rather than failing the load or the flush that called this.</para>
    /// </summary>
    public static void Sweep(string cacheDir, TimeSpan ttl)
    {
        // A non-positive TTL means "no expiry", not "everything expired" — without
        // this the cutoff would be now and the sweep would delete the whole cache on
        // the first tick.
        if (ttl <= TimeSpan.Zero) return;

        var now = DateTime.UtcNow;
        var cutoff = now - ttl;

        // Only files this service is known to have written, matched by name rather
        // than by a "*.json" glob. The cache directory is configurable, and an
        // operator who points it somewhere shared must not have unrelated JSON — or,
        // if pointed at the data directory itself, config.json and users.json —
        // deleted out from under them.
        foreach (var filename in AllCacheFiles)
        {
            foreach (var path in EnumerateVariants(cacheDir, filename))
            {
                try
                {
                    if (File.GetLastWriteTimeUtc(path) < cutoff) File.Delete(path);
                }
                catch { /* best effort */ }
            }
        }

        string[] folders;
        try { folders = Directory.GetDirectories(cacheDir); }
        catch { return; }

        foreach (var folder in folders)
        {
            var own = string.Equals(Path.GetFileName(folder), InstanceSuffix, StringComparison.Ordinal);

            // Scratch files from a writer that was killed mid-flush. Age-gated, so a
            // temp belonging to a write in progress right now is left alone.
            AtomicFile.SweepStaleTempsInDirectory(folder);

            try
            {
                foreach (var path in Directory.GetFiles(folder, "*" + RecordFileExtension))
                {
                    try
                    {
                        if (RecordFileTimeUtc(path) < cutoff) File.Delete(path);
                    }
                    catch { /* best effort */ }
                }
            }
            catch { continue; }

            if (own) continue;

            try
            {
                if (Directory.EnumerateFileSystemEntries(folder).Any()) continue;
                if (Directory.GetLastWriteTimeUtc(folder) >= cutoff) continue;
                Directory.Delete(folder);
            }
            catch { /* best effort */ }
        }
    }

    /// <summary>
    /// Loads caches from disk and primes the services. Returns null if the
    /// directory doesn't exist or contains no usable entries.
    ///
    /// <para>Legacy per-type files are read first and the record files applied on
    /// top, so a key present in both takes its newer value from the record files.
    /// Within the record files the entry with the latest fetch time wins, which is
    /// what merges several instances' folders into one view.</para>
    /// </summary>
    public static async Task<CacheLoadResult?> LoadAsync(string cacheDir, TimeSpan ttl, SmtpProbeService smtp,
        HttpProbeService http, DnsResolverService dns, bool retryErrors = false,
        DomainResultStore? domainResults = null)
    {
        if (!Directory.Exists(cacheDir))
            return null;

        // Clear out scratch files orphaned by a killed process, drop record files
        // whose contents have all expired, and remove folders left by instances that
        // are gone. Startup is enough for the folder work: a rolling deploy brings up
        // new pods and each one sweeps.
        foreach (var f in AllCacheFiles)
            AtomicFile.SweepStaleTemps(Path.Combine(cacheDir, f));
        Sweep(cacheDir, ttl);

        var cutoff = DateTime.UtcNow - ttl;

        var (legacy, legacyOldest) = await LoadLegacyAsync(cacheDir, cutoff, smtp, http, dns, domainResults, retryErrors);
        var (records, recordOldest) = await LoadRecordFilesAsync(cacheDir, cutoff, smtp, http, dns, domainResults, retryErrors);

        // Summed rather than de-duplicated. A key present in both models is counted
        // twice, which overstates the startup log line by however much overlap an
        // upgrade happens to have; it is a report, not a cache invariant, and the
        // legacy files disappear on their own within one TTL.
        var result = new CacheLoadResult
        {
            SmtpProbes = legacy.SmtpProbes + records.SmtpProbes,
            PortProbes = legacy.PortProbes + records.PortProbes,
            RcptProbes = legacy.RcptProbes + records.RcptProbes,
            HttpRequests = legacy.HttpRequests + records.HttpRequests,
            DnsQueries = legacy.DnsQueries + records.DnsQueries,
            PtrLookups = legacy.PtrLookups + records.PtrLookups
        };

        var oldest = legacyOldest < recordOldest ? legacyOldest : recordOldest;
        if (oldest != DateTime.MaxValue)
            result.Age = DateTime.UtcNow - oldest;

        return result.Total > 0 ? result : null;
    }

    /// <summary>
    /// Reads every <c>*.jsonl</c> under the cache directory — this instance's folder
    /// and every other's — keeping the entry with the latest fetch time per
    /// (type, key) and discarding anything already expired. An unparseable line is
    /// skipped rather than failing its file, and an unreadable file rather than
    /// failing the load.
    ///
    /// <para>Two expiry rules apply, and both are needed. An entry is dropped if its
    /// own <c>ExpiresUtc</c> has passed — that is the writer's judgement, and once
    /// DNS entries are bounded by their record TTLs it will be the tighter of the
    /// two. It is dropped equally if it was fetched before <paramref name="cutoff"/>,
    /// which is this reader's configured cap: an entry written by a process running
    /// without a TTL carries no expiry of its own, and the reader's setting must
    /// still bound how stale a value it will accept.</para>
    /// </summary>
    private static async Task<(CacheLoadResult, DateTime)> LoadRecordFilesAsync(string cacheDir, DateTime cutoff,
        SmtpProbeService smtp, HttpProbeService http, DnsResolverService dns,
        DomainResultStore? domainResults, bool retryErrors)
    {
        var result = new CacheLoadResult();
        var oldest = DateTime.MaxValue;

        string[] files;
        try { files = Directory.GetFiles(cacheDir, "*" + RecordFileExtension, SearchOption.AllDirectories); }
        catch { return (result, oldest); }
        if (files.Length == 0) return (result, oldest);

        var now = DateTime.UtcNow;
        var winners = new Dictionary<(string Type, string Key), CacheRecord>();

        foreach (var path in files)
        {
            string[] lines;
            try { lines = await File.ReadAllLinesAsync(path); }
            catch { continue; }

            foreach (var line in lines)
            {
                if (line.Length == 0) continue;

                CacheRecord? record;
                try { record = JsonSerializer.Deserialize<CacheRecord>(line, RecordOptions); }
                catch { continue; }

                if (record == null || record.Type.Length == 0 || record.Key.Length == 0) continue;
                if (record.ExpiresUtc <= now || record.WrittenUtc < cutoff) continue;

                var id = (record.Type, record.Key);
                if (winners.TryGetValue(id, out var seen) && seen.WrittenUtc >= record.WrittenUtc) continue;
                winners[id] = record;
            }
        }

        foreach (var record in winners.Values)
        {
            if (retryErrors && !PassesRetryFilter(record.Type, record.Value)) continue;

            // Each service claims the types it owns and reports whether it did, so a
            // record for a type nobody recognises is dropped rather than miscounted.
            var imported = dns.TryImportRecord(record.Type, record.Key, record.Value)
                || smtp.TryImportRecord(record.Type, record.Key, record.Value)
                || http.TryImportRecord(record.Type, record.Key, record.Value)
                || TryImportDomainResult(domainResults, record);
            if (!imported) continue;

            CountRecord(result, record.Type);
            if (record.WrittenUtc != default && record.WrittenUtc < oldest) oldest = record.WrittenUtc;
        }

        return (result, oldest);
    }

    private static bool TryImportDomainResult(DomainResultStore? store, CacheRecord record)
    {
        if (record.Type != CacheTypes.DomainResults) return false;
        if (store == null || record.Value == null) return true; // ours, but nowhere to put it

        try
        {
            var summary = record.Value.Deserialize<DomainResultSummary>();
            if (summary != null) store.Import(record.Key, summary);
        }
        catch { /* ours, but unreadable — skip the record, not the file */ }
        return true;
    }

    private static void CountRecord(CacheLoadResult result, string type)
    {
        switch (type)
        {
            case CacheTypes.Smtp: result.SmtpProbes++; break;
            case CacheTypes.Port: result.PortProbes++; break;
            case CacheTypes.Rcpt: result.RcptProbes++; break;
            case CacheTypes.HttpGet:
            case CacheTypes.HttpGetHeaders: result.HttpRequests++; break;
            case CacheTypes.Dns:
            case CacheTypes.DnsServer: result.DnsQueries++; break;
            case CacheTypes.Ptr: result.PtrLookups++; break;
            // relay, axfr, unreachable and domain-results are loaded but not
            // reported, exactly as before.
        }
    }

    /// <summary>
    /// The record-file equivalent of the <c>retryErrors</c> filtering the legacy
    /// loader applies: entries that look like a transient failure are left out so
    /// they get refetched. Deserialises the payload a second time for the survivors,
    /// which is only paid on the explicit retry path.
    /// </summary>
    private static bool PassesRetryFilter(string type, JsonNode? value)
    {
        if (value == null) return false;
        try
        {
            switch (type)
            {
                case CacheTypes.Smtp:
                {
                    var e = value.Deserialize<SmtpProbeCacheEntry>();
                    return e != null
                        && e.Error == null
                        && e.Connected
                        // Empty banner is likely a transient read timeout
                        && !string.IsNullOrEmpty(e.Banner)
                        // TLS expected but no cert obtained — transient TLS failure
                        && !(e.SupportsStartTls && e.CertSubject == null)
                        // Cert metadata without raw bytes — an older cache format
                        && !(e.CertSubject != null && e.CertRawBase64 == null);
                }
                case CacheTypes.Port:
                    return value.GetValue<bool>();
                case CacheTypes.Rcpt:
                    return value.Deserialize<RcptCacheEntry>()?.Accepted == true;
                case CacheTypes.Relay:
                {
                    var e = value.Deserialize<RelayCacheEntry>();
                    return e != null
                        && !e.Description.StartsWith("Error:")
                        && !e.Description.StartsWith("Connection timed out");
                }
                case CacheTypes.HttpGet:
                    return value.Deserialize<HttpGetCacheEntry>()?.Success == true;
                case CacheTypes.HttpGetHeaders:
                    return value.Deserialize<HttpGetWithHeadersCacheEntry>()?.Success == true;
                case CacheTypes.Unreachable:
                    return false; // let unreachable servers be retried
                case CacheTypes.Dns:
                case CacheTypes.DnsServer:
                {
                    var e = value.Deserialize<DnsCacheEntry>();
                    return e != null && !e.HasError;
                }
                default:
                    return true; // ptr, axfr, domain-results — nothing here is a failure
            }
        }
        catch { return false; }
    }

    /// <summary>
    /// Reads the one-file-per-cache-type layout written before the record files.
    /// Read-only: nothing writes these any more, and the sweep removes them once
    /// they are past the TTL.
    /// </summary>
    private static async Task<(CacheLoadResult, DateTime)> LoadLegacyAsync(string cacheDir, DateTime cutoff,
        SmtpProbeService smtp, HttpProbeService http, DnsResolverService dns,
        DomainResultStore? domainResults, bool retryErrors)
    {
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

        if (domainResults != null)
        {
            foreach (var kvp in await LoadLegacyDomainResultsAsync(cacheDir, cutoff))
                domainResults.Import(kvp.Key, kvp.Value);
        }

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

        return (result, allTimestamps.Count > 0 ? allTimestamps.Min() : DateTime.MaxValue);
    }

    // ── Private helpers ──────────────────────────────────────────────────

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

    // ── Legacy domain results ───────────────────────────────────────────

    /// <summary>
    /// Reads domain summaries from the pre-record-file layout, most recent validation
    /// per domain winning. Now TTL-filtered, which the old reader never was — it fed
    /// recheck decisions from records of any age.
    /// </summary>
    private static async Task<Dictionary<string, DomainResultSummary>> LoadLegacyDomainResultsAsync(
        string cacheDir, DateTime cutoff)
    {
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
                if (kvp.Value.ValidatedAtUtc < cutoff) continue;
                if (merged.TryGetValue(kvp.Key, out var seen) && seen.ValidatedAtUtc >= kvp.Value.ValidatedAtUtc)
                    continue;
                merged[kvp.Key] = kvp.Value;
            }
        }

        return merged;
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
    private readonly DomainResultStore? _domainResults;
    private readonly TimeSpan _ttl;
    private readonly Timer _timer;
    private readonly SemaphoreSlim _lock = new(1, 1);
    private bool _disposed;

    public BackgroundCacheFlusher(string cacheDir, SmtpProbeService smtp, HttpProbeService http,
        DnsResolverService dns, TimeSpan interval, TimeSpan ttl = default,
        DomainResultStore? domainResults = null)
    {
        _cacheDir = cacheDir;
        _smtp = smtp;
        _http = http;
        _dns = dns;
        _ttl = ttl;
        _domainResults = domainResults;
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
            await DiskCacheService.SaveAsync(_cacheDir, _smtp, _http, _dns, _domainResults);
            // Cheap when there is nothing to do, and it is the only thing that
            // removes files and folders once a process stops restarting.
            if (_ttl > TimeSpan.Zero) DiskCacheService.Sweep(_cacheDir, _ttl);
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
        // Final flush. Swallowed rather than thrown: a cache that fails to persist
        // on the way out must not turn shutdown into an unhandled exception.
        await _lock.WaitAsync();
        try
        {
            await DiskCacheService.SaveAsync(_cacheDir, _smtp, _http, _dns, _domainResults);
        }
        catch { /* best effort */ }
        finally
        {
            _lock.Release();
        }
    }
}

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
/// later fetch winning per key.</para>
/// </summary>
public class DiskCacheService
{
    /// <summary>Record serialisation. Compact — one line per record, no indenting —
    /// and property names come from the <c>[JsonPropertyName]</c> attributes on
    /// <see cref="CacheRecord"/> rather than a naming policy.</summary>
    private static readonly JsonSerializerOptions RecordOptions = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
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

    // ── Record files ─────────────────────────────────────────────────────

    private const string RecordFilePrefix = "cache.";
    private const string RecordFileExtension = ".jsonl";

    /// <summary>Sortable, filename-safe, and parseable back without ambiguity —
    /// the sweep reads the timestamp out of the name rather than opening the file.</summary>
    private const string FileTimeFormat = "yyyyMMdd'T'HHmmssfff'Z'";

    /// <summary>
    /// How long record files are kept when no TTL is configured (<c>CacheTtlHours=0</c>,
    /// or the CLI's <c>--cache-ttl 0</c>).
    ///
    /// <para><b>"Disables expiry" cannot mean "keeps everything forever" on disk.</b>
    /// The two tiers are not symmetric. MemoryCache is keyed, so its working set is
    /// the number of <i>distinct</i> keys and a refetch replaces the entry it had.
    /// Disk is append-only by design: every flush writes a new immutable file, so a
    /// key fetched again later appears <i>again</i> in a later file rather than
    /// replacing anything. Rechecks refetch on purpose, and each instance writes its
    /// own copy of what it fetched. Nothing collapses those duplicates — the sweep is
    /// the only thing that removes them, so switching it off makes the directory grow
    /// without bound even though memory stays flat.</para>
    ///
    /// <para>A day is chosen because it is the retention the design was sized against
    /// before the default dropped to two hours, and because the file-count arithmetic
    /// (<c>retention / flushInterval + 1</c>) stays comfortable there: 145 files per
    /// instance at a ten-minute flush.</para>
    ///
    /// <para>Only <i>retention</i> is capped. Reading stays uncapped, so whatever
    /// survives on disk is still loaded in full.</para>
    /// </summary>
    public static readonly TimeSpan UncappedRetention = TimeSpan.FromHours(24);

    /// <summary>The retention actually applied: the configured TTL, or the floor above
    /// when expiry is switched off.</summary>
    private static TimeSpan EffectiveRetention(TimeSpan ttl)
        => ttl > TimeSpan.Zero ? ttl : UncappedRetention;

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
    /// Deletes record files whose contents would all be discarded on load, and the
    /// folders of instances that are gone.
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
        // A non-positive TTL means "no expiry", not "everything expired" — taking it
        // literally would put the cutoff at now and delete the whole cache on the
        // first tick. It does not mean "never sweep" either: see UncappedRetention.
        var now = DateTime.UtcNow;
        var cutoff = now - EffectiveRetention(ttl);

        // Only ever this service's own record files, inside instance folders, matched
        // by extension there rather than anywhere under the cache directory. The
        // directory is configurable, and an operator who points it at something
        // shared — or at the data directory itself, alongside config.json and
        // users.json — must not have unrelated files deleted out from under them.
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
    /// <para>Every import is add-if-absent, so a value fetched from the network while
    /// this load runs beats the copy on disk rather than being overwritten by it. The
    /// entry with the latest fetch time wins between files, which is what merges
    /// several instances' folders into one view.</para>
    /// </summary>
    public static async Task<CacheLoadResult?> LoadAsync(string cacheDir, TimeSpan ttl, SmtpProbeService smtp,
        HttpProbeService http, DnsResolverService dns, bool retryErrors = false,
        DomainResultStore? domainResults = null)
    {
        if (!Directory.Exists(cacheDir))
            return null;

        // Drop record files whose contents have all expired, clear out scratch files
        // orphaned by a killed process, and remove folders left by instances that are
        // gone. Startup is enough for the folder work: a rolling deploy brings up new
        // pods and each one sweeps.
        Sweep(cacheDir, ttl);

        // A non-positive TTL means "no cap", which is what CacheTtlHours=0 has always
        // been documented as and what the in-memory cache already did with it. Taking
        // it literally would put the cutoff at now and discard the entire cache on
        // every load. Entries are still bounded by their own expiry, so with gating on
        // the record TTLs govern and only the floor applies.
        var cutoff = ttl > TimeSpan.Zero ? DateTime.UtcNow - ttl : DateTime.MinValue;

        var (result, oldest) = await LoadRecordFilesAsync(
            cacheDir, cutoff, smtp, http, dns, domainResults, retryErrors);

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
    ///
    /// <para><b>The payload is not parsed during the scan.</b> Reading the envelope
    /// with a <see cref="Utf8JsonReader"/> and skipping <c>v</c> makes the scan
    /// O(all lines) in cheap work, leaving the expensive part — rebuilding a full
    /// <c>IDnsQueryResponse</c> per entry, which dominates the load — O(live keys).
    /// Every superseded copy of a key across every instance's files, and everything
    /// already expired, is discarded having never been deserialised.</para>
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
        // The winner's raw bytes, kept so the payload can be parsed once at the end.
        var winners = new Dictionary<(string Type, string Key), (byte[] Line, DateTime WrittenUtc, DateTime ExpiresUtc)>();

        foreach (var path in files)
        {
            byte[] content;
            try { content = await File.ReadAllBytesAsync(path); }
            catch { continue; }

            foreach (var line in EnumerateLines(content))
            {
                if (!TryReadEnvelope(content.AsSpan(line.Start, line.Length),
                        out var type, out var key, out var written, out var expires))
                {
                    continue; // one bad line must not lose the rest of the file
                }
                if (expires <= now || written < cutoff) continue;

                var id = (type, key);
                if (winners.TryGetValue(id, out var seen) && seen.WrittenUtc >= written) continue;
                winners[id] = (content[line.Start..(line.Start + line.Length)], written, expires);
            }
        }

        foreach (var (id, winner) in winners)
        {
            JsonNode? value;
            try { value = JsonSerializer.Deserialize<CacheRecord>(winner.Line, RecordOptions)?.Value; }
            catch { continue; }
            if (value == null) continue;

            if (retryErrors && !PassesRetryFilter(id.Type, value)) continue;

            // Each service claims the types it owns and reports whether it did, so a
            // record for a type nobody recognises is dropped rather than miscounted.
            var imported = dns.TryImportRecord(id.Type, id.Key, value, winner.ExpiresUtc)
                || smtp.TryImportRecord(id.Type, id.Key, value, winner.ExpiresUtc)
                || http.TryImportRecord(id.Type, id.Key, value, winner.ExpiresUtc)
                || TryImportDomainResult(domainResults, id.Type, id.Key, value, winner.ExpiresUtc);
            if (!imported) continue;

            CountRecord(result, id.Type);
            if (winner.WrittenUtc != default && winner.WrittenUtc < oldest) oldest = winner.WrittenUtc;
        }

        return (result, oldest);
    }

    /// <summary>
    /// Line spans within a JSONL file, skipping blanks. Works on the raw bytes so the
    /// envelope scan never has to materialise a string per line. A trailing carriage
    /// return needs no special handling: CR is JSON whitespace, so the reader ignores
    /// it, and a line consisting only of one parses as no value and is rejected.
    /// </summary>
    private static IEnumerable<(int Start, int Length)> EnumerateLines(byte[] content)
    {
        var start = 0;
        for (var i = 0; i <= content.Length; i++)
        {
            if (i != content.Length && content[i] != (byte)'\n') continue;

            if (i > start) yield return (start, i - start);
            start = i + 1;
        }
    }

    /// <summary>
    /// Reads a record's type, key and timestamps without touching its payload.
    /// Returns false for anything malformed or missing a type or key.
    /// </summary>
    private static bool TryReadEnvelope(ReadOnlySpan<byte> line,
        out string type, out string key, out DateTime writtenUtc, out DateTime expiresUtc)
    {
        type = ""; key = ""; writtenUtc = default; expiresUtc = default;
        try
        {
            var reader = new Utf8JsonReader(line);
            if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject) return false;

            while (reader.Read() && reader.TokenType == JsonTokenType.PropertyName)
            {
                if (reader.ValueTextEquals("t"u8))
                {
                    if (!reader.Read()) return false;
                    type = reader.GetString() ?? "";
                }
                else if (reader.ValueTextEquals("k"u8))
                {
                    if (!reader.Read()) return false;
                    key = reader.GetString() ?? "";
                }
                else if (reader.ValueTextEquals("w"u8))
                {
                    if (!reader.Read() || !reader.TryGetDateTime(out writtenUtc)) return false;
                }
                else if (reader.ValueTextEquals("e"u8))
                {
                    if (!reader.Read() || !reader.TryGetDateTime(out expiresUtc)) return false;
                }
                else
                {
                    reader.Skip(); // the payload, and anything a later version adds
                }
            }

            return type.Length > 0 && key.Length > 0;
        }
        catch (JsonException) { return false; }
    }

    private static bool TryImportDomainResult(DomainResultStore? store, string type, string key,
        JsonNode? value, DateTime expiresUtc)
    {
        if (type != CacheTypes.DomainResults) return false;
        if (store == null || value == null) return true; // ours, but nowhere to put it

        try
        {
            var summary = value.Deserialize<DomainResultSummary>();
            if (summary != null) store.Import(key, summary, expiresUtc);
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
    /// The <c>retryErrors</c> filter: entries that look like a transient failure are
    /// left out so they get refetched. Deserialises the payload a second time for the
    /// survivors, which is only paid on the explicit retry path.
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

}

// ── Serializable DTOs for cache payloads ─────────────────────────────────
//
// The `v` half of a CacheRecord, and the same shapes the Redis L2 stores. They
// carry no timestamp of their own: the record envelope holds the fetch time and
// expiry, and duplicating either inside the payload would let the two disagree.

public class SmtpProbeCacheEntry
{
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

public class RcptCacheEntry
{
    public bool Accepted { get; set; }
    public string Response { get; set; } = "";
}

public class HttpGetCacheEntry
{
    public bool Success { get; set; }
    public string Content { get; set; } = "";
    public int StatusCode { get; set; }
}

public class HttpGetWithHeadersCacheEntry
{
    public bool Success { get; set; }
    public string Content { get; set; } = "";
    public int StatusCode { get; set; }
    public string? ContentType { get; set; }
}

public class RelayCacheEntry
{
    public bool IsRelay { get; set; }
    public string Description { get; set; } = "";
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

    /// <param name="ttl">Retention for the sweep. Required rather than optional: it
    /// decides what gets deleted, and a silently defaulted zero would apply the
    /// <see cref="DiskCacheService.UncappedRetention"/> floor to a directory the
    /// caller never meant to have swept.</param>
    public BackgroundCacheFlusher(string cacheDir, SmtpProbeService smtp, HttpProbeService http,
        DnsResolverService dns, TimeSpan interval, TimeSpan ttl,
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
            // Cheap when there is nothing to do, and it is the only thing that removes
            // files and folders once a process stops restarting. Runs unconditionally:
            // a zero TTL falls back to a retention floor rather than switching the
            // sweep off, or an append-only directory would grow for ever.
            DiskCacheService.Sweep(_cacheDir, _ttl);
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

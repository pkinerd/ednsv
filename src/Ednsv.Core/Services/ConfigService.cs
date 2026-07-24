using System.Text.Json;
using System.Text.Json.Serialization;
using StackExchange.Redis;

namespace Ednsv.Core.Services;

/// <summary>
/// Server-side runtime configuration persisted to {dataDir}/config.json.
/// Editable by admin users via the web UI; controls default validation
/// options and per-domain DKIM selector overrides.
/// </summary>
public sealed class AppConfig
{
    [JsonPropertyName("enableSmtpProbes")]
    public bool EnableSmtpProbes { get; set; } = true;

    [JsonPropertyName("enableHttpProbes")]
    public bool EnableHttpProbes { get; set; } = true;

    [JsonPropertyName("enableDnsbl")]
    public bool EnableDnsbl { get; set; } = true;

    /// <summary>
    /// Allow direct UDP/TCP 53 queries to specific authoritative nameservers and
    /// public resolvers (8.8.8.8 / 1.1.1.1 / 9.9.9.9) — used by propagation,
    /// lame-delegation, SOA-serial, glue-record, parent-delegation, AXFR and
    /// open-recursive-resolver checks. Disable in environments where outbound
    /// raw DNS is blocked but a local recursive resolver is permitted; checks
    /// that depend on direct DNS are reported as skipped.
    /// </summary>
    [JsonPropertyName("enableDirectDns")]
    public bool EnableDirectDns { get; set; } = true;

    /// <summary>
    /// Enable DNS-over-HTTPS for the public-resolver propagation check
    /// (8.8.8.8 / 1.1.1.1). When set, that check uses HTTPS to the
    /// providers' JSON DoH endpoints instead of raw UDP/53, which routes
    /// through HTTPS_PROXY when configured. The auth-NS direct-DNS checks
    /// (lame delegation, SOA serial, glue, parent delegation, AXFR) have
    /// no DoH equivalent — they remain gated by <see cref="EnableDirectDns"/>.
    /// </summary>
    [JsonPropertyName("enableDoh")]
    public bool EnableDoh { get; set; } = false;

    /// <summary>
    /// Default DKIM selectors probed when a domain has no per-domain entry
    /// and the request supplies no explicit list.
    /// </summary>
    [JsonPropertyName("defaultDkimSelectors")]
    public List<string> DefaultDkimSelectors { get; set; } = new();

    /// <summary>
    /// Per-domain DKIM selector overrides. Keys are bare domain names
    /// (lowercase, no trailing dot). When a key matches the domain being
    /// validated, those selectors are checked instead of the defaults.
    /// </summary>
    [JsonPropertyName("dkimSelectors")]
    public Dictionary<string, List<string>> DkimSelectors { get; set; } =
        new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Operator-curated list of well-known domains for the validator page's
    /// dropdown / autocomplete. Surfaced via /api/defaults; the UI merges
    /// this with the keys of <see cref="DkimSelectors"/> and the user's
    /// own client-side history.
    /// </summary>
    [JsonPropertyName("knownDomains")]
    public List<string> KnownDomains { get; set; } = new();

    // ── Configurable probe data lists (admin-editable) ───────────────────
    // Each defaults to the built-in list from ProbeDefaults so behaviour is
    // unchanged out of the box. Labeled entries use "value|label"; clearing a
    // list reverts the affected check to its built-in default.

    [JsonPropertyName("propagationResolvers")]
    public List<string> PropagationResolvers { get; set; } = new(Checks.ProbeDefaults.PropagationResolvers);

    [JsonPropertyName("propagationDohResolvers")]
    public List<string> PropagationDohResolvers { get; set; } = new(Checks.ProbeDefaults.PropagationDohResolvers);

    [JsonPropertyName("ipBlocklistsPublic")]
    public List<string> IpBlocklistsPublic { get; set; } = new(Checks.ProbeDefaults.IpBlocklistsPublic);

    [JsonPropertyName("ipBlocklistsPrivate")]
    public List<string> IpBlocklistsPrivate { get; set; } = new(Checks.ProbeDefaults.IpBlocklistsPrivate);

    [JsonPropertyName("extendedIpBlocklistsPublic")]
    public List<string> ExtendedIpBlocklistsPublic { get; set; } = new(Checks.ProbeDefaults.ExtendedIpBlocklistsPublic);

    [JsonPropertyName("extendedIpBlocklistsPrivate")]
    public List<string> ExtendedIpBlocklistsPrivate { get; set; } = new(Checks.ProbeDefaults.ExtendedIpBlocklistsPrivate);

    [JsonPropertyName("domainBlocklists")]
    public List<string> DomainBlocklists { get; set; } = new(Checks.ProbeDefaults.DomainBlocklists);

    [JsonPropertyName("arcSelectors")]
    public List<string> ArcSelectors { get; set; } = new(Checks.ProbeDefaults.ArcSelectors);

    [JsonPropertyName("dmarcDiscoverySubdomains")]
    public List<string> DmarcDiscoverySubdomains { get; set; } = new(Checks.ProbeDefaults.DmarcDiscoverySubdomains);

    [JsonPropertyName("mailSurveySubdomains")]
    public List<string> MailSurveySubdomains { get; set; } = new(Checks.ProbeDefaults.MailSurveySubdomains);

    [JsonPropertyName("spfSubdomains")]
    public List<string> SpfSubdomains { get; set; } = new(Checks.ProbeDefaults.SpfSubdomains);

    [JsonPropertyName("srvServiceNames")]
    public List<string> SrvServiceNames { get; set; } = new(Checks.ProbeDefaults.SrvServiceNames);

    [JsonPropertyName("vmcIssuers")]
    public List<string> VmcIssuers { get; set; } = new(Checks.ProbeDefaults.VmcIssuers);

    [JsonPropertyName("crtShBaseUrl")]
    public string CrtShBaseUrl { get; set; } = Checks.ProbeDefaults.CrtShBaseUrl;
}

/// <summary>Metadata for a revision, without the (potentially large) config body.</summary>
public sealed record ConfigRevisionInfo(int Id, DateTime SavedAt, string SavedBy);

/// <summary>Thrown when a distributed write loses the beacon compare-and-set:
/// another pod persisted a newer revision since the editor loaded. Maps to 409.</summary>
public sealed class RevisionConflictException : Exception
{
    public RevisionConflictException(string message) : base(message) { }
}

/// <summary>Thrown when a distributed write cannot reach Redis to coordinate:
/// the durable file is not written so pods can't silently diverge. Maps to 503.</summary>
public sealed class StoreUnavailableException : Exception
{
    public StoreUnavailableException(string message) : base(message) { }
}

public sealed class ConfigService
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never
    };

    /// <summary>Newest revisions kept; older ones are trimmed on save.</summary>
    public const int MaxRevisions = 300;

    /// <summary>
    /// Lightweight index of config history: the next revision id and per-revision
    /// metadata only. The (potentially large) config body for each revision lives
    /// in its own file, {historyDir}/config-rev-{id}.json, loaded on demand.
    /// </summary>
    private sealed class HistoryIndex
    {
        [JsonPropertyName("nextId")]
        public int NextId { get; set; } = 1;

        [JsonPropertyName("revisions")]
        public List<ConfigRevisionInfo> Revisions { get; set; } = new();
    }

    /// <summary>
    /// Read-side shape for the history index that tolerates BOTH the current
    /// body-less format and the legacy single-file format (pre config-history/
    /// split) that embedded each revision's full config inline under "config".
    /// A legacy inline body is migrated to its own config-rev-{id}.json on load
    /// so <see cref="GetRevision"/> can find it — otherwise every pre-upgrade
    /// revision 404s because its per-revision body file was never written.
    /// </summary>
    private sealed class HistoryIndexRead
    {
        [JsonPropertyName("nextId")]
        public int NextId { get; set; } = 1;

        [JsonPropertyName("revisions")]
        public List<LegacyRevisionEntry> Revisions { get; set; } = new();
    }

    private sealed class LegacyRevisionEntry
    {
        [JsonPropertyName("id")]
        public int Id { get; set; }

        [JsonPropertyName("savedAt")]
        public DateTime SavedAt { get; set; }

        [JsonPropertyName("savedBy")]
        public string SavedBy { get; set; } = "";

        /// <summary>Present only in legacy files; migrated to a per-revision body on load.</summary>
        [JsonPropertyName("config")]
        public AppConfig? Config { get; set; }
    }

    private readonly string _dataDir;
    private readonly string _filePath;
    private readonly string _historyIndexPath;
    private readonly string _historyDir;
    private readonly object _lock = new();
    private AppConfig _current = new();
    private readonly List<ConfigRevisionInfo> _history = new(); // oldest first
    private int _nextRevisionId = 1;

    // Distributed coordination (opt-in). When Redis is configured, a single
    // beacon key holds the GUID of the current head revision. Every save mints a
    // new GUID and promotes it via an atomic compare-and-set; reads check the
    // beacon on demand and reload the shared file when the GUID has moved.
    private readonly RedisConnection? _redis;
    private string _headGuid = Guid.NewGuid().ToString("N");
    private const string BeaconSuffix = "config:head";

    public ConfigService(string dataDir, RedisConnection? redis = null)
    {
        _dataDir = dataDir;
        _filePath = Path.Combine(dataDir, "config.json");
        _historyIndexPath = Path.Combine(dataDir, "config-history.json");
        _historyDir = Path.Combine(dataDir, "config-history");
        _redis = redis != null && redis.Enabled ? redis : null;
    }

    /// <summary>Current head-revision GUID this pod is serving. Clients echo this
    /// back on a subsequent save (via If-Match) to detect concurrent edits.</summary>
    public string Head { get { lock (_lock) return _headGuid; } }

    private string RevisionPath(int id) => Path.Combine(_historyDir, $"config-rev-{id}.json");

    /// <summary>
    /// Loads config.json if it exists, otherwise initializes from <paramref name="seed"/>
    /// (typically env-var defaults) and writes the seeded file. Returns the active config.
    /// </summary>
    public AppConfig LoadOrSeed(AppConfig seed)
    {
        LoadHistory();

        if (File.Exists(_filePath))
        {
            try
            {
                var json = File.ReadAllText(_filePath);
                if (!string.IsNullOrWhiteSpace(json))
                {
                    var parsed = JsonSerializer.Deserialize<AppConfig>(json, JsonOpts);
                    if (parsed != null)
                    {
                        // Normalize keys: lowercase, trim trailing dot
                        parsed.DkimSelectors = NormalizeKeys(parsed.DkimSelectors);
                        parsed.KnownDomains = NormalizeDomainList(parsed.KnownDomains);
                        lock (_lock)
                        {
                            _current = parsed;
                            SeedBaselineRevisionLocked();
                            InitBeaconLocked();
                        }
                        return Snapshot();
                    }
                }
            }
            catch
            {
                // Fall through to seeding if file is unreadable / malformed.
            }
        }

        seed.DkimSelectors = NormalizeKeys(seed.DkimSelectors ?? new Dictionary<string, List<string>>());
        seed.KnownDomains = NormalizeDomainList(seed.KnownDomains ?? new List<string>());
        lock (_lock)
        {
            _current = seed;
            SaveLocked();
            SeedBaselineRevisionLocked();
            InitBeaconLocked();
        }
        return Snapshot();
    }

    public AppConfig Snapshot()
    {
        EnsureFresh();
        lock (_lock) return CloneConfig(_current);
    }

    /// <summary>
    /// Replace the current config with <paramref name="incoming"/>, persist it,
    /// and record a revision attributed to <paramref name="savedBy"/> so the
    /// change is backed up and auditable.
    /// </summary>
    public void Replace(AppConfig incoming, string savedBy = "system", string? expectedHead = null)
    {
        if (incoming == null) throw new ArgumentNullException(nameof(incoming));
        incoming.DefaultDkimSelectors ??= new List<string>();
        incoming.DkimSelectors = NormalizeKeys(incoming.DkimSelectors ?? new Dictionary<string, List<string>>());
        incoming.KnownDomains = NormalizeDomainList(incoming.KnownDomains ?? new List<string>());
        // Trim/compact the probe data lists; null (field omitted) reverts to the
        // built-in default so a caller can't accidentally wipe a list to null.
        incoming.PropagationResolvers = NormalizeLines(incoming.PropagationResolvers, Checks.ProbeDefaults.PropagationResolvers);
        incoming.PropagationDohResolvers = NormalizeLines(incoming.PropagationDohResolvers, Checks.ProbeDefaults.PropagationDohResolvers);
        incoming.IpBlocklistsPublic = NormalizeLines(incoming.IpBlocklistsPublic, Checks.ProbeDefaults.IpBlocklistsPublic);
        incoming.IpBlocklistsPrivate = NormalizeLines(incoming.IpBlocklistsPrivate, Checks.ProbeDefaults.IpBlocklistsPrivate);
        incoming.ExtendedIpBlocklistsPublic = NormalizeLines(incoming.ExtendedIpBlocklistsPublic, Checks.ProbeDefaults.ExtendedIpBlocklistsPublic);
        incoming.ExtendedIpBlocklistsPrivate = NormalizeLines(incoming.ExtendedIpBlocklistsPrivate, Checks.ProbeDefaults.ExtendedIpBlocklistsPrivate);
        incoming.DomainBlocklists = NormalizeLines(incoming.DomainBlocklists, Checks.ProbeDefaults.DomainBlocklists);
        incoming.ArcSelectors = NormalizeLines(incoming.ArcSelectors, Checks.ProbeDefaults.ArcSelectors);
        incoming.DmarcDiscoverySubdomains = NormalizeLines(incoming.DmarcDiscoverySubdomains, Checks.ProbeDefaults.DmarcDiscoverySubdomains);
        incoming.MailSurveySubdomains = NormalizeLines(incoming.MailSurveySubdomains, Checks.ProbeDefaults.MailSurveySubdomains);
        incoming.SpfSubdomains = NormalizeLines(incoming.SpfSubdomains, Checks.ProbeDefaults.SpfSubdomains);
        incoming.SrvServiceNames = NormalizeLines(incoming.SrvServiceNames, Checks.ProbeDefaults.SrvServiceNames);
        incoming.VmcIssuers = NormalizeLines(incoming.VmcIssuers, Checks.ProbeDefaults.VmcIssuers);
        incoming.CrtShBaseUrl = string.IsNullOrWhiteSpace(incoming.CrtShBaseUrl)
            ? Checks.ProbeDefaults.CrtShBaseUrl : incoming.CrtShBaseUrl.Trim();

        if (_redis != null)
        {
            // Adopt the cluster's current head (and history / next-id) before writing.
            EnsureFresh();
            var db = _redis.GetDatabase();
            if (db == null)
                throw new StoreUnavailableException("Redis is unreachable; refusing to persist config to avoid divergence across pods.");
            var beacon = _redis.Key(BeaconSuffix);
            string baseHead;
            lock (_lock) baseHead = expectedHead ?? _headGuid;
            var newHead = Guid.NewGuid().ToString("N");
            // Atomic compare-and-set: promote only if the head is still the one
            // the editor based their change on. A concurrent save moved it → 409.
            var tran = db.CreateTransaction();
            tran.AddCondition(Condition.StringEqual(beacon, baseHead));
            _ = tran.StringSetAsync(beacon, newHead);
            bool committed;
            try { committed = tran.Execute(); }
            catch { throw new StoreUnavailableException("Redis transaction failed while coordinating the config write."); }
            if (!committed)
                throw new RevisionConflictException("The configuration was changed by another session. Reload and re-apply your changes.");
            lock (_lock)
            {
                _current = incoming;
                SaveLocked();
                AppendRevisionLocked(string.IsNullOrWhiteSpace(savedBy) ? "unknown" : savedBy);
                _headGuid = newHead;
            }
            return;
        }

        lock (_lock)
        {
            _current = incoming;
            SaveLocked();
            AppendRevisionLocked(string.IsNullOrWhiteSpace(savedBy) ? "unknown" : savedBy);
            _headGuid = Guid.NewGuid().ToString("N");
        }
    }

    // ── Distributed coordination (beacon) ────────────────────────────────

    /// <summary>On-demand staleness check: if another pod advanced the beacon,
    /// reload the shared config file and history so this pod serves current data.
    /// No-op in single-instance mode or when Redis is unreachable (serves local).</summary>
    public void EnsureFresh()
    {
        if (_redis == null) return;
        var db = _redis.GetDatabase();
        if (db == null) return; // Redis down — keep serving the last-known local copy.
        var beacon = _redis.Key(BeaconSuffix);
        RedisValue v;
        try { v = db.StringGet(beacon); }
        catch { return; }
        if (v.IsNullOrEmpty)
        {
            // Beacon absent (never set or flushed): publish our head so peers converge.
            try { db.StringSet(beacon, _headGuid, when: When.NotExists); } catch { /* best effort */ }
            return;
        }
        string remote = v!;
        lock (_lock)
        {
            if (remote == _headGuid) return;
            ReloadFromDiskLocked();
            _headGuid = remote;
        }
    }

    private void InitBeaconLocked()
    {
        if (_redis == null) return;
        var db = _redis.GetDatabase();
        if (db == null) return;
        var beacon = _redis.Key(BeaconSuffix);
        try
        {
            var existing = db.StringGet(beacon);
            if (existing.IsNullOrEmpty)
                db.StringSet(beacon, _headGuid, when: When.NotExists);
            else
                _headGuid = existing!; // adopt the cluster head for the shared file.
        }
        catch { /* best effort — fall back to local head */ }
    }

    private void ReloadFromDiskLocked()
    {
        if (File.Exists(_filePath))
        {
            try
            {
                var json = File.ReadAllText(_filePath);
                if (!string.IsNullOrWhiteSpace(json))
                {
                    var parsed = JsonSerializer.Deserialize<AppConfig>(json, JsonOpts);
                    if (parsed != null)
                    {
                        parsed.DkimSelectors = NormalizeKeys(parsed.DkimSelectors ?? new Dictionary<string, List<string>>());
                        parsed.KnownDomains = NormalizeDomainList(parsed.KnownDomains ?? new List<string>());
                        _current = parsed;
                    }
                }
            }
            catch { /* keep current in-memory copy if the file is momentarily unreadable */ }
        }
        LoadHistory(); // re-sync revision metadata and next-id from the shared index.
    }

    /// <summary>Revision metadata, newest first, capped at <see cref="MaxRevisions"/>.</summary>
    public IReadOnlyList<ConfigRevisionInfo> ListRevisions()
    {
        EnsureFresh();
        lock (_lock)
        {
            return _history.AsEnumerable().Reverse().ToList();
        }
    }

    /// <summary>The config saved in revision <paramref name="id"/>, or null if unknown.</summary>
    public AppConfig? GetRevision(int id)
    {
        EnsureFresh();
        lock (_lock)
        {
            if (!_history.Any(r => r.Id == id)) return null;
            var path = RevisionPath(id);
            if (!File.Exists(path)) return null;
            try
            {
                var json = File.ReadAllText(path);
                if (string.IsNullOrWhiteSpace(json)) return null;
                var cfg = JsonSerializer.Deserialize<AppConfig>(json, JsonOpts);
                if (cfg == null) return null;
                cfg.DkimSelectors = NormalizeKeys(cfg.DkimSelectors ?? new Dictionary<string, List<string>>());
                cfg.KnownDomains = NormalizeDomainList(cfg.KnownDomains ?? new List<string>());
                return CloneConfig(cfg);
            }
            catch
            {
                return null;
            }
        }
    }

    /// <summary>Per-domain selectors for <paramref name="domain"/>, or null if none configured.</summary>
    public IReadOnlyList<string>? GetDkimSelectorsFor(string domain)
    {
        if (string.IsNullOrEmpty(domain)) return null;
        var key = domain.Trim().TrimEnd('.').ToLowerInvariant();
        lock (_lock)
        {
            if (_current.DkimSelectors.TryGetValue(key, out var list) && list.Count > 0)
                return list.ToList();
        }
        return null;
    }

    private void SaveLocked()
    {
        Directory.CreateDirectory(_dataDir);
        var json = JsonSerializer.Serialize(_current, JsonOpts);
        var tmp = _filePath + ".tmp";
        File.WriteAllText(tmp, json);
        File.Move(tmp, _filePath, overwrite: true);
    }

    // ── Revision history ──────────────────────────────────────────────────

    private void LoadHistory()
    {
        if (!File.Exists(_historyIndexPath)) return;
        try
        {
            var json = File.ReadAllText(_historyIndexPath);
            if (string.IsNullOrWhiteSpace(json)) return;
            var index = JsonSerializer.Deserialize<HistoryIndexRead>(json, JsonOpts);
            if (index?.Revisions == null) return;
            lock (_lock)
            {
                _history.Clear();
                bool anyInline = false, anyFailed = false;
                foreach (var e in index.Revisions)
                {
                    _history.Add(new ConfigRevisionInfo(e.Id, e.SavedAt, e.SavedBy));
                    if (e.Config == null) continue;   // already body-less (new format)
                    anyInline = true;
                    // Externalise the legacy inline body so GetRevision can find it.
                    // Only fill gaps — never clobber a body already written.
                    if (File.Exists(RevisionPath(e.Id))) continue;
                    try
                    {
                        e.Config.DkimSelectors = NormalizeKeys(e.Config.DkimSelectors ?? new Dictionary<string, List<string>>());
                        e.Config.KnownDomains = NormalizeDomainList(e.Config.KnownDomains ?? new List<string>());
                        WriteRevisionBodyLocked(e.Id, e.Config);
                    }
                    catch { anyFailed = true; }   // best effort; retried on a later load
                }
                var maxId = _history.Count > 0 ? _history.Max(r => r.Id) : 0;
                _nextRevisionId = Math.Max(index.NextId, maxId + 1);
                // Collapse the legacy file to the body-less format once every inline
                // body has its own file, so the migration is one-time and the (large)
                // legacy index shrinks. Skip if any body failed to externalise, so we
                // never drop an inline copy we haven't safely relocated yet.
                if (anyInline && !anyFailed) SaveHistoryLocked();
            }
        }
        catch
        {
            // Corrupt history is non-fatal: config still loads, history restarts.
        }
    }

    // Records the config that was present before any user edit, so the very
    // first change is still rollback-able. No-op once any revision exists.
    private void SeedBaselineRevisionLocked()
    {
        if (_history.Count > 0) return;
        AppendRevisionLocked("(initial)");
    }

    private void AppendRevisionLocked(string savedBy)
    {
        var id = _nextRevisionId++;
        _history.Add(new ConfigRevisionInfo(id, DateTime.UtcNow, savedBy));
        WriteRevisionBodyLocked(id, _current);

        // Keep only the newest MaxRevisions entries; delete trimmed bodies.
        if (_history.Count > MaxRevisions)
        {
            var removeCount = _history.Count - MaxRevisions;
            foreach (var trimmed in _history.Take(removeCount))
                TryDeleteRevisionBody(trimmed.Id);
            _history.RemoveRange(0, removeCount);
        }
        SaveHistoryLocked();
    }

    private void WriteRevisionBodyLocked(int id, AppConfig config)
    {
        Directory.CreateDirectory(_historyDir);
        var json = JsonSerializer.Serialize(config, JsonOpts);
        var path = RevisionPath(id);
        var tmp = path + ".tmp";
        File.WriteAllText(tmp, json);
        File.Move(tmp, path, overwrite: true);
    }

    private void TryDeleteRevisionBody(int id)
    {
        try { File.Delete(RevisionPath(id)); } catch { /* best effort */ }
    }

    private void SaveHistoryLocked()
    {
        Directory.CreateDirectory(_dataDir);
        var index = new HistoryIndex { NextId = _nextRevisionId, Revisions = _history };
        var json = JsonSerializer.Serialize(index, JsonOpts);
        var tmp = _historyIndexPath + ".tmp";
        File.WriteAllText(tmp, json);
        File.Move(tmp, _historyIndexPath, overwrite: true);
    }

    private static AppConfig CloneConfig(AppConfig c) => new()
    {
        EnableSmtpProbes = c.EnableSmtpProbes,
        EnableHttpProbes = c.EnableHttpProbes,
        EnableDnsbl = c.EnableDnsbl,
        EnableDirectDns = c.EnableDirectDns,
        EnableDoh = c.EnableDoh,
        DefaultDkimSelectors = new List<string>(c.DefaultDkimSelectors),
        DkimSelectors = new Dictionary<string, List<string>>(
            c.DkimSelectors.Select(kv =>
                new KeyValuePair<string, List<string>>(kv.Key, new List<string>(kv.Value))),
            StringComparer.OrdinalIgnoreCase),
        KnownDomains = new List<string>(c.KnownDomains),
        PropagationResolvers = new List<string>(c.PropagationResolvers ?? new()),
        PropagationDohResolvers = new List<string>(c.PropagationDohResolvers ?? new()),
        IpBlocklistsPublic = new List<string>(c.IpBlocklistsPublic ?? new()),
        IpBlocklistsPrivate = new List<string>(c.IpBlocklistsPrivate ?? new()),
        ExtendedIpBlocklistsPublic = new List<string>(c.ExtendedIpBlocklistsPublic ?? new()),
        ExtendedIpBlocklistsPrivate = new List<string>(c.ExtendedIpBlocklistsPrivate ?? new()),
        DomainBlocklists = new List<string>(c.DomainBlocklists ?? new()),
        ArcSelectors = new List<string>(c.ArcSelectors ?? new()),
        DmarcDiscoverySubdomains = new List<string>(c.DmarcDiscoverySubdomains ?? new()),
        MailSurveySubdomains = new List<string>(c.MailSurveySubdomains ?? new()),
        SpfSubdomains = new List<string>(c.SpfSubdomains ?? new()),
        SrvServiceNames = new List<string>(c.SrvServiceNames ?? new()),
        VmcIssuers = new List<string>(c.VmcIssuers ?? new()),
        CrtShBaseUrl = string.IsNullOrWhiteSpace(c.CrtShBaseUrl) ? Checks.ProbeDefaults.CrtShBaseUrl : c.CrtShBaseUrl,
    };

    private static Dictionary<string, List<string>> NormalizeKeys(Dictionary<string, List<string>> src)
    {
        var result = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var kv in src)
        {
            var key = kv.Key?.Trim().TrimEnd('.').ToLowerInvariant() ?? "";
            if (key.Length == 0) continue;
            var list = (kv.Value ?? new List<string>())
                .Select(s => s?.Trim() ?? "")
                .Where(s => s.Length > 0)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            if (list.Count == 0) continue;
            result[key] = list;
        }
        return result;
    }

    private static List<string> NormalizeDomainList(List<string> src) =>
        (src ?? new List<string>())
            .Select(d => (d ?? "").Trim().TrimEnd('.').ToLowerInvariant())
            .Where(d => d.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

    // Trim entries and drop blanks/dupes for a probe data list. A null list
    // (JSON field explicitly null) reverts to the built-in default; an empty
    // list is preserved (the check falls back to its default at runtime).
    private static List<string> NormalizeLines(List<string>? src, IReadOnlyList<string> fallback)
    {
        if (src == null) return new List<string>(fallback);
        return src
            .Select(s => (s ?? "").Trim())
            .Where(s => s.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }
}

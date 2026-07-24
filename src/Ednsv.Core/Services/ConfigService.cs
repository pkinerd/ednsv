using System.Text.Json;
using System.Text.Json.Serialization;

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

    private readonly string _dataDir;
    private readonly string _filePath;
    private readonly string _historyIndexPath;
    private readonly string _historyDir;
    private readonly object _lock = new();
    private AppConfig _current = new();
    private readonly List<ConfigRevisionInfo> _history = new(); // oldest first
    private int _nextRevisionId = 1;

    public ConfigService(string dataDir)
    {
        _dataDir = dataDir;
        _filePath = Path.Combine(dataDir, "config.json");
        _historyIndexPath = Path.Combine(dataDir, "config-history.json");
        _historyDir = Path.Combine(dataDir, "config-history");
    }

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
        }
        return Snapshot();
    }

    public AppConfig Snapshot()
    {
        lock (_lock) return CloneConfig(_current);
    }

    /// <summary>
    /// Replace the current config with <paramref name="incoming"/>, persist it,
    /// and record a revision attributed to <paramref name="savedBy"/> so the
    /// change is backed up and auditable.
    /// </summary>
    public void Replace(AppConfig incoming, string savedBy = "system")
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
        lock (_lock)
        {
            _current = incoming;
            SaveLocked();
            AppendRevisionLocked(string.IsNullOrWhiteSpace(savedBy) ? "unknown" : savedBy);
        }
    }

    /// <summary>Revision metadata, newest first, capped at <see cref="MaxRevisions"/>.</summary>
    public IReadOnlyList<ConfigRevisionInfo> ListRevisions()
    {
        lock (_lock)
        {
            return _history.AsEnumerable().Reverse().ToList();
        }
    }

    /// <summary>The config saved in revision <paramref name="id"/>, or null if unknown.</summary>
    public AppConfig? GetRevision(int id)
    {
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
            var index = JsonSerializer.Deserialize<HistoryIndex>(json, JsonOpts);
            if (index?.Revisions == null) return;
            lock (_lock)
            {
                _history.Clear();
                _history.AddRange(index.Revisions);
                var maxId = _history.Count > 0 ? _history.Max(r => r.Id) : 0;
                _nextRevisionId = Math.Max(index.NextId, maxId + 1);
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

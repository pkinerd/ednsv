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
}

/// <summary>One saved version of <see cref="AppConfig"/> with who saved it and when.</summary>
public sealed class ConfigRevision
{
    [JsonPropertyName("id")]
    public int Id { get; set; }

    [JsonPropertyName("savedAt")]
    public DateTime SavedAt { get; set; }

    [JsonPropertyName("savedBy")]
    public string SavedBy { get; set; } = "";

    [JsonPropertyName("config")]
    public AppConfig Config { get; set; } = new();
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

    private sealed class HistoryFile
    {
        [JsonPropertyName("nextId")]
        public int NextId { get; set; } = 1;

        [JsonPropertyName("revisions")]
        public List<ConfigRevision> Revisions { get; set; } = new();
    }

    private readonly string _dataDir;
    private readonly string _filePath;
    private readonly string _historyPath;
    private readonly object _lock = new();
    private AppConfig _current = new();
    private readonly List<ConfigRevision> _history = new(); // oldest first
    private int _nextRevisionId = 1;

    public ConfigService(string dataDir)
    {
        _dataDir = dataDir;
        _filePath = Path.Combine(dataDir, "config.json");
        _historyPath = Path.Combine(dataDir, "config-history.json");
    }

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
            return _history
                .Select(r => new ConfigRevisionInfo(r.Id, r.SavedAt, r.SavedBy))
                .Reverse()
                .ToList();
        }
    }

    /// <summary>The config saved in revision <paramref name="id"/>, or null if unknown.</summary>
    public AppConfig? GetRevision(int id)
    {
        lock (_lock)
        {
            var rev = _history.FirstOrDefault(r => r.Id == id);
            return rev == null ? null : CloneConfig(rev.Config);
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
        if (!File.Exists(_historyPath)) return;
        try
        {
            var json = File.ReadAllText(_historyPath);
            if (string.IsNullOrWhiteSpace(json)) return;
            var file = JsonSerializer.Deserialize<HistoryFile>(json, JsonOpts);
            if (file?.Revisions == null) return;
            foreach (var r in file.Revisions)
            {
                r.Config ??= new AppConfig();
                r.Config.DkimSelectors = NormalizeKeys(r.Config.DkimSelectors ?? new Dictionary<string, List<string>>());
                r.Config.KnownDomains = NormalizeDomainList(r.Config.KnownDomains ?? new List<string>());
            }
            lock (_lock)
            {
                _history.Clear();
                _history.AddRange(file.Revisions);
                var maxId = _history.Count > 0 ? _history.Max(r => r.Id) : 0;
                _nextRevisionId = Math.Max(file.NextId, maxId + 1);
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
        _history.Add(new ConfigRevision
        {
            Id = _nextRevisionId++,
            SavedAt = DateTime.UtcNow,
            SavedBy = savedBy,
            Config = CloneConfig(_current)
        });
        // Keep only the newest MaxRevisions entries.
        if (_history.Count > MaxRevisions)
            _history.RemoveRange(0, _history.Count - MaxRevisions);
        SaveHistoryLocked();
    }

    private void SaveHistoryLocked()
    {
        Directory.CreateDirectory(_dataDir);
        var file = new HistoryFile { NextId = _nextRevisionId, Revisions = _history };
        var json = JsonSerializer.Serialize(file, JsonOpts);
        var tmp = _historyPath + ".tmp";
        File.WriteAllText(tmp, json);
        File.Move(tmp, _historyPath, overwrite: true);
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
        KnownDomains = new List<string>(c.KnownDomains)
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
}

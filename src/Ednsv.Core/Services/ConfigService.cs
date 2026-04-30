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
}

public sealed class ConfigService
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never
    };

    private readonly string _dataDir;
    private readonly string _filePath;
    private readonly object _lock = new();
    private AppConfig _current = new();

    public ConfigService(string dataDir)
    {
        _dataDir = dataDir;
        _filePath = Path.Combine(dataDir, "config.json");
    }

    /// <summary>
    /// Loads config.json if it exists, otherwise initializes from <paramref name="seed"/>
    /// (typically env-var defaults) and writes the seeded file. Returns the active config.
    /// </summary>
    public AppConfig LoadOrSeed(AppConfig seed)
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
                        // Normalize keys: lowercase, trim trailing dot
                        parsed.DkimSelectors = NormalizeKeys(parsed.DkimSelectors);
                        lock (_lock) _current = parsed;
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
        lock (_lock) _current = seed;
        SaveLocked();
        return Snapshot();
    }

    public AppConfig Snapshot()
    {
        lock (_lock)
        {
            return new AppConfig
            {
                EnableSmtpProbes = _current.EnableSmtpProbes,
                EnableHttpProbes = _current.EnableHttpProbes,
                EnableDnsbl = _current.EnableDnsbl,
                DefaultDkimSelectors = new List<string>(_current.DefaultDkimSelectors),
                DkimSelectors = new Dictionary<string, List<string>>(
                    _current.DkimSelectors.Select(kv =>
                        new KeyValuePair<string, List<string>>(kv.Key, new List<string>(kv.Value))),
                    StringComparer.OrdinalIgnoreCase)
            };
        }
    }

    /// <summary>Replace the current config with <paramref name="incoming"/> and persist.</summary>
    public void Replace(AppConfig incoming)
    {
        if (incoming == null) throw new ArgumentNullException(nameof(incoming));
        incoming.DefaultDkimSelectors ??= new List<string>();
        incoming.DkimSelectors = NormalizeKeys(incoming.DkimSelectors ?? new Dictionary<string, List<string>>());
        lock (_lock)
        {
            _current = incoming;
            SaveLocked();
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
}

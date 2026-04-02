using System.Collections.Concurrent;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Ednsv.Core.Services;

/// <summary>
/// Persists expensive probe results (SMTP, HTTP, ports) to disk so they can be
/// reused across runs. DNS queries are not cached (they're fast with caching resolvers).
/// </summary>
public class DiskCacheService
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    /// <summary>
    /// Saves current service caches to disk.
    /// </summary>
    public static async Task SaveAsync(string path, SmtpProbeService smtp, HttpProbeService http, DnsResolverService dns)
    {
        var data = new CacheData
        {
            Version = 1,
            CreatedUtc = DateTime.UtcNow,
            SmtpProbes = smtp.ExportProbeCache(),
            PortProbes = smtp.ExportPortCache(),
            HttpGet = http.ExportGetCache(),
            HttpGetWithHeaders = http.ExportGetWithHeadersCache(),
            UnreachableServers = dns.ExportUnreachableServers(),
            PtrLookups = dns.ExportPtrCache()
        };

        var json = JsonSerializer.Serialize(data, JsonOptions);
        await File.WriteAllTextAsync(path, json);
    }

    /// <summary>
    /// Loads caches from disk and primes the services. Returns false if the file
    /// doesn't exist or has expired.
    /// </summary>
    public static async Task<bool> LoadAsync(string path, TimeSpan ttl, SmtpProbeService smtp, HttpProbeService http, DnsResolverService dns)
    {
        if (!File.Exists(path))
            return false;

        try
        {
            var json = await File.ReadAllTextAsync(path);
            var data = JsonSerializer.Deserialize<CacheData>(json, JsonOptions);
            if (data == null || data.Version != 1)
                return false;

            // Check TTL
            if (DateTime.UtcNow - data.CreatedUtc > ttl)
                return false;

            if (data.SmtpProbes != null) smtp.ImportProbeCache(data.SmtpProbes);
            if (data.PortProbes != null) smtp.ImportPortCache(data.PortProbes);
            if (data.HttpGet != null) http.ImportGetCache(data.HttpGet);
            if (data.HttpGetWithHeaders != null) http.ImportGetWithHeadersCache(data.HttpGetWithHeaders);
            if (data.UnreachableServers != null) dns.ImportUnreachableServers(data.UnreachableServers);
            if (data.PtrLookups != null) dns.ImportPtrCache(data.PtrLookups);

            return true;
        }
        catch
        {
            // Corrupt cache — ignore
            return false;
        }
    }

    private class CacheData
    {
        public int Version { get; set; }
        public DateTime CreatedUtc { get; set; }
        public Dictionary<string, SmtpProbeCacheEntry>? SmtpProbes { get; set; }
        public Dictionary<string, bool>? PortProbes { get; set; }
        public Dictionary<string, HttpGetCacheEntry>? HttpGet { get; set; }
        public Dictionary<string, HttpGetWithHeadersCacheEntry>? HttpGetWithHeaders { get; set; }
        public Dictionary<string, int>? UnreachableServers { get; set; }
        public Dictionary<string, List<string>>? PtrLookups { get; set; }
    }
}

// Serializable DTOs for cache entries
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

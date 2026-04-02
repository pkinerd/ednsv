using System.Collections.Concurrent;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Ednsv.Core.Services;

/// <summary>
/// Persists probe results (SMTP, HTTP, DNS, ports) to disk so they can be
/// reused across runs.
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
            RcptProbes = smtp.ExportRcptCache(),
            HttpGet = http.ExportGetCache(),
            HttpGetWithHeaders = http.ExportGetWithHeadersCache(),
            UnreachableServers = dns.ExportUnreachableServers(),
            PtrLookups = dns.ExportPtrCache(),
            DnsQueries = dns.ExportQueryCache(),
            DnsServerQueries = dns.ExportServerQueryCache()
        };

        var json = JsonSerializer.Serialize(data, JsonOptions);
        await File.WriteAllTextAsync(path, json);
    }

    /// <summary>
    /// Loads caches from disk and primes the services. Returns null if the file
    /// doesn't exist, has expired, or is corrupt.
    /// </summary>
    public static async Task<CacheLoadResult?> LoadAsync(string path, TimeSpan ttl, SmtpProbeService smtp, HttpProbeService http, DnsResolverService dns, bool retryErrors = false)
    {
        if (!File.Exists(path))
            return null;

        try
        {
            var json = await File.ReadAllTextAsync(path);
            var data = JsonSerializer.Deserialize<CacheData>(json, JsonOptions);
            if (data == null || data.Version != 1)
                return null;

            // Check TTL
            if (DateTime.UtcNow - data.CreatedUtc > ttl)
                return null;

            if (retryErrors)
            {
                // Filter out failed entries so they get retried
                if (data.SmtpProbes != null)
                    data.SmtpProbes = data.SmtpProbes
                        .Where(kvp => kvp.Value.Error == null && kvp.Value.Connected)
                        .ToDictionary(kvp => kvp.Key, kvp => kvp.Value);

                if (data.PortProbes != null)
                    data.PortProbes = data.PortProbes
                        .Where(kvp => kvp.Value)
                        .ToDictionary(kvp => kvp.Key, kvp => kvp.Value);

                if (data.RcptProbes != null)
                    data.RcptProbes = data.RcptProbes
                        .Where(kvp => kvp.Value.Accepted)
                        .ToDictionary(kvp => kvp.Key, kvp => kvp.Value);

                if (data.HttpGet != null)
                    data.HttpGet = data.HttpGet
                        .Where(kvp => kvp.Value.Success)
                        .ToDictionary(kvp => kvp.Key, kvp => kvp.Value);

                if (data.HttpGetWithHeaders != null)
                    data.HttpGetWithHeaders = data.HttpGetWithHeaders
                        .Where(kvp => kvp.Value.Success)
                        .ToDictionary(kvp => kvp.Key, kvp => kvp.Value);

                // Don't import unreachable server tracking — let them be retried
                data.UnreachableServers = null;

                if (data.DnsQueries != null)
                    data.DnsQueries = data.DnsQueries
                        .Where(kvp => !kvp.Value.HasError)
                        .ToDictionary(kvp => kvp.Key, kvp => kvp.Value);

                if (data.DnsServerQueries != null)
                    data.DnsServerQueries = data.DnsServerQueries
                        .Where(kvp => !kvp.Value.HasError)
                        .ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
            }

            if (data.SmtpProbes != null) smtp.ImportProbeCache(data.SmtpProbes);
            if (data.PortProbes != null) smtp.ImportPortCache(data.PortProbes);
            if (data.RcptProbes != null) smtp.ImportRcptCache(data.RcptProbes);
            if (data.HttpGet != null) http.ImportGetCache(data.HttpGet);
            if (data.HttpGetWithHeaders != null) http.ImportGetWithHeadersCache(data.HttpGetWithHeaders);
            if (data.UnreachableServers != null) dns.ImportUnreachableServers(data.UnreachableServers);
            if (data.PtrLookups != null) dns.ImportPtrCache(data.PtrLookups);
            if (data.DnsQueries != null) dns.ImportQueryCache(data.DnsQueries);
            if (data.DnsServerQueries != null) dns.ImportServerQueryCache(data.DnsServerQueries);

            return new CacheLoadResult
            {
                Age = DateTime.UtcNow - data.CreatedUtc,
                SmtpProbes = data.SmtpProbes?.Count ?? 0,
                PortProbes = data.PortProbes?.Count ?? 0,
                RcptProbes = data.RcptProbes?.Count ?? 0,
                HttpRequests = (data.HttpGet?.Count ?? 0) + (data.HttpGetWithHeaders?.Count ?? 0),
                DnsQueries = (data.DnsQueries?.Count ?? 0) + (data.DnsServerQueries?.Count ?? 0),
                PtrLookups = data.PtrLookups?.Count ?? 0
            };
        }
        catch
        {
            // Corrupt cache — ignore
            return null;
        }
    }

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

    private class CacheData
    {
        public int Version { get; set; }
        public DateTime CreatedUtc { get; set; }
        public Dictionary<string, SmtpProbeCacheEntry>? SmtpProbes { get; set; }
        public Dictionary<string, bool>? PortProbes { get; set; }
        public Dictionary<string, RcptCacheEntry>? RcptProbes { get; set; }
        public Dictionary<string, HttpGetCacheEntry>? HttpGet { get; set; }
        public Dictionary<string, HttpGetWithHeadersCacheEntry>? HttpGetWithHeaders { get; set; }
        public Dictionary<string, int>? UnreachableServers { get; set; }
        public Dictionary<string, List<string>>? PtrLookups { get; set; }
        public Dictionary<string, DnsCacheEntry>? DnsQueries { get; set; }
        public Dictionary<string, DnsCacheEntry>? DnsServerQueries { get; set; }
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

public class RcptCacheEntry
{
    public bool Accepted { get; set; }
    public string Response { get; set; } = "";
}

public class HttpGetWithHeadersCacheEntry
{
    public bool Success { get; set; }
    public string Content { get; set; } = "";
    public int StatusCode { get; set; }
    public string? ContentType { get; set; }
}

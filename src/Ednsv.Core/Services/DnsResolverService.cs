using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using DnsClient;
using DnsClient.Protocol;

namespace Ednsv.Core.Services;

public class DnsResolverService
{
    private readonly LookupClient _client;
    private readonly LookupClient _directClient;
    private readonly LookupClient _dnsblClient;
    private static int MaxRetries = 3;

    // Application-level cache for DNS queries (survives across domains)
    private readonly ConcurrentDictionary<(string domain, QueryType type), IDnsQueryResponse> _queryCache = new();
    private readonly ConcurrentDictionary<string, List<string>> _ptrCache = new();
    // Cache for direct server queries (keyed by server+domain+type)
    private readonly ConcurrentDictionary<(string server, string domain, QueryType type), IDnsQueryResponse> _serverQueryCache = new();
    // Tracks servers that are completely unreachable (network/timeout failures).
    // Once a server fails MaxRetries times (across any domain), skip it immediately.
    private readonly ConcurrentDictionary<string, int> _unreachableServerCounts = new();

    public DnsResolverService() : this(null) { }

    /// <summary>
    /// Creates a resolver using the specified DNS server(s).
    /// Pass null or empty to use Google Public DNS (default).
    /// </summary>
    public DnsResolverService(IReadOnlyList<IPAddress>? nameservers)
    {
        var endpoints = nameservers?.Count > 0
            ? nameservers.Select(ip => new IPEndPoint(ip, 53)).ToArray()
            : new[] { NameServer.GooglePublicDns, NameServer.GooglePublicDns2 };

        var options = new LookupClientOptions(endpoints)
        {
            UseCache = true,
            Timeout = TimeSpan.FromSeconds(5),
            Retries = 2,
            ThrowDnsErrors = false
        };
        _client = new LookupClient(options);

        // DNSBL client — most responsive blocklists answer in <500ms. 3s timeout
        // with 1 retry gives slow-but-alive lists a fair chance without wasting time
        // on dead ones. Failures cached after 2 attempts (not 3).
        var dnsblOptions = new LookupClientOptions(endpoints)
        {
            UseCache = true,
            Timeout = TimeSpan.FromSeconds(3),
            Retries = 1,
            ThrowDnsErrors = false
        };
        _dnsblClient = new LookupClient(dnsblOptions);

        var directOptions = new LookupClientOptions
        {
            UseCache = false,
            Timeout = TimeSpan.FromSeconds(5),
            Retries = 1,
            ThrowDnsErrors = false
        };
        _directClient = new LookupClient(directOptions);
    }

    /// <summary>
    /// Tracks DNS query errors that occurred during the current validation.
    /// Reset between domains via <see cref="ResetErrors"/>.
    /// </summary>
    public ConcurrentBag<string> QueryErrors { get; private set; } = new();

    // Cache hit/miss counters for diagnostics (reset per domain)
    private int _cacheHits;
    private int _cacheMisses;
    public int CacheHits => _cacheHits;
    public int CacheMisses => _cacheMisses;
    public int CacheSize => _queryCache.Count;

    /// <summary>
    /// Clears per-validation error tracking while preserving the shared query cache.
    /// </summary>
    public void ResetErrors()
    {
        QueryErrors = new ConcurrentBag<string>();
        Interlocked.Exchange(ref _cacheHits, 0);
        Interlocked.Exchange(ref _cacheMisses, 0);
    }

    public async Task<IDnsQueryResponse> QueryAsync(string domain, QueryType type)
    {
        var key = (domain.ToLowerInvariant(), type);
        if (_queryCache.TryGetValue(key, out var cached))
        {
            Interlocked.Increment(ref _cacheHits);
            return cached;
        }

        Interlocked.Increment(ref _cacheMisses);
        try
        {
            var result = await _client.QueryAsync(domain, type);
            // Always cache — errors are filtered out by --retry-errors on load
            _queryCache.TryAdd(key, result);
            return result;
        }
        catch (DnsResponseException ex)
        {
            QueryErrors.Add($"DNS error querying {type} for {domain}: {ex.Message}");
            CacheFailureIfExhausted(key);
            return EmptyResponse.Instance;
        }
        catch (OperationCanceledException)
        {
            QueryErrors.Add($"DNS timeout querying {type} for {domain}");
            CacheFailureIfExhausted(key);
            return EmptyResponse.Instance;
        }
        catch (SocketException ex)
        {
            QueryErrors.Add($"DNS network error querying {type} for {domain}: {ex.Message}");
            CacheFailureIfExhausted(key);
            return EmptyResponse.Instance;
        }
        catch (Exception ex)
        {
            QueryErrors.Add($"DNS query failed for {type} {domain}: {ex.Message}");
            CacheFailureIfExhausted(key);
            return EmptyResponse.Instance;
        }
    }

    /// <summary>
    /// DNSBL query with 3s timeout and 1 retry. Uses the shared query cache so results
    /// are reused across domains. Failures cached after 2 attempts — gives slow-but-alive
    /// lists a second chance without wasting time on dead ones. Timeouts don't pollute
    /// the DNS error log (many obscure DNSBLs are simply unresponsive).
    /// </summary>
    public async Task<IDnsQueryResponse> QueryDnsblAsync(string query, QueryType type)
    {
        var key = (query.ToLowerInvariant(), type);
        if (_queryCache.TryGetValue(key, out var cached))
            return cached;

        try
        {
            var result = await _dnsblClient.QueryAsync(query, type);
            _queryCache.TryAdd(key, result);
            return result;
        }
        catch
        {
            _queryCache.TryAdd(key, EmptyResponse.Instance);
            return EmptyResponse.Instance;
        }
    }

    private void CacheFailureIfExhausted((string domain, QueryType type) key)
    {
        _queryCache.TryAdd(key, EmptyResponse.Instance);
    }

    public async Task<IDnsQueryResponse> QueryServerAsync(IPAddress server, string domain, QueryType type)
    {
        var serverStr = server.ToString();
        var key = (serverStr, domain.ToLowerInvariant(), type);
        if (_serverQueryCache.TryGetValue(key, out var cached))
            return cached;

        // If this server has been unreachable too many times, skip immediately
        if (_unreachableServerCounts.TryGetValue(serverStr, out var unreachCount) && unreachCount >= MaxRetries)
        {
            QueryErrors.Add($"DNS query to {server} skipped for {type} {domain}: server previously unreachable");
            return EmptyResponse.Instance;
        }

        try
        {
            var serverEndpoint = new IPEndPoint(server, 53);
            var opts = new LookupClientOptions(serverEndpoint)
            {
                UseCache = false,
                Timeout = TimeSpan.FromSeconds(5),
                Retries = 1,
                ThrowDnsErrors = false
            };
            var client = new LookupClient(opts);
            var result = await client.QueryAsync(domain, type);
            _serverQueryCache.TryAdd(key, result);
            if (!result.HasError)
            {
                // Server responded — clear unreachable tracking
                _unreachableServerCounts.TryRemove(serverStr, out _);
            }
            return result;
        }
        catch (Exception ex)
        {
            QueryErrors.Add($"DNS query to {server} failed for {type} {domain}: {ex.Message}");
            _serverQueryCache.TryAdd(key, EmptyResponse.Instance);
            // Track server-level unreachability
            _unreachableServerCounts.AddOrUpdate(serverStr, 1, (_, c) => c + 1);
            return EmptyResponse.Instance;
        }
    }

    public async Task<List<string>> ResolveAAsync(string hostname)
    {
        var result = await QueryAsync(hostname, QueryType.A);
        return result.Answers.ARecords().Select(a => a.Address.ToString()).ToList();
    }

    public async Task<List<string>> ResolveAAAAAsync(string hostname)
    {
        var result = await QueryAsync(hostname, QueryType.AAAA);
        return result.Answers.AaaaRecords().Select(a => a.Address.ToString()).ToList();
    }

    public async Task<List<string>> ResolvePtrAsync(string ip)
    {
        if (_ptrCache.TryGetValue(ip, out var cached))
            return cached;

        try
        {
            var result = await _client.QueryReverseAsync(IPAddress.Parse(ip));
            var ptrs = result.Answers.PtrRecords().Select(p => p.PtrDomainName.Value.TrimEnd('.')).ToList();
            _ptrCache.TryAdd(ip, ptrs);
            return ptrs;
        }
        catch
        {
            _ptrCache.TryAdd(ip, new List<string>());
            return new List<string>();
        }
    }

    public async Task<List<string>> ResolveCnameChainAsync(string hostname)
    {
        var chain = new List<string>();
        var current = hostname;
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        for (int i = 0; i < 10; i++)
        {
            if (!visited.Add(current)) break;
            var result = await QueryAsync(current, QueryType.CNAME);
            var cname = result.Answers.CnameRecords().FirstOrDefault();
            if (cname == null) break;
            var target = cname.CanonicalName.Value.TrimEnd('.');
            chain.Add($"{current} -> {target}");
            current = target;
        }
        return chain;
    }

    public async Task<List<NsRecord>> GetNsRecordsAsync(string domain)
    {
        var result = await QueryAsync(domain, QueryType.NS);
        return result.Answers.NsRecords().ToList();
    }

    public async Task<List<MxRecord>> GetMxRecordsAsync(string domain)
    {
        var result = await QueryAsync(domain, QueryType.MX);
        return result.Answers.MxRecords().OrderBy(m => m.Preference).ToList();
    }

    public async Task<List<TxtRecord>> GetTxtRecordsAsync(string domain)
    {
        var result = await QueryAsync(domain, QueryType.TXT);
        return result.Answers.OfType<TxtRecord>().ToList();
    }

    public async Task<SoaRecord?> GetSoaRecordAsync(string domain)
    {
        var result = await QueryAsync(domain, QueryType.SOA);
        return result.Answers.SoaRecords().FirstOrDefault()
            ?? result.Authorities.SoaRecords().FirstOrDefault();
    }

    public async Task<IDnsQueryResponse> QueryRawAsync(string domain, QueryType type)
    {
        return await QueryAsync(domain, type);
    }

    public async Task<bool> TestZoneTransferAsync(IPAddress nsIp, string domain)
    {
        try
        {
            var result = await PerformZoneTransferAsync(nsIp, domain);
            return result.Answers.Count > 0;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Performs AXFR and returns discovered DKIM selectors from _domainkey TXT records.
    /// </summary>
    public async Task<List<string>> ExtractDkimSelectorsFromAxfrAsync(IPAddress nsIp, string domain)
    {
        var selectors = new List<string>();
        try
        {
            var result = await PerformZoneTransferAsync(nsIp, domain);
            var domainkeySuffix = $"._domainkey.{domain}".ToLowerInvariant();
            foreach (var record in result.Answers)
            {
                var name = record.DomainName.Value.TrimEnd('.').ToLowerInvariant();
                if (name.EndsWith(domainkeySuffix))
                {
                    // Extract selector: everything before ._domainkey.domain
                    var selector = name.Substring(0, name.Length - domainkeySuffix.Length);
                    if (!string.IsNullOrWhiteSpace(selector) && !selector.Contains('.'))
                        selectors.Add(selector);
                }
            }
        }
        catch { }
        return selectors.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    private async Task<IDnsQueryResponse> PerformZoneTransferAsync(IPAddress nsIp, string domain)
    {
        var opts = new LookupClientOptions(new IPEndPoint(nsIp, 53))
        {
            UseCache = false,
            Timeout = TimeSpan.FromSeconds(5),
            Retries = 0,
            UseTcpOnly = true,
            ThrowDnsErrors = false
        };
        var client = new LookupClient(opts);
        return await client.QueryAsync(domain, QueryType.AXFR);
    }

    /// <summary>
    /// Gets parent zone NS records (delegation from parent)
    /// </summary>
    public async Task<IDnsQueryResponse> QueryParentNsAsync(string domain)
    {
        // Query the parent zone for NS records of this domain
        var parts = domain.Split('.');
        if (parts.Length < 2) return EmptyResponse.Instance;

        return await QueryAsync(domain, QueryType.NS);
    }

    // Minimal empty response implementation
    // ── Cache export/import for disk persistence ─────────────────────────

    public Dictionary<string, int> ExportUnreachableServers()
        => _unreachableServerCounts.ToDictionary(kvp => kvp.Key, kvp => kvp.Value);

    public void ImportUnreachableServers(Dictionary<string, int> entries)
    {
        foreach (var kvp in entries)
            _unreachableServerCounts.TryAdd(kvp.Key, kvp.Value);
    }

    public Dictionary<string, List<string>> ExportPtrCache()
        => _ptrCache.ToDictionary(kvp => kvp.Key, kvp => kvp.Value);

    public void ImportPtrCache(Dictionary<string, List<string>> entries)
    {
        foreach (var kvp in entries)
            _ptrCache.TryAdd(kvp.Key, kvp.Value);
    }

    /// <summary>
    /// Exports the DNS query cache as serializable DTOs.
    /// Queries containing unsupported record types (DNSSEC, TLSA, etc.) are skipped.
    /// </summary>
    public Dictionary<string, DnsCacheEntry> ExportQueryCache()
    {
        var result = new Dictionary<string, DnsCacheEntry>();
        foreach (var kvp in _queryCache)
        {
            var key = $"{kvp.Key.domain}|{kvp.Key.type}";
            var entry = DnsCacheSerializer.SerializeResponse(kvp.Value);
            if (entry != null)
                result[key] = entry;
        }
        return result;
    }

    /// <summary>
    /// Imports DNS query cache from serialized DTOs.
    /// </summary>
    public void ImportQueryCache(Dictionary<string, DnsCacheEntry> entries)
    {
        foreach (var kvp in entries)
        {
            var parts = kvp.Key.Split('|', 2);
            if (parts.Length != 2 || !Enum.TryParse<QueryType>(parts[1], out var type))
                continue;
            var key = (parts[0].ToLowerInvariant(), type);
            var response = DnsCacheSerializer.DeserializeResponse(kvp.Value);
            _queryCache.TryAdd(key, response);
        }
    }

    /// <summary>
    /// Exports the per-server DNS query cache as serializable DTOs.
    /// </summary>
    public Dictionary<string, DnsCacheEntry> ExportServerQueryCache()
    {
        var result = new Dictionary<string, DnsCacheEntry>();
        foreach (var kvp in _serverQueryCache)
        {
            var key = $"{kvp.Key.server}|{kvp.Key.domain}|{kvp.Key.type}";
            var entry = DnsCacheSerializer.SerializeResponse(kvp.Value);
            if (entry != null)
                result[key] = entry;
        }
        return result;
    }

    /// <summary>
    /// Imports per-server DNS query cache from serialized DTOs.
    /// </summary>
    public void ImportServerQueryCache(Dictionary<string, DnsCacheEntry> entries)
    {
        foreach (var kvp in entries)
        {
            var parts = kvp.Key.Split('|', 3);
            if (parts.Length != 3 || !Enum.TryParse<QueryType>(parts[2], out var type))
                continue;
            var key = (parts[0], parts[1].ToLowerInvariant(), type);
            var response = DnsCacheSerializer.DeserializeResponse(kvp.Value);
            _serverQueryCache.TryAdd(key, response);
        }
    }

    /// <summary>
    /// Doubles retry counts across all services for more persistent retries.
    /// </summary>
    public static void DoubleRetries()
    {
        MaxRetries = 6;
        SmtpProbeService.SetMaxRetries(6);
        HttpProbeService.SetMaxRetries(6);
    }

    private class EmptyResponse : IDnsQueryResponse
    {
        public static readonly EmptyResponse Instance = new();
        public IReadOnlyList<DnsQuestion> Questions => Array.Empty<DnsQuestion>();
        public IReadOnlyList<DnsResourceRecord> Answers => Array.Empty<DnsResourceRecord>();
        public IReadOnlyList<DnsResourceRecord> Additionals => Array.Empty<DnsResourceRecord>();
        public IReadOnlyList<DnsResourceRecord> Authorities => Array.Empty<DnsResourceRecord>();
        IEnumerable<DnsResourceRecord> IDnsQueryResponse.AllRecords => Array.Empty<DnsResourceRecord>();
        public string AuditTrail => "";
        public bool HasError => true;
        public string ErrorMessage => "Query failed";
        public DnsResponseHeader Header => throw new NotImplementedException();
        public int MessageSize => 0;
        public NameServer NameServer => throw new NotImplementedException();
        public DnsQuerySettings Settings => throw new NotImplementedException();
    }
}

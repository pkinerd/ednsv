using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using DnsClient;
using DnsClient.Protocol;
using Microsoft.Extensions.Caching.Memory;

namespace Ednsv.Core.Services;

public class DnsResolverService
{
    private readonly LookupClient _client;
    private readonly LookupClient _directClient;
    private readonly LookupClient _dnsblClient;
    private readonly LookupClient _speculativeClient;
    private static volatile int MaxRetries = 3;

    // ── Rate limiting ───────────────────────────────────────────────────
    // Token bucket: limits sustained query rate independent of response times.
    // Concurrency cap: prevents unbounded in-flight queries during slow periods.
    private readonly SemaphoreSlim _rateLimiter;
    private readonly SemaphoreSlim _concurrencyLimiter;
    private readonly Timer _refillTimer;
    private readonly int _tokensPerSecond;
    private readonly int _maxTokens;

    /// <summary>
    /// Optional trace callback for detailed timing diagnostics.
    /// Set to a non-null action to enable trace output.
    /// </summary>
    public Action<string>? Trace { get; set; }

    /// <summary>In-memory cache with per-entry TTL. Null = no expiry (CLI default).</summary>
    private readonly MemoryCache? _memCache;
    private readonly TimeSpan _cacheTtl;

    // Application-level cache for DNS queries — also used for disk persistence export.
    // When _memCache is set, reads check MemoryCache first (TTL-aware).
    private readonly ConcurrentDictionary<(string domain, QueryType type), IDnsQueryResponse> _queryCache = new();
    private readonly ConcurrentDictionary<string, List<string>> _ptrCache = new();
    // Cache for direct server queries (keyed by server+domain+type)
    private readonly ConcurrentDictionary<(string server, string domain, QueryType type), IDnsQueryResponse> _serverQueryCache = new();
    // Tracks servers that are completely unreachable (network/timeout failures).
    // Once a server fails MaxRetries times (across any domain), skip it immediately.
    private readonly ConcurrentDictionary<string, int> _unreachableServerCounts = new();
    private readonly ConcurrentDictionary<(string ip, string domain), bool> _axfrCache = new();
    private readonly ConcurrentDictionary<(string ip, string domain), IDnsQueryResponse> _axfrResponseCache = new();

    // Track keys loaded from disk cache (vs. generated during this run)
    private readonly ConcurrentDictionary<(string domain, QueryType type), bool> _importedQueryKeys = new();
    private readonly ConcurrentDictionary<(string server, string domain, QueryType type), bool> _importedServerQueryKeys = new();
    private readonly ConcurrentDictionary<string, bool> _importedPtrKeys = new();

    public DnsResolverService() : this(null) { }

    /// <summary>
    /// Creates a resolver using the specified DNS server(s).
    /// Pass null or empty to use Google Public DNS (default for CLI).
    /// </summary>
    public DnsResolverService(IReadOnlyList<IPAddress>? nameservers, TimeSpan? cacheTtl = null)
        : this(nameservers, tokensPerSecond: 40, maxConcurrency: 50, cacheTtl) { }

    /// <summary>
    /// Creates a resolver that uses the OS-configured DNS resolvers.
    /// </summary>
    public static DnsResolverService CreateWithSystemResolvers(int tokensPerSecond = 40, int maxConcurrency = 50, TimeSpan? cacheTtl = null)
        => new(useSystemResolvers: true, nameservers: null, tokensPerSecond, maxConcurrency, cacheTtl);

    /// <summary>
    /// Creates a resolver with custom rate limiting parameters.
    /// </summary>
    public DnsResolverService(IReadOnlyList<IPAddress>? nameservers, int tokensPerSecond, int maxConcurrency, TimeSpan? cacheTtl = null)
        : this(useSystemResolvers: false, nameservers, tokensPerSecond, maxConcurrency, cacheTtl) { }

    private DnsResolverService(bool useSystemResolvers, IReadOnlyList<IPAddress>? nameservers, int tokensPerSecond, int maxConcurrency, TimeSpan? cacheTtl)
    {
        IPEndPoint[]? endpoints = null;
        if (nameservers?.Count > 0)
            endpoints = nameservers.Select(ip => new IPEndPoint(ip, 53)).ToArray();
        else if (!useSystemResolvers)
            endpoints = new[] { NameServer.GooglePublicDns, NameServer.GooglePublicDns2 };
        // else endpoints stays null → LookupClientOptions() uses OS resolvers

        var options = endpoints != null
            ? new LookupClientOptions(endpoints)
            : new LookupClientOptions();
        options.UseCache = true;
        options.Timeout = TimeSpan.FromSeconds(15);
        options.Retries = 2;
        options.ThrowDnsErrors = false;
        _client = new LookupClient(options);

        // DNSBL client — short timeout (3s), 1 retry (2 attempts total).
        // DNSBL failures are best-effort and don't produce error reports.
        var dnsblOptions = endpoints != null
            ? new LookupClientOptions(endpoints)
            : new LookupClientOptions();
        dnsblOptions.UseCache = true;
        dnsblOptions.Timeout = TimeSpan.FromSeconds(3);
        dnsblOptions.Retries = 1;
        dnsblOptions.ThrowDnsErrors = false;
        _dnsblClient = new LookupClient(dnsblOptions);

        // Speculative client — for optional probes (DKIM selectors, SRV, etc.)
        // where a timeout simply means "skip this" rather than "report error".
        // Short timeout (3s), 1 retry (2 attempts = 6s max per query).
        var speculativeOptions = endpoints != null
            ? new LookupClientOptions(endpoints)
            : new LookupClientOptions();
        speculativeOptions.UseCache = true;
        speculativeOptions.Timeout = TimeSpan.FromSeconds(3);
        speculativeOptions.Retries = 1;
        speculativeOptions.ThrowDnsErrors = false;
        _speculativeClient = new LookupClient(speculativeOptions);

        var directOptions = new LookupClientOptions();
        directOptions.UseCache = false;
        directOptions.Timeout = TimeSpan.FromSeconds(15);
        directOptions.Retries = 2;
        directOptions.ThrowDnsErrors = false;
        _directClient = new LookupClient(directOptions);

        // Rate limiting
        _tokensPerSecond = tokensPerSecond;
        _maxTokens = tokensPerSecond;
        _rateLimiter = new SemaphoreSlim(tokensPerSecond, tokensPerSecond);
        _concurrencyLimiter = new SemaphoreSlim(maxConcurrency, maxConcurrency);
        _refillTimer = new Timer(_ => RefillTokens(), null, TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(1));

        // In-memory cache TTL — when set, entries expire after the specified duration.
        _cacheTtl = cacheTtl ?? TimeSpan.Zero;
        if (_cacheTtl > TimeSpan.Zero)
            _memCache = new MemoryCache(new MemoryCacheOptions());
    }

    private bool TryGetQueryCache((string domain, QueryType type) key, out IDnsQueryResponse value)
    {
        // Check MemoryCache (cross-validation TTL cache) — skip if rechecking DNS
        var recheckDeps = RecheckHelper.CurrentRecheckDeps.Value;
        if (_memCache != null && !recheckDeps.HasFlag(RecheckHelper.CacheDep.Dns))
        {
            var memKey = $"q:{key.domain}:{key.type}";
            if (_memCache.TryGetValue(memKey, out IDnsQueryResponse? memVal) && memVal != null)
            {
                value = memVal;
                return true;
            }
        }
        // Always check ConcurrentDictionary for within-validation dedup
        return _queryCache.TryGetValue(key, out value!);
    }

    private void SetQueryCache((string domain, QueryType type) key, IDnsQueryResponse value)
    {
        _queryCache[key] = value;
        if (_memCache != null)
            _memCache.Set($"q:{key.domain}:{key.type}", value, _cacheTtl);
    }

    private bool TryGetPtrCache(string ip, out List<string> value)
    {
        var recheckDeps = RecheckHelper.CurrentRecheckDeps.Value;
        if (_memCache != null && !recheckDeps.HasFlag(RecheckHelper.CacheDep.Ptr))
        {
            if (_memCache.TryGetValue($"ptr:{ip}", out List<string>? memVal) && memVal != null)
            {
                value = memVal;
                return true;
            }
        }
        return _ptrCache.TryGetValue(ip, out value!);
    }

    private void SetPtrCache(string ip, List<string> value)
    {
        _ptrCache[ip] = value;
        if (_memCache != null)
            _memCache.Set($"ptr:{ip}", value, _cacheTtl);
    }

    private bool TryGetServerQueryCache((string server, string domain, QueryType type) key, out IDnsQueryResponse value)
    {
        var recheckDeps = RecheckHelper.CurrentRecheckDeps.Value;
        if (_memCache != null && !recheckDeps.HasFlag(RecheckHelper.CacheDep.ServerDns))
        {
            if (_memCache.TryGetValue($"sq:{key.server}:{key.domain}:{key.type}", out IDnsQueryResponse? memVal) && memVal != null)
            {
                value = memVal;
                return true;
            }
        }
        return _serverQueryCache.TryGetValue(key, out value!);
    }

    private void SetServerQueryCache((string server, string domain, QueryType type) key, IDnsQueryResponse value)
    {
        _serverQueryCache[key] = value;
        if (_memCache != null)
            _memCache.Set($"sq:{key.server}:{key.domain}:{key.type}", value, _cacheTtl);
    }

    private void RefillTokens()
    {
        int toRelease = _maxTokens - _rateLimiter.CurrentCount;
        if (toRelease > 0)
        {
            try { _rateLimiter.Release(toRelease); }
            catch (SemaphoreFullException) { /* race with Release — harmless */ }
        }
    }

    /// <summary>
    /// Acquires a rate-limit token and a concurrency slot before executing a DNS query.
    /// The token bucket limits sustained QPS; the concurrency cap prevents runaway
    /// in-flight queries when the resolver is slow.
    /// </summary>
    private async Task<T> RateLimitedAsync<T>(Func<Task<T>> query, string? traceLabel = null)
    {
        Stopwatch? sw = null;
        if (Trace != null) { sw = Stopwatch.StartNew(); }
        await _rateLimiter.WaitAsync();
        var rateLimitMs = sw?.ElapsedMilliseconds ?? 0;
        await _concurrencyLimiter.WaitAsync();
        var concurrencyMs = sw?.ElapsedMilliseconds ?? 0;
        try
        {
            var result = await query();
            if (Trace != null && sw != null)
                Trace($"[DNS] {traceLabel ?? "query"}: {sw.ElapsedMilliseconds}ms (rate-wait:{rateLimitMs}ms concurrency-wait:{concurrencyMs - rateLimitMs}ms network:{sw.ElapsedMilliseconds - concurrencyMs}ms)");
            return result;
        }
        catch (Exception ex)
        {
            if (Trace != null && sw != null)
                Trace($"[DNS] {traceLabel ?? "query"} FAILED: {sw.ElapsedMilliseconds}ms ({ex.GetType().Name}: {ex.Message})");
            throw;
        }
        finally
        {
            _concurrencyLimiter.Release();
        }
    }

    /// <summary>
    /// Legacy error tracking — only used by CLI for per-domain error display.
    /// Web API should use CheckContext.QueryErrors instead.
    /// </summary>
    public ConcurrentBag<string> QueryErrors { get; private set; } = new();

    // Cumulative counters — never reset, only incremented.
    // Web API uses baseline snapshots to compute per-validation deltas.
    private int _cacheHits;
    private int _cacheMisses;
    private int _responsesReceived;
    public int CacheHits => _cacheHits;
    public int CacheMisses => _cacheMisses;
    /// <summary>Number of network DNS queries that have completed (success or error).</summary>
    public int ResponsesReceived => _responsesReceived;
    public int CacheSize => _queryCache.Count;

    /// <summary>
    /// Resets per-validation error list for CLI use. Does NOT reset cumulative
    /// counters (those are append-only for thread safety with concurrent web requests).
    /// </summary>
    public void ResetErrors()
    {
        QueryErrors = new ConcurrentBag<string>();
    }

    public async Task<IDnsQueryResponse> QueryAsync(string domain, QueryType type)
    {
        var key = (domain.ToLowerInvariant(), type);
        if (TryGetQueryCache(key, out var cached))
        {
            Interlocked.Increment(ref _cacheHits);
            Trace?.Invoke($"[DNS] CACHE HIT {type} {domain}");
            return cached;
        }

        Interlocked.Increment(ref _cacheMisses);
        try
        {
            var result = await RateLimitedAsync(() => _client.QueryAsync(domain, type), $"{type} {domain}");
            Interlocked.Increment(ref _responsesReceived);
            // Always cache — errors are filtered out by --retry-errors on load
            SetQueryCache(key, result);
            return result;
        }
        catch (DnsResponseException ex)
        {
            Interlocked.Increment(ref _responsesReceived);
            QueryErrors.Add($"DNS error querying {type} for {domain}: {ex.Message}");
            CacheFailureIfExhausted(key);
            return EmptyResponse.Instance;
        }
        catch (OperationCanceledException)
        {
            Interlocked.Increment(ref _responsesReceived);
            QueryErrors.Add($"DNS timeout querying {type} for {domain}");
            CacheFailureIfExhausted(key);
            return EmptyResponse.Instance;
        }
        catch (SocketException ex)
        {
            Interlocked.Increment(ref _responsesReceived);
            QueryErrors.Add($"DNS network error querying {type} for {domain}: {ex.Message}");
            CacheFailureIfExhausted(key);
            return EmptyResponse.Instance;
        }
        catch (Exception ex)
        {
            Interlocked.Increment(ref _responsesReceived);
            QueryErrors.Add($"DNS query failed for {type} {domain}: {ex.Message}");
            CacheFailureIfExhausted(key);
            return EmptyResponse.Instance;
        }
    }

    /// <summary>
    /// DNSBL query with 3s timeout and 1 retry (2 attempts total). Uses the shared
    /// query cache so results are reused across domains. Timeouts don't pollute the
    /// DNS error log (many obscure DNSBLs are simply unresponsive). Rate limited
    /// alongside all other DNS queries.
    /// </summary>
    public async Task<IDnsQueryResponse> QueryDnsblAsync(string query, QueryType type)
    {
        var key = (query.ToLowerInvariant(), type);
        if (TryGetQueryCache(key, out var cached))
        {
            Interlocked.Increment(ref _cacheHits);
            return cached;
        }

        Interlocked.Increment(ref _cacheMisses);
        try
        {
            var result = await RateLimitedAsync(() => _dnsblClient.QueryAsync(query, type), $"DNSBL {query}");
            Interlocked.Increment(ref _responsesReceived);
            SetQueryCache(key, result);
            return result;
        }
        catch
        {
            Interlocked.Increment(ref _responsesReceived);
            SetQueryCache(key, EmptyResponse.Instance);
            return EmptyResponse.Instance;
        }
    }

    /// <summary>
    /// Speculative query with 3s timeout and 1 retry (6s max). For optional probes
    /// where a timeout means "skip" not "error". Uses the shared query cache so a
    /// successful result from prefetch will be returned immediately. Timeouts are
    /// NOT cached — a later full QueryAsync can still try with the longer timeout.
    /// </summary>
    public async Task<IDnsQueryResponse> QuerySpeculativeAsync(string domain, QueryType type)
    {
        var key = (domain.ToLowerInvariant(), type);
        if (TryGetQueryCache(key, out var cached))
        {
            Interlocked.Increment(ref _cacheHits);
            Trace?.Invoke($"[DNS] CACHE HIT {type} {domain}");
            return cached;
        }

        Interlocked.Increment(ref _cacheMisses);
        try
        {
            var result = await RateLimitedAsync(() => _speculativeClient.QueryAsync(domain, type), $"SPEC {type} {domain}");
            Interlocked.Increment(ref _responsesReceived);
            // Cache successful responses (including NXDOMAIN — that's a valid "not found")
            SetQueryCache(key, result);
            return result;
        }
        catch
        {
            // Timeouts are NOT cached — don't poison the cache for the main client
            Interlocked.Increment(ref _responsesReceived);
            return EmptyResponse.Instance;
        }
    }

    private void CacheFailureIfExhausted((string domain, QueryType type) key)
    {
        SetQueryCache(key, EmptyResponse.Instance);
    }

    public async Task<IDnsQueryResponse> QueryServerAsync(IPAddress server, string domain, QueryType type)
    {
        var serverStr = server.ToString();
        var key = (serverStr, domain.ToLowerInvariant(), type);
        if (TryGetServerQueryCache(key, out var cached))
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
                Timeout = TimeSpan.FromSeconds(15),
                Retries = 2,
                ThrowDnsErrors = false
            };
            var client = new LookupClient(opts);
            var result = await RateLimitedAsync(() => client.QueryAsync(domain, type), $"SERVER {server} {type} {domain}");
            Interlocked.Increment(ref _responsesReceived);
            SetServerQueryCache(key, result);
            if (!result.HasError)
            {
                // Server responded — clear unreachable tracking
                _unreachableServerCounts.TryRemove(serverStr, out _);
            }
            return result;
        }
        catch (Exception ex)
        {
            Interlocked.Increment(ref _responsesReceived);
            QueryErrors.Add($"DNS query to {server} failed for {type} {domain}: {ex.Message}");
            SetServerQueryCache(key, EmptyResponse.Instance);
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
        if (TryGetPtrCache(ip, out var cached))
            return cached;

        try
        {
            var parsedIp = IPAddress.Parse(ip);
            var result = await RateLimitedAsync(() => _client.QueryReverseAsync(parsedIp), $"PTR {ip}");
            Interlocked.Increment(ref _responsesReceived);
            var ptrs = result.Answers.PtrRecords().Select(p => p.PtrDomainName.Value.TrimEnd('.')).ToList();
            SetPtrCache(ip, ptrs);
            return ptrs;
        }
        catch
        {
            Interlocked.Increment(ref _responsesReceived);
            SetPtrCache(ip, new List<string>());
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

    /// <summary>
    /// Short-timeout TXT lookup for speculative probes (DKIM selectors, etc.).
    /// Returns empty list on timeout without caching the failure.
    /// </summary>
    public async Task<List<TxtRecord>> GetTxtRecordsSpeculativeAsync(string domain)
    {
        var result = await QuerySpeculativeAsync(domain, QueryType.TXT);
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
        var key = (nsIp.ToString(), domain.ToLowerInvariant());
        if (_axfrCache.TryGetValue(key, out var cached))
            return cached;

        var response = await CachedAxfrAsync(nsIp, domain);
        var vulnerable = response.Answers.Count > 0;
        _axfrCache.TryAdd(key, vulnerable);
        return vulnerable;
    }

    /// <summary>
    /// Performs AXFR and returns discovered DKIM selectors from _domainkey TXT records.
    /// </summary>
    public async Task<List<string>> ExtractDkimSelectorsFromAxfrAsync(IPAddress nsIp, string domain)
    {
        var selectors = new List<string>();

        // If we already know AXFR was denied from disk cache, skip the TCP attempt
        var boolKey = (nsIp.ToString(), domain.ToLowerInvariant());
        if (_axfrCache.TryGetValue(boolKey, out var wasDenied) && !wasDenied)
            return selectors;

        try
        {
            var response = await CachedAxfrAsync(nsIp, domain);
            var domainkeySuffix = $"._domainkey.{domain}".ToLowerInvariant();
            foreach (var record in response.Answers)
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

    private async Task<IDnsQueryResponse> CachedAxfrAsync(IPAddress nsIp, string domain)
    {
        var key = (nsIp.ToString(), domain.ToLowerInvariant());
        if (_axfrResponseCache.TryGetValue(key, out var cached))
            return cached;

        try
        {
            var result = await PerformZoneTransferAsync(nsIp, domain);
            _axfrResponseCache.TryAdd(key, result);
            return result;
        }
        catch
        {
            _axfrResponseCache.TryAdd(key, EmptyResponse.Instance);
            return EmptyResponse.Instance;
        }
    }

    private async Task<IDnsQueryResponse> PerformZoneTransferAsync(IPAddress nsIp, string domain)
    {
        var opts = new LookupClientOptions(new IPEndPoint(nsIp, 53))
        {
            UseCache = false,
            Timeout = TimeSpan.FromSeconds(10),
            Retries = 0,
            UseTcpOnly = true,
            ThrowDnsErrors = false
        };
        var client = new LookupClient(opts);
        return await RateLimitedAsync(() => client.QueryAsync(domain, QueryType.AXFR), $"AXFR {nsIp} {domain}");
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

    public Dictionary<string, bool> ExportAxfrCache()
        => _axfrCache.ToDictionary(kvp => $"{kvp.Key.ip}|{kvp.Key.domain}", kvp => kvp.Value);

    public void ImportAxfrCache(Dictionary<string, bool> entries)
    {
        foreach (var kvp in entries)
        {
            var parts = kvp.Key.Split('|', 2);
            if (parts.Length == 2)
                _axfrCache.TryAdd((parts[0], parts[1]), kvp.Value);
        }
    }

    public Dictionary<string, List<string>> ExportPtrCache()
        => _ptrCache.ToDictionary(kvp => kvp.Key, kvp => kvp.Value);

    public void ImportPtrCache(Dictionary<string, List<string>> entries)
    {
        foreach (var kvp in entries)
        {
            _ptrCache.TryAdd(kvp.Key, kvp.Value);
            _importedPtrKeys.TryAdd(kvp.Key, true);
        }
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
            _importedQueryKeys.TryAdd(key, true);
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
            _importedServerQueryKeys.TryAdd(key, true);
        }
    }

    // ── Recheck support: remove entries matching a predicate ──────────────

    /// <summary>
    /// Removes DNS query cache entries matching the predicate.
    /// When importedOnly is true, only entries loaded from disk are affected;
    /// when false, all matching entries are removed (for long-lived processes).
    /// </summary>
    public void RemoveQueryEntries(Func<string, QueryType, bool> predicate, bool importedOnly = true)
    {
        if (importedOnly)
        {
            foreach (var key in _importedQueryKeys.Keys)
            {
                if (predicate(key.domain, key.type))
                {
                    _queryCache.TryRemove(key, out _);
                    _importedQueryKeys.TryRemove(key, out _);
                    _memCache?.Remove($"q:{key.domain}:{key.type}");
                }
            }
        }
        else
        {
            foreach (var key in _queryCache.Keys)
            {
                if (predicate(key.domain, key.type))
                {
                    _queryCache.TryRemove(key, out _);
                    _importedQueryKeys.TryRemove(key, out _);
                    _memCache?.Remove($"q:{key.domain}:{key.type}");
                }
            }
        }
    }

    /// <summary>
    /// Removes server query cache entries matching the predicate.
    /// </summary>
    public void RemoveServerQueryEntries(Func<string, string, QueryType, bool> predicate, bool importedOnly = true)
    {
        if (importedOnly)
        {
            foreach (var key in _importedServerQueryKeys.Keys)
            {
                if (predicate(key.server, key.domain, key.type))
                {
                    _serverQueryCache.TryRemove(key, out _);
                    _importedServerQueryKeys.TryRemove(key, out _);
                    _memCache?.Remove($"sq:{key.server}:{key.domain}:{key.type}");
                }
            }
        }
        else
        {
            foreach (var key in _serverQueryCache.Keys)
            {
                if (predicate(key.server, key.domain, key.type))
                {
                    _serverQueryCache.TryRemove(key, out _);
                    _importedServerQueryKeys.TryRemove(key, out _);
                    _memCache?.Remove($"sq:{key.server}:{key.domain}:{key.type}");
                }
            }
        }
    }

    /// <summary>
    /// Removes PTR cache entries matching the predicate.
    /// </summary>
    public void RemovePtrEntries(Func<string, bool> predicate, bool importedOnly = true)
    {
        if (importedOnly)
        {
            foreach (var key in _importedPtrKeys.Keys)
            {
                if (predicate(key))
                {
                    _ptrCache.TryRemove(key, out _);
                    _importedPtrKeys.TryRemove(key, out _);
                    _memCache?.Remove($"ptr:{key}");
                }
            }
        }
        else
        {
            foreach (var key in _ptrCache.Keys)
            {
                if (predicate(key))
                {
                    _ptrCache.TryRemove(key, out _);
                    _importedPtrKeys.TryRemove(key, out _);
                    _memCache?.Remove($"ptr:{key}");
                }
            }
        }
    }

    // Backward-compatible aliases for CLI code
    public void RemoveImportedQueryEntries(Func<string, QueryType, bool> predicate) => RemoveQueryEntries(predicate, importedOnly: true);
    public void RemoveImportedServerQueryEntries(Func<string, string, QueryType, bool> predicate) => RemoveServerQueryEntries(predicate, importedOnly: true);
    public void RemoveImportedPtrEntries(Func<string, bool> predicate) => RemovePtrEntries(predicate, importedOnly: true);

    /// <summary>
    /// Returns MX hostnames from the query cache for a domain, if available.
    /// Used by recheck logic to identify SMTP entries to clear.
    /// </summary>
    public List<string> GetCachedMxHosts(string domain)
    {
        var key = (domain.ToLowerInvariant(), QueryType.MX);
        if (TryGetQueryCache(key, out var response))
            return response.Answers.MxRecords().Select(m => m.Exchange.Value.TrimEnd('.')).ToList();
        return new List<string>();
    }

    /// <summary>
    /// Returns A-record IPs from the query cache for a host, if available.
    /// Used by recheck logic to identify PTR entries to clear.
    /// </summary>
    public List<string> GetCachedIps(string host)
    {
        var ips = new List<string>();
        var aKey = (host.ToLowerInvariant(), QueryType.A);
        if (TryGetQueryCache(aKey, out var aResponse))
            ips.AddRange(aResponse.Answers.ARecords().Select(r => r.Address.ToString()));
        var aaaaKey = (host.ToLowerInvariant(), QueryType.AAAA);
        if (TryGetQueryCache(aaaaKey, out var aaaaResponse))
            ips.AddRange(aaaaResponse.Answers.AaaaRecords().Select(r => r.Address.ToString()));
        return ips;
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

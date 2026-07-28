using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.Json.Nodes;
using DnsClient;
using DnsClient.Protocol;
using Microsoft.Extensions.Caching.Memory;

namespace Ednsv.Core.Services;

/// <summary>
/// Optional performance/robustness tuning for <see cref="DnsResolverService"/>.
/// All values default to the built-in behaviour, so passing null (or omitting
/// the argument) preserves the original settings. Applied at construction —
/// the DNS service is a startup singleton, so changes require a restart.
/// </summary>
public sealed record DnsTuning
{
    /// <summary>Sustained query rate (token bucket). Default 40/sec.</summary>
    public int TokensPerSecond { get; init; } = 40;
    /// <summary>Cap on simultaneous in-flight queries. Default 50.</summary>
    public int MaxConcurrency { get; init; } = 50;
    /// <summary>Per-query timeout for the main/direct/per-server clients. Default 15s.</summary>
    public double QueryTimeoutSeconds { get; init; } = 15;
    /// <summary>Per-query retries (DnsClient-level) for those clients. Default 2.</summary>
    public int QueryRetries { get; init; } = 2;
    /// <summary>Application-level retry count for failed queries. Default 3.</summary>
    public int MaxRetries { get; init; } = 3;
    /// <summary>Window after which an unreachable server is retried. Default 5 min.</summary>
    public double UnreachableDecayMinutes { get; init; } = 5;

    /// <summary>
    /// Floor for bounding cached DNS answers by their own record TTLs, in seconds.
    /// <b>0 (the default) turns the gating off entirely</b>, so every DNS entry gets
    /// the full cache TTL — the behaviour before this existed.
    ///
    /// <para>Set it above zero and a cached answer lives for
    /// <c>clamp(published TTL, this floor, the cache TTL)</c> — the minimum record TTL
    /// for a positive answer, the RFC 2308 negative TTL for an NXDOMAIN or NODATA. The
    /// floor is what stops a domain with 30-second records forcing a refetch on
    /// essentially every validation; the cache TTL remains the ceiling, which also keeps
    /// an entry from outliving the record file it was written into.</para>
    ///
    /// <para><b>A floor, not a default.</b> It bounds TTLs that came back from the wire;
    /// a response that published none inherits the cache TTL instead. See
    /// <see cref="DnsCacheTtl.For"/> for why that distinction is load-bearing.</para>
    /// </summary>
    public double CacheMinTtlSeconds { get; init; } = 0;
}

public class DnsResolverService
{
    private readonly LookupClient _client;
    private readonly LookupClient _directClient;
    private readonly LookupClient _dnsblClient;
    private readonly LookupClient _speculativeClient;
    private static volatile int MaxRetries = 3;
    /// <summary>Sets the application-level retry count (shared across all instances).</summary>
    public static void SetMaxRetries(int value) => MaxRetries = value;

    // Per-query timeout / retries for the authoritative + recursive lookup clients
    // (main, direct and per-server). Configurable so operators on slow or
    // aggressively-throttled links can tune them. The short-timeout speculative
    // and DNSBL clients keep their own fixed "skip if slow" budgets.
    private readonly TimeSpan _queryTimeout;
    private readonly int _queryRetries;

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
    /// Backed by <see cref="TraceContext.Sink"/> (AsyncLocal) so concurrent
    /// validations get their own sink instead of clobbering a shared field.
    /// </summary>
    public Action<string>? Trace
    {
        get => TraceContext.Sink;
        set => TraceContext.Sink = value;
    }

    /// <summary>In-memory cache with per-entry TTL. Null = no expiry (CLI default).</summary>
    private readonly TimeSpan? _cacheTtl;

    /// <summary>Floor for record-TTL gating. Zero disables the gating entirely —
    /// see <see cref="DnsTuning.CacheMinTtlSeconds"/>.</summary>
    private readonly TimeSpan _dnsMinTtl;

    // Unified caches — single source of truth (MemoryCache) with export log
    private readonly ProbeCache<IDnsQueryResponse> _queryCache;
    private readonly ProbeCache<List<string>> _ptrCache;
    private readonly ProbeCache<IDnsQueryResponse> _serverQueryCache;
    // Tracks servers that are completely unreachable (network/timeout failures).
    // Once a server fails MaxRetries times within the decay window, skip it.
    // Entries older than _unreachableDecay are ignored, allowing recovery.
    private readonly ExpiringMap<string, (int count, DateTime lastFailure)> _unreachableServerCounts;
    private readonly TimeSpan _unreachableDecay;
    private readonly ExpiringMap<(string ip, string domain), bool> _axfrCache;

    // The two ExpiringMap caches above are not ProbeCaches, so they carry their own
    // write queues. See WriteBag for why they are queued rather than written out whole
    // on every flush.
    private readonly WriteBag<int> _unreachableBag;
    private readonly WriteBag<bool> _axfrBag;
    // The zone transfers themselves. Not persisted — a whole zone is far too large to
    // write out — but expiring all the same: an AXFR response is the largest thing this
    // service caches, so holding one per (nameserver, domain) for the life of the
    // process is the most expensive way to leak.
    private readonly ExpiringMap<(string ip, string domain), IDnsQueryResponse> _axfrResponseCache;

    // One LookupClient per target server IP, reused across queries. LookupClient is
    // thread-safe, holds an internal UDP socket pool, and is not IDisposable, so
    // constructing a fresh one per query (as this code previously did) wasted
    // allocations and prevented socket reuse for repeat queries to the same server
    // (e.g. propagation / lame-delegation / SOA-serial checks that hit each NS IP
    // for multiple record types). The per-server options are identical to what was
    // built inline, so behaviour is unchanged.
    // Expires on the cache TTL like everything else, which for a pool rather than a
    // cache means only that a client unused for that long is rebuilt on next use. The
    // alternative is one LookupClient — and its socket pool — per nameserver IP ever
    // queried, held for the life of the process.
    private readonly ExpiringMap<string, LookupClient> _serverClients;

    private LookupClient GetServerClient(IPAddress server) =>
        _serverClients.GetOrAdd(server.ToString(), _ =>
        {
            var opts = new LookupClientOptions(new IPEndPoint(server, 53))
            {
                UseCache = false,
                Timeout = _queryTimeout,
                Retries = _queryRetries,
                ThrowDnsErrors = false
            };
            return new LookupClient(opts);
        });

    public DnsResolverService() : this(null) { }

    /// <summary>
    /// Creates a resolver using the specified DNS server(s).
    /// Pass null or empty to use Google Public DNS (default for CLI).
    /// </summary>
    public DnsResolverService(IReadOnlyList<IPAddress>? nameservers, TimeSpan? cacheTtl = null, DnsTuning? tuning = null,
        RedisConnection? redis = null, bool persistToDisk = true, bool warmSharedCache = true)
        : this(useSystemResolvers: false, nameservers, cacheTtl, tuning, redis, persistToDisk, warmSharedCache) { }

    /// <summary>
    /// Creates a resolver that uses the OS-configured DNS resolvers.
    /// </summary>
    public static DnsResolverService CreateWithSystemResolvers(TimeSpan? cacheTtl = null, DnsTuning? tuning = null,
        RedisConnection? redis = null, bool persistToDisk = true, bool warmSharedCache = true)
        => new(useSystemResolvers: true, nameservers: null, cacheTtl, tuning, redis, persistToDisk, warmSharedCache);

    private DnsResolverService(bool useSystemResolvers, IReadOnlyList<IPAddress>? nameservers, TimeSpan? cacheTtl,
        DnsTuning? tuning, RedisConnection? redis = null, bool persistToDisk = true, bool warmSharedCache = true)
    {
        var t = tuning ?? new DnsTuning();
        _queryTimeout = TimeSpan.FromSeconds(t.QueryTimeoutSeconds);
        _queryRetries = t.QueryRetries;
        _unreachableDecay = TimeSpan.FromMinutes(t.UnreachableDecayMinutes);

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
        options.Timeout = _queryTimeout;
        options.Retries = _queryRetries;
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
        directOptions.Timeout = _queryTimeout;
        directOptions.Retries = _queryRetries;
        directOptions.ThrowDnsErrors = false;
        _directClient = new LookupClient(directOptions);

        // Rate limiting
        _tokensPerSecond = t.TokensPerSecond;
        _maxTokens = t.TokensPerSecond;
        _rateLimiter = new SemaphoreSlim(t.TokensPerSecond, t.TokensPerSecond);
        _concurrencyLimiter = new SemaphoreSlim(t.MaxConcurrency, t.MaxConcurrency);
        _refillTimer = new Timer(_ => RefillTokens(), null, TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(1));

        // In-memory caches with optional TTL, optionally backed by a shared Redis L2.
        _cacheTtl = cacheTtl;
        _dnsMinTtl = t.CacheMinTtlSeconds > 0 ? TimeSpan.FromSeconds(t.CacheMinTtlSeconds) : TimeSpan.Zero;
        _unreachableBag = new WriteBag<int>(cacheTtl, persistToDisk);
        _axfrBag = new WriteBag<bool>(cacheTtl, persistToDisk);
        _unreachableServerCounts = new ExpiringMap<string, (int count, DateTime lastFailure)>(cacheTtl);
        _axfrCache = new ExpiringMap<(string ip, string domain), bool>(cacheTtl);
        _axfrResponseCache = new ExpiringMap<(string ip, string domain), IDnsQueryResponse>(cacheTtl);
        _serverClients = new ExpiringMap<string, LookupClient>(cacheTtl);
        ProbeCacheL2<IDnsQueryResponse>? DnsL2(string type) =>
            redis != null && redis.Enabled
                ? new ProbeCacheL2<IDnsQueryResponse>(redis, type, cacheTtl,
                    resp =>
                    {
                        var e = DnsCacheSerializer.SerializeResponse(resp);
                        return e == null ? null : JsonSerializer.Serialize(e);
                    },
                    json =>
                    {
                        var e = JsonSerializer.Deserialize<DnsCacheEntry>(json);
                        return e == null ? null : DnsCacheSerializer.DeserializeResponse(e);
                    })
                : null;
        ProbeCacheL2<List<string>>? ptrL2 =
            redis != null && redis.Enabled
                ? new ProbeCacheL2<List<string>>(redis, "ptr", cacheTtl,
                    list => JsonSerializer.Serialize(list),
                    json => JsonSerializer.Deserialize<List<string>>(json))
                : null;
        _queryCache = new ProbeCache<IDnsQueryResponse>(cacheTtl, DnsL2("dns"), persistToDisk, warmSharedCache);
        _ptrCache = new ProbeCache<List<string>>(cacheTtl, ptrL2, persistToDisk, warmSharedCache);
        _serverQueryCache = new ProbeCache<IDnsQueryResponse>(cacheTtl, DnsL2("dns-srv"), persistToDisk, warmSharedCache);
    }

    private bool TryGetQueryCache((string domain, QueryType type) key, out IDnsQueryResponse value)
        => _queryCache.TryGet($"q:{key.domain}:{key.type}", out value, RecheckHelper.CacheDep.Dns);

    private void SetQueryCache((string domain, QueryType type) key, IDnsQueryResponse value)
        => _queryCache.Set($"q:{key.domain}:{key.type}", value);

    private bool TryGetPtrCache(string ip, out List<string> value)
        => _ptrCache.TryGet($"ptr:{ip}", out value, RecheckHelper.CacheDep.Ptr);

    private void SetPtrCache(string ip, List<string> value)
        => _ptrCache.Set($"ptr:{ip}", value);

    private bool TryGetServerQueryCache((string server, string domain, QueryType type) key, out IDnsQueryResponse value)
        => _serverQueryCache.TryGet($"sq:{key.server}:{key.domain}:{key.type}", out value, RecheckHelper.CacheDep.ServerDns);

    private void SetServerQueryCache((string server, string domain, QueryType type) key, IDnsQueryResponse value)
        => _serverQueryCache.Set($"sq:{key.server}:{key.domain}:{key.type}", value);

    private void RefillTokens()
    {
        // Release tokens one at a time to avoid the TOCTOU race where reading
        // CurrentCount then calling Release(N) could skip an entire refill cycle
        // if the count changed between read and release (SemaphoreFullException).
        for (int i = 0; i < _tokensPerSecond; i++)
        {
            if (_rateLimiter.CurrentCount >= _maxTokens) break;
            try { _rateLimiter.Release(); }
            catch (SemaphoreFullException) { break; }
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
    /// Per-async-flow error tracking. Set by DomainValidator at validation start.
    /// DNS errors are routed here when set, otherwise to the shared QueryErrors.
    /// Each concurrent validation has its own value — no cross-validation bleed.
    /// </summary>
    public static readonly AsyncLocal<ConcurrentBag<string>?> CurrentQueryErrors = new();

    /// <summary>
    /// Shared error tracking — fallback for CLI use when CurrentQueryErrors is not set.
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
    public int CacheSize => _queryCache.Count + _ptrCache.Count + _serverQueryCache.Count;

    // The maps that are not ProbeCaches. Counted separately because they answer a
    // different question: whether anything here grows without bound. These are what each
    // map is *holding*, expired-but-unswept entries included — see ExpiringMap.Count. For
    // whether a given entry is still live, read it.
    public int UnreachableServerCount => _unreachableServerCounts.Count;
    public int AxfrCacheCount => _axfrCache.Count;

    private void AddError(string error)
    {
        var bag = CurrentQueryErrors.Value ?? QueryErrors;
        bag.Add(error);
    }

    /// <summary>
    /// Resets shared error list for CLI use. Does NOT reset cumulative
    /// counters (those are append-only for thread safety with concurrent web requests).
    /// </summary>
    public void ResetErrors()
    {
        QueryErrors = new ConcurrentBag<string>();
    }

    /// <summary>Evicts all cached DNS data (query/PTR/server/AXFR) and forgets
    /// unreachable-server state, so subsequent lookups re-query from scratch.</summary>
    public async Task<IDnsQueryResponse> QueryAsync(string domain, QueryType type)
    {
        var cacheKey = $"q:{domain.ToLowerInvariant()}:{type}";
        return await _queryCache.GetOrCreateAsync(cacheKey, async () =>
        {
            Interlocked.Increment(ref _cacheMisses);
            try
            {
                var result = await RateLimitedAsync(() => _client.QueryAsync(domain, type), $"{type} {domain}");
                Interlocked.Increment(ref _responsesReceived);
                return result;
            }
            catch (DnsResponseException ex)
            {
                Interlocked.Increment(ref _responsesReceived);
                AddError($"DNS error querying {type} for {domain}: {ex.Message}");
                return EmptyResponse.Instance;
            }
            catch (OperationCanceledException)
            {
                Interlocked.Increment(ref _responsesReceived);
                AddError($"DNS timeout querying {type} for {domain}");
                return EmptyResponse.Instance;
            }
            catch (SocketException ex)
            {
                Interlocked.Increment(ref _responsesReceived);
                AddError($"DNS network error querying {type} for {domain}: {ex.Message}");
                return EmptyResponse.Instance;
            }
            catch (Exception ex)
            {
                Interlocked.Increment(ref _responsesReceived);
                AddError($"DNS query failed for {type} {domain}: {ex.Message}");
                return EmptyResponse.Instance;
            }
        }, RecheckHelper.CacheDep.Dns,
        shouldPersist: response => response != EmptyResponse.Instance,
        onHit: () => Interlocked.Increment(ref _cacheHits),
        entryTtl: DnsEntryTtl);
    }

    /// <summary>
    /// DNSBL query with 3s timeout and 1 retry (2 attempts total). Uses the shared
    /// query cache so results are reused across domains. Timeouts don't pollute the
    /// DNS error log (many obscure DNSBLs are simply unresponsive). Rate limited
    /// alongside all other DNS queries.
    /// </summary>
    public async Task<IDnsQueryResponse> QueryDnsblAsync(string query, QueryType type)
    {
        var cacheKey = $"q:{query.ToLowerInvariant()}:{type}";
        return await _queryCache.GetOrCreateAsync(cacheKey, async () =>
        {
            Interlocked.Increment(ref _cacheMisses);
            try
            {
                var result = await RateLimitedAsync(() => _dnsblClient.QueryAsync(query, type), $"DNSBL {query}");
                Interlocked.Increment(ref _responsesReceived);
                return result;
            }
            catch
            {
                Interlocked.Increment(ref _responsesReceived);
                return EmptyResponse.Instance;
            }
        }, RecheckHelper.CacheDep.Dns,
        shouldPersist: response => response != EmptyResponse.Instance,
        onHit: () => Interlocked.Increment(ref _cacheHits),
        entryTtl: DnsEntryTtl);
    }

    /// <summary>
    /// Speculative query with 3s timeout and 1 retry (6s max). For optional probes
    /// where a timeout means "skip" not "error". Uses the shared query cache so a
    /// successful result from prefetch will be returned immediately. Timeouts are
    /// NOT cached — a later full QueryAsync can still try with the longer timeout.
    /// </summary>
    public async Task<IDnsQueryResponse> QuerySpeculativeAsync(string domain, QueryType type)
    {
        var cacheKey = $"q:{domain.ToLowerInvariant()}:{type}";
        // L1, then the shared tier — if a standard query or a peer already populated
        // it, use that. A plain TryGet here left this path blind to the L2, which for
        // the DKIM selector sweep is most of what it asks for: every pod re-probed the
        // same 39 absent names because no pod could see another's answer.
        var cached = await _queryCache.TryGetSharedAsync(cacheKey, RecheckHelper.CacheDep.Dns);
        if (cached != null)
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
            // Record-TTL gated like every other write to this cache. It writes straight
            // to the cache rather than through GetOrCreateAsync, so the TTL has to be
            // passed explicitly — omitting it gave the 39 DKIM selector probes and the
            // SRV lookups the full CacheTtlHours while every gated path around them was
            // honouring what the zone published. Set writes through to the L2 too, so a
            // selector this pod found absent is a selector its peers need not re-probe.
            _queryCache.Set(cacheKey, result, DnsEntryTtl(result));
            return result;
        }
        catch
        {
            // Timeouts are NOT cached — don't poison the cache for the main client
            Interlocked.Increment(ref _responsesReceived);
            return EmptyResponse.Instance;
        }
    }


    public async Task<IDnsQueryResponse> QueryServerAsync(IPAddress server, string domain, QueryType type)
    {
        var serverStr = server.ToString();
        var cacheKey = $"sq:{serverStr}:{domain.ToLowerInvariant()}:{type}";

        // If this server has been unreachable too many times recently, skip immediately.
        // Entries older than the decay window are ignored, allowing recovery.
        //
        // A recheck of this cache type ignores the skip. The breaker sits in front of
        // the cache, so leaving it in would defeat the bypass entirely in the one
        // workflow that needs it most: a recheck run straight after the failure that
        // prompted it falls well inside the five-minute decay window, and every server
        // that just failed would be skipped rather than retried — returning the same
        // finding without a single query.
        if (_unreachableServerCounts.TryGetValue(serverStr, out var unreachEntry,
                RecheckHelper.CacheDep.ServerDns)
            && unreachEntry.count >= MaxRetries
            && (DateTime.UtcNow - unreachEntry.lastFailure) < _unreachableDecay)
        {
            AddError($"DNS query to {server} skipped for {type} {domain}: server previously unreachable");
            return EmptyResponse.Instance;
        }

        return await _serverQueryCache.GetOrCreateAsync(cacheKey, async () =>
        {
            Interlocked.Increment(ref _cacheMisses);
            try
            {
                var client = GetServerClient(server);
                var result = await RateLimitedAsync(() => client.QueryAsync(domain, type), $"SERVER {server} {type} {domain}");
                Interlocked.Increment(ref _responsesReceived);
                if (!result.HasError)
                {
                    _unreachableServerCounts.TryRemove(serverStr);
                    _unreachableBag.Remove(serverStr); // recovered — don't persist the old count
                }
                return result;
            }
            catch (Exception ex)
            {
                Interlocked.Increment(ref _responsesReceived);
                AddError($"DNS query to {server} failed for {type} {domain}: {ex.Message}");
                var updated = _unreachableServerCounts.AddOrUpdate(serverStr,
                    (1, DateTime.UtcNow),
                    existing => (existing.count + 1, DateTime.UtcNow));
                _unreachableBag.Add(serverStr, updated.count);
                return EmptyResponse.Instance;
            }
        }, RecheckHelper.CacheDep.ServerDns,
        shouldPersist: response => response != EmptyResponse.Instance,
        onHit: () => Interlocked.Increment(ref _cacheHits),
        entryTtl: DnsEntryTtl);
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
        var cacheKey = $"ptr:{ip}";
        bool succeeded = false;
        // The cached value is the name list, not the response, so the TTL has to be
        // carried out of the factory rather than read back off the value.
        TimeSpan? recordTtl = null;
        return await _ptrCache.GetOrCreateAsync(cacheKey, async () =>
        {
            Interlocked.Increment(ref _cacheMisses);
            try
            {
                var parsedIp = IPAddress.Parse(ip);
                var result = await RateLimitedAsync(() => _client.QueryReverseAsync(parsedIp), $"PTR {ip}");
                Interlocked.Increment(ref _responsesReceived);
                succeeded = true;
                recordTtl = DnsEntryTtl(result);
                return result.Answers.PtrRecords().Select(p => p.PtrDomainName.Value.TrimEnd('.')).ToList();
            }
            catch
            {
                Interlocked.Increment(ref _responsesReceived);
                return new List<string>();
            }
        }, RecheckHelper.CacheDep.Ptr,
        shouldPersist: _ => succeeded,
        onHit: () => Interlocked.Increment(ref _cacheHits),
        entryTtl: _ => recordTtl);
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
        if (_axfrCache.TryGetValue(key, out var cached, RecheckHelper.CacheDep.Axfr))
            return cached;

        var response = await CachedAxfrAsync(nsIp, domain);

        // A transfer that never happened is not a verdict. EmptyResponse means the TCP
        // attempt failed outright, which looks identical to a refused transfer once it
        // is reduced to a bool — so caching it would record "not vulnerable" for a
        // server nobody reached, and on a recheck would overwrite a real finding with
        // it. The equivalent of every other cache's shouldPersist.
        if (ReferenceEquals(response, EmptyResponse.Instance)) return false;

        var vulnerable = response.Answers.Count > 0;
        _axfrCache.Set(key, vulnerable);
        _axfrBag.Add(AxfrKey(key.Item1, key.Item2), vulnerable);
        return vulnerable;
    }

    /// <summary>
    /// Performs AXFR and returns discovered DKIM selectors from _domainkey TXT records.
    /// </summary>
    public async Task<List<string>> ExtractDkimSelectorsFromAxfrAsync(IPAddress nsIp, string domain)
    {
        var selectors = new List<string>();

        // If we already know AXFR was denied from disk cache, skip the TCP attempt —
        // unless this validation is rechecking zone transfers, in which case skipping
        // on the strength of the cached verdict is exactly what it asked us not to do.
        var boolKey = (nsIp.ToString(), domain.ToLowerInvariant());
        if (_axfrCache.TryGetValue(boolKey, out var wasDenied, RecheckHelper.CacheDep.Axfr) && !wasDenied)
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
        // Bypassed by the same flag as the verdict it feeds. Recomputing a verdict from
        // a cached response would be a recheck in name only.
        var key = (nsIp.ToString(), domain.ToLowerInvariant());
        if (_axfrResponseCache.TryGetValue(key, out var cached, RecheckHelper.CacheDep.Axfr))
            return cached;

        try
        {
            var result = await PerformZoneTransferAsync(nsIp, domain);
            _axfrResponseCache.Set(key, result);
            return result;
        }
        catch
        {
            // Don't cache transient failures — next caller retries
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

    /// <summary>
    /// Import one record from a cache file. Keys are this service's own cache keys,
    /// written verbatim by <see cref="CollectPendingWrites"/>, so there is no disk-key
    /// translation. Returns false when the record belongs to another service.
    /// </summary>
    public bool TryImportRecord(string type, string key, JsonNode? value, DateTime expiresUtc)
    {
        if (value == null) return false;
        try
        {
            switch (type)
            {
                case CacheTypes.Dns:
                case CacheTypes.DnsServer:
                {
                    var entry = value.Deserialize<DnsCacheEntry>();
                    if (entry == null) return true;
                    var response = DnsCacheSerializer.DeserializeResponse(entry);
                    if (response == null) return true;
                    if (type == CacheTypes.Dns) _queryCache.Import(key, response, expiresUtc);
                    else _serverQueryCache.Import(key, response, expiresUtc);
                    return true;
                }
                case CacheTypes.Ptr:
                {
                    var names = value.Deserialize<List<string>>();
                    if (names != null) _ptrCache.Import(key, names, expiresUtc);
                    return true;
                }
                case CacheTypes.Unreachable:
                {
                    var count = value.Deserialize<int>();
                    _unreachableServerCounts.TryAdd(key, (count, DateTime.UtcNow), expiresUtc);
                    return true;
                }
                case CacheTypes.Axfr:
                {
                    var parts = key.Split('|', 2);
                    if (parts.Length == 2)
                        _axfrCache.TryAdd((parts[0], parts[1]), value.Deserialize<bool>(), expiresUtc);
                    return true;
                }
                default:
                    return false;
            }
        }
        catch
        {
            return true; // ours, but unreadable — skip the record, not the file
        }
    }

    // ── Flush sources ────────────────────────────────────────────────────

    /// <summary>Everything this resolver has fetched and not yet written out.
    /// Keys are the cache's own keys; the load path imports them back unchanged.</summary>
    public IEnumerable<PendingWrites> CollectPendingWrites()
    {
        yield return _queryCache.CollectPending(CacheTypes.Dns, DnsToNode);
        yield return _serverQueryCache.CollectPending(CacheTypes.DnsServer, DnsToNode);
        yield return _ptrCache.CollectPending(CacheTypes.Ptr,
            names => JsonSerializer.SerializeToNode(names));
        yield return _unreachableBag.Collect(CacheTypes.Unreachable,
            count => JsonSerializer.SerializeToNode(count));
        yield return _axfrBag.Collect(CacheTypes.Axfr,
            vulnerable => JsonSerializer.SerializeToNode(vulnerable));
    }

    // ── Shared-cache recovery ────────────────────────────────────────────

    /// <summary>Republish this resolver's cached answers into the shared L2 — see
    /// <see cref="ProbeCache{T}.WarmSharedCache"/>.</summary>
    public int WarmSharedCache()
        => _queryCache.WarmSharedCache() + _serverQueryCache.WarmSharedCache() + _ptrCache.WarmSharedCache();

    /// <summary>See <see cref="ProbeCache{T}.PruneSharedCacheIndex"/>.</summary>
    public void PruneSharedCacheIndex()
    {
        _queryCache.PruneSharedCacheIndex();
        _serverQueryCache.PruneSharedCacheIndex();
        _ptrCache.PruneSharedCacheIndex();
    }

    /// <summary>See <see cref="ProbeCache{T}.SharedCacheIndexCount"/>. Zero when no
    /// index is kept, which is the whole point of it being observable.</summary>
    public int SharedCacheIndexCount => _queryCache.SharedCacheIndexCount
        + _serverQueryCache.SharedCacheIndexCount + _ptrCache.SharedCacheIndexCount;

    /// <summary>The persisted key for an AXFR result. The tuple key cannot be written
    /// as-is, and the pipe is safe: an IP never contains one.</summary>
    private static string AxfrKey(string ip, string domain) => $"{ip}|{domain}";

    // ── Record-TTL gating ────────────────────────────────────────────────
    //
    // See DnsCacheTtl for the policy itself. Off unless CacheMinTtlSeconds is set,
    // in which case an answer lives for clamp(published TTL, floor, cache TTL).
    //
    // Two sections can publish that TTL, and both must be read. A positive answer
    // carries its own record TTLs. A negative one — NXDOMAIN or NODATA — carries an
    // SOA in the authority section instead, which is where RFC 2308 puts the lifetime
    // of "this does not exist". Reading only the answers made every negative response
    // look TTL-less, and negative responses are the bulk of what a validation issues:
    // blocklist misses, absent DKIM selectors, probed subdomains that do not exist.
    //
    // A response publishing neither yields null, which leaves the cache-wide TTL
    // governing. The floor raises TTLs we were given; it is not a stand-in for one.

    private TimeSpan? DnsEntryTtl(IDnsQueryResponse response)
        => DnsCacheTtl.For(
            DnsCacheTtl.MinRecordTtl(response.Answers) ?? DnsCacheTtl.NegativeTtl(response.Authorities),
            _dnsMinTtl, _cacheTtl);

    private static JsonNode? DnsToNode(IDnsQueryResponse response)
    {
        var entry = DnsCacheSerializer.SerializeResponse(response);
        return entry == null ? null : JsonSerializer.SerializeToNode(entry);
    }

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

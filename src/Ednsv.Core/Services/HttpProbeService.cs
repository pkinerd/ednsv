using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Ednsv.Core.Services;

public class HttpProbeService
{
    private readonly HttpClient _client;
    private static volatile int MaxRetries = 3;
    public static void SetMaxRetries(int value) => MaxRetries = value;

    /// <summary>
    /// Optional trace callback. Backed by <see cref="TraceContext.Sink"/>
    /// (AsyncLocal) so concurrent validations don't share a sink.
    /// </summary>
    public Action<string>? Trace
    {
        get => TraceContext.Sink;
        set => TraceContext.Sink = value;
    }

    // Wrapper classes so value tuples can be stored in ProbeCache<T> (requires class constraint)
    private sealed class GetResult
    {
        public bool Success; public string Content = ""; public int StatusCode;
        public (bool, string, int) ToTuple() => (Success, Content, StatusCode);
    }
    private sealed class GetWithHeadersResult
    {
        public bool Success; public string Content = ""; public int StatusCode; public string? ContentType;
        public (bool, string, int, string?) ToTuple() => (Success, Content, StatusCode, ContentType);
    }

    private readonly ProbeCache<GetResult> _getCache;
    private readonly ProbeCache<GetWithHeadersResult> _getWithHeadersCache;
    private readonly SemaphoreSlim _concurrencyLimiter;

    /// <param name="validateCertificates">
    /// When true (default), outbound HTTPS uses normal PKIX certificate validation.
    /// This matters for correctness as well as security: RFC 8461 requires the
    /// MTA-STS policy to be fetched over a validated HTTPS connection, so accepting
    /// any certificate would let a MITM present a forged policy that this tool then
    /// reports as valid. Set to false ONLY for environments behind a TLS-intercepting
    /// egress proxy whose CA is not in the system trust store (the original reason
    /// validation was disabled) — doing so makes all HTTPS verdicts untrustworthy.
    /// </param>
    /// <param name="timeoutSeconds">Per-request HTTP timeout. Default 10s.</param>
    /// <param name="maxConcurrency">Cap on simultaneous outbound requests. Default 20.</param>
    /// <param name="persistToDisk">False when no cache directory is configured — see
    /// <see cref="SmtpProbeService"/>.</param>
    /// <param name="warmSharedCache">False when nothing will republish this cache into
    /// the shared tier — see <see cref="ProbeCache{T}"/>.</param>
    public HttpProbeService(TimeSpan? cacheTtl = null, bool validateCertificates = true, double timeoutSeconds = 10,
        int maxConcurrency = 20, RedisConnection? redis = null, bool persistToDisk = true,
        bool warmSharedCache = true)
    {
        _concurrencyLimiter = new SemaphoreSlim(maxConcurrency, maxConcurrency);
        ProbeCacheL2<GetResult>? getL2 =
            redis != null && redis.Enabled
                ? new ProbeCacheL2<GetResult>(redis, "http-get", cacheTtl,
                    r => JsonSerializer.Serialize(new HttpGetCacheEntry { Success = r.Success, Content = r.Content, StatusCode = r.StatusCode }),
                    json =>
                    {
                        var e = JsonSerializer.Deserialize<HttpGetCacheEntry>(json);
                        return e == null ? null : new GetResult { Success = e.Success, Content = e.Content, StatusCode = e.StatusCode };
                    })
                : null;
        ProbeCacheL2<GetWithHeadersResult>? getHeadersL2 =
            redis != null && redis.Enabled
                ? new ProbeCacheL2<GetWithHeadersResult>(redis, "http-get-headers", cacheTtl,
                    r => JsonSerializer.Serialize(new HttpGetWithHeadersCacheEntry { Success = r.Success, Content = r.Content, StatusCode = r.StatusCode, ContentType = r.ContentType }),
                    json =>
                    {
                        var e = JsonSerializer.Deserialize<HttpGetWithHeadersCacheEntry>(json);
                        return e == null ? null : new GetWithHeadersResult { Success = e.Success, Content = e.Content, StatusCode = e.StatusCode, ContentType = e.ContentType };
                    })
                : null;
        _getCache = new ProbeCache<GetResult>(cacheTtl, getL2, persistToDisk, warmSharedCache);
        _getWithHeadersCache = new ProbeCache<GetWithHeadersResult>(
            cacheTtl, getHeadersL2, persistToDisk, warmSharedCache);
        var handler = new HttpClientHandler
        {
            AllowAutoRedirect = true
        };
        if (!validateCertificates)
            handler.ServerCertificateCustomValidationCallback = (_, _, _, _) => true;
        _client = new HttpClient(handler)
        {
            Timeout = TimeSpan.FromSeconds(timeoutSeconds)
        };
        _client.DefaultRequestHeaders.UserAgent.ParseAdd("ednsv/1.0");
    }

    public async Task<(bool success, string content, int statusCode)> GetAsync(string url, int? maxRetries = null)
    {
        var retries = maxRetries ?? MaxRetries;
        var result = await _getCache.GetOrCreateAsync(url, async () =>
        {
            Trace?.Invoke($"[HTTP] GET START {url}");
            var sw = Trace != null ? Stopwatch.StartNew() : null;
            (bool success, string content, int statusCode) lastResult = default;
            for (int attempt = 0; attempt < retries; attempt++)
            {
                await _concurrencyLimiter.WaitAsync();
                try
                {
                    var response = await _client.GetAsync(url);
                    var content = await response.Content.ReadAsStringAsync();
                    if (Trace != null && sw != null)
                        Trace($"[HTTP] GET DONE {url}: {sw.ElapsedMilliseconds}ms status={response.StatusCode}");
                    return new GetResult { Success = response.IsSuccessStatusCode, Content = content, StatusCode = (int)response.StatusCode };
                }
                catch (Exception ex)
                {
                    lastResult = (false, ex.Message, 0);
                    Trace?.Invoke($"[HTTP] GET RETRY {url} attempt {attempt + 1}/{retries} ({ex.Message})");
                }
                finally
                {
                    _concurrencyLimiter.Release();
                }
            }
            if (Trace != null && sw != null)
                Trace($"[HTTP] GET FAILED {url}: {sw.ElapsedMilliseconds}ms after {retries} attempts");
            return new GetResult { Success = lastResult.success, Content = lastResult.content ?? "", StatusCode = lastResult.statusCode };
        }, RecheckHelper.CacheDep.Http,
        shouldPersist: result => result.Success || result.StatusCode > 0);
        return result.ToTuple();
    }

    /// <summary>
    /// GET with a custom Accept header. Used for DoH JSON endpoints where the
    /// resolver requires <c>Accept: application/dns-json</c> to return JSON
    /// instead of the default <c>application/dns-message</c> binary format.
    /// Cache key includes the Accept value so different Accepts don't collide.
    /// </summary>
    public async Task<(bool success, string content, int statusCode)> GetWithAcceptAsync(string url, string accept, int? maxRetries = null)
    {
        var retries = maxRetries ?? MaxRetries;
        var cacheKey = $"{url}\nAccept:{accept}";
        var result = await _getCache.GetOrCreateAsync(cacheKey, async () =>
        {
            Trace?.Invoke($"[HTTP] GET START {url} (accept={accept})");
            var sw = Trace != null ? Stopwatch.StartNew() : null;
            (bool success, string content, int statusCode) lastResult = default;
            for (int attempt = 0; attempt < retries; attempt++)
            {
                await _concurrencyLimiter.WaitAsync();
                try
                {
                    using var req = new HttpRequestMessage(HttpMethod.Get, url);
                    req.Headers.Accept.ParseAdd(accept);
                    var response = await _client.SendAsync(req);
                    var content = await response.Content.ReadAsStringAsync();
                    if (Trace != null && sw != null)
                        Trace($"[HTTP] GET DONE {url}: {sw.ElapsedMilliseconds}ms status={response.StatusCode}");
                    return new GetResult { Success = response.IsSuccessStatusCode, Content = content, StatusCode = (int)response.StatusCode };
                }
                catch (Exception ex)
                {
                    lastResult = (false, ex.Message, 0);
                    Trace?.Invoke($"[HTTP] GET RETRY {url} attempt {attempt + 1}/{retries} ({ex.Message})");
                }
                finally
                {
                    _concurrencyLimiter.Release();
                }
            }
            if (Trace != null && sw != null)
                Trace($"[HTTP] GET FAILED {url}: {sw.ElapsedMilliseconds}ms after {retries} attempts");
            return new GetResult { Success = lastResult.success, Content = lastResult.content ?? "", StatusCode = lastResult.statusCode };
        }, RecheckHelper.CacheDep.Http,
        shouldPersist: result => result.Success || result.StatusCode > 0);
        return result.ToTuple();
    }

    public async Task<(bool success, string content, int statusCode, string? contentType)> GetWithHeadersAsync(string url)
    {
        var result = await _getWithHeadersCache.GetOrCreateAsync(url, async () =>
        {
            Trace?.Invoke($"[HTTP] GET START {url} (with-headers)");
            var sw = Trace != null ? Stopwatch.StartNew() : null;
            (bool success, string content, int statusCode, string? contentType) lastResult = default;
            for (int attempt = 0; attempt < MaxRetries; attempt++)
            {
                await _concurrencyLimiter.WaitAsync();
                try
                {
                    var response = await _client.GetAsync(url);
                    var content = await response.Content.ReadAsStringAsync();
                    var contentType = response.Content.Headers.ContentType?.MediaType;
                    if (Trace != null && sw != null)
                        Trace($"[HTTP] GET DONE {url}: {sw.ElapsedMilliseconds}ms status={response.StatusCode} type={contentType}");
                    return new GetWithHeadersResult { Success = response.IsSuccessStatusCode, Content = content, StatusCode = (int)response.StatusCode, ContentType = contentType };
                }
                catch (Exception ex)
                {
                    lastResult = (false, ex.Message, 0, (string?)null);
                    Trace?.Invoke($"[HTTP] GET RETRY {url} attempt {attempt + 1}/{MaxRetries} ({ex.Message})");
                }
                finally
                {
                    _concurrencyLimiter.Release();
                }
            }
            if (Trace != null && sw != null)
                Trace($"[HTTP] GET FAILED {url}: {sw.ElapsedMilliseconds}ms after {MaxRetries} attempts");
            return new GetWithHeadersResult { Success = lastResult.success, Content = lastResult.content ?? "", StatusCode = lastResult.statusCode, ContentType = lastResult.contentType };
        }, RecheckHelper.CacheDep.Http,
        shouldPersist: result => result.Success || result.StatusCode > 0);
        return result.ToTuple();
    }

    /// <summary>Evicts all cached HTTP GET results.</summary>
    // ── Cache export/import for disk persistence ─────────────────────────

    /// <summary>Import one record from a cache file — see
    /// <see cref="DnsResolverService.TryImportRecord"/>.</summary>
    public bool TryImportRecord(string type, string key, JsonNode? value, DateTime expiresUtc)
    {
        if (value == null) return false;
        try
        {
            switch (type)
            {
                case CacheTypes.HttpGet:
                {
                    var e = value.Deserialize<HttpGetCacheEntry>();
                    if (e != null)
                        _getCache.Import(key, new GetResult { Success = e.Success, Content = e.Content, StatusCode = e.StatusCode }, expiresUtc);
                    return true;
                }
                case CacheTypes.HttpGetHeaders:
                {
                    var e = value.Deserialize<HttpGetWithHeadersCacheEntry>();
                    if (e != null)
                        _getWithHeadersCache.Import(key, new GetWithHeadersResult { Success = e.Success, Content = e.Content, StatusCode = e.StatusCode, ContentType = e.ContentType }, expiresUtc);
                    return true;
                }
                default:
                    return false;
            }
        }
        catch
        {
            return true;
        }
    }

    // ── Shared-cache recovery ────────────────────────────────────────────

    /// <summary>Republish cached HTTP responses into the shared L2.</summary>
    public int WarmSharedCache() => _getCache.WarmSharedCache() + _getWithHeadersCache.WarmSharedCache();

    /// <summary>See <see cref="ProbeCache{T}.PruneSharedCacheIndex"/>.</summary>
    public void PruneSharedCacheIndex()
    {
        _getCache.PruneSharedCacheIndex();
        _getWithHeadersCache.PruneSharedCacheIndex();
    }

    /// <summary>See <see cref="ProbeCache{T}.SharedCacheIndexCount"/>.</summary>
    public int SharedCacheIndexCount =>
        _getCache.SharedCacheIndexCount + _getWithHeadersCache.SharedCacheIndexCount;

    // ── Flush sources ────────────────────────────────────────────────────

    /// <summary>Everything this prober has fetched and not yet written out.</summary>
    public IEnumerable<PendingWrites> CollectPendingWrites()
    {
        yield return _getCache.CollectPending(CacheTypes.HttpGet,
            r => JsonSerializer.SerializeToNode(
                new HttpGetCacheEntry { Success = r.Success, Content = r.Content, StatusCode = r.StatusCode }));
        yield return _getWithHeadersCache.CollectPending(CacheTypes.HttpGetHeaders,
            r => JsonSerializer.SerializeToNode(
                new HttpGetWithHeadersCacheEntry { Success = r.Success, Content = r.Content, StatusCode = r.StatusCode, ContentType = r.ContentType }));
    }

}

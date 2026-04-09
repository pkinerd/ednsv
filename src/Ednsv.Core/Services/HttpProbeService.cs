using System.Collections.Concurrent;
using System.Diagnostics;

namespace Ednsv.Core.Services;

public class HttpProbeService
{
    private readonly HttpClient _client;
    private static volatile int MaxRetries = 3;
    public static void SetMaxRetries(int value) => MaxRetries = value;

    /// <summary>Optional trace callback for detailed timing diagnostics.</summary>
    public Action<string>? Trace
    {
        get => _trace;
        set
        {
            _trace = value;
            _getCache.Trace = value;
            _getWithHeadersCache.Trace = value;
        }
    }
    private Action<string>? _trace;

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
    private readonly SemaphoreSlim _concurrencyLimiter = new(20, 20);

    public HttpProbeService(TimeSpan? cacheTtl = null)
    {
        _getCache = new ProbeCache<GetResult>(cacheTtl);
        _getWithHeadersCache = new ProbeCache<GetWithHeadersResult>(cacheTtl);
        var handler = new HttpClientHandler
        {
            AllowAutoRedirect = true,
            ServerCertificateCustomValidationCallback = (_, _, _, _) => true
        };
        _client = new HttpClient(handler)
        {
            Timeout = TimeSpan.FromSeconds(10)
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
        shouldCache: result => result.Success || result.StatusCode > 0);
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
        shouldCache: result => result.Success || result.StatusCode > 0);
        return result.ToTuple();
    }

    // ── Cache export/import for disk persistence ─────────────────────────

    public Dictionary<string, HttpGetCacheEntry> ExportGetCache()
    {
        var result = new Dictionary<string, HttpGetCacheEntry>();
        foreach (var kvp in _getCache.Export())
            result[kvp.Key] = new HttpGetCacheEntry { Success = kvp.Value.Success, Content = kvp.Value.Content, StatusCode = kvp.Value.StatusCode };
        return result;
    }

    public void ImportGetCache(Dictionary<string, HttpGetCacheEntry> entries)
    {
        foreach (var kvp in entries)
            _getCache.Import(kvp.Key, new GetResult { Success = kvp.Value.Success, Content = kvp.Value.Content, StatusCode = kvp.Value.StatusCode });
    }

    public Dictionary<string, HttpGetWithHeadersCacheEntry> ExportGetWithHeadersCache()
    {
        var result = new Dictionary<string, HttpGetWithHeadersCacheEntry>();
        foreach (var kvp in _getWithHeadersCache.Export())
            result[kvp.Key] = new HttpGetWithHeadersCacheEntry { Success = kvp.Value.Success, Content = kvp.Value.Content, StatusCode = kvp.Value.StatusCode, ContentType = kvp.Value.ContentType };
        return result;
    }

    public void ImportGetWithHeadersCache(Dictionary<string, HttpGetWithHeadersCacheEntry> entries)
    {
        foreach (var kvp in entries)
            _getWithHeadersCache.Import(kvp.Key, new GetWithHeadersResult { Success = kvp.Value.Success, Content = kvp.Value.Content, StatusCode = kvp.Value.StatusCode, ContentType = kvp.Value.ContentType });
    }

    // ── Cache entry removal ───────────────────────────────────────────────

    public void RemoveGetEntries(Func<string, bool> predicate)
        => _getCache.Remove(predicate);

    public void RemoveGetWithHeadersEntries(Func<string, bool> predicate)
        => _getWithHeadersCache.Remove(predicate);
}

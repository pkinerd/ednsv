using System.Collections.Concurrent;

namespace Ednsv.Core.Services;

public class HttpProbeService
{
    private readonly HttpClient _client;
    private static int MaxRetries = 3;
    public static void SetMaxRetries(int value) => MaxRetries = value;
    private readonly ConcurrentDictionary<string, (bool success, string content, int statusCode)> _getCache = new();
    private readonly ConcurrentDictionary<string, (bool success, string content, int statusCode, string? contentType)> _getWithHeadersCache = new();

    public HttpProbeService()
    {
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

    public async Task<(bool success, string content, int statusCode)> GetAsync(string url)
    {
        if (_getCache.TryGetValue(url, out var cached))
            return cached;

        try
        {
            var response = await _client.GetAsync(url);
            var content = await response.Content.ReadAsStringAsync();
            var result = (response.IsSuccessStatusCode, content, (int)response.StatusCode);
            // Any HTTP response (even 4xx/5xx) is a real answer — cache it
            _getCache.TryAdd(url, result);

            return result;
        }
        catch (Exception ex)
        {
            // Always cache — failures are filtered out by --retry-errors on load
            var result = (false, ex.Message, 0);
            _getCache.TryAdd(url, result);
            return result;
        }
    }

    public async Task<(bool success, string content, int statusCode, string? contentType)> GetWithHeadersAsync(string url)
    {
        if (_getWithHeadersCache.TryGetValue(url, out var cached))
            return cached;

        try
        {
            var response = await _client.GetAsync(url);
            var content = await response.Content.ReadAsStringAsync();
            var contentType = response.Content.Headers.ContentType?.MediaType;
            var result = (response.IsSuccessStatusCode, content, (int)response.StatusCode, contentType);
            // Any HTTP response is a real answer — cache it
            _getWithHeadersCache.TryAdd(url, result);

            return result;
        }
        catch (Exception ex)
        {
            // Always cache — failures are filtered out by --retry-errors on load
            var result = (false, ex.Message, 0, (string?)null);
            _getWithHeadersCache.TryAdd(url, result);
            return result;
        }
    }

    // ── Cache export/import for disk persistence ─────────────────────────

    public Dictionary<string, HttpGetCacheEntry> ExportGetCache()
    {
        var result = new Dictionary<string, HttpGetCacheEntry>();
        foreach (var kvp in _getCache)
            result[kvp.Key] = new HttpGetCacheEntry { Success = kvp.Value.success, Content = kvp.Value.content, StatusCode = kvp.Value.statusCode };
        return result;
    }

    public void ImportGetCache(Dictionary<string, HttpGetCacheEntry> entries)
    {
        foreach (var kvp in entries)
            _getCache.TryAdd(kvp.Key, (kvp.Value.Success, kvp.Value.Content, kvp.Value.StatusCode));
    }

    public Dictionary<string, HttpGetWithHeadersCacheEntry> ExportGetWithHeadersCache()
    {
        var result = new Dictionary<string, HttpGetWithHeadersCacheEntry>();
        foreach (var kvp in _getWithHeadersCache)
            result[kvp.Key] = new HttpGetWithHeadersCacheEntry { Success = kvp.Value.success, Content = kvp.Value.content, StatusCode = kvp.Value.statusCode, ContentType = kvp.Value.contentType };
        return result;
    }

    public void ImportGetWithHeadersCache(Dictionary<string, HttpGetWithHeadersCacheEntry> entries)
    {
        foreach (var kvp in entries)
            _getWithHeadersCache.TryAdd(kvp.Key, (kvp.Value.Success, kvp.Value.Content, kvp.Value.StatusCode, kvp.Value.ContentType));
    }
}

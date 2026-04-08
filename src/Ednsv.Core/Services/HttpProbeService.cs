using System.Collections.Concurrent;
using Microsoft.Extensions.Caching.Memory;

namespace Ednsv.Core.Services;

public class HttpProbeService
{
    private readonly HttpClient _client;
    private static volatile int MaxRetries = 3;
    public static void SetMaxRetries(int value) => MaxRetries = value;

    private readonly MemoryCache? _memCache;
    private readonly TimeSpan _cacheTtl;
    private readonly ConcurrentDictionary<string, (bool success, string content, int statusCode)> _getCache = new();
    private readonly ConcurrentDictionary<string, (bool success, string content, int statusCode, string? contentType)> _getWithHeadersCache = new();

    // Track keys loaded from disk cache
    private readonly ConcurrentDictionary<string, bool> _importedGetKeys = new();
    private readonly ConcurrentDictionary<string, bool> _importedGetWithHeadersKeys = new();

    public HttpProbeService(TimeSpan? cacheTtl = null)
    {
        _cacheTtl = cacheTtl ?? TimeSpan.Zero;
        if (_cacheTtl > TimeSpan.Zero)
            _memCache = new MemoryCache(new MemoryCacheOptions());
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
        var recheckDeps = RecheckHelper.CurrentRecheckDeps.Value;
        if (_memCache != null && !recheckDeps.HasFlag(RecheckHelper.CacheDep.Http))
        {
            if (_memCache.TryGetValue($"get:{url}", out (bool, string, int) memVal))
                return memVal;
        }
        else if (_memCache == null && _getCache.TryGetValue(url, out var cached))
            return cached;

        var retries = maxRetries ?? MaxRetries;
        (bool success, string content, int statusCode) lastResult = default;
        for (int attempt = 0; attempt < retries; attempt++)
        {
            try
            {
                var response = await _client.GetAsync(url);
                var content = await response.Content.ReadAsStringAsync();
                var result = (response.IsSuccessStatusCode, content, (int)response.StatusCode);
                // Any HTTP response (even 4xx/5xx) is a real answer — cache immediately
                _getCache.TryAdd(url, result);
                if (_memCache != null) _memCache.Set($"get:{url}", result, _cacheTtl);
                return result;
            }
            catch (Exception ex)
            {
                lastResult = (false, ex.Message, 0);
            }
        }

        // All attempts failed — cache the failure
        _getCache.TryAdd(url, lastResult);
        if (_memCache != null) _memCache.Set($"get:{url}", lastResult, _cacheTtl);
        return lastResult;
    }

    public async Task<(bool success, string content, int statusCode, string? contentType)> GetWithHeadersAsync(string url)
    {
        var recheckDeps = RecheckHelper.CurrentRecheckDeps.Value;
        if (_memCache != null && !recheckDeps.HasFlag(RecheckHelper.CacheDep.Http))
        {
            if (_memCache.TryGetValue($"gwh:{url}", out (bool, string, int, string?) memVal))
                return memVal;
        }
        else if (_memCache == null && _getWithHeadersCache.TryGetValue(url, out var cached))
            return cached;

        (bool success, string content, int statusCode, string? contentType) lastResult = default;
        for (int attempt = 0; attempt < MaxRetries; attempt++)
        {
            try
            {
                var response = await _client.GetAsync(url);
                var content = await response.Content.ReadAsStringAsync();
                var contentType = response.Content.Headers.ContentType?.MediaType;
                var result = (response.IsSuccessStatusCode, content, (int)response.StatusCode, contentType);
                _getWithHeadersCache.TryAdd(url, result);
                if (_memCache != null) _memCache.Set($"gwh:{url}", result, _cacheTtl);
                return result;
            }
            catch (Exception ex)
            {
                lastResult = (false, ex.Message, 0, (string?)null);
            }
        }

        _getWithHeadersCache.TryAdd(url, lastResult);
        if (_memCache != null) _memCache.Set($"gwh:{url}", lastResult, _cacheTtl);
        return lastResult;
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
        {
            _getCache.TryAdd(kvp.Key, (kvp.Value.Success, kvp.Value.Content, kvp.Value.StatusCode));
            _importedGetKeys.TryAdd(kvp.Key, true);
        }
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
        {
            _getWithHeadersCache.TryAdd(kvp.Key, (kvp.Value.Success, kvp.Value.Content, kvp.Value.StatusCode, kvp.Value.ContentType));
            _importedGetWithHeadersKeys.TryAdd(kvp.Key, true);
        }
    }

    // ── Recheck support ─────────────────────────────────────────────────

    public void RemoveGetEntries(Func<string, bool> predicate, bool importedOnly = true)
    {
        var keys = importedOnly ? _importedGetKeys.Keys : (ICollection<string>)_getCache.Keys;
        foreach (var key in keys)
            if (predicate(key)) { _getCache.TryRemove(key, out _); _importedGetKeys.TryRemove(key, out _); _memCache?.Remove($"get:{key}"); }
    }

    public void RemoveGetWithHeadersEntries(Func<string, bool> predicate, bool importedOnly = true)
    {
        var keys = importedOnly ? _importedGetWithHeadersKeys.Keys : (ICollection<string>)_getWithHeadersCache.Keys;
        foreach (var key in keys)
            if (predicate(key)) { _getWithHeadersCache.TryRemove(key, out _); _importedGetWithHeadersKeys.TryRemove(key, out _); _memCache?.Remove($"gwh:{key}"); }
    }

    // Backward-compatible aliases for CLI code
    public void RemoveImportedGetEntries(Func<string, bool> predicate) => RemoveGetEntries(predicate, importedOnly: true);
    public void RemoveImportedGetWithHeadersEntries(Func<string, bool> predicate) => RemoveGetWithHeadersEntries(predicate, importedOnly: true);
}

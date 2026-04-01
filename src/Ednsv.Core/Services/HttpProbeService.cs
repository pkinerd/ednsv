using System.Collections.Concurrent;

namespace Ednsv.Core.Services;

public class HttpProbeService
{
    private readonly HttpClient _client;
    private const int MaxRetries = 3;
    private readonly ConcurrentDictionary<string, (bool success, string content, int statusCode)> _getCache = new();
    private readonly ConcurrentDictionary<string, int> _getFailCounts = new();
    private readonly ConcurrentDictionary<string, (bool success, string content, int statusCode, string? contentType)> _getWithHeadersCache = new();
    private readonly ConcurrentDictionary<string, int> _getWithHeadersFailCounts = new();

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
            _getFailCounts.TryRemove(url, out _);
            return result;
        }
        catch (Exception ex)
        {
            // Network/timeout/DNS failure — only cache after max retries
            var result = (false, ex.Message, 0);
            var attempts = _getFailCounts.AddOrUpdate(url, 1, (_, c) => c + 1);
            if (attempts >= MaxRetries)
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
            _getWithHeadersFailCounts.TryRemove(url, out _);
            return result;
        }
        catch (Exception ex)
        {
            // Network/timeout/DNS failure — only cache after max retries
            var result = (false, ex.Message, 0, (string?)null);
            var attempts = _getWithHeadersFailCounts.AddOrUpdate(url, 1, (_, c) => c + 1);
            if (attempts >= MaxRetries)
                _getWithHeadersCache.TryAdd(url, result);
            return result;
        }
    }
}

using System.Collections.Concurrent;

namespace Ednsv.Core.Services;

public class HttpProbeService
{
    private readonly HttpClient _client;
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
            _getCache.TryAdd(url, result);
            return result;
        }
        catch (Exception ex)
        {
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
            _getWithHeadersCache.TryAdd(url, result);
            return result;
        }
        catch (Exception ex)
        {
            var result = (false, ex.Message, 0, (string?)null);
            _getWithHeadersCache.TryAdd(url, result);
            return result;
        }
    }
}

namespace Ednsv.Core.Services;

public class HttpProbeService
{
    private readonly HttpClient _client;

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
        try
        {
            var response = await _client.GetAsync(url);
            var content = await response.Content.ReadAsStringAsync();
            return (response.IsSuccessStatusCode, content, (int)response.StatusCode);
        }
        catch (Exception ex)
        {
            return (false, ex.Message, 0);
        }
    }
}

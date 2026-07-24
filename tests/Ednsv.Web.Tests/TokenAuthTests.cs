using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;

namespace Ednsv.Web.Tests;

/// <summary>Regression baseline for the pre-existing token auth behavior.</summary>
public sealed class TokenAuthTests : IClassFixture<TokenAuthTests.Fixture>
{
    public sealed class Fixture : IDisposable
    {
        public EdnsvAppFactory Factory { get; } = EdnsvAppFactory.WithTokenAuth();
        public void Dispose() => Factory.Dispose();
    }

    private readonly EdnsvAppFactory _factory;

    public TokenAuthTests(Fixture fx) => _factory = fx.Factory;

    private HttpClient Client() => _factory.CreateClient(new() { AllowAutoRedirect = false });

    [Fact]
    public async Task ApiWithoutCredentialsIs401Json()
    {
        var res = await Client().GetAsync("/api/auth/me");
        Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);
        Assert.Contains("Bearer", res.Headers.WwwAuthenticate.ToString());
        var body = await res.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("unauthorized", body.GetProperty("error").GetString());
    }

    [Fact]
    public async Task BrowserWithoutCredentialsRedirectsToLogin()
    {
        var client = Client();
        var req = new HttpRequestMessage(HttpMethod.Get, "/");
        req.Headers.Accept.ParseAdd("text/html");
        var res = await client.SendAsync(req);
        Assert.Equal(HttpStatusCode.Redirect, res.StatusCode);
        Assert.Equal("/login.html", res.Headers.Location?.ToString());
    }

    [Fact]
    public async Task LoginPageIsPublic()
    {
        var res = await Client().GetAsync("/login.html");
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
    }

    [Fact]
    public async Task BearerTokenAuthenticatesRoot()
    {
        var client = Client();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", EdnsvAppFactory.RootToken);
        var me = await client.GetFromJsonAsync<JsonElement>("/api/auth/me");
        Assert.Equal("ednsv", me.GetProperty("username").GetString());
        Assert.True(me.GetProperty("isAdmin").GetBoolean());
        Assert.True(me.GetProperty("isRoot").GetBoolean());
        Assert.True(me.GetProperty("tokenAuthEnabled").GetBoolean());
        Assert.Equal("token", me.GetProperty("authMethod").GetString());
    }

    [Fact]
    public async Task BasicAuthAuthenticatesRoot()
    {
        var client = Client();
        var basic = Convert.ToBase64String(Encoding.UTF8.GetBytes($"ednsv:{EdnsvAppFactory.RootToken}"));
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", basic);
        var me = await client.GetFromJsonAsync<JsonElement>("/api/auth/me");
        Assert.Equal("ednsv", me.GetProperty("username").GetString());
    }

    [Fact]
    public async Task LoginSetsTokenCookieAndCookieAuthenticates()
    {
        var client = Client();
        var login = await client.PostAsJsonAsync("/api/auth/login",
            new { username = "ednsv", token = EdnsvAppFactory.RootToken });
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        var setCookie = Assert.Single(login.Headers.GetValues("Set-Cookie"),
            v => v.StartsWith("ednsv-auth="));
        Assert.Contains("httponly", setCookie, StringComparison.OrdinalIgnoreCase);

        var req = new HttpRequestMessage(HttpMethod.Get, "/api/auth/me");
        req.Headers.Add("Cookie", $"ednsv-auth={EdnsvAppFactory.RootToken}");
        var me = await (await client.SendAsync(req)).Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("ednsv", me.GetProperty("username").GetString());
    }

    [Fact]
    public async Task InvalidLoginIs401()
    {
        var res = await Client().PostAsJsonAsync("/api/auth/login",
            new { username = "ednsv", token = "wrong-token" });
        Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);
    }

    [Fact]
    public async Task NonAdminGets403OnConfigAdminGets200()
    {
        var client = Client();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", EdnsvAppFactory.RootToken);

        var issue = await client.PostAsJsonAsync("/api/auth/users",
            new { username = "standard-user", isAdmin = false });
        Assert.Equal(HttpStatusCode.OK, issue.StatusCode);
        var issued = await issue.Content.ReadFromJsonAsync<JsonElement>();
        var userToken = issued.GetProperty("token").GetString()!;

        var userClient = Client();
        userClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", userToken);
        Assert.Equal(HttpStatusCode.Forbidden, (await userClient.GetAsync("/api/config")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/config")).StatusCode);
    }
}

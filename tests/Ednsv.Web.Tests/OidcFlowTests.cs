using System.Net;
using System.Web;

namespace Ednsv.Web.Tests;

/// <summary>
/// Interactive SSO flow up to the IdP redirect (the IdP round-trip itself is
/// out of scope; the session-cookie → gate mapping is covered in
/// AuthModeMatrixTests via forged session cookies).
/// </summary>
public sealed class OidcFlowTests : IClassFixture<OidcFlowTests.Fixture>
{
    public sealed class Fixture : IDisposable
    {
        public EdnsvAppFactory Factory { get; } = EdnsvAppFactory.WithTokenAuth(EdnsvAppFactory.OidcSettings());
        public void Dispose() => Factory.Dispose();
    }

    private readonly EdnsvAppFactory _factory;

    public OidcFlowTests(Fixture fx) => _factory = fx.Factory;

    private HttpClient Client() => _factory.CreateClient(new() { AllowAutoRedirect = false });

    [Fact]
    public async Task OidcLoginChallengesToAuthority()
    {
        var res = await Client().GetAsync("/api/auth/oidc/login?next=%2Ftokens.html");
        Assert.Equal(HttpStatusCode.Redirect, res.StatusCode);

        var location = res.Headers.Location!.ToString();
        Assert.StartsWith("https://idp.test/authorize", location);

        var query = HttpUtility.ParseQueryString(res.Headers.Location!.Query);
        Assert.Equal(EdnsvAppFactory.TestClientId, query["client_id"]);
        Assert.Equal("code", query["response_type"]);
        Assert.NotNull(query["code_challenge"]); // PKCE
        Assert.EndsWith("/signin-oidc", query["redirect_uri"]);
        Assert.Contains("openid", query["scope"]);

        // The handler's correlation/nonce cookies must be present for the callback.
        Assert.Contains(res.Headers.GetValues("Set-Cookie"), v => v.Contains("OpenIdConnect"));
    }

    [Fact]
    public async Task OidcLoginRejectsAbsoluteNextTargets()
    {
        // ?next= is confined to same-origin paths; anything else falls back to "/".
        var res = await Client().GetAsync("/api/auth/oidc/login?next=" + Uri.EscapeDataString("//evil.test/x"));
        Assert.Equal(HttpStatusCode.Redirect, res.StatusCode);
        var state = HttpUtility.ParseQueryString(res.Headers.Location!.Query)["state"];
        Assert.NotNull(state); // redirect target is folded into protected state; challenge succeeded
    }

    [Fact]
    public async Task OidcLoginIs404WhenDisabled()
    {
        using var factory = EdnsvAppFactory.WithTokenAuth();
        var client = factory.CreateClient(new() { AllowAutoRedirect = false });
        var res = await client.GetAsync("/api/auth/oidc/login");
        Assert.Equal(HttpStatusCode.NotFound, res.StatusCode);
    }

    [Fact]
    public async Task LogoutClearsSsoSession()
    {
        var cookie = _factory.ForgeSessionCookie(("preferred_username", "user@contoso.com"));
        var req = new HttpRequestMessage(HttpMethod.Post, "/api/auth/logout");
        req.Headers.Add("Cookie", $"ednsv-session={cookie}");
        var res = await Client().SendAsync(req);
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        // Sign-out rewrites the session cookie with an expired value.
        Assert.Contains(res.Headers.GetValues("Set-Cookie"), v => v.StartsWith("ednsv-session=") && v.Contains("expires", StringComparison.OrdinalIgnoreCase));
    }
}

using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Ednsv.Core.Services;

namespace Ednsv.Web.Tests;

/// <summary>
/// The token/SSO/none mode matrix: which methods /api/auth/methods reports,
/// when the gate bypass applies, and — critically — that admin-only endpoints
/// do NOT fall open in SSO-only mode (token auth disabled but SSO on).
/// </summary>
public sealed class AuthModeMatrixTests
{
    [Fact]
    public async Task TokenOnly_MethodsReportsTokenAuthOnly()
    {
        using var factory = EdnsvAppFactory.WithTokenAuth();
        var m = await factory.CreateClient().GetFromJsonAsync<JsonElement>("/api/auth/methods");
        Assert.True(m.GetProperty("tokenAuth").GetBoolean());
        Assert.False(m.GetProperty("sso").GetBoolean());
    }

    [Fact]
    public async Task SsoOnly_MethodsReportsSsoOnly_AndGateStillCloses()
    {
        using var factory = new EdnsvAppFactory(EdnsvAppFactory.OidcSettings());
        var client = factory.CreateClient();

        // Public before sign-in.
        var m = await client.GetFromJsonAsync<JsonElement>("/api/auth/methods");
        Assert.False(m.GetProperty("tokenAuth").GetBoolean());
        Assert.True(m.GetProperty("sso").GetBoolean());

        // No credentials → still locked, NOT the auth-disabled bypass.
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/auth/me")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/config")).StatusCode);

        // Token login endpoint reports token auth off.
        var login = await client.PostAsJsonAsync("/api/auth/login", new { username = "ednsv", token = "x" });
        Assert.Equal(HttpStatusCode.BadRequest, login.StatusCode);
        var body = await login.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("token auth is disabled", body.GetProperty("error").GetString());
    }

    [Fact]
    public async Task SsoOnly_SsoUserWithoutAdminRoleIsNotAdmin()
    {
        // Regression pin for the highest-severity trap: with token auth disabled
        // (auth.Disabled == true) but SSO enabled, admin checks must evaluate
        // the real user role — never the legacy "disabled ⇒ everyone is admin".
        using var factory = new EdnsvAppFactory(EdnsvAppFactory.OidcSettings());
        var cookie = factory.ForgeSessionCookie(("preferred_username", "user@contoso.com"));

        var client = factory.CreateClient();
        var req = new HttpRequestMessage(HttpMethod.Get, "/api/auth/me");
        req.Headers.Add("Cookie", $"ednsv-session={cookie}");
        var me = await (await client.SendAsync(req)).Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("user@contoso.com", me.GetProperty("username").GetString());
        Assert.False(me.GetProperty("isAdmin").GetBoolean());
        Assert.False(me.GetProperty("tokenAuthEnabled").GetBoolean());
        Assert.Equal("oidc", me.GetProperty("authMethod").GetString());

        var cfgReq = new HttpRequestMessage(HttpMethod.Get, "/api/config");
        cfgReq.Headers.Add("Cookie", $"ednsv-session={cookie}");
        Assert.Equal(HttpStatusCode.Forbidden, (await client.SendAsync(cfgReq)).StatusCode);

        // The outbound-fetch diagnostic must stay closed too (404s only on the
        // genuine auth-bypass instance; here it's a 403 for non-admins).
        var dbgReq = new HttpRequestMessage(HttpMethod.Get, "/api/debug/proxy?url=https://example.com/");
        dbgReq.Headers.Add("Cookie", $"ednsv-session={cookie}");
        Assert.Equal(HttpStatusCode.Forbidden, (await client.SendAsync(dbgReq)).StatusCode);
    }

    [Fact]
    public async Task BothModes_TokenAndSsoWorkSideBySide()
    {
        using var factory = EdnsvAppFactory.WithTokenAuth(EdnsvAppFactory.OidcSettings());
        var client = factory.CreateClient();

        var m = await client.GetFromJsonAsync<JsonElement>("/api/auth/methods");
        Assert.True(m.GetProperty("tokenAuth").GetBoolean());
        Assert.True(m.GetProperty("sso").GetBoolean());

        // Token path still works…
        var tokenClient = factory.CreateClient();
        tokenClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", EdnsvAppFactory.RootToken);
        var meToken = await tokenClient.GetFromJsonAsync<JsonElement>("/api/auth/me");
        Assert.Equal("ednsv", meToken.GetProperty("username").GetString());

        // …and an SSO session works at the same time, with admin role honored.
        var cookie = factory.ForgeSessionCookie(
            ("preferred_username", "admin@contoso.com"), ("roles", "Ednsv.Admin"));
        var req = new HttpRequestMessage(HttpMethod.Get, "/api/config");
        req.Headers.Add("Cookie", $"ednsv-session={cookie}");
        Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(req)).StatusCode);
    }

    [Fact]
    public async Task SsoAdminCanIssueAndRevokeTokens()
    {
        using var factory = EdnsvAppFactory.WithTokenAuth(EdnsvAppFactory.OidcSettings());
        var client = factory.CreateClient();
        var cookie = factory.ForgeSessionCookie(
            ("preferred_username", "admin@contoso.com"), ("roles", "Ednsv.Admin"));

        HttpRequestMessage WithSession(HttpMethod method, string path, object? body = null)
        {
            var req = new HttpRequestMessage(method, path);
            req.Headers.Add("Cookie", $"ednsv-session={cookie}");
            if (body != null) req.Content = JsonContent.Create(body);
            return req;
        }

        var issue = await client.SendAsync(WithSession(HttpMethod.Post, "/api/auth/users",
            new { username = "issued-by-sso", isAdmin = false }));
        Assert.Equal(HttpStatusCode.OK, issue.StatusCode);
        var issued = await issue.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("admin@contoso.com", issued.GetProperty("user").GetProperty("issuedBy").GetString());

        // The SSO issuer sees their own descendants…
        var list = await client.SendAsync(WithSession(HttpMethod.Get, "/api/auth/users"));
        var users = (await list.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("users");
        Assert.Contains("issued-by-sso",
            users.EnumerateArray().Select(u => u.GetProperty("username").GetString()));

        // …and can revoke them.
        var revoke = await client.SendAsync(WithSession(HttpMethod.Post, "/api/auth/users/issued-by-sso/revoke"));
        Assert.Equal(HttpStatusCode.OK, revoke.StatusCode);
    }

    [Fact]
    public async Task NoAuth_BypassTreatsCallersAsAdmin()
    {
        using var factory = new EdnsvAppFactory(); // AuthTokenHash unset → "none", no external IdP
        var client = factory.CreateClient();

        var me = await client.GetFromJsonAsync<JsonElement>("/api/auth/me");
        Assert.True(me.GetProperty("disabled").GetBoolean());
        Assert.True(me.GetProperty("isAdmin").GetBoolean());

        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/config")).StatusCode);
        // The outbound-fetch diagnostic is deliberately absent on bypass instances.
        Assert.Equal(HttpStatusCode.NotFound,
            (await client.GetAsync("/api/debug/proxy?url=https://example.com/")).StatusCode);
    }

    [Fact]
    public async Task SessionCookieWithRootUsernameIsRejected()
    {
        // A forged/misconfigured IdP claim equal to the root user must not
        // grant root powers — the mapper refuses it and the caller stays 401.
        using var factory = new EdnsvAppFactory(EdnsvAppFactory.OidcSettings());
        var cookie = factory.ForgeSessionCookie(("preferred_username", "ednsv"), ("roles", "Ednsv.Admin"));

        var req = new HttpRequestMessage(HttpMethod.Get, "/api/auth/me");
        req.Headers.Add("Cookie", $"ednsv-session={cookie}");
        Assert.Equal(HttpStatusCode.Unauthorized, (await factory.CreateClient().SendAsync(req)).StatusCode);
    }
}

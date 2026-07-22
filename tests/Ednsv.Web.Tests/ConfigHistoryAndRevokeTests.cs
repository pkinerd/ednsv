using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;

namespace Ednsv.Web.Tests;

/// <summary>
/// Config revision history endpoints (user recorded on save, list, load) and
/// elevated revoke for external-IdP admins.
/// </summary>
public sealed class ConfigHistoryAndRevokeTests
{
    // ── Config history ────────────────────────────────────────────────────

    [Fact]
    public async Task PutConfigRecordsRevisionAttributedToCaller()
    {
        using var factory = EdnsvAppFactory.WithTokenAuth();
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", EdnsvAppFactory.RootToken);

        var put = await client.PutAsJsonAsync("/api/config",
            new { enableSmtpProbes = false, enableHttpProbes = true, enableDnsbl = true, enableDirectDns = true, enableDoh = false });
        Assert.Equal(HttpStatusCode.OK, put.StatusCode);

        var history = await client.GetFromJsonAsync<JsonElement>("/api/config/history");
        var revs = history.EnumerateArray().ToList();
        Assert.True(revs.Count >= 2); // baseline + this change
        Assert.Equal("ednsv", revs[0].GetProperty("savedBy").GetString());   // newest first, attributed to root
        Assert.True(revs[0].GetProperty("id").GetInt32() > revs[1].GetProperty("id").GetInt32());
    }

    [Fact]
    public async Task GetRevisionReturnsSavedConfig()
    {
        using var factory = EdnsvAppFactory.WithTokenAuth();
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", EdnsvAppFactory.RootToken);

        await client.PutAsJsonAsync("/api/config",
            new { enableSmtpProbes = false, enableHttpProbes = true, enableDnsbl = true, enableDirectDns = true, enableDoh = false, knownDomains = new[] { "rev.test" } });

        var revs = (await client.GetFromJsonAsync<JsonElement>("/api/config/history")).EnumerateArray().ToList();
        var id = revs[0].GetProperty("id").GetInt32();

        var cfg = await client.GetFromJsonAsync<JsonElement>($"/api/config/history/{id}");
        Assert.False(cfg.GetProperty("enableSmtpProbes").GetBoolean());
        Assert.Contains("rev.test",
            cfg.GetProperty("knownDomains").EnumerateArray().Select(x => x.GetString()));

        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync("/api/config/history/999999")).StatusCode);
    }

    [Fact]
    public async Task ConfigHistoryIsAdminOnly()
    {
        using var factory = EdnsvAppFactory.WithTokenAuth();
        var admin = factory.CreateClient();
        admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", EdnsvAppFactory.RootToken);

        var issued = await (await admin.PostAsJsonAsync("/api/auth/users",
            new { username = "standard", isAdmin = false })).Content.ReadFromJsonAsync<JsonElement>();
        var userToken = issued.GetProperty("token").GetString()!;

        var user = factory.CreateClient();
        user.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", userToken);
        Assert.Equal(HttpStatusCode.Forbidden, (await user.GetAsync("/api/config/history")).StatusCode);
    }

    [Fact]
    public async Task SsoUsernameRecordedOnConfigSave()
    {
        using var factory = EdnsvAppFactory.WithTokenAuth(EdnsvAppFactory.OidcSettings());
        var client = factory.CreateClient();
        var cookie = factory.ForgeSessionCookie(
            ("preferred_username", "admin@contoso.com"), ("roles", "Ednsv.Admin"));

        var put = new HttpRequestMessage(HttpMethod.Put, "/api/config")
        {
            Content = JsonContent.Create(new { enableSmtpProbes = true, enableHttpProbes = true, enableDnsbl = true, enableDirectDns = true, enableDoh = true })
        };
        put.Headers.Add("Cookie", $"ednsv-session={cookie}");
        Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(put)).StatusCode);

        var list = new HttpRequestMessage(HttpMethod.Get, "/api/config/history");
        list.Headers.Add("Cookie", $"ednsv-session={cookie}");
        var revs = (await (await client.SendAsync(list)).Content.ReadFromJsonAsync<JsonElement>()).EnumerateArray().ToList();
        Assert.Equal("admin@contoso.com", revs[0].GetProperty("savedBy").GetString());
    }

    // ── Elevated revoke ───────────────────────────────────────────────────

    [Fact]
    public async Task SsoAdminCanRevokeTokenIssuedByRoot()
    {
        using var factory = EdnsvAppFactory.WithTokenAuth(EdnsvAppFactory.OidcSettings());

        // Root issues a token the SSO admin has no tree relationship to.
        var admin = factory.CreateClient();
        admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", EdnsvAppFactory.RootToken);
        await admin.PostAsJsonAsync("/api/auth/users", new { username = "root-issued", isAdmin = false });

        // The SSO admin revokes it despite not being an ancestor.
        var client = factory.CreateClient();
        var cookie = factory.ForgeSessionCookie(
            ("preferred_username", "admin@contoso.com"), ("roles", "Ednsv.Admin"));
        var req = new HttpRequestMessage(HttpMethod.Post, "/api/auth/users/root-issued/revoke");
        req.Headers.Add("Cookie", $"ednsv-session={cookie}");
        var res = await client.SendAsync(req);
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        var body = await res.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Contains("root-issued",
            body.GetProperty("revoked").EnumerateArray().Select(x => x.GetString()));
    }

    [Fact]
    public async Task SsoNonAdminCannotRevokeUnrelatedToken()
    {
        using var factory = EdnsvAppFactory.WithTokenAuth(EdnsvAppFactory.OidcSettings());

        var admin = factory.CreateClient();
        admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", EdnsvAppFactory.RootToken);
        await admin.PostAsJsonAsync("/api/auth/users", new { username = "root-issued2", isAdmin = false });

        // A standard (non-admin) SSO user is not elevated — tree-scoped, empty subtree.
        var client = factory.CreateClient();
        var cookie = factory.ForgeSessionCookie(("preferred_username", "plain@contoso.com"));
        var req = new HttpRequestMessage(HttpMethod.Post, "/api/auth/users/root-issued2/revoke");
        req.Headers.Add("Cookie", $"ednsv-session={cookie}");
        Assert.Equal(HttpStatusCode.Forbidden, (await client.SendAsync(req)).StatusCode);
    }

    [Fact]
    public async Task SsoAdminCannotRevokeRootUser()
    {
        using var factory = EdnsvAppFactory.WithTokenAuth(EdnsvAppFactory.OidcSettings());
        var client = factory.CreateClient();
        var cookie = factory.ForgeSessionCookie(
            ("preferred_username", "admin@contoso.com"), ("roles", "Ednsv.Admin"));
        var req = new HttpRequestMessage(HttpMethod.Post, "/api/auth/users/ednsv/revoke");
        req.Headers.Add("Cookie", $"ednsv-session={cookie}");
        Assert.Equal(HttpStatusCode.Forbidden, (await client.SendAsync(req)).StatusCode);
    }
}

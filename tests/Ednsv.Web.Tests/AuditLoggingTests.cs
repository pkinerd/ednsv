using System.Net.Http.Headers;
using System.Net.Http.Json;

namespace Ednsv.Web.Tests;

/// <summary>
/// Verifies security-sensitive operations and validation requests are logged,
/// and that user/domain details are masked when trace masking is enabled.
/// Each test uses its own factory so log sinks stay isolated.
/// </summary>
public sealed class AuditLoggingTests
{
    private const string Domain = "audit-example.com";

    private static HttpClient RootClient(EdnsvAppFactory f)
    {
        var c = f.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", EdnsvAppFactory.RootToken);
        return c;
    }

    private static bool Any(EdnsvAppFactory f, string needle) =>
        f.LogSnapshot().Any(l => l.Message.Contains(needle, StringComparison.OrdinalIgnoreCase));

    [Fact]
    public async Task ValidationRequestIsLogged_DomainMaskedByDefault()
    {
        using var factory = EdnsvAppFactory.WithTokenAuth(); // masking on by default
        var res = await RootClient(factory).PostAsJsonAsync("/api/validate", new { domain = Domain });
        res.EnsureSuccessStatusCode();

        var logs = factory.LogSnapshot();
        Assert.Contains(logs, l => l.Message.Contains("Validation requested"));
        // Raw domain must not appear anywhere with masking enabled.
        Assert.DoesNotContain(logs, l => l.Message.Contains(Domain));
    }

    [Fact]
    public async Task ValidationRequestIsLogged_RawDomainWhenMaskingOff()
    {
        using var factory = EdnsvAppFactory.WithTokenAuth(new() { ["MaskTrace"] = "false" });
        var res = await RootClient(factory).PostAsJsonAsync("/api/validate", new { domain = Domain });
        res.EnsureSuccessStatusCode();

        Assert.Contains(factory.LogSnapshot(),
            l => l.Message.Contains("Validation requested") && l.Message.Contains(Domain));
    }

    [Fact]
    public async Task ValidationRequestRecordsInputFlags()
    {
        using var factory = EdnsvAppFactory.WithTokenAuth();
        var res = await RootClient(factory).PostAsJsonAsync("/api/validate",
            new { domain = Domain, options = new { enableSmtpProbes = false, enableHttpProbes = true, enableDnsbl = true, enableDirectDns = true, enableDoh = false } });
        res.EnsureSuccessStatusCode();

        Assert.Contains(factory.LogSnapshot(),
            l => l.Message.Contains("Validation requested") && l.Message.Contains("smtp=False"));
    }

    [Fact]
    public async Task RecheckAllIsAcceptedAndLogged()
    {
        using var factory = EdnsvAppFactory.WithTokenAuth();
        var res = await RootClient(factory).PostAsJsonAsync("/api/validate",
            new { domain = Domain, recheckSeverity = "all" });
        res.EnsureSuccessStatusCode();

        Assert.Contains(factory.LogSnapshot(),
            l => l.Message.Contains("Validation requested") && l.Message.Contains("recheck=all"));
    }

    [Fact]
    public async Task ConfigChangeIsAudited()
    {
        using var factory = EdnsvAppFactory.WithTokenAuth();
        var res = await RootClient(factory).PutAsJsonAsync("/api/config",
            new { enableSmtpProbes = true, enableHttpProbes = true, enableDnsbl = true, enableDirectDns = true, enableDoh = false });
        res.EnsureSuccessStatusCode();

        Assert.Contains(factory.LogSnapshot(),
            l => l.Category == "Ednsv.Audit" && l.Message.Contains("Config updated"));
    }

    [Fact]
    public async Task TokenIssuanceIsAudited()
    {
        using var factory = EdnsvAppFactory.WithTokenAuth();
        var res = await RootClient(factory).PostAsJsonAsync("/api/auth/users",
            new { username = "audited-user", isAdmin = false });
        res.EnsureSuccessStatusCode();

        Assert.Contains(factory.LogSnapshot(),
            l => l.Category == "Ednsv.Audit" && l.Message.Contains("Token issued"));
    }

    [Fact]
    public async Task TokenRevokeIsAudited()
    {
        using var factory = EdnsvAppFactory.WithTokenAuth();
        var client = RootClient(factory);
        await client.PostAsJsonAsync("/api/auth/users", new { username = "to-revoke", isAdmin = false });
        var res = await client.PostAsync("/api/auth/users/to-revoke/revoke", null);
        res.EnsureSuccessStatusCode();

        Assert.Contains(factory.LogSnapshot(),
            l => l.Category == "Ednsv.Audit" && l.Message.Contains("Token revoked"));
    }

    [Fact]
    public async Task SuccessfulTokenSignInIsAudited()
    {
        using var factory = EdnsvAppFactory.WithTokenAuth();
        var res = await factory.CreateClient().PostAsJsonAsync("/api/auth/login",
            new { username = "ednsv", token = EdnsvAppFactory.RootToken });
        res.EnsureSuccessStatusCode();

        Assert.Contains(factory.LogSnapshot(),
            l => l.Category == "Ednsv.Audit" && l.Message.Contains("Sign-in:"));
    }

    [Fact]
    public async Task FailedTokenSignInIsAudited()
    {
        using var factory = EdnsvAppFactory.WithTokenAuth();
        await factory.CreateClient().PostAsJsonAsync("/api/auth/login",
            new { username = "ednsv", token = "wrong-token" });

        Assert.Contains(factory.LogSnapshot(),
            l => l.Category == "Ednsv.Audit" && l.Message.Contains("Sign-in failed"));
    }

    [Fact]
    public async Task SsoUsernameIsMaskedInLogsByDefault()
    {
        // A per-request SSO session (forged cookie) drives an admin action that
        // gets audited. With masking on, the raw UPN must not appear in any log
        // line — the request scope and audit entries carry the masked form.
        using var factory = EdnsvAppFactory.WithTokenAuth(EdnsvAppFactory.OidcSettings());
        var cookie = factory.ForgeSessionCookie(("preferred_username", "sso-user@contoso.com"), ("roles", "Ednsv.Admin"));
        var req = new HttpRequestMessage(HttpMethod.Put, "/api/config")
        {
            Content = JsonContent.Create(new { enableSmtpProbes = true, enableHttpProbes = true, enableDnsbl = true, enableDirectDns = true, enableDoh = false })
        };
        req.Headers.Add("Cookie", $"ednsv-session={cookie}");
        (await factory.CreateClient().SendAsync(req)).EnsureSuccessStatusCode();

        var logs = factory.LogSnapshot();
        Assert.Contains(logs, l => l.Message.Contains("Config updated"));       // the action was audited
        Assert.DoesNotContain(logs, l => l.Message.Contains("sso-user@contoso.com")); // but not in the clear
    }

    [Fact]
    public async Task UsernameAppearsRawWhenMaskingOff()
    {
        using var factory = EdnsvAppFactory.WithTokenAuth(new()
        {
            ["MaskTrace"] = "false",
            ["Auth:Oidc:Enabled"] = "true",
            ["Auth:Oidc:Authority"] = EdnsvAppFactory.TestIssuer,
            ["Auth:Oidc:ClientId"] = EdnsvAppFactory.TestClientId
        });
        var cookie = factory.ForgeSessionCookie(("preferred_username", "clear-user@contoso.com"), ("roles", "Ednsv.Admin"));
        var req = new HttpRequestMessage(HttpMethod.Put, "/api/config")
        {
            Content = JsonContent.Create(new { enableSmtpProbes = true, enableHttpProbes = true, enableDnsbl = true, enableDirectDns = true, enableDoh = false })
        };
        req.Headers.Add("Cookie", $"ednsv-session={cookie}");
        (await factory.CreateClient().SendAsync(req)).EnsureSuccessStatusCode();

        Assert.Contains(factory.LogSnapshot(),
            l => l.Message.Contains("Config updated") && l.Message.Contains("clear-user@contoso.com"));
    }
}

using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;

namespace Ednsv.Web.Tests;

/// <summary>Service-account API access via IdP-issued JWT bearer tokens.</summary>
public sealed class JwtBearerAuthTests : IClassFixture<JwtBearerAuthTests.Fixture>
{
    public sealed class Fixture : IDisposable
    {
        // Token auth AND JWT bearer on — the side-by-side configuration.
        public EdnsvAppFactory Factory { get; } = EdnsvAppFactory.WithTokenAuth(EdnsvAppFactory.JwtSettings());
        public void Dispose() => Factory.Dispose();
    }

    private readonly EdnsvAppFactory _factory;

    public JwtBearerAuthTests(Fixture fx) => _factory = fx.Factory;

    private HttpClient ClientWithBearer(string token)
    {
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return client;
    }

    [Fact]
    public async Task ValidJwtAuthenticatesAsAppPrincipal()
    {
        var jwt = EdnsvAppFactory.MintJwt(azp: "svc-client-id");
        var me = await ClientWithBearer(jwt).GetFromJsonAsync<JsonElement>("/api/auth/me");
        Assert.Equal("app:svc-client-id", me.GetProperty("username").GetString());
        Assert.False(me.GetProperty("isAdmin").GetBoolean());
        Assert.Equal("jwt", me.GetProperty("authMethod").GetString());
    }

    [Fact]
    public async Task AdminRoleGrantsAdminEndpoints()
    {
        var jwt = EdnsvAppFactory.MintJwt(roles: new[] { "Ednsv.Admin" });
        Assert.Equal(HttpStatusCode.OK, (await ClientWithBearer(jwt).GetAsync("/api/config")).StatusCode);
    }

    [Fact]
    public async Task NoAdminRoleGets403OnAdminEndpoints()
    {
        var jwt = EdnsvAppFactory.MintJwt();
        Assert.Equal(HttpStatusCode.Forbidden, (await ClientWithBearer(jwt).GetAsync("/api/config")).StatusCode);
    }

    [Fact]
    public async Task WrongAudienceIs401()
    {
        var jwt = EdnsvAppFactory.MintJwt(audience: "api://some-other-app");
        Assert.Equal(HttpStatusCode.Unauthorized, (await ClientWithBearer(jwt).GetAsync("/api/auth/me")).StatusCode);
    }

    [Fact]
    public async Task WrongIssuerIs401()
    {
        var jwt = EdnsvAppFactory.MintJwt(issuer: "https://evil.test/v2.0");
        Assert.Equal(HttpStatusCode.Unauthorized, (await ClientWithBearer(jwt).GetAsync("/api/auth/me")).StatusCode);
    }

    [Fact]
    public async Task ExpiredJwtIs401()
    {
        var jwt = EdnsvAppFactory.MintJwt(expires: DateTime.UtcNow.AddHours(-1));
        Assert.Equal(HttpStatusCode.Unauthorized, (await ClientWithBearer(jwt).GetAsync("/api/auth/me")).StatusCode);
    }

    [Fact]
    public async Task WrongSigningKeyIs401()
    {
        var otherKey = new RsaSecurityKey(System.Security.Cryptography.RSA.Create(2048)) { KeyId = "other" };
        var jwt = EdnsvAppFactory.MintJwt(key: otherKey);
        Assert.Equal(HttpStatusCode.Unauthorized, (await ClientWithBearer(jwt).GetAsync("/api/auth/me")).StatusCode);
    }

    [Fact]
    public async Task GarbageBearerIs401()
    {
        Assert.Equal(HttpStatusCode.Unauthorized,
            (await ClientWithBearer("not-a-token-at-all").GetAsync("/api/auth/me")).StatusCode);
    }

    [Fact]
    public async Task EdnsvTokensStillWorkSideBySide()
    {
        // A 43-char ednsv token must resolve via the hash store, not get eaten
        // by the JWT branch.
        var me = await ClientWithBearer(EdnsvAppFactory.RootToken).GetFromJsonAsync<JsonElement>("/api/auth/me");
        Assert.Equal("ednsv", me.GetProperty("username").GetString());
        Assert.Equal("token", me.GetProperty("authMethod").GetString());
    }

    [Fact]
    public async Task JwtOnly_NonAdminJwtDoesNotBecomeAdmin()
    {
        // Token auth fully disabled, JWT bearer only: auth.Disabled is true but
        // admin checks must still evaluate the JWT principal's roles.
        using var factory = new EdnsvAppFactory(EdnsvAppFactory.JwtSettings());
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", EdnsvAppFactory.MintJwt());

        var me = await client.GetFromJsonAsync<JsonElement>("/api/auth/me");
        Assert.False(me.GetProperty("disabled").GetBoolean());
        Assert.False(me.GetProperty("isAdmin").GetBoolean());
        Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync("/api/config")).StatusCode);
    }

    [Fact]
    public async Task RequiredRolesRejectsTokensWithoutThem()
    {
        var settings = EdnsvAppFactory.JwtSettings();
        settings["Auth:JwtBearer:RequiredRoles:0"] = "Ednsv.Access";
        using var factory = EdnsvAppFactory.WithTokenAuth(settings);

        var without = factory.CreateClient();
        without.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", EdnsvAppFactory.MintJwt());
        Assert.Equal(HttpStatusCode.Unauthorized, (await without.GetAsync("/api/auth/me")).StatusCode);

        var with = factory.CreateClient();
        with.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", EdnsvAppFactory.MintJwt(roles: new[] { "Ednsv.Access" }));
        Assert.Equal(HttpStatusCode.OK, (await with.GetAsync("/api/auth/me")).StatusCode);
    }
}

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Ednsv.Core.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace Ednsv.Web.Tests;

/// <summary>
/// Boots the real app (via the <c>public partial class Program</c> hook) against
/// a temp DataDir with per-test config. External IdP metadata is replaced with a
/// static in-memory configuration and a test RSA key, so no network is touched.
/// </summary>
public sealed class EdnsvAppFactory : WebApplicationFactory<Program>
{
    public const string RootToken = "test-root-token-with-plenty-of-entropy";
    public const string TestIssuer = "https://idp.test/tenant/v2.0";
    public const string TestClientId = "11111111-1111-1111-1111-111111111111";
    public const string TestAudience = "api://ednsv-test";

    public static readonly RsaSecurityKey SigningKey = new(RSA.Create(2048)) { KeyId = "test-key" };

    private readonly Dictionary<string, string?> _settings;
    public string DataDir { get; } = Path.Combine(Path.GetTempPath(), $"ednsv-web-test-{Guid.NewGuid():N}");

    public EdnsvAppFactory(Dictionary<string, string?>? settings = null)
    {
        _settings = settings ?? new Dictionary<string, string?>();
    }

    /// <summary>Factory for an instance with token auth enabled (root token = RootToken).</summary>
    public static EdnsvAppFactory WithTokenAuth(Dictionary<string, string?>? extra = null)
    {
        var settings = new Dictionary<string, string?> { ["AuthTokenHash"] = AuthService.Hash(RootToken) };
        if (extra != null) foreach (var kv in extra) settings[kv.Key] = kv.Value;
        return new EdnsvAppFactory(settings);
    }

    public static Dictionary<string, string?> OidcSettings() => new()
    {
        ["Auth:Oidc:Enabled"] = "true",
        ["Auth:Oidc:Authority"] = TestIssuer,
        ["Auth:Oidc:ClientId"] = TestClientId
    };

    public static Dictionary<string, string?> JwtSettings() => new()
    {
        ["Auth:JwtBearer:Enabled"] = "true",
        ["Auth:JwtBearer:Authority"] = TestIssuer,
        ["Auth:JwtBearer:Audiences:0"] = TestAudience
    };

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseSetting("DataDir", DataDir);
        foreach (var kv in _settings)
            builder.UseSetting(kv.Key, kv.Value);

        builder.ConfigureTestServices(services =>
        {
            // Pin both external handlers to static metadata + the test signing
            // key. The built-in post-configure created network-backed
            // ConfigurationManagers from Authority; these run later and win.
            services.PostConfigure<JwtBearerOptions>("EntraBearer", o =>
            {
                var config = new OpenIdConnectConfiguration { Issuer = TestIssuer };
                config.SigningKeys.Add(SigningKey);
                o.Configuration = config;
                o.ConfigurationManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(config);
                o.TokenValidationParameters.ValidIssuer = TestIssuer;
                o.TokenValidationParameters.IssuerSigningKey = SigningKey;
            });
            services.PostConfigure<OpenIdConnectOptions>("Oidc", o =>
            {
                var config = new OpenIdConnectConfiguration
                {
                    Issuer = TestIssuer,
                    AuthorizationEndpoint = "https://idp.test/authorize",
                    TokenEndpoint = "https://idp.test/token",
                    EndSessionEndpoint = "https://idp.test/logout"
                };
                o.Configuration = config;
                o.ConfigurationManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(config);
            });
        });
    }

    /// <summary>Mints an IdP-style JWT access token signed with the test key.</summary>
    public static string MintJwt(
        string? azp = "22222222-2222-2222-2222-222222222222",
        string audience = TestAudience,
        string issuer = TestIssuer,
        string[]? roles = null,
        DateTime? expires = null,
        SecurityKey? key = null)
    {
        var claims = new List<Claim>();
        if (azp != null) claims.Add(new Claim("azp", azp));
        foreach (var r in roles ?? Array.Empty<string>()) claims.Add(new Claim("roles", r));
        var exp = expires ?? DateTime.UtcNow.AddMinutes(10);
        var token = new JwtSecurityToken(
            issuer, audience, claims,
            notBefore: exp.AddMinutes(-30),
            expires: exp,
            signingCredentials: new SigningCredentials(key ?? SigningKey, SecurityAlgorithms.RsaSha256));
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    /// <summary>
    /// Produces a valid ednsv-session cookie value for the given claims by
    /// protecting a cookie-auth ticket with the app's own Data Protection key
    /// ring — i.e. exactly what the OIDC sign-in would have written.
    /// </summary>
    public string ForgeSessionCookie(params (string Type, string Value)[] claims)
    {
        var protector = Services.GetRequiredService<IDataProtectionProvider>()
            .CreateProtector("Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationMiddleware", "EdnsvSession", "v2");
        var identity = new ClaimsIdentity(claims.Select(c => new Claim(c.Type, c.Value)), "EdnsvSession");
        var ticket = new AuthenticationTicket(new ClaimsPrincipal(identity), "EdnsvSession");
        return new TicketDataFormat(protector).Protect(ticket);
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        try { Directory.Delete(DataDir, recursive: true); } catch { /* best effort */ }
    }
}

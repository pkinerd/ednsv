// Startup-time settings for the optional external-IdP auth methods (config
// section "Auth"). These are deliberately plain mutable classes bound once at
// startup — like AuthTokenHash, they are not part of the runtime-editable
// AppConfig, so changing them requires a restart.

/// <summary>
/// Interactive single sign-on via OpenID Connect (config section "Auth:Oidc").
/// Works with any spec-compliant IdP; the defaults target Entra ID (Azure AD)
/// app-role conventions.
/// </summary>
public sealed class OidcSettings
{
    public bool Enabled { get; set; }
    public string? Authority { get; set; }
    public string? ClientId { get; set; }
    public string? ClientSecret { get; set; }
    /// <summary>
    /// OIDC response type. Default "id_token": the signed ID token is returned
    /// straight from the authorization endpoint (via form_post), so sign-in
    /// needs NO client secret or certificate — nothing to expire or rotate.
    /// ednsv only authenticates users (it never calls downstream APIs on their
    /// behalf), so it has no need for the token endpoint. Set "code" for the
    /// authorization-code flow (requires ClientSecret on Entra ID, or a public
    /// client with PKCE on IdPs that allow one).
    /// </summary>
    public string ResponseType { get; set; } = "id_token";
    public string ResponseMode { get; set; } = "form_post";
    public string CallbackPath { get; set; } = "/signin-oidc";
    public string SignedOutCallbackPath { get; set; } = "/signout-callback-oidc";
    public string Scopes { get; set; } = "openid profile email";
    public string UsernameClaim { get; set; } = "preferred_username";
    public string RoleClaim { get; set; } = "roles";
    public List<string> AdminRoles { get; set; } = new();
    public List<string> RequiredRoles { get; set; } = new();
    public int SessionHours { get; set; } = 8;
    public bool SingleLogout { get; set; }

    public static OidcSettings Load(IConfiguration config)
    {
        var s = config.GetSection("Auth:Oidc").Get<OidcSettings>() ?? new OidcSettings();
        // List defaults can't live in the property initializer: the binder
        // appends configured items to any pre-seeded list instead of replacing.
        if (s.AdminRoles.Count == 0) s.AdminRoles.Add("Ednsv.Admin");
        var envSecret = Environment.GetEnvironmentVariable("EDNSV_OIDC_CLIENT_SECRET");
        if (!string.IsNullOrEmpty(envSecret)) s.ClientSecret = envSecret;
        return s;
    }

    public void Validate()
    {
        if (!Enabled) return;
        if (string.IsNullOrWhiteSpace(Authority) || string.IsNullOrWhiteSpace(ClientId))
            throw new InvalidOperationException(
                "Auth:Oidc:Enabled is true but Auth:Oidc:Authority and/or Auth:Oidc:ClientId is missing. "
                + "For Entra ID use Authority=https://login.microsoftonline.com/{tenantId}/v2.0 and the app registration's client ID.");
        if (!CallbackPath.StartsWith('/') || !SignedOutCallbackPath.StartsWith('/'))
            throw new InvalidOperationException("Auth:Oidc:CallbackPath and Auth:Oidc:SignedOutCallbackPath must start with '/'.");
        if (SessionHours <= 0)
            throw new InvalidOperationException("Auth:Oidc:SessionHours must be positive.");
        // Never allow response types that put ACCESS tokens in the front
        // channel; only the ID token (validated, nonce-bound, form_post) or the
        // code flow are supported.
        var rt = ResponseType.Trim();
        if (rt != "id_token" && rt != "code" && rt != "code id_token")
            throw new InvalidOperationException(
                "Auth:Oidc:ResponseType must be 'id_token' (default, no client secret needed), 'code', or 'code id_token'.");
    }
}

/// <summary>
/// Service-account API auth: validates IdP-issued OAuth2 access tokens (JWTs,
/// e.g. Entra ID client-credentials tokens) presented as Authorization: Bearer
/// (config section "Auth:JwtBearer").
/// </summary>
public sealed class JwtBearerSettings
{
    public bool Enabled { get; set; }
    public string? Authority { get; set; }
    public List<string> Audiences { get; set; } = new();
    public string RoleClaim { get; set; } = "";
    public List<string> AdminRoles { get; set; } = new();
    public List<string> RequiredRoles { get; set; } = new();
    public string NameClaim { get; set; } = "azp";

    public static JwtBearerSettings Load(IConfiguration config, OidcSettings oidc)
    {
        var s = config.GetSection("Auth:JwtBearer").Get<JwtBearerSettings>() ?? new JwtBearerSettings();
        // Unset values inherit from the OIDC section so a single-tenant setup
        // only has to configure Authority/roles once.
        if (string.IsNullOrWhiteSpace(s.Authority)) s.Authority = oidc.Authority;
        if (string.IsNullOrWhiteSpace(s.RoleClaim)) s.RoleClaim = oidc.RoleClaim;
        if (s.AdminRoles.Count == 0) s.AdminRoles.AddRange(oidc.AdminRoles);
        return s;
    }

    public void Validate()
    {
        if (!Enabled) return;
        if (string.IsNullOrWhiteSpace(Authority))
            throw new InvalidOperationException(
                "Auth:JwtBearer:Enabled is true but no Authority is set (Auth:JwtBearer:Authority, or Auth:Oidc:Authority as fallback).");
        if (Audiences.Count == 0)
            throw new InvalidOperationException(
                "Auth:JwtBearer:Enabled is true but Auth:JwtBearer:Audiences is empty. "
                + "Set the audience(s) your IdP puts in access tokens, e.g. api://{clientId} and/or the client ID.");
    }
}

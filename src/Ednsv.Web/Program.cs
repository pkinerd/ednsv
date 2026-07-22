using System.Collections.Concurrent;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using Ednsv.Core;
using Ednsv.Core.Checks;
using Ednsv.Core.Models;
using Ednsv.Core.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Logging.Console;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

// ── Console log formatter ───────────────────────────────────────────────
// JSON in Production (or whenever Logging:Console:FormatterName=Json), Simple
// in Development. Override either default with Logging:Console:FormatterName.
// The JSON formatter emits structured fields including any active scope
// values — e.g. JobId, Username, Domain, Phase, Check from the validation
// pipeline — so logs from concurrent requests can be filtered with jq.
var explicitFormatter = builder.Configuration.GetValue<string>("Logging:Console:FormatterName");
var useJsonLogs = string.Equals(explicitFormatter, "Json", StringComparison.OrdinalIgnoreCase)
    || (string.IsNullOrEmpty(explicitFormatter) && !builder.Environment.IsDevelopment());

if (useJsonLogs)
{
    builder.Logging.AddConsoleFormatter<CleanJsonFormatter, JsonConsoleFormatterOptions>(options =>
    {
        options.IncludeScopes = true;
        options.TimestampFormat = "yyyy-MM-ddTHH:mm:ss.fffZ";
        options.UseUtcTimestamp = true;
    });
    builder.Logging.AddConsole(options => options.FormatterName = CleanJsonFormatter.FormatterName);
}
else
{
    builder.Logging.AddSimpleConsole(options =>
    {
        options.TimestampFormat = "yyyy-MM-dd HH:mm:ss.fff ";
        options.SingleLine = true;
        options.IncludeScopes = true;
    });
}

// ── Configuration ────────────────────────────────────────────────────────
var dataDir = builder.Configuration.GetValue<string>("DataDir") ?? ".ednsv-data";
var cacheDir = Path.Combine(dataDir, "cache");
var authDir = Path.Combine(dataDir, "auth");
var cacheTtlHours = builder.Configuration.GetValue<int>("CacheTtlHours", 24);
var flushIntervalSeconds = builder.Configuration.GetValue<int>("FlushIntervalSeconds", 120);
var dnsServerStr = builder.Configuration.GetValue<string>("DnsServer");
var dkimSelectorsStr = builder.Configuration.GetValue<string>("DkimSelectors");
var enableTrace = builder.Configuration.GetValue<bool>("Trace", false);
var maskTrace = builder.Configuration.GetValue<bool>("MaskTrace", true); // default ON for privacy
var maskSalt = builder.Configuration.GetValue<string>("MaskSalt");
// Network-category server defaults (default ON; operators can centrally disable
// a category for the whole instance — clients cannot re-enable what's disabled here).
var defaultEnableSmtpProbes = builder.Configuration.GetValue<bool>("EnableSmtpProbes", true);
var defaultEnableHttpProbes = builder.Configuration.GetValue<bool>("EnableHttpProbes", true);
var defaultEnableDnsbl      = builder.Configuration.GetValue<bool>("EnableDnsbl",      true);
var defaultEnableDirectDns  = builder.Configuration.GetValue<bool>("EnableDirectDns",  true);
var defaultEnableDoh        = builder.Configuration.GetValue<bool>("EnableDoh",        false);

// Auth: env var EDNSV_AUTH_TOKEN_HASH wins, then config "AuthTokenHash", else "none" (disabled).
var authTokenHash = Environment.GetEnvironmentVariable("EDNSV_AUTH_TOKEN_HASH")
    ?? builder.Configuration.GetValue<string>("AuthTokenHash")
    ?? AuthService.DisabledMarker;

// External-IdP auth (optional, off by default): interactive OIDC SSO for the
// UI and IdP-issued JWT bearer tokens for service accounts. Both run alongside
// token auth; any combination may be enabled. Invalid config fails startup.
var oidcSettings = OidcSettings.Load(builder.Configuration);
var jwtSettings = JwtBearerSettings.Load(builder.Configuration, oidcSettings);
oidcSettings.Validate();
jwtSettings.Validate();

// Scheme names for the ASP.NET Core authentication handlers registered below.
const string SessionScheme = "EdnsvSession"; // signed SSO session cookie
const string OidcScheme = "Oidc";            // interactive OIDC challenge/callback
const string EntraBearerScheme = "EntraBearer"; // IdP-issued JWT access tokens

// ── Shared services (singletons — thread-safe via ConcurrentDictionary) ──
// Use OS-configured resolvers by default; override with DnsServer env var.
// CacheTtlHours controls per-entry in-memory cache expiry.
var inMemoryTtl = cacheTtlHours > 0 ? TimeSpan.FromHours(cacheTtlHours) : (TimeSpan?)null;

DnsResolverService dns;
if (!string.IsNullOrEmpty(dnsServerStr))
{
    var dnsServers = new List<IPAddress>();
    foreach (var s in dnsServerStr.Split(',', StringSplitOptions.RemoveEmptyEntries))
        if (IPAddress.TryParse(s.Trim(), out var ip))
            dnsServers.Add(ip);
    dns = dnsServers.Count > 0
        ? new DnsResolverService(dnsServers, cacheTtl: inMemoryTtl)
        : DnsResolverService.CreateWithSystemResolvers(cacheTtl: inMemoryTtl);
}
else
{
    dns = DnsResolverService.CreateWithSystemResolvers(cacheTtl: inMemoryTtl);
}
var smtp = new SmtpProbeService(cacheTtl: inMemoryTtl);
// HTTPS certificate validation is ON by default (required for trustworthy MTA-STS /
// BIMI / DoH results). Only disable it for a TLS-intercepting egress proxy whose CA
// isn't trusted by the host — this makes all HTTPS verdicts untrustworthy.
var validateHttpsCerts = builder.Configuration.GetValue<bool>("ValidateHttpsCertificates", true);
var http = new HttpProbeService(cacheTtl: inMemoryTtl, validateCertificates: validateHttpsCerts);
if (!validateHttpsCerts)
    Console.Error.WriteLine("WARNING: HTTPS certificate validation is DISABLED (ValidateHttpsCertificates=false) — MTA-STS/BIMI/DoH TLS results cannot be trusted.");

builder.Services.AddSingleton(dns);
builder.Services.AddSingleton(smtp);
builder.Services.AddSingleton(http);

// ── Trace masker (singleton — same salt for session, consistent hashes) ───
var traceMasker = maskTrace
    ? (!string.IsNullOrEmpty(maskSalt) ? new TraceMasker(maskSalt) : new TraceMasker())
    : null;

// ── App config (persisted to {dataDir}/config.json) ──────────────────────
// On first run, seed from env vars + DkimSelectorsCheck.CommonSelectors so an
// out-of-the-box install matches built-in behavior. After that the file is the
// source of truth and admins edit it via the web UI.
var configService = new ConfigService(dataDir);
var seedConfig = new AppConfig
{
    EnableSmtpProbes = defaultEnableSmtpProbes,
    EnableHttpProbes = defaultEnableHttpProbes,
    EnableDnsbl      = defaultEnableDnsbl,
    EnableDirectDns  = defaultEnableDirectDns,
    EnableDoh        = defaultEnableDoh,
    DefaultDkimSelectors = !string.IsNullOrEmpty(dkimSelectorsStr)
        ? dkimSelectorsStr.Split(',', StringSplitOptions.RemoveEmptyEntries)
            .Select(s => s.Trim()).Where(s => s.Length > 0).ToList()
        : DkimSelectorsCheck.CommonSelectors.ToList()
};
configService.LoadOrSeed(seedConfig);
builder.Services.AddSingleton(configService);

// Default validation options track the live config snapshot. Endpoints that
// compose per-request options pull a fresh snapshot from ConfigService.
ValidationOptions BuildDefaultOptions()
{
    var cfg = configService.Snapshot();
    return new ValidationOptions
    {
        EnableSmtpProbes        = cfg.EnableSmtpProbes,
        EnableHttpProbes        = cfg.EnableHttpProbes,
        EnableDnsbl             = cfg.EnableDnsbl,
        EnableDirectDns         = cfg.EnableDirectDns,
        EnableDoh               = cfg.EnableDoh,
        AdditionalDkimSelectors = new List<string>(cfg.DefaultDkimSelectors),
        PerDomainDkimSelectors  = cfg.DkimSelectors
            .ToDictionary(kv => kv.Key, kv => new List<string>(kv.Value), StringComparer.OrdinalIgnoreCase)
    };
}

// Basic hostname sanity check for the (already lowercased, dot-trimmed) domain
// input. Internal tool — this is deliberately lightweight: it rejects the obvious
// bad/hostile inputs (userinfo '@', path '/', port ':', whitespace, schemes) that
// would otherwise be interpolated into probe URLs, but is not a full public-suffix
// or egress-policy check.
var DomainPattern = new Regex(
    @"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$",
    RegexOptions.Compiled);
bool IsPlausibleDomain(string d) => !string.IsNullOrEmpty(d) && DomainPattern.IsMatch(d);

// ── Cache manager ────────────────────────────────────────────────────────
var cacheManager = new CacheManager(cacheDir, TimeSpan.FromHours(cacheTtlHours), dns, smtp, http);
builder.Services.AddSingleton(cacheManager);

// ── Auth ─────────────────────────────────────────────────────────────────
var authService = new AuthService(authDir, authTokenHash);
authService.Load();
builder.Services.AddSingleton(authService);

// True when at least one auth method protects the instance. Token-subsystem
// endpoints keep keying off authService.Disabled ("token auth off"); the gate
// middleware and the fail-closed startup guard key off this instead.
var anyAuthEnabled = !authService.Disabled || oidcSettings.Enabled || jwtSettings.Enabled;
var externalAuthEnabled = oidcSettings.Enabled || jwtSettings.Enabled;

if (externalAuthEnabled)
{
    // SSO sessions are Data Protection tickets; persist the key ring under
    // DataDir (alongside auth/ and cache/) so sessions survive restarts.
    builder.Services.AddDataProtection()
        .PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(dataDir, "keys")))
        .SetApplicationName("ednsv");

    var authBuilder = builder.Services.AddAuthentication();

    if (oidcSettings.Enabled)
    {
        authBuilder.AddCookie(SessionScheme, o =>
        {
            o.Cookie.Name = "ednsv-session";
            o.Cookie.HttpOnly = true;
            // Lax, not Strict: the sign-in landing after the cross-site IdP
            // redirect must carry the cookie. Lax still withholds it on
            // cross-site non-GET requests, preserving CSRF protection for all
            // state-changing endpoints (parity with the Strict token cookie).
            o.Cookie.SameSite = SameSiteMode.Lax;
            o.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
            o.Cookie.Path = "/";
            o.ExpireTimeSpan = TimeSpan.FromHours(oidcSettings.SessionHours);
            o.SlidingExpiration = true;
            // The gate middleware owns the 302-vs-401 decision; the handler
            // must never redirect on its own.
            o.Events.OnRedirectToLogin = ctx => { ctx.Response.StatusCode = StatusCodes.Status401Unauthorized; return Task.CompletedTask; };
            o.Events.OnRedirectToAccessDenied = ctx => { ctx.Response.StatusCode = StatusCodes.Status403Forbidden; return Task.CompletedTask; };
        });

        authBuilder.AddOpenIdConnect(OidcScheme, o =>
        {
            o.SignInScheme = SessionScheme;
            o.Authority = oidcSettings.Authority;
            o.ClientId = oidcSettings.ClientId;
            o.ClientSecret = oidcSettings.ClientSecret;
            o.ResponseType = OpenIdConnectResponseType.Code; // + PKCE (handler default)
            o.CallbackPath = oidcSettings.CallbackPath;
            o.SignedOutCallbackPath = oidcSettings.SignedOutCallbackPath;
            o.SignedOutRedirectUri = "/login.html";
            // Keep raw claim names (preferred_username, roles, …) instead of
            // the legacy SOAP-era ClaimTypes remapping.
            o.MapInboundClaims = false;
            o.TokenValidationParameters.NameClaimType = oidcSettings.UsernameClaim;
            o.TokenValidationParameters.RoleClaimType = oidcSettings.RoleClaim;
            // Session cookie stays small: no IdP tokens are stored, identity is
            // re-derived from the ticket's claims on each request.
            o.SaveTokens = false;
            o.Scope.Clear();
            foreach (var s in oidcSettings.Scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries))
                o.Scope.Add(s);
            o.Events = new OpenIdConnectEvents
            {
                // Enforce RequiredRoles and the root-collision guard at sign-in
                // so a rejected user never gets a session cookie at all.
                OnTokenValidated = ctx =>
                {
                    var mapped = ExternalUserMapper.Map(
                        ctx.Principal!,
                        new[] { oidcSettings.UsernameClaim, "upn", "email", "sub" },
                        oidcSettings.RoleClaim, oidcSettings.AdminRoles, oidcSettings.RequiredRoles);
                    if (mapped.Status != ExternalUserMapper.MapStatus.Success)
                        ctx.Fail($"SSO sign-in rejected: {mapped.Status}");
                    return Task.CompletedTask;
                },
                // Covers IdP errors, correlation failures, and our own Fail()
                // above — land back on the login page with a generic error.
                OnRemoteFailure = ctx =>
                {
                    ctx.Response.Redirect("/login.html?error=sso_failed");
                    ctx.HandleResponse();
                    return Task.CompletedTask;
                }
            };
        });
    }

    if (jwtSettings.Enabled)
    {
        authBuilder.AddJwtBearer(EntraBearerScheme, o =>
        {
            o.Authority = jwtSettings.Authority;
            o.MapInboundClaims = false;
            o.TokenValidationParameters.ValidAudiences = jwtSettings.Audiences;
            o.TokenValidationParameters.NameClaimType = jwtSettings.NameClaim;
            o.TokenValidationParameters.RoleClaimType = jwtSettings.RoleClaim;
        });
    }
}

// ── In-flight validation tracking ────────────────────────────────────────
var validationTracker = new ValidationTracker();
builder.Services.AddSingleton(validationTracker);

builder.Services.ConfigureHttpJsonOptions(opts =>
{
    opts.SerializerOptions.Converters.Add(new JsonStringEnumConverter());
    opts.SerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
});

// ── OpenAPI / Swagger ────────────────────────────────────────────────────
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "ednsv API",
        Version = "v1",
        Description = "Email/DNS validation service. All endpoints require "
            + "authentication when any auth method is enabled (token hash, OIDC "
            + "SSO, or JWT bearer). A browser signed in via token or SSO is "
            + "already authenticated here — its session cookie is sent with "
            + "\"Try it out\" requests automatically."
    });
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = "bearer",
        Description = "ednsv token issued via /api/auth/users, or an IdP-issued "
            + "OAuth2 access token (e.g. Entra ID client credentials) when "
            + "Auth:JwtBearer is enabled."
    });
    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        [new OpenApiSecurityScheme
        {
            Reference = new OpenApiReference
            {
                Type = ReferenceType.SecurityScheme,
                Id = "Bearer"
            }
        }] = Array.Empty<string>()
    });
});

var app = builder.Build();

// ── Load cache from disk at startup ──────────────────────────────────────
var cacheResult = await cacheManager.LoadAsync();
if (cacheResult != null)
    app.Logger.LogInformation("Loaded cache ({Total} entries, {Age:F0}m old): {Dns} DNS, {Smtp} SMTP, {Rcpt} RCPT, {Http} HTTP, {Ptr} PTR, {Port} port",
        cacheResult.Total, cacheResult.Age.TotalMinutes,
        cacheResult.DnsQueries, cacheResult.SmtpProbes, cacheResult.RcptProbes,
        cacheResult.HttpRequests, cacheResult.PtrLookups, cacheResult.PortProbes);

// Start periodic background flush
cacheManager.StartBackgroundFlusher(TimeSpan.FromSeconds(flushIntervalSeconds));

// Fail closed: an instance with NO auth method enabled (no token hash, no
// OIDC SSO, no JWT bearer) may only run when it is bound to loopback
// addresses (localhost) — never when reachable from the network.
if (!anyAuthEnabled && !IsLoopbackOnlyBinding(builder))
{
    app.Logger.LogCritical(
        "Refusing to start: no authentication method is enabled (EDNSV_AUTH_TOKEN_HASH=none, Auth:Oidc and Auth:JwtBearer disabled) but the server is bound to a non-loopback address. " +
        "Enable at least one auth method, or bind to localhost only (e.g. ASPNETCORE_URLS=http://127.0.0.1:5000).");
    throw new InvalidOperationException(
        "No authentication method is enabled but the server is network-exposed. Enable auth or bind to localhost only.");
}

if (!anyAuthEnabled)
    app.Logger.LogWarning("Authentication is DISABLED (EDNSV_AUTH_TOKEN_HASH=none, no external IdP configured) and the server is bound to localhost only. All endpoints are open to local callers.");
else
    app.Logger.LogInformation(
        "Authentication enabled — token auth: {Token}, OIDC SSO: {Oidc}, JWT bearer: {Jwt}. Auth data: {Path}",
        authService.Disabled ? "off" : $"on (root user '{AuthService.RootUsername}')",
        oidcSettings.Enabled ? $"on ({oidcSettings.Authority})" : "off",
        jwtSettings.Enabled ? $"on ({jwtSettings.Authority})" : "off",
        authDir);

if (oidcSettings.Enabled)
    app.Logger.LogInformation(
        "OIDC SSO callback paths: {Callback}, {SignedOut}. Behind a reverse proxy, serve over HTTPS and set ASPNETCORE_FORWARDEDHEADERS_ENABLED=true so the redirect URI and cookie security reflect the public scheme/host.",
        oidcSettings.CallbackPath, oidcSettings.SignedOutCallbackPath);

// Determines whether the configured Kestrel binding is loopback-only. Errs on the
// side of "exposed" (returns false) whenever the binding can't be proven local, so
// an auth-disabled instance only runs when it is definitely not network-reachable.
static bool IsLoopbackOnlyBinding(WebApplicationBuilder b)
{
    // ASPNETCORE_HTTP_PORTS / HTTPS_PORTS bind every interface (0.0.0.0 / [::]).
    if (!string.IsNullOrEmpty(Environment.GetEnvironmentVariable("ASPNETCORE_HTTP_PORTS"))
        || !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("ASPNETCORE_HTTPS_PORTS")))
        return false;

    // Explicit Kestrel endpoint config can bind anywhere; we don't parse it here,
    // so treat its presence as "exposed" to stay safe.
    if (b.Configuration.GetSection("Kestrel:Endpoints").GetChildren().Any())
        return false;

    var urls = b.Configuration["urls"]
        ?? Environment.GetEnvironmentVariable("ASPNETCORE_URLS")
        ?? b.Configuration["ASPNETCORE_URLS"];

    // No explicit binding → the .NET host default is http://localhost:5000 (+https:5001).
    if (string.IsNullOrWhiteSpace(urls))
        return true;

    foreach (var raw in urls.Split(new[] { ';', ',' }, StringSplitOptions.RemoveEmptyEntries))
    {
        if (!Uri.TryCreate(raw.Trim(), UriKind.Absolute, out var uri))
            return false; // unparseable → assume exposed
        var host = uri.Host.Trim('[', ']');
        var isLoopback = host.Equals("localhost", StringComparison.OrdinalIgnoreCase)
            || (IPAddress.TryParse(host, out var ip) && IPAddress.IsLoopback(ip));
        if (!isLoopback)
            return false;
    }
    return true;
}

// ── Per-request log scope ───────────────────────────────────────────────
// Every log line emitted while handling this request carries RequestId,
// Path, and Method. The auth middleware below adds Username on top once
// resolved. Validation endpoints layer JobId / Domain / Phase / Check
// inside that. With JSON logs, every line is grep-able by any of these.
var requestScopeLogger = app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("Ednsv.Request");
app.Use(async (ctx, next) =>
{
    using var scope = requestScopeLogger.BeginScope(
        "RequestId={RequestId} Method={Method} Path={Path}",
        ctx.TraceIdentifier, ctx.Request.Method, ctx.Request.Path.Value);
    await next();
});

// ── External auth handlers (OIDC callback + credential verification) ────
// UseAuthentication runs the OIDC remote handler, which consumes its own
// callback paths (/signin-oidc, /signout-callback-oidc) before the gate
// below ever sees them. It performs no authorization — the gate middleware
// remains the single enforcement point for every request.
if (externalAuthEnabled)
    app.UseAuthentication();

// ── Auth middleware ──────────────────────────────────────────────────────
// Runs before static files so the entire site requires credentials when enabled.
// Auth resolution order: ednsv-auth cookie → Authorization: Bearer (ednsv token,
// then IdP JWT) → Authorization: Basic → SSO session cookie.
// Public paths (login page + auth bootstrap endpoints) pass through without auth.
app.Use(async (ctx, next) =>
{
    if (!anyAuthEnabled)
    {
        // Marker read by RequireAdmin and /api/auth/me: a genuinely
        // unauthenticated (localhost-only) instance treats callers as admin.
        ctx.Items["AuthBypass"] = true;
        using var anonScope = requestScopeLogger.BeginScope("Username={Username}", "(auth-disabled)");
        await next();
        return;
    }

    var path = ctx.Request.Path.Value ?? "";
    if (path.Equals("/login.html", StringComparison.OrdinalIgnoreCase) ||
        path.Equals("/api/auth/login", StringComparison.OrdinalIgnoreCase) ||
        path.Equals("/api/auth/logout", StringComparison.OrdinalIgnoreCase) ||
        path.Equals("/api/auth/methods", StringComparison.OrdinalIgnoreCase) ||
        path.Equals("/api/auth/oidc/login", StringComparison.OrdinalIgnoreCase) ||
        (oidcSettings.Enabled &&
         (path.Equals(oidcSettings.CallbackPath, StringComparison.OrdinalIgnoreCase) ||
          path.Equals(oidcSettings.SignedOutCallbackPath, StringComparison.OrdinalIgnoreCase))))
    {
        using var anonScope = requestScopeLogger.BeginScope("Username={Username}", "(anonymous)");
        await next();
        return;
    }

    AuthService.User? user = null;
    string? authMethod = null;

    if (!authService.Disabled &&
        ctx.Request.Cookies.TryGetValue("ednsv-auth", out var cookieToken) && !string.IsNullOrEmpty(cookieToken))
    {
        user = authService.AuthenticateBearer(cookieToken);
        if (user != null) authMethod = "token";
    }

    if (user == null)
    {
        string? raw = ctx.Request.Headers.Authorization;
        if (!string.IsNullOrEmpty(raw))
        {
            if (raw.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                var bearer = raw["Bearer ".Length..].Trim();
                // ednsv tokens are 43-char base64url (no dots) — the hash
                // lookup cheaply rejects JWTs before the JWT handler runs.
                if (!authService.Disabled)
                {
                    user = authService.AuthenticateBearer(bearer);
                    if (user != null) authMethod = "token";
                }
                if (user == null && jwtSettings.Enabled)
                {
                    var jwtResult = await ctx.AuthenticateAsync(EntraBearerScheme);
                    if (jwtResult.Succeeded)
                    {
                        var mapped = ExternalUserMapper.Map(
                            jwtResult.Principal,
                            new[] { jwtSettings.NameClaim, "appid" },
                            jwtSettings.RoleClaim, jwtSettings.AdminRoles, jwtSettings.RequiredRoles,
                            usernamePrefix: "app:");
                        if (mapped.Status == ExternalUserMapper.MapStatus.Success)
                        {
                            user = mapped.User;
                            authMethod = "jwt";
                        }
                    }
                }
            }
            else if (!authService.Disabled && raw.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(raw["Basic ".Length..].Trim()));
                    var idx = decoded.IndexOf(':');
                    if (idx >= 0)
                        user = authService.AuthenticateBasic(decoded[..idx], decoded[(idx + 1)..]);
                    if (user != null) authMethod = "token";
                }
                catch (FormatException) { /* bad base64 → treat as unauth */ }
            }
        }
    }

    if (user == null && oidcSettings.Enabled)
    {
        var session = await ctx.AuthenticateAsync(SessionScheme);
        if (session.Succeeded)
        {
            // Re-map claims on every request (rather than trusting values
            // frozen into the ticket) so AdminRoles/RequiredRoles config
            // changes take effect on restart without forcing re-login.
            var mapped = ExternalUserMapper.Map(
                session.Principal,
                new[] { oidcSettings.UsernameClaim, "upn", "email", "sub" },
                oidcSettings.RoleClaim, oidcSettings.AdminRoles, oidcSettings.RequiredRoles);
            if (mapped.Status == ExternalUserMapper.MapStatus.Success)
            {
                user = mapped.User;
                authMethod = "oidc";
            }
        }
    }

    if (user == null)
    {
        ctx.Response.Headers.CacheControl = "no-store";
        var accept = ctx.Request.Headers.Accept.ToString();
        if (accept.Contains("text/html", StringComparison.OrdinalIgnoreCase))
        {
            // Browser navigation → redirect to login page
            ctx.Response.Redirect("/login.html");
            return;
        }
        ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
        ctx.Response.Headers.Append("WWW-Authenticate", "Bearer realm=\"ednsv\"");
        await ctx.Response.WriteAsJsonAsync(new { error = "unauthorized" });
        return;
    }

    ctx.Items["AuthUser"] = user;
    ctx.Items["AuthMethod"] = authMethod;

    using var userScope = requestScopeLogger.BeginScope(
        "Username={Username} IsAdmin={IsAdmin}",
        user.Username, user.IsAdmin);

    // Admin-only static pages: gate /config.html before static files serve it.
    var pathLower = (ctx.Request.Path.Value ?? "").ToLowerInvariant();
    if (pathLower == "/config.html" && !user.IsAdmin)
    {
        ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
        await ctx.Response.WriteAsync("Forbidden: admin only");
        return;
    }

    await next();
});

// ── Swagger UI (auth-gated by the middleware above) ──────────────────────
app.UseSwagger();
app.UseSwaggerUI(c =>
{
    c.SwaggerEndpoint("/swagger/v1/swagger.json", "ednsv API v1");
    c.DocumentTitle = "ednsv API";
});

// ── Static files (wwwroot/index.html) ────────────────────────────────────
app.UseDefaultFiles();
app.UseStaticFiles();

// ── API endpoints ────────────────────────────────────────────────────────

// POST /api/validate  { "domain": "example.com" }
// Starts an async validation and returns a job ID.
app.MapPost("/api/validate", (HttpContext httpCtx, ValidateRequest req, ValidationTracker tracker,
    DnsResolverService dnsSvc, SmtpProbeService smtpSvc, HttpProbeService httpSvc,
    CacheManager cache, ILogger<Program> logger) =>
{
    var domain = req.Domain?.Trim().TrimEnd('.').ToLowerInvariant();
    if (string.IsNullOrEmpty(domain))
        return Results.BadRequest(new { error = "domain is required" });
    if (!IsPlausibleDomain(domain))
        return Results.BadRequest(new { error = "invalid domain" });

    var username = (httpCtx.Items["AuthUser"] as AuthService.User)?.Username;

    CheckSeverity? recheckSeverity = null;
    if (!string.IsNullOrEmpty(req.RecheckSeverity) &&
        Enum.TryParse<CheckSeverity>(req.RecheckSeverity, ignoreCase: true, out var parsed))
        recheckSeverity = parsed;

    // Config supplies defaults only — the request body wins. When the client
    // omits Options entirely we fall back to the config snapshot wholesale;
    // when the client sends Options we trust them as authoritative for the
    // network-category toggles. Per-domain DKIM selectors and the global
    // default DKIM list are still pulled from config when the request hasn't
    // supplied any (clients can override via AdditionalDkimSelectors /
    // ForceDkimSelectors).
    var defaults = BuildDefaultOptions();
    var options = req.Options ?? defaults;
    if (!options.AdditionalDkimSelectors.Any() && defaults.AdditionalDkimSelectors.Any())
        options.AdditionalDkimSelectors = defaults.AdditionalDkimSelectors;
    if (options.PerDomainDkimSelectors.Count == 0)
        options.PerDomainDkimSelectors = defaults.PerDomainDkimSelectors;

    var jobId = tracker.StartValidation(domain, dnsSvc, smtpSvc, httpSvc, options, cache, logger, recheckSeverity, enableTrace, traceMasker, username);
    return Results.Accepted($"/api/status/{jobId}", new { jobId, domain, status = "running" });
})
.WithName("StartValidation")
.WithTags("Validation");

// GET /api/status/{jobId}
// Returns the current status and results (if complete) for a validation job.
app.MapGet("/api/status/{jobId}", (string jobId, ValidationTracker tracker) =>
{
    if (!tracker.TryGetJob(jobId, out var job))
        return Results.NotFound(new { error = "Job not found" });

    return Results.Ok(new
    {
        jobId,
        job!.Domain,
        status = job.Status.ToString().ToLowerInvariant(),
        currentCheck = job.CurrentCheck,
        completedChecks = job.CompletedChecks,
        results = new
        {
            pass = job.PassCount,
            info = job.InfoCount,
            warning = job.WarningCount,
            error = job.ErrorCount,
            critical = job.CriticalCount
        },
        dns = job.Dns != null ? new
        {
            queries = (job.Dns.CacheHits - job.DnsHitsBaseline) + (job.Dns.CacheMisses - job.DnsMissesBaseline),
            cacheHits = job.Dns.CacheHits - job.DnsHitsBaseline,
            sent = job.Dns.CacheMisses - job.DnsMissesBaseline,
            received = job.Dns.ResponsesReceived - job.DnsResponsesBaseline,
            totalCacheHits = job.Dns.CacheHits,
            totalCacheMisses = job.Dns.CacheMisses,
            totalCacheSize = job.Dns.CacheSize
        } : null,
        smtp = job.Smtp != null ? new
        {
            probesStarted = job.Smtp.ProbesStarted - job.SmtpProbesStartedBaseline,
            probesDone = job.Smtp.ProbesCompleted - job.SmtpProbesCompletedBaseline,
            portsStarted = job.Smtp.PortsStarted - job.PortsStartedBaseline,
            portsDone = job.Smtp.PortsCompleted - job.PortsCompletedBaseline
        } : null,
        elapsed = (DateTime.UtcNow - job.StartedAt).TotalSeconds,
        duration = job.Report?.Duration.TotalSeconds,
        report = job.Report,
        error = job.Error
    });
})
.WithName("GetValidationStatus")
.WithTags("Validation");

// GET /api/validate/{domain}
// Synchronous convenience endpoint — runs validation and returns the full report.
// Times out after 3 minutes.
//
// Query parameters mirror the CLI flags so the GET form is as flexible as POST:
//   ?recheck=warning|error|critical     bypass cache for matching prior issues
//   ?noSmtp=true                        skip SMTP probes (--no-smtp)
//   ?noHttp=true                        skip HTTP/HTTPS probes (--no-http)
//   ?noDnsbl=true                       skip DNSBL queries (--no-dnsbl)
//   ?noDirectDns=true                   skip checks that talk directly to nameservers / public resolvers
//   ?noDoh=true                         force the propagation check to use raw UDP/53 even when DoH is enabled
//   ?restricted=true                    preset: noSmtp + noHttp + noDnsbl + noDirectDns
//   ?dkimSelectors=a,b,c                replace built-in DKIM selectors
//   ?axfr=true                          enable AXFR test
//   ?catchAll=true                      enable catch-all detection
//   ?openRelay=true                     enable open-relay test
//   ?openResolver=true                  enable open-resolver test
//   ?privateDnsbl=true                  include private/registered DNSBLs
app.MapGet("/api/validate/{domain}", async (HttpContext httpCtx, string domain, string? recheck,
    DnsResolverService dnsSvc, SmtpProbeService smtpSvc, HttpProbeService httpSvc,
    CacheManager cache, ILogger<Program> logger, CancellationToken ct) =>
{
    domain = domain.Trim().TrimEnd('.').ToLowerInvariant();
    if (string.IsNullOrEmpty(domain))
        return Results.BadRequest(new { error = "domain is required" });
    if (!IsPlausibleDomain(domain))
        return Results.BadRequest(new { error = "invalid domain" });

    var requestId = httpCtx.TraceIdentifier;
    var username = (httpCtx.Items["AuthUser"] as AuthService.User)?.Username;
    var displayDomain = traceMasker != null ? traceMasker.Hash(domain) : domain;

    using var requestScope = logger.BeginScope(
        "RequestId={RequestId} Username={Username} Endpoint={Endpoint} Domain={Domain}",
        requestId, username, "validateDomainSync", displayDomain);

    var validator = new DomainValidator(dnsSvc, smtpSvc, httpSvc);
    if (traceMasker != null) validator.TraceMask = traceMasker;
    if (enableTrace) validator.Trace = msg =>
    {
        using var traceScope = logger.BeginScope(
            "Phase={Phase} Check={Check}",
            TraceContext.Phase, TraceContext.Check);
        logger.LogDebug("{Trace}", msg);
    };

    if (!string.IsNullOrEmpty(recheck) &&
        Enum.TryParse<CheckSeverity>(recheck, ignoreCase: true, out var recheckSev))
        validator.RecheckDeps = cache.GetRecheckDeps(domain, recheckSev);

    // Build per-request options, starting from the live config snapshot so
    // admin-pinned categories stay disabled regardless of query-string input
    // (AND-logic) and per-domain DKIM config is honoured.
    var defaults = BuildDefaultOptions();
    bool ParseBool(string name) =>
        bool.TryParse(httpCtx.Request.Query[name].ToString(), out var v) && v;
    var restricted = ParseBool("restricted");
    var options = new ValidationOptions
    {
        EnableSmtpProbes = defaults.EnableSmtpProbes && !restricted && !ParseBool("noSmtp"),
        EnableHttpProbes = defaults.EnableHttpProbes && !restricted && !ParseBool("noHttp"),
        EnableDnsbl      = defaults.EnableDnsbl      && !restricted && !ParseBool("noDnsbl"),
        EnableDirectDns  = defaults.EnableDirectDns  && !restricted && !ParseBool("noDirectDns"),
        EnableDoh        = defaults.EnableDoh        && !ParseBool("noDoh"),
        EnableAxfr         = ParseBool("axfr"),
        EnableCatchAll     = ParseBool("catchAll"),
        EnableOpenRelay    = ParseBool("openRelay"),
        EnableOpenResolver = ParseBool("openResolver"),
        EnablePrivateDnsbl = ParseBool("privateDnsbl"),
        ForceDkimSelectors = ParseBool("forceDkimSelectors"),
        AdditionalDkimSelectors = defaults.AdditionalDkimSelectors,
        PerDomainDkimSelectors  = defaults.PerDomainDkimSelectors
    };
    var dkimRaw = httpCtx.Request.Query["dkimSelectors"].ToString();
    if (!string.IsNullOrWhiteSpace(dkimRaw))
        options.AdditionalDkimSelectors = dkimRaw
            .Split(new[] { ',', ' ' }, StringSplitOptions.RemoveEmptyEntries)
            .Select(s => s.Trim()).Where(s => s.Length > 0).ToList();

    using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
    cts.CancelAfter(TimeSpan.FromMinutes(3));

    try
    {
        var report = await validator.ValidateAsync(domain, options);
        _ = cache.SaveDomainResultAsync(domain, ValidationTracker.BuildSummary(report));
        cache.RequestFlush();
        return Results.Ok(report);
    }
    catch (OperationCanceledException)
    {
        return Results.StatusCode(504);
    }
})
.WithName("ValidateDomainSync")
.WithTags("Validation");

// GET /api/cache/stats
app.MapGet("/api/cache/stats", (DnsResolverService dnsSvc) =>
{
    return Results.Ok(new
    {
        dnsCacheSize = dnsSvc.CacheSize,
        dnsCacheHits = dnsSvc.CacheHits,
        dnsCacheMisses = dnsSvc.CacheMisses
    });
})
.WithName("GetCacheStats")
.WithTags("Cache");

// POST /api/cache/flush
app.MapPost("/api/cache/flush", async (CacheManager cache) =>
{
    await cache.FlushAsync();
    return Results.Ok(new { flushed = true });
})
.WithName("FlushCache")
.WithTags("Cache");

// GET /api/checks
app.MapGet("/api/checks", () => Results.Ok(CheckDescriptions.Categories))
    .WithName("ListChecks")
    .WithTags("Meta");

// GET /api/defaults — surface server-side defaults the UI needs to pre-fill
// the validation form (default DKIM list and the per-domain overrides map so
// the UI can hide/show the Force-selectors checkbox per domain).
app.MapGet("/api/defaults", (ConfigService cfgSvc) =>
{
    var cfg = cfgSvc.Snapshot();
    return Results.Ok(new
    {
        enableSmtpProbes = cfg.EnableSmtpProbes,
        enableHttpProbes = cfg.EnableHttpProbes,
        enableDnsbl      = cfg.EnableDnsbl,
        enableDirectDns  = cfg.EnableDirectDns,
        dkimSelectors    = cfg.DefaultDkimSelectors.Count > 0
            ? cfg.DefaultDkimSelectors
            : DkimSelectorsCheck.CommonSelectors.ToList(),
        perDomainDkimSelectors = cfg.DkimSelectors,
        knownDomains     = cfg.KnownDomains
    });
})
.WithName("GetDefaults")
.WithTags("Meta");

// ── Config endpoints (admin-only) ────────────────────────────────────────

static bool RequireAdmin(HttpContext ctx, AuthService auth, out IResult? error)
{
    error = null;
    // Only a truly unauthenticated (localhost-only) instance treats all callers
    // as admin. auth.Disabled alone is NOT sufficient: with token auth off but
    // SSO/JWT on, callers are real authenticated users who must hold the role.
    if (ctx.Items.ContainsKey("AuthBypass")) return true;
    var u = (AuthService.User?)ctx.Items["AuthUser"];
    if (u == null || !u.IsAdmin)
    {
        error = Results.StatusCode(StatusCodes.Status403Forbidden);
        return false;
    }
    return true;
}

// GET /api/config — return the current persisted config.
app.MapGet("/api/config", (HttpContext ctx, AuthService auth, ConfigService cfgSvc) =>
{
    if (!RequireAdmin(ctx, auth, out var err)) return err!;
    return Results.Ok(cfgSvc.Snapshot());
})
.WithName("GetConfig")
.WithTags("Config");

// PUT /api/config — replace the config and persist to disk.
app.MapPut("/api/config", async (HttpContext ctx, AuthService auth, ConfigService cfgSvc) =>
{
    if (!RequireAdmin(ctx, auth, out var err)) return err!;
    AppConfig? incoming;
    try
    {
        incoming = await ctx.Request.ReadFromJsonAsync<AppConfig>();
    }
    catch (JsonException ex)
    {
        return Results.BadRequest(new { error = $"invalid JSON: {ex.Message}" });
    }
    if (incoming == null) return Results.BadRequest(new { error = "body is required" });
    // Attribute the change to the caller (or "(auth-disabled)" on a bypass
    // instance) so each saved revision records who made it.
    var savedBy = ctx.Items.ContainsKey("AuthBypass")
        ? "(auth-disabled)"
        : ((AuthService.User?)ctx.Items["AuthUser"])?.Username ?? "unknown";
    cfgSvc.Replace(incoming, savedBy);
    return Results.Ok(cfgSvc.Snapshot());
})
.WithName("UpdateConfig")
.WithTags("Config");

// GET /api/config/history — revision metadata (id, savedAt, savedBy), newest first.
app.MapGet("/api/config/history", (HttpContext ctx, AuthService auth, ConfigService cfgSvc) =>
{
    if (!RequireAdmin(ctx, auth, out var err)) return err!;
    return Results.Ok(cfgSvc.ListRevisions());
})
.WithName("GetConfigHistory")
.WithTags("Config");

// GET /api/config/history/{id} — the config saved in a specific revision.
app.MapGet("/api/config/history/{id:int}", (int id, HttpContext ctx, AuthService auth, ConfigService cfgSvc) =>
{
    if (!RequireAdmin(ctx, auth, out var err)) return err!;
    var cfg = cfgSvc.GetRevision(id);
    return cfg == null ? Results.NotFound(new { error = "revision not found" }) : Results.Ok(cfg);
})
.WithName("GetConfigRevision")
.WithTags("Config");

// ── Debug / diagnostics (admin-only) ─────────────────────────────────────

// GET /api/debug/proxy?url=https://example.com/foo
// Reports what HttpClient.DefaultProxy resolves for the given URL plus the
// proxy-related env vars actually visible to the running process, AND
// performs a real GET so the caller can see the actual status code,
// response headers, timing, and any exception. Useful when "(HTTP 0)"
// failures suggest the proxy env vars aren't being picked up — e.g.
// NO_PROXY is suffix-matching the host, the vars were set after the
// process started, the proxy itself is unreachable, or TLS interception
// is breaking the handshake.
app.MapGet("/api/debug/proxy", async (HttpContext ctx, AuthService auth, string? url) =>
{
    // This endpoint is a deliberate outbound-fetch diagnostic. It is only ever
    // available when authentication is enabled AND the caller is an admin — never
    // on an auth-bypass instance (where RequireAdmin treats everyone as admin),
    // so it can't become an open SSRF surface on an unauthenticated instance.
    if (ctx.Items.ContainsKey("AuthBypass")) return Results.NotFound();
    if (!RequireAdmin(ctx, auth, out var err)) return err!;
    if (string.IsNullOrEmpty(url) || !Uri.TryCreate(url, UriKind.Absolute, out var u))
        return Results.BadRequest(new { error = "url must be an absolute URI, e.g. ?url=https://example.com/foo" });

    Uri? proxyUri = null;
    bool bypassed = false;
    string? proxyError = null;
    try
    {
        proxyUri = HttpClient.DefaultProxy.GetProxy(u);
        bypassed = HttpClient.DefaultProxy.IsBypassed(u);
    }
    catch (Exception ex)
    {
        proxyError = $"{ex.GetType().Name}: {ex.Message}";
    }

    string? Pick(params string[] names) =>
        names.Select(Environment.GetEnvironmentVariable).FirstOrDefault(v => !string.IsNullOrEmpty(v));

    // Use a dictionary so the JSON serializer's camelCase policy doesn't
    // rewrite the env-var keys (HTTPS_PROXY → httpS_PROXY etc.).
    var envSeenByProcess = new Dictionary<string, string?>
    {
        ["HTTPS_PROXY"] = Pick("HTTPS_PROXY", "https_proxy"),
        ["HTTP_PROXY"]  = Pick("HTTP_PROXY", "http_proxy"),
        ["ALL_PROXY"]   = Pick("ALL_PROXY", "all_proxy"),
        ["NO_PROXY"]    = Pick("NO_PROXY", "no_proxy")
    };

    // Actually retrieve the URL through a default HttpClient so the same
    // proxy resolution that HttpProbeService sees is exercised here.
    int statusCode = 0;
    string? statusReason = null;
    string? httpVersion = null;
    long? contentLength = null;
    long? bodyBytesRead = null;
    var responseHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    string? fetchError = null;
    long elapsedMs = 0;

    var sw = System.Diagnostics.Stopwatch.StartNew();
    try
    {
        using var handler = new HttpClientHandler();
        using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(15) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd("ednsv-debug/1.0");
        using var resp = await http.GetAsync(u, HttpCompletionOption.ResponseHeadersRead, ctx.RequestAborted);
        statusCode = (int)resp.StatusCode;
        statusReason = resp.ReasonPhrase;
        httpVersion = resp.Version.ToString();
        contentLength = resp.Content.Headers.ContentLength;

        foreach (var h in resp.Headers)
            responseHeaders[h.Key] = string.Join(", ", h.Value);
        foreach (var h in resp.Content.Headers)
            responseHeaders[h.Key] = string.Join(", ", h.Value);

        // Drain a small slice of the body so timing/error reflects the
        // full request — capped to avoid pulling large payloads.
        const int MaxBodyBytes = 4096;
        await using var stream = await resp.Content.ReadAsStreamAsync(ctx.RequestAborted);
        var buf = new byte[MaxBodyBytes];
        long total = 0;
        int n;
        while ((n = await stream.ReadAsync(buf.AsMemory(0, buf.Length), ctx.RequestAborted)) > 0)
        {
            total += n;
            if (total >= MaxBodyBytes) break;
        }
        bodyBytesRead = total;
    }
    catch (Exception ex)
    {
        var inner = ex.InnerException is null ? "" : $" → {ex.InnerException.GetType().Name}: {ex.InnerException.Message}";
        fetchError = $"{ex.GetType().Name}: {ex.Message}{inner}";
    }
    finally
    {
        sw.Stop();
        elapsedMs = sw.ElapsedMilliseconds;
    }

    return Results.Ok(new
    {
        target = u.ToString(),
        proxyResolved = proxyUri?.ToString(),
        bypassed,
        proxyError,
        envSeenByProcess,
        fetch = new
        {
            statusCode,
            statusReason,
            httpVersion,
            contentLength,
            bodyBytesRead,
            elapsedMs,
            error = fetchError,
            headers = responseHeaders
        },
        notes = new[]
        {
            "proxyResolved == target URL itself means HttpClient is going direct (no proxy applied).",
            "bypassed=true means NO_PROXY matched — entries starting with '.' suffix-match.",
            "Env vars listed here are what THIS process sees right now; if they differ from your shell, the process didn't inherit them.",
            "DefaultProxy is initialised once on first use; vars set AFTER the process started are not picked up.",
            "fetch.statusCode=0 with a non-null fetch.error means the request never produced an HTTP response — typically proxy/DNS/TLS failure. Check fetch.error for the reason.",
            "fetch.headers reflects what the server (or proxy) actually returned; a Via or X-Cache header often confirms the proxy was traversed."
        }
    });
})
.WithName("DebugProxy")
.WithTags("Debug");

// ── Auth endpoints ───────────────────────────────────────────────────────

// GET /api/auth/methods — which sign-in methods are available (public: the
// login page needs this before the user has any credentials).
app.MapGet("/api/auth/methods", (AuthService auth) =>
    Results.Ok(new { tokenAuth = !auth.Disabled, sso = oidcSettings.Enabled }))
.WithName("GetAuthMethods")
.WithTags("Auth");

// GET /api/auth/me — current user info (or { disabled: true } when no auth
// method is enabled at all).
app.MapGet("/api/auth/me", (HttpContext ctx, AuthService auth) =>
{
    if (ctx.Items.ContainsKey("AuthBypass"))
        return Results.Ok(new { disabled = true, isAdmin = true, isRoot = false, tokenAuthEnabled = false, authMethod = (string?)null, singleLogout = false });
    var u = (AuthService.User?)ctx.Items["AuthUser"];
    var isRoot = u?.Username.Equals(AuthService.RootUsername, StringComparison.OrdinalIgnoreCase) ?? false;
    return Results.Ok(new
    {
        disabled = false,
        username = u?.Username,
        isAdmin = u?.IsAdmin ?? false,
        isRoot,
        tokenAuthEnabled = !auth.Disabled,
        authMethod = ctx.Items["AuthMethod"] as string,
        singleLogout = oidcSettings.Enabled && oidcSettings.SingleLogout
    });
})
.WithName("GetCurrentUser")
.WithTags("Auth");

// POST /api/auth/login — exchange username + token for an HttpOnly session cookie.
app.MapPost("/api/auth/login", (LoginRequest req, HttpContext ctx, AuthService auth) =>
{
    if (auth.Disabled) return Results.BadRequest(new { error = "token auth is disabled" });
    if (string.IsNullOrEmpty(req.Username) || string.IsNullOrEmpty(req.Token))
        return Results.BadRequest(new { error = "username and token are required" });

    var user = auth.AuthenticateBasic(req.Username, req.Token);
    if (user == null)
    {
        return Results.Json(new { error = "invalid credentials" }, statusCode: StatusCodes.Status401Unauthorized);
    }

    ctx.Response.Cookies.Append("ednsv-auth", req.Token, new CookieOptions
    {
        HttpOnly = true,
        SameSite = SameSiteMode.Strict,
        Secure = ctx.Request.IsHttps,
        Path = "/",
        MaxAge = TimeSpan.FromDays(30)
    });
    return Results.Ok(new { username = user.Username, isAdmin = user.IsAdmin });
})
.WithName("Login")
.WithTags("Auth");

// POST /api/auth/logout — clears the token cookie and any SSO session.
app.MapPost("/api/auth/logout", async (HttpContext ctx) =>
{
    ctx.Response.Cookies.Delete("ednsv-auth", new CookieOptions { Path = "/" });
    if (oidcSettings.Enabled)
        await ctx.SignOutAsync(SessionScheme);
    return Results.Ok(new { ok = true });
})
.WithName("Logout")
.WithTags("Auth");

// GET /api/auth/oidc/login — start the interactive SSO flow. Public; lands on
// ?next= (same-origin path only) after the IdP round-trip.
app.MapGet("/api/auth/oidc/login", (HttpContext ctx, string? next) =>
{
    if (!oidcSettings.Enabled) return Results.NotFound();
    var target = next != null && next.StartsWith('/') && !next.StartsWith("//") ? next : "/";
    return Results.Challenge(new AuthenticationProperties { RedirectUri = target }, new[] { OidcScheme });
})
.WithName("OidcLogin")
.WithTags("Auth");

// GET /api/auth/oidc/logout — single logout: end the local session AND the
// IdP session via the front-channel end-session redirect. Only exposed when
// Auth:Oidc:SingleLogout is enabled; the default logout is local-only.
app.MapGet("/api/auth/oidc/logout", (HttpContext ctx) =>
{
    if (!oidcSettings.Enabled || !oidcSettings.SingleLogout) return Results.NotFound();
    ctx.Response.Cookies.Delete("ednsv-auth", new CookieOptions { Path = "/" });
    return Results.SignOut(new AuthenticationProperties { RedirectUri = "/login.html" },
        new[] { SessionScheme, OidcScheme });
})
.WithName("OidcLogout")
.WithTags("Auth");

// GET /api/auth/users — list users visible to the caller (descendants; root sees all).
app.MapGet("/api/auth/users", (HttpContext ctx, AuthService auth) =>
{
    if (auth.Disabled) return Results.Ok(new { disabled = true, users = Array.Empty<object>() });
    var u = (AuthService.User)ctx.Items["AuthUser"]!;
    var list = auth.ListVisibleTo(u.Username);
    var isRoot = u.Username.Equals(AuthService.RootUsername, StringComparison.OrdinalIgnoreCase);
    return Results.Ok(new
    {
        disabled = false,
        currentUser = u.Username,
        isAdmin = u.IsAdmin,
        isRoot,
        users = list.Select(x => new
        {
            x.Username,
            x.IsAdmin,
            x.IssuedBy,
            x.IssuedAt,
            x.IssuedFromIp,
            x.Revoked,
            x.RevokedAt,
            x.RevokedBy
        })
    });
})
.WithName("ListUsers")
.WithTags("Auth");

// POST /api/auth/users — issue a new token. Returns the raw token exactly once.
app.MapPost("/api/auth/users", (IssueTokenRequest req, HttpContext ctx, AuthService auth) =>
{
    if (auth.Disabled) return Results.BadRequest(new { error = "token auth is disabled" });
    var u = (AuthService.User)ctx.Items["AuthUser"]!;
    if (!u.IsAdmin) return Results.StatusCode(StatusCodes.Status403Forbidden);

    var ip = ctx.Connection.RemoteIpAddress?.ToString();
    var result = auth.Issue(req.Username ?? "", req.IsAdmin, u.Username, ip);
    return result.Status switch
    {
        AuthService.IssueStatus.Success => Results.Ok(new
        {
            token = result.Token,
            user = new
            {
                result.User!.Username,
                result.User.IsAdmin,
                result.User.IssuedBy,
                result.User.IssuedAt,
                result.User.IssuedFromIp
                // NOTE: the stored token hash (the verifier) is deliberately NOT
                // returned. The raw one-time token above is the only secret the
                // caller needs; echoing the hash would expose a credential-equivalent.
            }
        }),
        AuthService.IssueStatus.UsernameTaken => Results.Conflict(new { error = "username taken" }),
        AuthService.IssueStatus.InvalidUsername => Results.BadRequest(new { error = "invalid username (allowed: letters, digits, '.', '_', '-', max 64 chars)" }),
        _ => Results.BadRequest(new { error = "issue failed" })
    };
})
.WithName("IssueToken")
.WithTags("Auth");

// POST /api/auth/users/{username}/revoke — cascade-revoke target and descendants.
app.MapPost("/api/auth/users/{username}/revoke", (string username, HttpContext ctx, AuthService auth) =>
{
    if (auth.Disabled) return Results.BadRequest(new { error = "token auth is disabled" });
    var u = (AuthService.User)ctx.Items["AuthUser"]!;
    // External-IdP admins (SSO / JWT) sit outside the issuance tree and may
    // revoke any token except the config root user; token admins stay scoped
    // to their own issuance subtree.
    var method = ctx.Items["AuthMethod"] as string;
    var elevated = u.IsAdmin && (method == "oidc" || method == "jwt");
    var result = auth.Revoke(username, u.Username, elevated);
    return result.Status switch
    {
        AuthService.RevokeStatus.Success => Results.Ok(new { revoked = result.Affected }),
        AuthService.RevokeStatus.AlreadyRevoked => Results.Ok(new { revoked = Array.Empty<string>(), note = "already revoked" }),
        AuthService.RevokeStatus.NotFound => Results.NotFound(new { error = "user not found" }),
        AuthService.RevokeStatus.NotAllowed => Results.StatusCode(StatusCodes.Status403Forbidden),
        _ => Results.BadRequest(new { error = "revoke failed" })
    };
})
.WithName("RevokeUser")
.WithTags("Auth");

// DELETE /api/auth/users/{username} — root-only permanent removal of a revoked user.
app.MapDelete("/api/auth/users/{username}", (string username, HttpContext ctx, AuthService auth) =>
{
    if (auth.Disabled) return Results.BadRequest(new { error = "token auth is disabled" });
    var u = (AuthService.User)ctx.Items["AuthUser"]!;
    var result = auth.Delete(username, u.Username);
    return result.Status switch
    {
        AuthService.DeleteStatus.Success => Results.Ok(new { deleted = result.Affected }),
        AuthService.DeleteStatus.NotFound => Results.NotFound(new { error = "user not found" }),
        AuthService.DeleteStatus.NotAllowed => Results.StatusCode(StatusCodes.Status403Forbidden),
        AuthService.DeleteStatus.NotRevoked => Results.BadRequest(new { error = "user is not revoked; revoke first" }),
        _ => Results.BadRequest(new { error = "delete failed" })
    };
})
.WithName("DeleteUser")
.WithTags("Auth");

app.Run();

// ── Supporting types ─────────────────────────────────────────────────────

record ValidateRequest(string? Domain, ValidationOptions? Options = null, string? RecheckSeverity = null);

record IssueTokenRequest(string? Username, bool IsAdmin);

record LoginRequest(string? Username, string? Token);

enum JobStatus { Running, Completed, Failed }

class ValidationJob
{
    public string Domain { get; set; } = "";
    // Fields read by status endpoint, written by background task.
    // volatile ensures cross-thread visibility without locks.
    private volatile string? _currentCheck;
    private volatile int _status = (int)JobStatus.Running;
    private volatile ValidationReport? _report;
    private volatile string? _error;
    public string? CurrentCheck { get => _currentCheck; set => _currentCheck = value; }
    public JobStatus Status { get => (JobStatus)_status; set => _status = (int)value; }
    public ValidationReport? Report { get => _report; set => _report = value; }
    public string? Error { get => _error; set => _error = value; }
    public int CompletedChecks;
    public DateTime StartedAt { get; set; } = DateTime.UtcNow;
    // References to services for live stats (read-only, shared singletons)
    public DnsResolverService? Dns { get; set; }
    public SmtpProbeService? Smtp { get; set; }
    // Baseline snapshots taken at job start — deltas computed at read time
    public int DnsHitsBaseline;
    public int DnsMissesBaseline;
    public int DnsResponsesBaseline;
    public int SmtpProbesStartedBaseline;
    public int SmtpProbesCompletedBaseline;
    public int PortsStartedBaseline;
    public int PortsCompletedBaseline;
    // Live severity counts — updated as each check result arrives
    public int PassCount;
    public int InfoCount;
    public int WarningCount;
    public int ErrorCount;
    public int CriticalCount;

    public void SnapshotBaselines()
    {
        if (Dns != null)
        {
            DnsHitsBaseline = Dns.CacheHits;
            DnsMissesBaseline = Dns.CacheMisses;
            DnsResponsesBaseline = Dns.ResponsesReceived;
        }
        if (Smtp != null)
        {
            SmtpProbesStartedBaseline = Smtp.ProbesStarted;
            SmtpProbesCompletedBaseline = Smtp.ProbesCompleted;
            PortsStartedBaseline = Smtp.PortsStarted;
            PortsCompletedBaseline = Smtp.PortsCompleted;
        }
    }
}

class ValidationTracker : IDisposable
{
    private readonly ConcurrentDictionary<string, ValidationJob> _jobs = new();
    private readonly Timer _cleanupTimer;
    private static readonly TimeSpan _jobRetention = TimeSpan.FromHours(1);
    // Hard cap for jobs still marked Running. A validation is bounded by its own
    // check timeouts (45s + 30s retry) and the caller's request lifetime, so a job
    // that is still "running" well past this is stuck/abandoned and must not leak.
    private static readonly TimeSpan _runningJobMaxAge = TimeSpan.FromHours(2);

    public ValidationTracker()
    {
        _cleanupTimer = new Timer(_ => Cleanup(), null,
            TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(5));
    }

    private void Cleanup()
    {
        var now = DateTime.UtcNow;
        var cutoff = now - _jobRetention;
        var runningCutoff = now - _runningJobMaxAge;
        foreach (var kvp in _jobs)
        {
            var job = kvp.Value;
            // Evict finished jobs after the retention window, and stuck/abandoned
            // Running jobs after a hard maximum age so they can't accumulate.
            if ((job.Status != JobStatus.Running && job.StartedAt < cutoff)
                || (job.Status == JobStatus.Running && job.StartedAt < runningCutoff))
                _jobs.TryRemove(kvp.Key, out _);
        }
    }

    public void Dispose() => _cleanupTimer.Dispose();

    public string StartValidation(string domain, DnsResolverService dns,
        SmtpProbeService smtp, HttpProbeService http, ValidationOptions? options,
        CacheManager cache, ILogger logger, CheckSeverity? recheckSeverity = null,
        bool trace = false, TraceMasker? traceMasker = null,
        string? username = null)
    {
        var jobId = Guid.NewGuid().ToString("N")[..12];
        var job = new ValidationJob { Domain = domain, Dns = dns, Smtp = smtp };
        _jobs[jobId] = job;

        // Domain in logs/scopes is masked when masking is enabled. JobId and
        // Username are deliberately NOT masked (they're identifiers, not PII
        // like the validated target).
        var displayDomain = traceMasker != null ? traceMasker.Hash(domain) : domain;

        _ = Task.Run(async () =>
        {
            // Top-level scope for the whole validation: every log line emitted
            // by this task (including those from the singleton DNS/SMTP/HTTP
            // services via AsyncLocal) carries these structured fields.
            using var jobScope = logger.BeginScope(
                "JobId={JobId} Username={Username} Endpoint={Endpoint} Domain={Domain}",
                jobId, username, "validateDomainAsync", displayDomain);

            try
            {
                var validator = new DomainValidator(dns, smtp, http);
                if (traceMasker != null) validator.TraceMask = traceMasker;
                if (trace) validator.Trace = msg =>
                {
                    using var traceScope = logger.BeginScope(
                        "Phase={Phase} Check={Check}",
                        TraceContext.Phase, TraceContext.Check);
                    logger.LogDebug("{Trace}", msg);
                };

                // Determine recheck deps (bypass MemoryCache without clearing shared entries)
                if (recheckSeverity != null)
                {
                    var deps = cache.GetRecheckDeps(domain, recheckSeverity.Value);
                    if (deps != RecheckHelper.CacheDep.None)
                    {
                        validator.RecheckDeps = deps;
                        logger.LogInformation("Recheck: bypassing cache ({Deps})", deps);
                    }
                }

                // Snapshot baselines AFTER validator is created but BEFORE ValidateAsync
                // runs (which calls ResetErrors and starts incrementing counters).
                job.SnapshotBaselines();

                validator.OnCheckStarted += name => job.CurrentCheck = name;
                validator.OnCheckCompleted += (_, result) =>
                {
                    Interlocked.Increment(ref job.CompletedChecks);
                    switch (result.Severity)
                    {
                        case CheckSeverity.Pass: Interlocked.Increment(ref job.PassCount); break;
                        case CheckSeverity.Info: Interlocked.Increment(ref job.InfoCount); break;
                        case CheckSeverity.Warning: Interlocked.Increment(ref job.WarningCount); break;
                        case CheckSeverity.Error: Interlocked.Increment(ref job.ErrorCount); break;
                        case CheckSeverity.Critical: Interlocked.Increment(ref job.CriticalCount); break;
                    }
                };

                var report = await validator.ValidateAsync(domain, options);
                job.Report = report;
                job.CurrentCheck = null;
                job.Status = JobStatus.Completed;

                _ = cache.SaveDomainResultAsync(domain, ValidationTracker.BuildSummary(report));
                cache.RequestFlush();
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Validation failed");
                job.Error = ex.Message;
                job.Status = JobStatus.Failed;
            }
        });

        return jobId;
    }

    public bool TryGetJob(string jobId, out ValidationJob? job) => _jobs.TryGetValue(jobId, out job);

    public static DomainResultSummary BuildSummary(ValidationReport report)
    {
        return new DomainResultSummary
        {
            ValidatedAtUtc = DateTime.UtcNow,
            PassCount = report.PassCount,
            WarningCount = report.WarningCount,
            ErrorCount = report.ErrorCount,
            CriticalCount = report.CriticalCount,
            IssueChecks = report.Results
                .Where(r => r.Severity >= CheckSeverity.Warning)
                .Select(r => new IssueCheckEntry
                {
                    Name = r.CheckName,
                    Category = r.Category.ToString(),
                    Severity = r.Severity.ToString()
                })
                .ToList()
        };
    }
}

// ── Clean JSON formatter ─────────────────────────────────────────────────
// Strips {OriginalFormat} template strings and redundant Message duplicates
// from State and Scope objects so JSON output contains only typed values.
sealed class CleanJsonFormatter : ConsoleFormatter, IDisposable
{
    public const string FormatterName = "CleanJson";

    IDisposable? _reload;
    JsonConsoleFormatterOptions _opts;

    public CleanJsonFormatter(IOptionsMonitor<JsonConsoleFormatterOptions> options)
        : base(FormatterName)
    {
        _opts = options.CurrentValue;
        _reload = options.OnChange(o => _opts = o);
    }

    public override void Write<TState>(in LogEntry<TState> logEntry,
        IExternalScopeProvider? scopeProvider, TextWriter textWriter)
    {
        var message = logEntry.Formatter?.Invoke(logEntry.State, logEntry.Exception);
        if (message is null && logEntry.Exception is null) return;

        using var buf = new MemoryStream();
        var jw = new Utf8JsonWriter(buf);
        jw.WriteStartObject();

        if (_opts.TimestampFormat is not null)
        {
            var ts = _opts.UseUtcTimestamp ? DateTimeOffset.UtcNow : DateTimeOffset.Now;
            jw.WriteString("Timestamp", ts.ToString(_opts.TimestampFormat));
        }
        jw.WriteNumber("EventId", logEntry.EventId.Id);
        jw.WriteString("LogLevel", GetLogLevelString(logEntry.LogLevel));
        jw.WriteString("Category", logEntry.Category);
        jw.WriteString("Message", message ?? "");

        if (logEntry.Exception is not null)
            jw.WriteString("Exception", logEntry.Exception.ToString());

        if (logEntry.State is IEnumerable<KeyValuePair<string, object?>> stateKvps)
        {
            jw.WriteStartObject("State");
            foreach (var (k, v) in stateKvps)
            {
                if (k is "{OriginalFormat}" or "Message") continue;
                WriteValue(jw, k, v);
            }
            jw.WriteEndObject();
        }

        if (_opts.IncludeScopes && scopeProvider is not null)
        {
            jw.WriteStartArray("Scopes");
            scopeProvider.ForEachScope((scope, w) =>
            {
                if (scope is IEnumerable<KeyValuePair<string, object?>> kvps)
                {
                    w.WriteStartObject();
                    foreach (var (k, v) in kvps)
                    {
                        if (k is "{OriginalFormat}" or "Message") continue;
                        WriteValue(w, k, v);
                    }
                    w.WriteEndObject();
                }
                else if (scope is not null)
                {
                    w.WriteStringValue(scope.ToString());
                }
            }, jw);
            jw.WriteEndArray();
        }

        jw.WriteEndObject();
        jw.Flush();
        textWriter.Write(Encoding.UTF8.GetString(buf.ToArray()));
        textWriter.Write('\n');
    }

    static void WriteValue(Utf8JsonWriter jw, string key, object? value)
    {
        switch (value)
        {
            case null:     jw.WriteNull(key);            break;
            case bool b:   jw.WriteBoolean(key, b);      break;
            case byte n:   jw.WriteNumber(key, n);       break;
            case sbyte n:  jw.WriteNumber(key, n);       break;
            case short n:  jw.WriteNumber(key, n);       break;
            case ushort n: jw.WriteNumber(key, n);       break;
            case int n:    jw.WriteNumber(key, n);       break;
            case uint n:   jw.WriteNumber(key, n);       break;
            case long n:   jw.WriteNumber(key, n);       break;
            case ulong n:  jw.WriteNumber(key, n);       break;
            case float n:  jw.WriteNumber(key, (double)n); break;
            case double n: jw.WriteNumber(key, n);       break;
            case decimal n:jw.WriteNumber(key, n);       break;
            default:       jw.WriteString(key, value.ToString()); break;
        }
    }

    static string GetLogLevelString(LogLevel l) => l switch
    {
        LogLevel.Trace =>       "Trace",
        LogLevel.Debug =>       "Debug",
        LogLevel.Information => "Information",
        LogLevel.Warning =>     "Warning",
        LogLevel.Error =>       "Error",
        LogLevel.Critical =>    "Critical",
        _                =>     l.ToString()
    };

    public void Dispose() => _reload?.Dispose();
}

// Make Program accessible for logging DI
public partial class Program { }

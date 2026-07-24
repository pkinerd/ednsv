# Configuration

`Ednsv.Web` reads configuration through the standard ASP.NET Core
`IConfiguration` pipeline. Sources, in order of increasing precedence:

1. `src/Ednsv.Web/appsettings.json`
2. `appsettings.{Environment}.json` (where `{Environment}` is `ASPNETCORE_ENVIRONMENT`, e.g. `Production`)
3. Environment variables
4. Command-line arguments

Nested keys are joined with `:` in JSON / CLI args and `__` (double
underscore) in environment variables. Example:
`Logging:LogLevel:Default` ⇄ `Logging__LogLevel__Default`.

## Application settings

All keys can be set in `appsettings.json` or as environment variables of the
same name (top-level keys map directly — e.g. `DataDir` → `DataDir`).

| Key                    | Type     | Default          | Notes |
|------------------------|----------|------------------|-------|
| `DataDir`              | path     | `.ednsv-data`    | Root directory for persistent state. `cache/` and `auth/` are created underneath it. |
| `CacheTtlHours`        | int      | `24`             | TTL for the in-memory and on-disk DNS/SMTP/HTTP probe caches. `0` disables expiry. |
| `FlushIntervalSeconds` | int      | `120`            | How often the cache manager flushes pending writes to `DataDir/cache/`. |
| `DnsServer`            | string   | OS resolvers     | Comma-separated list of DNS resolver IPs (e.g. `1.1.1.1,8.8.8.8`). Invalid entries are ignored; if none parse, OS resolvers are used. |
| `DkimSelectors`        | string   | built-in list    | Comma-separated default DKIM selectors used when seeding `config.json` on first run. After first run the persisted config wins. |
| `EnableSmtpProbes`     | bool     | `true`           | Server-wide **default** for the validator UI — surfaced via `/api/defaults`. POST `/api/validate` request body overrides; new web sessions inherit this when the user hasn't ticked anything. |
| `EnableHttpProbes`     | bool     | `true`           | Same — server-side default, request-body wins. |
| `EnableDnsbl`          | bool     | `true`           | Same — server-side default, request-body wins. |
| `EnableDirectDns`      | bool     | `true`           | Same — server-side default, request-body wins. Allows checks to talk directly to authoritative nameservers and public resolvers (8.8.8.8 / 1.1.1.1 / 9.9.9.9). Set to `false` when outbound raw DNS is blocked but a configured recursive resolver works — propagation, lame-delegation, SOA-serial, glue-record, parent-delegation, open-recursive-resolver and AXFR checks are reported as skipped instead of timing out. |
| `EnableDoh`            | bool     | `false`          | Same — server-side default, request-body wins. When the validation runs with this set, the public-resolver propagation check uses Google + Cloudflare's JSON DNS-over-HTTPS endpoints over HTTPS instead of raw UDP/53 — this routes through `HTTPS_PROXY` when configured. Useful in the common shape "no raw DNS egress, HTTPS proxy available". Only the propagation check has a DoH path; the auth-NS direct checks remain gated by `EnableDirectDns`. |
| `Trace`                | bool     | `false`          | Emits per-check trace messages at `Debug` level. See **Trace logging** below. |
| `MaskTrace`            | bool     | `true`           | Hashes domains/recipients in trace output for privacy. |
| `MaskSalt`             | string   | random per-run   | Stable salt for `MaskTrace` hashes — set this to keep hashes consistent across runs. |
| `AuthTokenHash`        | string   | `none`           | Token hash for the root `ednsv` user. `none` disables **token** auth — and a server with **no** auth method enabled (no token hash, no `Auth:Oidc`, no `Auth:JwtBearer`) refuses to start unless it is bound to loopback only (see **Authentication** below). Overridden by `EDNSV_AUTH_TOKEN_HASH`. |
| `EDNSV_AUTH_TOKEN_HASH`| env only | —                | Highest-precedence source for the root token hash. See `appsettings.json` for the hash recipe and the minimum-entropy requirement. |
| `Auth:Oidc:Enabled`    | bool     | `false`          | Interactive **single sign-on** via an external OIDC IdP (e.g. Entra ID). Adds a "single sign-on" button to the login page; SSO sessions get the same UI/API access (including Swagger) as token sessions. See **Authentication** below and [entra-setup.md](entra-setup.md). |
| `Auth:Oidc:Authority`  | string   | —                | Issuer/authority URL. Entra ID: `https://login.microsoftonline.com/{tenantId}/v2.0`. Required when OIDC is enabled. |
| `Auth:Oidc:ClientId`   | string   | —                | OIDC client (application) ID. Required when OIDC is enabled. |
| `Auth:Oidc:ResponseType` | string | `id_token`       | Sign-in flow. The default `id_token` flow is **secret-less**: the signed ID token comes straight from the authorization endpoint (via `form_post`) and is validated against the IdP's published keys — no token-endpoint call, so no client secret or certificate to manage/rotate. Set `code` (or `code id_token`) for the authorization-code flow. |
| `Auth:Oidc:ResponseMode` | string | `form_post`      | How the IdP returns the response to `CallbackPath`. Leave as `form_post` for the `id_token` flow. |
| `Auth:Oidc:ClientSecret` | string | —                | **Only needed when `ResponseType` includes `code`** (the token-endpoint exchange; required by Entra ID unless using a certificate/federated credential — public clients with PKCE work on IdPs that allow them). The default `id_token` flow needs no secret. Overridden by `EDNSV_OIDC_CLIENT_SECRET`. |
| `Auth:Oidc:CallbackPath` | string | `/signin-oidc`   | Redirect URI path registered at the IdP (`https://<host>/signin-oidc`). |
| `Auth:Oidc:SignedOutCallbackPath` | string | `/signout-callback-oidc` | Post-sign-out redirect path (single logout). |
| `Auth:Oidc:Scopes`     | string   | `openid profile email` | Space-separated scopes requested at sign-in. |
| `Auth:Oidc:UsernameClaim` | string | `preferred_username` | Claim used as the username; falls back to `upn` → `email` → `sub`. Prefer a claim containing `@` so SSO usernames can never collide with issued-token usernames (which forbid `@`). |
| `Auth:Oidc:RoleClaim`  | string   | `roles`          | Claim holding role values. Set to `groups` to map Entra group object IDs instead of app roles. |
| `Auth:Oidc:AdminRoles` | array    | `["Ednsv.Admin"]` | Role values (any match, case-insensitive) that grant admin. |
| `Auth:Oidc:RequiredRoles` | array | `[]`             | When non-empty, sign-in is rejected unless the user holds at least one of these roles. Empty = any authenticated IdP user may sign in. |
| `Auth:Oidc:SessionHours` | int    | `8`              | Sliding lifetime of the SSO session cookie (`ednsv-session`). |
| `Auth:Oidc:SingleLogout` | bool   | `false`          | Sign out of the IdP too (front-channel end-session) when the user signs out. Default is local-only logout. |
| `EDNSV_OIDC_CLIENT_SECRET` | env only | —            | Highest-precedence source for `Auth:Oidc:ClientSecret`. |
| `Auth:JwtBearer:Enabled` | bool   | `false`          | Accept IdP-issued OAuth2 **JWT access tokens** on `Authorization: Bearer` — service-account API access via e.g. Entra client credentials. Runs alongside ednsv tokens on the same header. |
| `Auth:JwtBearer:Authority` | string | `Auth:Oidc:Authority` | Token issuer/authority. Defaults to the OIDC authority. |
| `Auth:JwtBearer:Audiences` | array | —               | Accepted `aud` values (e.g. `api://{clientId}`, `{clientId}`). **Required** when enabled. |
| `Auth:JwtBearer:RoleClaim` | string | `Auth:Oidc:RoleClaim` | Claim holding role values in access tokens. |
| `Auth:JwtBearer:AdminRoles` | array | `Auth:Oidc:AdminRoles` | Role values granting admin to service accounts. |
| `Auth:JwtBearer:RequiredRoles` | array | `[]`        | When non-empty, tokens must carry at least one of these roles. Strongly recommended (e.g. `["Ednsv.Access"]`) so not every token minted for the audience is accepted. |
| `Auth:JwtBearer:NameClaim` | string | `azp`          | Claim identifying the calling application (falls back to `appid` for v1 tokens). The username becomes `app:{value}`. |
| `ValidateHttpsCertificates` | bool | `true`         | Validate TLS certificates on outbound HTTPS probes (MTA-STS policy, BIMI logo/VMC, DoH, security.txt, crt.sh). Keep `true` — RFC 8461 requires MTA-STS policies to be fetched over a validated connection, so disabling this makes those HTTPS verdicts untrustworthy. Set to `false` **only** behind a TLS-intercepting egress proxy whose CA is not in the host trust store. |

### Probe tuning (startup-only)

These control the throughput/timeout behaviour of the DNS, SMTP and HTTP
probe engines. They are read **once at startup** when the singleton probe
services are constructed, so **a change requires a restart** to take effect
(unlike the runtime probe data lists below, which are hot-editable via the
Config page). All are optional — omit them to keep the defaults shown.

| Key                          | Type   | Default | Notes |
|------------------------------|--------|---------|-------|
| `Dns:TokensPerSecond`        | int    | `40`    | Global DNS query rate limit (token-bucket refill per second). |
| `Dns:MaxConcurrency`         | int    | `50`    | Max concurrent in-flight DNS queries. |
| `Dns:QueryTimeoutSeconds`    | int    | `15`    | Per-query timeout for the main/direct resolvers. (The fast DNSBL and speculative resolvers keep their fixed short 3s/1-retry skip-if-slow budget.) |
| `Dns:QueryRetries`           | int    | `2`     | Per-query retry count for the main/direct resolvers. |
| `Dns:MaxRetries`             | int    | `3`     | Application-level retry ceiling for transient DNS failures. `--retry` (CLI) doubles this at runtime. |
| `Dns:UnreachableDecayMinutes`| int    | `5`     | How long a nameserver marked unreachable is skipped before being retried. |
| `Smtp:TimeoutSeconds`        | double | `10`    | SMTP conversation timeout for banner/EHLO/STARTTLS probes. |
| `Smtp:PortTimeoutSeconds`    | double | `5`     | TCP connect timeout for the SMTP port-reachability probe. |
| `Smtp:MaxRetries`            | int    | `3`     | Application-level retry ceiling for transient SMTP failures. |
| `Http:TimeoutSeconds`        | double | `10`    | Per-request timeout for outbound HTTP/HTTPS probes. |
| `Http:MaxConcurrency`        | int    | `20`    | Max concurrent outbound HTTP/HTTPS probes. |
| `Http:MaxRetries`            | int    | `3`     | Application-level retry ceiling for transient HTTP failures. |


`ASPNETCORE_HTTP_PORTS` (built-in ASP.NET Core variable) controls the HTTP
listen port. The Docker image sets it to `8080`.

## Log format

The console emits **structured JSON in Production** and the human-friendly
single-line **Simple format in Development**. Override either default:

```sh
# Force JSON anywhere (recommended for log aggregators)
export Logging__Console__FormatterName=Json

# Force Simple anywhere (e.g. running Production locally for debugging)
export Logging__Console__FormatterName=Simple
```

Both formatters are configured with `IncludeScopes=true`, so every log line
inherits the structured scope set by the middleware:

| Field | Source | Notes |
|---|---|---|
| `RequestId` | ASP.NET Core `TraceIdentifier` | one per HTTP request |
| `Method`, `Path` | request line | unmasked |
| `Username` | resolved auth user (or `(anonymous)` / `(auth-disabled)`) | **masked** when `MaskTrace=true` (default), raw otherwise |
| `IsAdmin` | resolved auth user | only present when authenticated; unmasked |
| `JobId` | the 12-char validation job id | unmasked — an opaque per-request identifier |
| `Endpoint` | `validateDomainSync` or `validateDomainAsync` | which validation entry point |
| `Domain` | the validation target | **masked** when `MaskTrace=true` (default), raw otherwise |
| `Phase` | `PREFETCH` / `FOUNDATION` / `CONCURRENT` | populated by `DomainValidator` while inside that phase |
| `Check` | the running check name | populated for messages emitted during a single check |

In JSON mode every field appears as a top-level key on each log entry, so
filtering with `jq` is trivial:

```sh
# All trace lines from one validation job
docker logs ednsv | jq 'select(.Scopes[].JobId == "abc123def456")'

# Just the prefetch traces from any validation
docker logs ednsv | jq 'select(.Scopes[].Phase == "PREFETCH" and .LogLevel == "Debug")'

# Errors from a specific user (Username is masked when MaskTrace=true —
# use the masked value, which is stable for a given MaskSalt)
docker logs ednsv | jq 'select(.Scopes[].Username == "h:8fK2xQ" and .LogLevel == "Error")'
```

In Simple mode the same fields appear in the prefixed scope block:

```
2026-05-01 12:34:56.789 dbug: Program[0] => RequestId:0HABC Username:h:8fK2xQpL JobId:abc123 Domain:h:nwAVisfCYL Phase:PREFETCH
      [      0ms] [PHASE] PREFETCH START for h:nwAVisfCYL
```

## Audit &amp; operational logging

Security-sensitive operations and every non-trivial API call emit an
`Information` log entry recording the actor and the key details. Simple
read-only UI calls (`/api/auth/me`, `/api/defaults`, `/api/checks`,
`/api/status/{jobId}` job polling, config reads) are intentionally not logged
to keep the stream signal-dense.

| Event | Category | Recorded details |
|---|---|---|
| Sign-in (token) | `Ednsv.Audit` | user, admin flag; failures log the attempted user + client IP at `Warning` |
| Sign-in (SSO) | `Ednsv.Audit` | user, admin flag (on the IdP callback); rejected sign-ins log the reason |
| Token issued | `Ednsv.Audit` | new user, admin flag, issuer, client IP |
| Token revoked | `Ednsv.Audit` | affected count + targets, actor, whether elevated (external-IdP admin) |
| Token deleted | `Ednsv.Audit` | affected count + targets, actor |
| Config updated | `Ednsv.Audit` | actor (a revision is also saved — see revision history) |
| Proxy diagnostic | `Ednsv.Audit` | target host, actor |
| Cache flushed | `Ednsv.Audit` | actor |
| Validation requested | `Program` | job id, domain, user, input flags (smtp/http/dnsbl/directDns/doh), recheck, DKIM-selector count |
| Validation completed | `Program` | duration, check count, severity breakdown, **DNS cache hits/misses** for the job |

All usernames and domains in these entries obey `MaskTrace`: masked (hashed,
correlatable) when it is `true` (the default), raw when `false`. Filter the
audit stream with the dedicated category:

```sh
docker logs ednsv | jq 'select(.Category == "Ednsv.Audit")'
```

## Trace logging without leaky ASP.NET Core logs

`Trace=true` causes the validator to emit per-check trace messages via
`ILogger.LogDebug`. The default `Logging:LogLevel:Default` is `Information`,
so these messages are filtered out — but raising `Default` to `Debug` also
turns on the verbose internal logs from `Microsoft.*` (request pipelines,
routing, model binding, hosting diagnostics, etc.), which leak request
bodies, header values, and routing internals.

Enable trace _just_ for the validator by raising the log level on the two
categories that emit trace messages, while leaving everything else at the
defaults:

- `Program` — `ILogger<Program>` used by the async POST `/api/validate` job.
- `Ednsv.Web` — `app.Logger` (category = application name) used by the sync
  GET `/api/validate/{domain}` endpoint.

### Environment variables (recommended)

```sh
export Trace=true
export Logging__LogLevel__Default=Information
export Logging__LogLevel__Microsoft__AspNetCore=Warning
export Logging__LogLevel__Program=Debug
export Logging__LogLevel__Ednsv__Web=Debug
```

Note: in env-var form the `.` in category names becomes `__` (so
`Microsoft.AspNetCore` → `Microsoft__AspNetCore`, `Ednsv.Web` →
`Ednsv__Web`).

### `appsettings.Production.json`

```json
{
  "Trace": true,
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning",
      "Program": "Debug",
      "Ednsv.Web": "Debug"
    }
  }
}
```

### Docker

```sh
docker run --rm -p 8080:8080 \
  -e Trace=true \
  -e Logging__LogLevel__Program=Debug \
  -e Logging__LogLevel__Ednsv__Web=Debug \
  ghcr.io/pkinerd/ednsv:latest
```

Keep `MaskTrace=true` (the default) in any environment where trace output
might be retained — it hashes domains and recipients so logs do not record
real addresses.

## HTTP/HTTPS proxy

`HttpProbeService` uses a default `HttpClientHandler`, so the standard .NET
proxy resolution applies — set the env vars before the process starts and
all HTTP/HTTPS lookups (MTA-STS, security.txt, BIMI, Certificate
Transparency / `crt.sh`) route through the proxy automatically. **No code
changes needed.**

### Linux / macOS / Docker

```sh
# HTTPS — covers crt.sh, .well-known/security.txt, BIMI, MTA-STS
export HTTPS_PROXY=http://proxy.corp.local:3128
# Plain HTTP — use lowercase. The .NET runtime intentionally ignores the
# uppercase HTTP_PROXY on Unix to mitigate an old Apache/CGI hijack
# (see https://httpoxy.org).
export http_proxy=http://proxy.corp.local:3128
# Bypass list (comma-separated; a leading dot = suffix match)
export NO_PROXY=localhost,127.0.0.1,.internal.example.com
# Optional fallback when neither HTTP_/HTTPS_ matches
export ALL_PROXY=http://proxy.corp.local:3128
```

If the proxy needs auth: `https://user:pass@proxy.corp.local:3128`. URL-
encode any special characters in the credentials.

In Docker:

```sh
docker run \
  -e HTTPS_PROXY=http://proxy.corp.local:3128 \
  -e NO_PROXY=localhost,127.0.0.1,.internal.example.com \
  ghcr.io/pkinerd/ednsv:latest
```

### Windows host

`HttpClient` ignores these env vars on Windows and uses the WinHTTP / IE
proxy settings. Inside Linux containers running on Windows the env-var
path above applies normally.

### Scope and gotchas

- The proxy applies **only** to `HttpClient`. It does **not** route DNS
  queries (configured resolver or direct-to-IP), SMTP TCP probes, or
  authoritative-nameserver probes. For DNS egress in restricted networks
  see `EnableDirectDns` above.
- `NO_PROXY` matching: entries starting with `.` match by suffix; others
  match by exact host. CIDRs aren't supported.
- Env vars are read **once** when `HttpClient.DefaultProxy` is initialised.
  Set them in the unit/compose file or before `dotnet` is invoked — don't
  expect a running container to pick up changes.

### Diagnosing proxy issues

Admin-only endpoint `GET /api/debug/proxy?url=https://example.com/foo`
returns the proxy URL .NET would actually use for that target, whether
`NO_PROXY` would bypass it, the proxy-related env vars currently visible
to the running process, **and the result of actually fetching the URL**
(status code, response headers, timing, and any exception). Useful when
an HTTP probe shows `(HTTP 0)` (BIMI logo, MTA-STS policy, security.txt,
crt.sh) — the endpoint will tell you whether the issue is "vars not seen
by the process", "NO_PROXY suffix-matching the host", "DefaultProxy
resolved nothing", or the request itself is failing (proxy unreachable,
TLS interception, DNS failure, etc.):

```json
{
  "target": "https://amplify.valimail.com/bimi/...svg",
  "proxyResolved": "http://proxy.corp.local:3128/",
  "bypassed": false,
  "envSeenByProcess": {
    "HTTPS_PROXY": "http://proxy.corp.local:3128",
    "NO_PROXY": "localhost,.internal.example.com"
  },
  "fetch": {
    "statusCode": 200,
    "statusReason": "OK",
    "httpVersion": "1.1",
    "contentLength": 4321,
    "bodyBytesRead": 4096,
    "elapsedMs": 187,
    "error": null,
    "headers": {
      "Content-Type": "image/svg+xml",
      "Via": "1.1 proxy.corp.local",
      "X-Cache": "MISS"
    }
  }
}
```

If `proxyResolved` equals `target`, the proxy isn't being applied — most
commonly `NO_PROXY` is matching, or the env vars aren't visible to this
process. If `fetch.statusCode=0` and `fetch.error` is non-null, the
request never produced an HTTP response — check `fetch.error` for the
underlying reason (`HttpRequestException → SocketException` typically
means the proxy itself isn't reachable from the process). The `Via` and
`X-Cache` headers (when present) confirm the proxy was actually
traversed.

## Authentication

Three independent auth methods can protect an instance, in any combination:

| Method | Config | Who it's for | How callers authenticate |
|---|---|---|---|
| **Token auth** | `AuthTokenHash` / `EDNSV_AUTH_TOKEN_HASH` | humans + scripts | `ednsv-auth` cookie (set by the login form), `Authorization: Bearer <token>`, or Basic auth |
| **OIDC SSO** | `Auth:Oidc:*` | humans via an external IdP (Entra ID or any OIDC IdP) | "single sign-on" button → IdP redirect → signed `ednsv-session` cookie |
| **JWT bearer** | `Auth:JwtBearer:*` | service accounts | `Authorization: Bearer <IdP access token>` (e.g. Entra client credentials) |

Enable any subset: token-only (the pre-existing behavior), SSO-only
(set `AuthTokenHash` to `none` and enable `Auth:Oidc`), or side-by-side.
Disabling token auth disables the login form, token issuance, and the tokens
page; SSO/JWT users are unaffected. All methods produce the same caller
identity internally, so every endpoint — including the Swagger UI, whose
"Try it out" requests carry the browser's session cookie automatically —
works identically regardless of how the caller authenticated.

**Sign-in flow & client secret.** By default SSO uses the **secret-less
ID-token flow** (`Auth:Oidc:ResponseType=id_token` via `form_post`): the IdP
returns a signed, nonce-bound ID token directly from the authorization
endpoint, which ednsv validates against the IdP's published (auto-rotating)
signing keys. There is no token-endpoint call, so **no client secret or
certificate exists to expire or rotate**. ednsv only authenticates users —
it never calls downstream APIs on their behalf — so it has no need for access
or refresh tokens. Deployments that prefer the authorization-code flow can set
`ResponseType=code`; on Entra ID that requires a `ClientSecret` (or
certificate/federated credential), while IdPs that support public clients can
run code+PKCE without one.

**Why `id_token` is the default, and its security properties.** ednsv is a
pure authentication consumer: it needs the user's identity and role claims to
establish a session and nothing more — it never calls a downstream API on the
user's behalf, so it has no use for access or refresh tokens or the token
endpoint. That makes the ID-token flow both sufficient and the least-privilege
choice (no client credential is held, so none can leak, expire, or be abused
to mint tokens). The general "avoid the implicit flow" guidance (OAuth 2.0
Security BCP, RFC 9700) targets a specific hazard — **access tokens** returned
in the URL fragment, where they land in browser history, `Referer` headers,
and server logs. ednsv structurally avoids that hazard:

- **No access tokens, ever.** Only an ID token is requested. `ResponseType` is
  validated at startup and rejects anything that would deliver an access token
  in the front channel — only `id_token`, `code`, and `code id_token` are
  accepted.
- **`form_post`, not URL fragment.** The ID token is POSTed to `CallbackPath`
  in the request body, so it never appears in a URL, browser history, or access
  logs.
- **Signature + audience + issuer validated** against the IdP's published,
  auto-rotating signing keys (fetched from OIDC metadata); a tampered or
  wrong-audience token is rejected.
- **Nonce replay/injection protection.** Each sign-in carries a nonce bound to
  a correlation cookie; a replayed or injected token whose nonce doesn't match
  is rejected.
- **Single-use, then discarded.** The ID token is consumed once at the callback
  to mint the `ednsv-session` cookie and is not stored (`SaveTokens=false`).
  After sign-in the credential is that session cookie (HttpOnly, `SameSite=Lax`,
  Data Protection-encrypted — see below), not the ID token.
- **HTTPS required.** Like the code flow, this depends on TLS end-to-end and on
  correct forwarded headers behind a reverse proxy (below); the correlation and
  session cookies are `Secure`.

Choose `ResponseType=code` if your policy forbids front-channel token delivery
outright, or if ednsv will later need to call APIs on the user's behalf — it
adds a back-channel exchange and (on Entra) a client credential, but no
additional security for an auth-only app.

**Roles.** ednsv has two roles: standard and admin. Token users carry an
explicit admin flag set at issue time. SSO and JWT callers are mapped from
claims on every request: any role in `AdminRoles` (default `Ednsv.Admin`,
matched against `Auth:Oidc:RoleClaim` / `Auth:JwtBearer:RoleClaim`) grants
admin. SSO users are **not** persisted to `users.json` — their identity and
role come from the IdP each time, so revocation and role changes are managed
in the IdP. SSO admins can still issue ednsv tokens (when token auth is on);
tokens they issue record the SSO username as `issuedBy`. Because external-IdP
admins (SSO **and** JWT) sit outside the token issuance tree, they may
**revoke any token**, not only ones in a subtree they issued — the sole
exception is the config root user `ednsv`, which no one can revoke. Token
admins keep the scoped behavior: they see and revoke only their own issuance
subtree. A username claim that would collide with the root user `ednsv` is
rejected outright.

**SSO session state.** SSO sessions are ASP.NET Core Data Protection tickets
in the `ednsv-session` cookie. The key ring is persisted to `{DataDir}/keys`
— keep it on the same persistent volume as the rest of `DataDir`, or every
restart signs everyone out. The cookie is `SameSite=Lax` (required for the
IdP redirect to land signed-in); state-changing cross-site requests still
don't carry it, preserving CSRF protection.

**Reverse proxies / HTTPS.** OIDC needs the externally visible scheme/host to
build the redirect URI and mark cookies `Secure`. Terminate TLS in front of
ednsv and set `ASPNETCORE_FORWARDEDHEADERS_ENABLED=true` so
`X-Forwarded-Proto`/`X-Forwarded-Host` are honored. The IdP round-trip will
not work over plain HTTP on a non-localhost host (correlation cookies are
`Secure`).

**Logout.** Sign-out clears the local cookies only, by default — the IdP
session survives, so the next SSO click signs straight back in. Set
`Auth:Oidc:SingleLogout=true` to also end the IdP session via the
front-channel end-session redirect.

For a step-by-step Entra ID (Azure AD) setup — app registration, admin app
role, and service-account client-credentials — see [entra-setup.md](entra-setup.md).

## Runtime probe data lists (config.json)

Beyond the on/off toggles, the **Config** page exposes the data lists the
checks probe against. These live in `{DataDir}/config.json`, are edited from
the *Probe data lists* panel (or the raw-JSON editor), and take effect on the
**next validation** — no restart needed. Each is seeded on first run with the
built-in defaults, so the panel always shows the real values in use.

Enter one entry per line. Some lists accept an optional label after a `|`
(the `value|label` convention) — the label is what the report displays.
**Clearing a list falls back to the built-in defaults** for that list.

| JSON field                    | Meaning | Entry form |
|-------------------------------|---------|------------|
| `propagationResolvers`        | Public resolvers queried by the propagation-consistency check (direct DNS). | `ip\|label` |
| `propagationDohResolvers`     | JSON DoH endpoints used instead of raw DNS when DoH is enabled. | `url\|label` |
| `ipBlocklistsPublic`          | DNSBL zones that answer reliably over public DNS. | `zone` |
| `ipBlocklistsPrivate`         | DNSBL zones needing a registered/private resolver. | `zone` |
| `extendedIpBlocklistsPublic`  | Extra DNSBL zones for the extended IP-blocklist check (public). | `zone\|label` |
| `extendedIpBlocklistsPrivate` | Extra DNSBL zones for the extended check (private resolver). | `zone\|label` |
| `domainBlocklists`            | Domain/URI (RHSBL) zones for the MX-hostname and domain blocklist checks. | `zone` |
| `arcSelectors`                | Selectors probed for ARC signing records. | `selector` |
| `dmarcDiscoverySubdomains`    | Subdomains checked for weaker DMARC overrides. | `subdomain` |
| `mailSurveySubdomains`        | Subdomains probed by the mail-subdomain survey. | `subdomain` |
| `spfSubdomains`               | Mail-sending subdomains checked for SPF coverage. | `subdomain` |
| `srvServiceNames`             | SRV prefixes queried for mail services. | `_service._proto` |
| `vmcIssuers`                  | CA names treated as recognised VMC issuers. | `name` |
| `crtShBaseUrl`                | Base URL for Certificate Transparency lookups (blank = `https://crt.sh/`). | URL |

The CLI does not expose these lists; it always uses the built-in defaults.

## Runtime config revision history

Every save of the runtime config (`PUT /api/config`, i.e. the **Config** page's
Save button) is backed up: the saved config's body is written to its own file
`{DataDir}/config-history/config-rev-{id}.json`, and a lightweight index at
`{DataDir}/config-history.json` records the **id**, **who** saved it (the
caller's username, or `(auth-disabled)` on a localhost-only open instance) and
**when** — without duplicating the (potentially large) config body. The newest
~300 revisions are kept; older ones are trimmed from the index and their
per-revision files deleted. On first run a baseline revision (`(initial)`)
captures the seeded config so even the first change is recoverable.

The Config page shows a **Revision history** dropdown listing each revision as
"date — user", newest first. Selecting one loads that config into both the form
and JSON views without applying it — review it, then click **Save config** to
apply it as a new revision (attributed to you). Keep the `config-history.json`
index **and** the `config-history/` directory on the persistent volume
alongside the rest of `DataDir` to retain history across restarts. The history
endpoints (`GET /api/config/history` and `GET /api/config/history/{id}`) are
admin-only, like the rest of the config API.

### Token auth

`EDNSV_AUTH_TOKEN_HASH` takes precedence over `AuthTokenHash` in
`appsettings.json`. Set either to the base64url-encoded SHA-256 hash of the
root token:

```sh
TOKEN=$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')
HASH=$(printf '%s' "$TOKEN" | openssl dgst -sha256 -binary | basenc --base64url | tr -d '=')
echo "token: $TOKEN"
echo "hash:  $HASH"
export EDNSV_AUTH_TOKEN_HASH="$HASH"
```

**Root-token entropy.** The root token is verified with a single unsalted
SHA-256, so it must be a cryptographically random, high-entropy value —
**at least 128 bits** (≥ 22 base64url or 32 hex characters). The
`openssl rand -base64 32` recipe above yields 256 bits and is the recommended
way to generate it. Never use a human-chosen password: a fast unsalted hash
makes a weak root token trivially brute-forceable offline if the hash or
`users.json` ever leaks. (Tokens issued to non-root users are always generated
this way automatically.)

**Disabling all auth is gated to localhost.** With `AuthTokenHash` set to
`none` (the default) and no external IdP configured, authentication is off
and every endpoint is open. To prevent an accidentally network-exposed open
instance, the server **refuses to start** with no auth method enabled unless
it is bound to loopback addresses only (e.g.
`ASPNETCORE_URLS=http://127.0.0.1:5000`). Any non-loopback binding —
including the Docker image's `ASPNETCORE_HTTP_PORTS=8080`, `0.0.0.0`, `*`, or a
real IP/host — requires at least one enabled auth method (token hash, OIDC
SSO, or JWT bearer). The `/api/debug/proxy` diagnostic is likewise
unavailable whenever no auth method is enabled.

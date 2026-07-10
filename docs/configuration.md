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
| `AuthTokenHash`        | string   | `none`           | Token hash for the root `ednsv` user. `none` disables auth — **but an auth-disabled server refuses to start unless it is bound to loopback only** (see **Authentication** below). Overridden by `EDNSV_AUTH_TOKEN_HASH`. |
| `EDNSV_AUTH_TOKEN_HASH`| env only | —                | Highest-precedence source for the root token hash. See `appsettings.json` for the hash recipe and the minimum-entropy requirement. |
| `ValidateHttpsCertificates` | bool | `true`         | Validate TLS certificates on outbound HTTPS probes (MTA-STS policy, BIMI logo/VMC, DoH, security.txt, crt.sh). Keep `true` — RFC 8461 requires MTA-STS policies to be fetched over a validated connection, so disabling this makes those HTTPS verdicts untrustworthy. Set to `false` **only** behind a TLS-intercepting egress proxy whose CA is not in the host trust store. |

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
| `Username` | resolved auth user (or `(anonymous)` / `(auth-disabled)`) | unmasked — this is an identifier, not PII |
| `IsAdmin` | resolved auth user | only present when authenticated |
| `JobId` | the 12-char validation job id | unmasked, present for the async POST `/api/validate` job |
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

# Errors from a specific user
docker logs ednsv | jq 'select(.Scopes[].Username == "alice" and .LogLevel == "Error")'
```

In Simple mode the same fields appear in the prefixed scope block:

```
2026-05-01 12:34:56.789 dbug: Program[0] => RequestId:0HABC Username:alice JobId:abc123 Domain:h:nwAVisfCYL Phase:PREFETCH
      [      0ms] [PHASE] PREFETCH START for h:nwAVisfCYL
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

**Disabling auth is gated to localhost.** Setting either value to `none` (the
default) disables authentication and opens every endpoint. To prevent an
accidentally network-exposed open instance, the server **refuses to start**
with auth disabled unless it is bound to loopback addresses only (e.g.
`ASPNETCORE_URLS=http://127.0.0.1:5000`). Any non-loopback binding —
including the Docker image's `ASPNETCORE_HTTP_PORTS=8080`, `0.0.0.0`, `*`, or a
real IP/host — requires a configured root token hash. The `/api/debug/proxy`
diagnostic is likewise unavailable whenever auth is disabled.

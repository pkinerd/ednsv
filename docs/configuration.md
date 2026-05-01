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
| `EnableSmtpProbes`     | bool     | `true`           | Server-wide kill-switch (AND-logic): clients cannot re-enable a category disabled here. |
| `EnableHttpProbes`     | bool     | `true`           | Same kill-switch semantics. |
| `EnableDnsbl`          | bool     | `true`           | Same kill-switch semantics. |
| `EnableDirectDns`      | bool     | `true`           | Same kill-switch semantics. Allows checks to talk directly to authoritative nameservers and public resolvers (8.8.8.8 / 1.1.1.1 / 9.9.9.9). Disable when outbound raw DNS is blocked but a configured recursive resolver works — propagation, lame-delegation, SOA-serial, glue-record, parent-delegation, open-recursive-resolver and AXFR checks are reported as skipped instead of timing out. |
| `Trace`                | bool     | `false`          | Emits per-check trace messages at `Debug` level. See **Trace logging** below. |
| `MaskTrace`            | bool     | `true`           | Hashes domains/recipients in trace output for privacy. |
| `MaskSalt`             | string   | random per-run   | Stable salt for `MaskTrace` hashes — set this to keep hashes consistent across runs. |
| `AuthTokenHash`        | string   | `none`           | Token hash for the root `ednsv` user. `none` disables auth entirely. Overridden by `EDNSV_AUTH_TOKEN_HASH`. |
| `EDNSV_AUTH_TOKEN_HASH`| env only | —                | Highest-precedence source for the root token hash. See `appsettings.json` for the hash recipe. |

`ASPNETCORE_HTTP_PORTS` (built-in ASP.NET Core variable) controls the HTTP
listen port. The Docker image sets it to `8080`.

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

Setting either value to `none` (the default) disables authentication and
opens every endpoint — only acceptable for local development.

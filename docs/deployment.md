# Deployment Modes & API

EDNSV can be run as a command-line tool for batch processing or as a web service with a REST API and web UI.

## CLI Mode

**Entry point**: `src/Ednsv.Cli/Program.cs`

### Basic Usage

```bash
# Validate a single domain
dotnet run --project src/Ednsv.Cli -- example.com

# Validate multiple domains
dotnet run --project src/Ednsv.Cli -- example.com gmail.com google.com

# Validate from a file (one domain per line, or CSV)
dotnet run --project src/Ednsv.Cli -- --domains-file domains.txt
```

### Output Formats

```bash
# JSON output
dotnet run --project src/Ednsv.Cli -- example.com --format json

# HTML report
dotnet run --project src/Ednsv.Cli -- example.com --format html --output report.html

# Markdown
dotnet run --project src/Ednsv.Cli -- example.com --format markdown

# Per-domain reports + index + cross-domain issues
dotnet run --project src/Ednsv.Cli -- --domains-file domains.txt --output-dir results/
```

### Key Options

| Option | Description |
|--------|-------------|
| `--domains-file <file>` / `-F` | Read domains from a text (one per line) or CSV file (`domain`/`fqdn` column) |
| `--format text\|json\|html\|markdown` / `-f` | Output format (default: text) |
| `--output <file>` / `-o` | Write output to file |
| `--output-dir <dir>` / `-D` | Per-domain reports, index file, cross-domain issues |
| `--live-index` | Rewrite the index/issues files after each domain (with `--output-dir`) |
| `--verbose` | Show check category explanations |
| `--trace` | Detailed DNS/SMTP/cache timing diagnostics |
| `--mask-trace` / `--no-mask-trace` | Privacy masking for trace output (default: on) |
| `--mask-salt <salt>` | Deterministic hash salt for consistent masks |
| `--cache [dir]` / `-c` | Persist probe cache between runs (default dir: `.ednsv-cache/`) |
| `--cache-ttl <hours>` | Cache time-to-live in hours (default: 24) |
| `--recheck warning\|error\|critical` | Re-validate previously failing checks (bypasses stale cache only) |
| `--retry` | Double retry counts for unreliable networks |
| `--retry-errors` | With `--cache`, re-probe previously failed checks, keep successful cached results |
| `--dns-server <ip,...>` / `-s` | Custom DNS server(s), comma-separated, round-robin (default: Google Public DNS) |
| `--dkim-selectors <sel,...>` | Additional DKIM selectors to probe |
| `--axfr` | Attempt zone transfers for DKIM discovery |
| `--catch-all` | Test for catch-all mail acceptance |
| `--open-relay` | Test MX hosts for open relay |
| `--open-resolver` | Test NS hosts for open recursive resolution |
| `--resolver-test-domain <domain>` | Probe target for the open-resolver test (default: `www.google.com`) |
| `--private-dnsbl` | Include blocklists requiring registered resolvers (Spamhaus, Barracuda, SURBL, URIBL) |
| `--list-checks` | Show detailed descriptions of all check categories |

**Restricted-network flags** (all default ON; pass to disable a probe class where egress is blocked):

| Option | Disables |
|--------|----------|
| `--no-smtp` | SMTP probes (ports 25/465/587): SMTP, DANE, MX STARTTLS, Postmaster/Abuse, submission ports, IPv6 SMTP |
| `--no-http` | HTTP/HTTPS probes: MTA-STS, security.txt, BIMI, Certificate Transparency |
| `--no-dnsbl` | Public DNSBL/RHSBL queries |
| `--no-direct-dns` | Direct authoritative / public-resolver queries: propagation, lame delegation, SOA serial, glue, parent delegation, AXFR, open recursive resolver |
| `--doh` | (opt-*in*) Run the propagation check over JSON DNS-over-HTTPS instead of raw UDP/53 (routes via `HTTPS_PROXY`) |
| `--restricted-network` | Preset for `--no-smtp --no-http --no-dnsbl --no-direct-dns` (DNS-only against the configured resolver) |

### Cache Workflow

```bash
# First run: cold cache, all queries go to network
dotnet run --project src/Ednsv.Cli -- gmail.com --cache .ednsv-cache/

# Second run: warm cache, most queries served from disk
dotnet run --project src/Ednsv.Cli -- gmail.com --cache .ednsv-cache/

# Recheck only previously failing checks
dotnet run --project src/Ednsv.Cli -- gmail.com --cache .ednsv-cache/ --recheck warning
```

## Web API Mode

**Entry point**: `src/Ednsv.Web/Program.cs`

### Starting the Server

```bash
dotnet run --project src/Ednsv.Web
```

### Configuration

Environment variables or command-line configuration. See [configuration.md](configuration.md) for the full list, including authentication, log formatting, and proxy settings.

| Setting | Default | Description |
|---------|---------|-------------|
| `DataDir` | `.ednsv-data` | Root for persistent state; cache lives in `<DataDir>/cache/` |
| `CacheTtlHours` | 24 | TTL for cached DNS/SMTP/HTTP results |
| `FlushIntervalSeconds` | 120 | Background flush interval |
| `DnsServer` | system | Custom DNS server(s), comma-separated |
| `DkimSelectors` | (built-in seed) | Default DKIM selectors, comma-separated |
| `EnableSmtpProbes` / `EnableHttpProbes` / `EnableDnsbl` | `true` | Server-side defaults for the validator UI; per-request body overrides |
| `EnableDirectDns` | `true` | Allow checks to talk directly to authoritative nameservers / public resolvers |
| `EnableDoh` | `false` | Use DNS-over-HTTPS for the propagation check (routes via `HTTPS_PROXY`) |
| `Trace` | `false` | Enable trace logging (per-check timing, cache hits, semaphore waits) |
| `MaskTrace` | `true` | Hash domains/recipients/IPs in trace output |
| `MaskSalt` | (random) | Deterministic salt for `MaskTrace` |
| `AuthTokenHash` / `EDNSV_AUTH_TOKEN_HASH` | `none` | Root-token hash; `none` disables auth |

### API Endpoints

```mermaid
sequenceDiagram
    participant Client
    participant API as Web API
    participant Tracker as ValidationTracker
    participant DV as DomainValidator

    Client->>API: POST /api/validate<br/>{"domain": "example.com"}
    API->>Tracker: StartValidation()
    Tracker-->>API: jobId
    API-->>Client: 202 Accepted<br/>{"jobId": "abc123", "status": "running"}

    Tracker->>DV: ValidateAsync() [background]

    loop Poll for status
        Client->>API: GET /api/status/abc123
        API->>Tracker: TryGetJob()
        API-->>Client: {"status": "running",<br/>"completedChecks": 45,<br/>"currentCheck": "SmtpTlsCertCheck"}
    end

    DV-->>Tracker: ValidationReport
    Client->>API: GET /api/status/abc123
    API-->>Client: {"status": "completed",<br/>"report": {...}}
```

#### POST /api/validate

Start an async validation job.

**Request body**:
```json
{
  "domain": "example.com",
  "recheckSeverity": "warning",
  "options": {
    "enableAxfr": false,
    "enableCatchAll": false,
    "additionalDkimSelectors": ["custom1"]
  }
}
```

**Response** (202 Accepted):
```json
{
  "jobId": "abc123def456",
  "domain": "example.com",
  "status": "running"
}
```

#### GET /api/status/{jobId}

Poll job status with real-time progress.

**Response**:
```json
{
  "jobId": "abc123def456",
  "domain": "example.com",
  "status": "running",
  "currentCheck": "SmtpTlsCertCheck",
  "completedChecks": 45,
  "results": {
    "pass": 30,
    "info": 5,
    "warning": 8,
    "error": 2,
    "critical": 0
  },
  "dns": {
    "queries": 120,
    "cacheHits": 85,
    "sent": 35,
    "received": 35,
    "totalCacheHits": 9421,
    "totalCacheMisses": 1830,
    "totalCacheSize": 2104
  },
  "smtp": {
    "probesStarted": 3,
    "probesDone": 3,
    "portsStarted": 6,
    "portsDone": 6
  },
  "elapsed": 12.5,
  "duration": null,
  "report": null
}
```

`dns.queries` / `cacheHits` / `sent` / `received` are **per-job deltas** computed by subtracting the baseline snapshot taken when the validator was constructed. `totalCacheHits` / `totalCacheMisses` / `totalCacheSize` are the cumulative process-wide counters, useful for tracking warm-cache behaviour across many concurrent jobs. `elapsed` is wall-clock time since the job started; `duration` is null until the job finishes and then carries the validator's own measurement.

When `status` is `"completed"`, the `report` field contains the full `ValidationReport`.

#### GET /api/validate/{domain}

Synchronous convenience endpoint. Runs validation and returns the full report directly. Times out after 3 minutes (HTTP 504).

Optional query parameter: `?recheck=warning|error|critical`

#### GET /api/cache/stats

Returns DNS cache statistics:
```json
{
  "dnsCacheSize": 1250,
  "dnsCacheHits": 4500,
  "dnsCacheMisses": 800
}
```

#### POST /api/cache/flush

Triggers an immediate disk cache flush.

#### GET /api/checks

Returns the list of check category descriptions (from `CheckDescriptions.Categories`).

#### Additional endpoints

Beyond the core validation flow above, the service exposes configuration, cache-management, and authentication endpoints. All are browsable (with request/response schemas) via **Swagger UI at `/swagger`**.

| Endpoint | Auth | Purpose |
|----------|------|---------|
| `GET /api/defaults` | none | Effective server-side default `ValidationOptions` used to pre-populate the UI |
| `POST /api/cache/clear` | admin | Clear the on-disk + in-memory cache |
| `GET /api/config` | admin | Read the live runtime config (toggles, DKIM selectors, probe data lists) |
| `PUT /api/config` | admin | Update the live runtime config (writes a new revision) |
| `GET /api/config/history` | admin | List config revision history |
| `GET /api/config/history/{id}` | admin | Fetch a specific config revision |
| `GET /api/debug/proxy` | admin | Diagnostic outbound-proxy connectivity probe |
| `GET /api/auth/methods` | none | Which auth methods are enabled (token / OIDC) |
| `GET /api/auth/me` | any | Current identity + roles |
| `POST /api/auth/login` / `logout` | none | Token-based session login/logout |
| `GET /api/auth/oidc/login` / `logout` | none | Start / end an OIDC browser flow |
| `GET \| POST /api/auth/users` | admin | List / issue user tokens |
| `POST /api/auth/users/{username}/revoke` | admin | Revoke a user's token |
| `DELETE /api/auth/users/{username}` | admin | Delete a user |

See [configuration.md](configuration.md) for auth modes and config semantics, and [entra-setup.md](entra-setup.md) for OIDC/Entra ID setup.

### ValidationTracker

The `ValidationTracker` class (in `src/Ednsv.Web/Program.cs`) manages async job state:

- Jobs stored in `ConcurrentDictionary<string, ValidationJob>`
- Job IDs are 12-character hex strings from `Guid.NewGuid().ToString("N")[..12]`
- Each job snapshots service counter baselines at start — status endpoint computes per-job deltas while still exposing the cumulative totals
- Live severity counters updated via `Interlocked.Increment` as checks complete
- On completion, domain results are saved for recheck decisions and a non-blocking `cache.RequestFlush()` runs in the background
- Implements `IDisposable`. A 5-minute `Timer` evicts completed/failed jobs older than 1 hour from the dictionary so long-running web servers don't accumulate every job they ever ran in memory
- The whole `Task.Run` body runs inside a structured logger scope (`JobId`, `Username`, `Endpoint`, `Domain`) so trace lines emitted from the singleton DNS/SMTP/HTTP services — captured via `TraceContext` AsyncLocal — automatically carry the right job identifier even though the services are shared

### Web UI

Single-page web apps served from `src/Ednsv.Web/wwwroot/`:

- **`index.html`** — the validator: dark theme, vanilla JavaScript (no framework dependencies); submits via POST /api/validate, polls GET /api/status/{jobId} for real-time progress, displays results with severity filtering, and supports recheck.
- **`config.html`** — admin console for the live runtime config (toggles, DKIM selectors, probe data lists) and user/token management, backed by the `/api/config*` and `/api/auth/users*` endpoints.

## Docker

The web service ships as a container. The multi-stage [`Dockerfile`](../Dockerfile) restores and publishes `Ednsv.Web` on the .NET 8 SDK image, then runs it on the ASP.NET runtime image.

```bash
# Build locally
docker build -t ednsv .

# Run (listens on 8080 inside the container)
docker run --rm -p 8080:8080 ednsv
```

- The container listens on port **8080** (`ASPNETCORE_HTTP_PORTS=8080`, `EXPOSE 8080`).
- Pass configuration as environment variables, e.g. `-e DnsServer=1.1.1.1 -e EnableSmtpProbes=false`. See [configuration.md](configuration.md) for the full list.
- Persist cache/state by mounting a volume at the configured `DataDir` (default `.ednsv-data`), e.g. `-v ednsv-data:/app/.ednsv-data`.

CI publishes images to GitHub Container Registry (`ghcr.io/<owner>/ednsv`): `latest` on the default branch and `latest-any` for every successful build.

```bash
docker run --rm -p 8080:8080 ghcr.io/<owner>/ednsv:latest
```

## Network egress (outbound ports)

EDNSV validates third-party infrastructure, so it makes outbound connections to
**arbitrary internet hosts** (both IPv4 and IPv6). IPv6-only probes self-skip when the
host has no IPv6 route. If `HTTPS_PROXY` is set, all HTTPS (443) egress goes through the
proxy while raw DNS (UDP/TCP 53) and SMTP go direct. The one exception is **DoH**
(`EnableDoh`): it carries DNS over HTTPS/443, so it uses the proxy like any other HTTPS
fetch — which is its purpose, letting the propagation check work where raw UDP/53 egress
is blocked but an HTTPS proxy is available (the auth-nameserver direct-DNS checks have no
DoH path and still need raw 53). See [Configuration → proxy](configuration.md#httphttps-proxy).

### Core — needed for a full validation

| Port | Protocol | Purpose | Destinations |
|------|----------|---------|--------------|
| **53** | UDP + TCP | All DNS: record lookups, DNSBL, propagation, direct-to-nameserver checks (lame delegation, SOA-serial, glue, parent delegation), AXFR (TCP, opt-in). TCP/53 is also the truncation fallback. | Configured resolver (web default = OS resolvers; CLI default = Google `8.8.8.8`/`8.8.4.4`); direct-DNS checks also hit `8.8.8.8`/`1.1.1.1`/`9.9.9.9` and arbitrary authoritative nameservers |
| **25** | TCP | SMTP probing: banner/EHLO/STARTTLS, RCPT (postmaster@, abuse@), open-relay, IPv6 connectivity | Arbitrary MX hosts |
| **443** | TCP | HTTPS: MTA-STS policy, BIMI logo + VMC, security.txt, Certificate Transparency (crt.sh), DoH (`dns.google`, `cloudflare-dns.com`) | `mta-sts.{domain}`, `{domain}`, `crt.sh`, BIMI/VMC hosts, `dns.google`, `cloudflare-dns.com` — or the `HTTPS_PROXY` host |

### Secondary — conditional

| Port | Protocol | Purpose | When |
|------|----------|---------|------|
| **587** | TCP | Submission-port reachability + STARTTLS detail | Submission-ports check (default with SMTP probes) |
| **465** | TCP | SMTPS (implicit-TLS) port reachability | Submission-ports check (default with SMTP probes) |
| **80** | TCP | HTTP — only when a **BIMI record publishes an `http://` logo (`l=`) or VMC (`a=`) URL** (fetched as-published, with a "should use HTTPS" warning), or when an HTTPS fetch redirects to `http://` | Domain has an http BIMI URL, or a redirect drops to http |

> The BIMI logo (`l=`) and VMC (`a=`) are the only URLs taken verbatim from DNS data and
> fetched as-is; every other HTTP request uses a hardcoded `https://` URL. DMARC/TLS-RPT
> `https` report URIs are parsed and noted but never fetched.

### Reducing the set

The network-category toggles narrow egress: `--no-smtp` drops 25/587/465; `--no-http`
drops 443/80; `--no-direct-dns` limits 53 to the configured resolver only; `--restricted`
(no-smtp + no-http + no-dnsbl + no-direct-dns) leaves **only UDP/TCP 53 to the configured
resolver**. A locked-down deployment can allow just 53 to its resolver plus 443 to
`HTTPS_PROXY` so MTA-STS/BIMI/DoH still work.

## CI/CD

**Configuration**: `.github/workflows/ci.yml`

**Triggers**: Push to any branch, PR to main

**Jobs**:
1. **Build & Unit Tests** — `dotnet restore` → `dotnet build --configuration Release` → `dotnet test` (Ednsv.Core.Tests + Ednsv.Web.Tests). Gates the integration and docker jobs.
2. **Integration Tests** — validate real domains (google.com, gmail.com, cnn.com, example.com) with JSON output parsing; cache cold/warm speedup, recheck-with-clear, and multi-domain cache-reuse verification.
3. **Docker** — build the Web image and push to GHCR (`latest` on default branch, `latest-any` per build; fork PRs build without pushing).
4. **Build log archival** — logs pushed to a `build-logs` orphan branch.

## Build Commands

```bash
# Restore dependencies
dotnet restore

# Build
dotnet build --configuration Release

# Run tests
dotnet test --configuration Release

# Run CLI
dotnet run --project src/Ednsv.Cli -- example.com

# Run web server
dotnet run --project src/Ednsv.Web
```

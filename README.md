# ednsv

**EDNSV (Email DNS Validator)** is a comprehensive DNS and email-infrastructure validation tool built on **.NET 8.0**. It runs **87 automated checks** against a domain to assess mail deliverability, security posture, and DNS hygiene, covering everything from A/MX/NS records to SPF, DKIM, DMARC, MTA-STS, TLS-RPT, BIMI, DANE, DNSSEC, blocklists, and live SMTP/HTTP probing.

It can be used two ways:

- **CLI** (`Ednsv.Cli`) - validate one or many domains, batch from a file/CSV, and emit text, JSON, HTML, or Markdown reports.
- **Web service** (`Ednsv.Web`) - a REST API with async job tracking, a single-page validator UI, an admin console, optional authentication (token / OIDC / JWT bearer), and Swagger docs at `/swagger`.

## Quick start

Requires the .NET 8.0 SDK.

```bash
# Validate a single domain (CLI)
dotnet run --project src/Ednsv.Cli -- example.com

# Batch from a file, write per-domain reports + an index
dotnet run --project src/Ednsv.Cli -- --domains-file domains.txt --output-dir results/

# JSON output
dotnet run --project src/Ednsv.Cli -- example.com --format json

# Start the web service (Swagger UI at /swagger, validator UI at /)
dotnet run --project src/Ednsv.Web
```

Run it in Docker:

```bash
docker build -t ednsv .
docker run --rm -p 8080:8080 ednsv        # or: ghcr.io/<owner>/ednsv:latest
```

## Build & test

```bash
dotnet build ednsv.sln
dotnet test ednsv.sln
```

## Documentation

Start with the architecture overview, then dive into the area you need:

| Document | What it covers |
|----------|----------------|
| [Architecture](docs/architecture.md) | System overview, project structure, components, tech stack, key design decisions |
| [Validation pipeline](docs/validation-pipeline.md) | How a validation runs end-to-end: foundation → concurrent → aggregation phases, timeouts, tracing |
| [Check framework](docs/check-framework.md) | The `ICheck` model, check categories, severities, and `ValidationOptions` |
| [Caching architecture](docs/caching-architecture.md) | In-memory + disk cache, dependency-based invalidation, decay, and recheck |
| [Service layer](docs/service-layer.md) | DNS/SMTP/HTTP probe services, rate limiting, config, auth, and startup wiring |
| [Deployment & API](docs/deployment.md) | CLI options, the REST API (all endpoints), the web UI, Docker, and CI/CD |
| [Configuration](docs/configuration.md) | Environment variables, runtime config, probe tuning, and the editable probe data lists |
| [Entra ID setup](docs/entra-setup.md) | Single sign-on (OIDC) for users and client-credentials API access for service accounts |

Copyright 2026, all rights reserved.

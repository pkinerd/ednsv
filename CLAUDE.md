# Working in this repository

EDNSV (Email DNS Validator) runs 87 checks against a domain to assess mail
deliverability, security posture and DNS hygiene. It ships as a CLI
(`Ednsv.Cli`) and a web service (`Ednsv.Web`) over a shared engine
(`Ednsv.Core`).

For what the system *is*, start at [docs/architecture.md](docs/architecture.md);
the README indexes the rest. This file covers only what you need to build, test
and run it without tripping over something non-obvious.

## Toolchain

.NET 10.0 SDK (LTS). `global.json` pins the 10.0.1xx feature band, which has a
consequence worth knowing: with an older SDK installed, `dotnet --version` fails
outright rather than reporting the older number.

In Claude Code web sessions `.claude/hooks/session-start.sh` installs the SDK and
starts Redis for you. Everywhere else, `apt-get install dotnet-sdk-10.0` on
Ubuntu 24.04 or newer.

## Build and test

```bash
dotnet build ednsv.sln
dotnet test ednsv.sln
```

**A bare `dotnet test` under-reports.** Everything covering the shared Redis
tier — L2 reads and writes, the emptied-cache re-warm, config and auth beacons,
write leases — self-skips when nothing is listening on port 6380, and logs
`SKIPPED: no Redis` as it goes (52 such skips as of this commit). The suite
reports a clean pass without having exercised any of it. To actually run them:

```bash
redis-server --port 6380 --daemonize yes --save '' --appendonly no
EDNSV_REQUIRE_REDIS=1 dotnet test ednsv.sln
```

`EDNSV_REQUIRE_REDIS=1` turns the self-skip into a failure, so a missing server
is reported rather than silently tolerated. CI sets it, and supplies Redis as a
service container. Port 6380 rather than 6379 is deliberate — it keeps a
developer's own Redis on the default port out of the test keyspace.

One test, `DiskCacheTests.RetryErrors_KeepsSuccessfulEntries`, makes a live
plain-HTTP request to example.com and fails in any sandbox without open egress.

## Running it

```bash
# CLI
dotnet run --project src/Ednsv.Cli -- example.com

# …with no outbound SMTP, HTTP, DNSBL or direct-DNS (restricted networks)
dotnet run --project src/Ednsv.Cli -- example.com --restricted-network

# Web service — Swagger at /swagger, validator UI at /
dotnet run --project src/Ednsv.Web
```

`run-web.sh` is the local launcher; it reads secrets from a sibling `Keys/`
directory outside the repository, so it will not work on a fresh clone without
them.

**The web service refuses to start bound to a non-loopback address with no
authentication enabled.** That is a deliberate gate, not a bug. Either bind to
loopback:

```bash
ASPNETCORE_URLS=http://127.0.0.1:8080 dotnet run --project src/Ednsv.Web
```

or enable an auth method (`EDNSV_AUTH_TOKEN_HASH`, `Auth:Oidc`, or
`Auth:JwtBearer`). See [docs/configuration.md](docs/configuration.md).

Spectre.Console renders nothing useful when stdout is not a terminal — a
redirected CLI run produces blank lines rather than the report. Use `script -qec
"…" /dev/null` to capture real output.

## Things that bite

- **Cache correctness is the sharp edge of this codebase.** A wrong answer cached
  at the wrong TTL is the failure mode that matters, and the reasoning is dense
  and already written down. Read [docs/caching-architecture.md](docs/caching-architecture.md)
  and [docs/cache-behaviour-map.md](docs/cache-behaviour-map.md) before changing
  anything under `Services/` that caches.
- **Comments here carry rationale, not description.** They explain what went
  wrong before and why the code is shaped the way it is. When you change such
  code, update the reasoning too — a stale rationale is worse than none.
- **CI parses CLI output with regexes**, including the `Duration │ 3.2s` row of
  the Spectre summary table. Changing that table's shape breaks the cache
  effectiveness analysis in `.github/workflows/ci.yml` silently, without failing
  the build.
- **Images carry provenance, not versions.** There are no git tags and no
  `<Version>`, so every build reports `1.0.0`; commit, branch and PR are stamped
  in via `SOURCE_COMMIT`/`SOURCE_BRANCH`/`SOURCE_PR` build args and surfaced by
  `BuildInfo`, `/api/defaults` and the startup log. `sha-<short>` is the only
  immutable image tag.

## CI

`.github/workflows/ci.yml` runs build + unit tests (gating), then integration
tests against real domains and a Docker build/push to GHCR in parallel. Job logs
and test artifacts are pushed to a `build-logs` orphan branch; the
`/poll-build-logs` command walks them.

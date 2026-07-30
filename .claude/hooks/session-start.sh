#!/bin/bash
set -euo pipefail

# Only run in Claude Code web (remote) sessions
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

# Signal async execution so session startup isn't blocked
echo '{"async": true, "asyncTimeout": 300000}'

# Configure apt proxy if one is set (avoids shell truncation of large proxy URLs)
configure_apt_proxy() {
  python3 -c "
import os
proxy = os.environ.get('GLOBAL_AGENT_HTTP_PROXY', '')
if proxy:
    with open('/etc/apt/apt.conf.d/99proxy', 'w') as f:
        f.write(f'Acquire::http::Proxy \"{proxy}\";\n')
        f.write(f'Acquire::https::Proxy \"{proxy}\";\n')
"
}

# ── .NET SDK ────────────────────────────────────────────────────────────────
# Must match global.json, which pins the 10.0.1xx band. Note that the version
# check below is not merely a version *comparison*: with an SDK older than the
# pin, `dotnet --version` fails outright rather than reporting the older number,
# so a .NET 8 box takes the install path here exactly as an empty one does.
if dotnet --version 2>/dev/null | grep -q '^10\.'; then
  echo ".NET SDK already installed: $(dotnet --version)"
else
  configure_apt_proxy
  # Allow partial failures (e.g. egress-blocked PPAs); install will fail clearly if dotnet is unreachable
  DEBIAN_FRONTEND=noninteractive apt-get update -qq || true
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq dotnet-sdk-10.0
  echo ".NET SDK installed: $(dotnet --version)"
fi

# ── Redis on 6380, for the shared-cache tests ───────────────────────────────
# Every Redis-backed test — shared L2, the emptied-cache re-warm, config and auth
# beacons, write leases — self-skips when nothing is listening. That keeps them
# runnable without a server, at the cost of a session that runs `dotnet test`
# seeing 43 tests quietly not run and reporting a green suite anyway. CI solves
# this with a service container and EDNSV_REQUIRE_REDIS=1; a session has neither,
# so it gets a server instead.
#
# 6380 rather than 6379 is what the tests connect to, deliberately: it keeps a
# developer's own Redis on the default port out of the test keyspace.
#
# Best-effort throughout: no Redis is the documented, supported state, so nothing
# here is allowed to fail a session that is only being opened to read code.
if redis-cli -p 6380 ping >/dev/null 2>&1; then
  echo "Redis already listening on 6380"
else
  if ! command -v redis-server >/dev/null 2>&1; then
    configure_apt_proxy
    DEBIAN_FRONTEND=noninteractive apt-get update -qq || true
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq redis-server || true
  fi
  if command -v redis-server >/dev/null 2>&1; then
    # No persistence: this is a scratch keyspace, and an RDB/AOF write failure in
    # a container with a read-only or full data dir makes Redis reject writes.
    redis-server --port 6380 --daemonize yes --save '' --appendonly no >/dev/null 2>&1 || true
    sleep 1
    if redis-cli -p 6380 ping >/dev/null 2>&1; then
      echo "Redis started on 6380 — the shared-cache tests will run"
    else
      echo "WARNING: Redis did not come up on 6380; its tests will self-skip"
    fi
  else
    echo "WARNING: redis-server unavailable; the shared-cache tests will self-skip"
  fi
fi

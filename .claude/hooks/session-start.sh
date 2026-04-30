#!/bin/bash
set -euo pipefail

# Only run in Claude Code web (remote) sessions
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

# Signal async execution so session startup isn't blocked
echo '{"async": true, "asyncTimeout": 300000}'

if dotnet --version 2>/dev/null | grep -q '^8\.'; then
  echo ".NET SDK already installed: $(dotnet --version)"
  exit 0
fi

# Configure apt proxy if one is set (avoids shell truncation of large proxy URLs)
python3 -c "
import os
proxy = os.environ.get('GLOBAL_AGENT_HTTP_PROXY', '')
if proxy:
    with open('/etc/apt/apt.conf.d/99proxy', 'w') as f:
        f.write(f'Acquire::http::Proxy \"{proxy}\";\n')
        f.write(f'Acquire::https::Proxy \"{proxy}\";\n')
"

# Allow partial failures (e.g. egress-blocked PPAs); install will fail clearly if dotnet is unreachable
DEBIAN_FRONTEND=noninteractive apt-get update -qq || true
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq dotnet-sdk-8.0

echo ".NET SDK installed: $(dotnet --version)"

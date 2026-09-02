#!/usr/bin/env bash
set -euo pipefail
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy
test "$(cat /root/probe/agent.ok)" = ok
curl -fsSL --retry 0 --connect-timeout 15 --max-time 90 https://github.com/ >/dev/null
curl -fsSL --retry 0 --connect-timeout 15 --max-time 90 https://astral.sh/uv/install.sh >/dev/null
curl -fsSL --retry 0 --connect-timeout 15 --max-time 90 https://www.python.org/ >/dev/null
printf 'VERIFIER_NETWORK_OK\n'
mkdir -p /logs/verifier
printf '1\n' > /logs/verifier/reward.txt

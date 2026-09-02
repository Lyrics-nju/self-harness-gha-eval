#!/usr/bin/env bash
set -euo pipefail
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy
mkdir -p /root/probe
curl -fsSL --retry 0 --connect-timeout 15 --max-time 90 https://github.com/ >/dev/null
curl -fsSL --retry 0 --connect-timeout 15 --max-time 90 https://astral.sh/uv/install.sh >/dev/null
curl -fsSL --retry 0 --connect-timeout 15 --max-time 90 https://www.python.org/ >/dev/null
printf 'ok\n' > /root/probe/agent.ok

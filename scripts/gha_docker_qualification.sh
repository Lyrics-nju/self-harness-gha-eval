#!/usr/bin/env bash
set -euo pipefail
out=${1:?output CSV required}
mkdir -p "$(dirname "$out")" work/gha/docker/build work/gha/docker/mount
printf 'operation,category,target,success,exit_code,curl_exit_35\n' > "$out"
docker version --format '{{json .Server}}' > work/gha/docker/server.json
docker run --rm hello-world >/dev/null
echo mounted > work/gha/docker/mount/probe
docker run --rm -v "$PWD/work/gha/docker/mount:/probe:ro" alpine:3.20 sh -c 'test "$(cat /probe/probe)" = mounted'
printf 'FROM alpine:3.20\nRUN printf built >/built\n' > work/gha/docker/build/Dockerfile
docker build -t self-harness-gha-probe:local work/gha/docker/build >/dev/null
docker run --rm self-harness-gha-probe:local test -f /built
docker network create self-harness-gha-net >/dev/null
trap 'docker network rm self-harness-gha-net >/dev/null 2>&1 || true' EXIT
docker run --rm --network bridge curlimages/curl:8.10.1 -fsS --retry 0 https://github.com/ >/dev/null
docker run --rm --network self-harness-gha-net curlimages/curl:8.10.1 -fsS --retry 0 https://github.com/ >/dev/null
fail=0
targets=(https://github.com/ https://astral.sh/uv/install.sh https://www.python.org/ https://pypi.org/simple/ https://registry-1.docker.io/v2/)
for i in $(seq 1 20); do
  target=${targets[$(((i-1)%5))]}; network=bridge; [ $((i%2)) -eq 0 ] && network=self-harness-gha-net
  set +e; docker run --rm --network "$network" curlimages/curl:8.10.1 -fsSL --connect-timeout 15 --max-time 120 --retry 0 "$target" >/dev/null 2>work/gha/docker/curl.err; rc=$?; set -e
  ok=0; [ "$rc" -eq 0 ] && ok=1; e35=0; [ "$rc" -eq 35 ] && e35=1
  printf '%s,container_https,%s,%s,%s,%s\n' "$i" "$target" "$ok" "$rc" "$e35" >> "$out"
  [ "$ok" -eq 1 ] || fail=$((fail+1))
done
[ "$fail" -eq 0 ]

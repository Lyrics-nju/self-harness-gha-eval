#!/usr/bin/env bash
set -euo pipefail
out=${1:?output CSV required}; mkdir -p "$(dirname "$out")" work/gha/docker/build work/gha/docker/mount
printf 'operation,category,target,endpoint_class,transport_ok,curl_exit_code,http_status,expected_status,auth_challenge_present,registry_api_header_present,tls_failure,dns_failure,timeout,final_operation_result\n' > "$out"
docker version --format '{{json .Server}}' > work/gha/docker/server.json
docker run --rm hello-world >/dev/null
echo mounted > work/gha/docker/mount/probe
docker run --rm -v "$PWD/work/gha/docker/mount:/probe:ro" alpine:3.20 sh -c 'test "$(cat /probe/probe)" = mounted'
printf 'FROM alpine:3.20\nRUN printf built >/built\n' > work/gha/docker/build/Dockerfile
docker build -t self-harness-gha-probe:local work/gha/docker/build >/dev/null
docker run --rm self-harness-gha-probe:local test -f /built
docker network create self-harness-gha-net >/dev/null
trap 'docker network rm self-harness-gha-net >/dev/null 2>&1 || true' EXIT
docker run --rm --network bridge curlimages/curl:8.10.1 -sS -o /dev/null https://github.com/
docker run --rm --network self-harness-gha-net curlimages/curl:8.10.1 -sS -o /dev/null https://github.com/
fail=0
targets=(https://github.com/ https://astral.sh/uv/install.sh https://www.python.org/ https://pypi.org/simple/ https://registry-1.docker.io/v2/)
for i in $(seq 1 20); do
  target=${targets[$(((i-1)%5))]}; network=bridge; [ $((i%2)) -eq 0 ] && network=self-harness-gha-net
  class=generic_https; [ "$target" = https://registry-1.docker.io/v2/ ] && class=docker_registry_v2
  headers="work/gha/docker/headers-$i.txt"; set +e
  output=$(docker run --rm --network "$network" curlimages/curl:8.10.1 -sS -L --connect-timeout 15 --max-time 120 --retry 0 -D - -o /dev/null -w '__STATUS__=%{http_code}' "$target" 2>work/gha/docker/curl.err); rc=$?
  set -e; printf '%s\n' "$output" | sed '/__STATUS__=/d' > "$headers"; status=$(printf '%s\n' "$output" | sed -n 's/^__STATUS__=//p' | tail -1); status=${status:-0}
  set +e; fields=$(python3 scripts/docker_endpoint_policy.py "$class" "$rc" "$status" "$headers"); policy_rc=$?; set -e
  printf '%s,container_https,%s,%s,%s\n' "$i" "$target" "$class" "$fields" >> "$out"
  [ "$policy_rc" -eq 0 ] || fail=$((fail+1))
done
[ "$fail" -eq 0 ]

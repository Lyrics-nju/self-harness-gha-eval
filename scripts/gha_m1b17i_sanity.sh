#!/usr/bin/env bash
set -euo pipefail
mkdir -p reports work/sanity
out=reports/compact_sanity.csv
printf 'operation,category,target,success,exit_code,http_status,tls_failure,dns_failure,timeout\n' > "$out"
op=0
record_curl() {
  local category=$1 mode=$2 target=$3; op=$((op+1)); local body headers rc status tls=0 dns=0 timeout=0 ok=0
  body="work/sanity/body-$op"; headers="work/sanity/headers-$op"
  set +e
  if [ "$mode" = host ]; then curl --proto '=https' --tlsv1.2 -sS -L --retry 0 --connect-timeout 15 --max-time 90 -D "$headers" -o "$body" -w '%{http_code}' "$target" >"work/sanity/status-$op" 2>"work/sanity/error-$op"
  else docker run --rm curlimages/curl:8.10.1 --proto '=https' --tlsv1.2 -sS -L --retry 0 --connect-timeout 15 --max-time 90 -D - -o /dev/null -w '%{http_code}' "$target" >"work/sanity/status-$op" 2>"work/sanity/error-$op"
  fi
  rc=$?; set -e; status=$(tail -c 3 "work/sanity/status-$op"); status=${status:-0}
  [ "$rc" -eq 35 ] && tls=1; [ "$rc" -eq 6 ] && dns=1; [ "$rc" -eq 28 ] && timeout=1
  [ "$rc" -eq 0 ] && [ "$status" -ge 200 ] && [ "$status" -lt 400 ] && ok=1
  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s\n' "$op" "$category" "$target" "$ok" "$rc" "$status" "$tls" "$dns" "$timeout" >> "$out"
  [ "$ok" -eq 1 ]
}
for _ in 1 2; do record_curl host_github host https://github.com/; done
for _ in 1 2; do
  op=$((op+1)); set +e
  output=$(docker run --rm curlimages/curl:8.10.1 -sS -L --retry 0 --connect-timeout 15 --max-time 90 -D - -o /dev/null -w '__STATUS__=%{http_code}' https://registry-1.docker.io/v2/ 2>"work/sanity/error-$op"); rc=$?; set -e
  printf '%s\n' "$output" | sed '/__STATUS__=/d' >"work/sanity/headers-$op"; status=$(printf '%s\n' "$output" | sed -n 's/^__STATUS__=//p' | tail -1); status=${status:-0}
  set +e; fields=$(python3 scripts/docker_endpoint_policy.py docker_registry_v2 "$rc" "$status" "work/sanity/headers-$op"); policy_rc=$?; set -e
  IFS=, read -r transport _ _ _ _ _ tls dns timeout final <<<"$fields"; ok=0; [ "$final" = PASS ] && ok=1
  printf '%s,docker_registry,https://registry-1.docker.io/v2/,%s,%s,%s,%s,%s,%s\n' "$op" "$ok" "$rc" "$status" "$tls" "$dns" "$timeout" >> "$out"
  [ "$policy_rc" -eq 0 ]
done
for _ in 1 2; do record_curl container_github container https://github.com/; done
docker version > reports/docker_sanity.txt 2>&1
docker run --rm hello-world >> reports/docker_sanity.txt 2>&1
python3 - "$out" <<'PY'
import csv,sys
r=list(csv.DictReader(open(sys.argv[1])))
assert len(r)==6 and all(x['success']=='1' for x in r)
assert sum(int(x[k]) for x in r for k in ('tls_failure','dns_failure','timeout'))==0
print('GHA_17I_COMPACT_SANITY=6/6 PASS; DOCKER_BASIC=PASS; CURL35_TLS_DNS_TIMEOUT=0')
PY

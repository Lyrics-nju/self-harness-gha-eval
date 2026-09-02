#!/usr/bin/env bash
set -euo pipefail
out=${1:?output CSV required}; mkdir -p "$(dirname "$out")" work/gha/network
printf 'operation,category,target,success,exit_code,http_status,tls_failure,dns_failure,timeout,elapsed_seconds\n' > "$out"
fail=0; op=0
curl_op() {
  local category=$1 target=$2; op=$((op+1)); local start rc status elapsed tls dns timeout ok
  start=$(date +%s); set +e
  status=$(curl --proto '=https' --tlsv1.2 --connect-timeout 15 --max-time 120 --retry 0 -L -sS -w '%{http_code}' -o /dev/null "$target" 2>work/gha/network/error.txt); rc=$?
  set -e; elapsed=$(( $(date +%s)-start )); tls=0; dns=0; timeout=0
  [ "$rc" -eq 35 ] && tls=1; [ "$rc" -eq 6 ] && dns=1; [ "$rc" -eq 28 ] && timeout=1
  ok=0; [ "$rc" -eq 0 ] && [ "$status" -ge 200 ] && [ "$status" -lt 400 ] && ok=1
  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' "$op" "$category" "$target" "$ok" "$rc" "$status" "$tls" "$dns" "$timeout" "$elapsed" >> "$out"
  [ "$ok" -eq 1 ] || fail=$((fail+1))
}
for i in $(seq 1 10); do curl_op github_https https://github.com/; done
for i in $(seq 1 5); do
  op=$((op+1)); d="work/gha/network/clone-$i"; start=$(date +%s); set +e
  git clone --depth 1 https://github.com/octocat/Hello-World.git "$d" >/dev/null 2>work/gha/network/error.txt; rc=$?; set -e
  elapsed=$(( $(date +%s)-start )); ok=0; [ "$rc" -eq 0 ] && ok=1
  tls=0; dns=0; timeout=0
  grep -qiE 'TLS|SSL' work/gha/network/error.txt && tls=1 || true
  grep -qiE 'resolve host|name resolution' work/gha/network/error.txt && dns=1 || true
  grep -qiE 'timed out|timeout' work/gha/network/error.txt && timeout=1 || true
  printf '%s,github_clone,https://github.com/octocat/Hello-World.git,%s,%s,NA,%s,%s,%s,%s\n' "$op" "$ok" "$rc" "$tls" "$dns" "$timeout" "$elapsed" >> "$out"
  [ "$ok" -eq 1 ] || fail=$((fail+1)); rm -rf "$d"
done
for i in $(seq 1 10); do curl_op uv_bootstrap https://astral.sh/uv/install.sh; done
for i in $(seq 1 10); do curl_op cpython_download https://www.python.org/ftp/python/3.13.7/Python-3.13.7.tgz; done
for i in $(seq 1 5); do curl_op moderate_transfer https://github.com/git/git/archive/refs/tags/v2.51.0.tar.gz; done
[ "$op" -eq 40 ] && [ "$fail" -eq 0 ]

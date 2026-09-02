#!/usr/bin/env bash
set -euo pipefail
gate=${1:?gate}; count=${2:?count}; out=${3:?CSV}
mkdir -p "$(dirname "$out")" work/gha/jobs
[ -f "$out" ] || printf 'gate,index,job_name,harbor_exit,raw_reward,success,curl_exit_35,tls_error,harbor_exception\n' > "$out"
for i in $(seq 1 "$count"); do
  job="gha-synthetic-${gate}-$(printf '%02d' "$i")"
  set +e
  harbor run --path gha/synthetic-direct --agent oracle --env docker --n-concurrent 1 --n-attempts 1 --max-retries 0 --job-name "$job" --jobs-dir work/gha/jobs --yes >"work/gha/${job}.log" 2>&1
  rc=$?; set -e
  trial=$(find "work/gha/jobs/$job" -mindepth 1 -maxdepth 1 -type d | head -1 || true)
  reward=$(find "$trial" -type f -name 'reward.txt' -print -quit | xargs -r cat || true)
  e35=$(grep -RihE 'curl[^[:cntrl:]]*exit( code)?[=: ]+35|CURLE_SSL_CONNECT_ERROR' "$trial" "work/gha/${job}.log" 2>/dev/null | wc -l || true)
  tls=$(grep -RihE 'TLS|SSL connect error' "$trial" "work/gha/${job}.log" 2>/dev/null | wc -l || true)
  exc=$(grep -ciE 'Traceback|Exception|ERROR' "work/gha/${job}.log" || true)
  ok=0; [ "$rc" -eq 0 ] && [ "$reward" = "1" ] && [ "$e35" -eq 0 ] && [ "$tls" -eq 0 ] && [ "$exc" -eq 0 ] && ok=1
  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s\n' "$gate" "$i" "$job" "$rc" "${reward:-NA}" "$ok" "$e35" "$tls" "$exc" >> "$out"
  [ "$ok" -eq 1 ] || exit 1
done

#!/usr/bin/env bash
set -euo pipefail
task=${1:?task name}; out=${2:?CSV}
[ -f "$out" ] || printf 'task,job_name,harbor_exit,raw_reward,normalized_outcome,reason_code,harbor_exception,curl_exit_35,tls_failure,dns_failure,minimum_free_bytes,wall_seconds\n' > "$out"
case "$task" in portfolio-optimization|build-cython-ext|financial-document-processor) ;; *) exit 64;; esac
root=${TB21_DIR:-terminal-bench/terminal-bench-2-1}; path="$root/$task"; test -d "$path"
job="gha-real-${task}"; start=$(date +%s); before=$(df --output=avail -B1 / | tail -1 | tr -d ' ')
set +e
harbor run --path "$path" --agent oracle --env docker --n-concurrent 1 --n-attempts 1 --max-retries 0 --job-name "$job" --jobs-dir work/gha/jobs --yes >"work/gha/${job}.log" 2>&1
rc=$?; set -e
after=$(df --output=avail -B1 / | tail -1 | tr -d ' '); minimum=$after; [ "$before" -lt "$after" ] && minimum=$before
trial=$(find "work/gha/jobs/$job" -mindepth 1 -maxdepth 1 -type d | head -1); norm="work/gha/${job}.normalized.json"
python3 evaluation/normalize_outcome_v2.py "$trial" --output "$norm"
reward=$(find "$trial" -type f -name reward.txt -print -quit | xargs -r cat || true)
outcome=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["outcome"])' "$norm")
reason=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["reason_code"])' "$norm")
e35=$(grep -RihE 'curl[^[:cntrl:]]*exit( code)?[=: ]+35|CURLE_SSL_CONNECT_ERROR' "$trial" "work/gha/${job}.log" 2>/dev/null | wc -l || true)
tls=$(grep -RihE 'TLS|SSL connect error' "$trial" "work/gha/${job}.log" 2>/dev/null | wc -l || true)
dns=$(grep -RihE 'could not resolve|temporary failure in name resolution' "$trial" "work/gha/${job}.log" 2>/dev/null | wc -l || true)
exc=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print((d.get("raw_exception_info") or {}).get("exception_type",""))' "$norm")
printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' "$task" "$job" "$rc" "${reward:-NA}" "$outcome" "$reason" "${exc:-NONE}" "$e35" "$tls" "$dns" "$minimum" "$(( $(date +%s)-start ))" >> "$out"
# Infrastructure qualification is fail-closed. Task failure itself remains diagnostic evidence.
[ "$rc" -eq 0 ] && [ "$e35" -eq 0 ] && [ "$tls" -eq 0 ] && [ "$dns" -eq 0 ] && [[ "$outcome" != *_INFRA_ERROR ]] && [ "$outcome" != ENVIRONMENT_ERROR ] && [ "$outcome" != UNCLASSIFIED ]

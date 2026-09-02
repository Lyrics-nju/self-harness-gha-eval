#!/usr/bin/env bash
set -euo pipefail
task=${1:?task name}; out=${2:?CSV}; [ "$task" = portfolio-optimization ] || exit 64
[ -f "$out" ] || printf 'task,job_name,trial_name,harbor_process_exit,raw_reward,normalized_outcome,reason_code,structured_exception_status,verifier_completed,artifact_complete,task_network_status,oracle_network_status,verifier_network_status,curl_exit_35,tls_failure,dns_failure,minimum_free_bytes,wall_seconds,infrastructure_qualified\n' > "$out"
root=${TB21_DIR:-terminal-bench/terminal-bench-2-1}; path="$root/$task"; test -d "$path"
job="gha-real-${task}"; start=$(date +%s); before=$(df --output=avail -B1 / | tail -1 | tr -d ' ')
stdout="work/gha/streams/${job}.stdout"; stderr="work/gha/streams/${job}.stderr"; mkdir -p work/gha/streams reports/real_probe
set +e
harbor run --path "$path" --agent oracle --env docker --n-concurrent 1 --n-attempts 1 --max-retries 0 --job-name "$job" --jobs-dir work/gha/jobs --yes >"$stdout" 2>"$stderr"
rc=$?; set -e
after=$(df --output=avail -B1 / | tail -1 | tr -d ' '); minimum=$after; [ "$before" -lt "$after" ] && minimum=$before
mapfile -t trials < <(find "work/gha/jobs/$job" -mindepth 1 -maxdepth 1 -type d | sort); [ "${#trials[@]}" -eq 1 ] || exit 1
trial=${trials[0]}; norm=reports/real_probe/normalizer_v2.json
python3 evaluation/normalize_outcome_v2.py "$trial" --output "$norm"
python3 scripts/capture_real_probe.py --task "$task" --job "$job" --trial "$trial" --stdout "$stdout" --stderr "$stderr" --exit "$rc" --normalizer "$norm" --minimum-free "$minimum" --wall-seconds "$(( $(date +%s)-start ))" --csv "$out" --out reports/real_probe

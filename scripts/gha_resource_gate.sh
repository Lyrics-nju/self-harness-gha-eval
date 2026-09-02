#!/usr/bin/env bash
set -euo pipefail
out=${1:?disk CSV required}; start=$(cat work/gha/job_started_epoch); now=$(date +%s); elapsed=$((now-start))
free=$(df --output=avail -B1 / | tail -1 | tr -d ' ')
printf 'probe_gate,FREE_BYTES,%s,elapsed_seconds=%s\n' "$free" "$elapsed" >> "$out"
# A 300-minute job reserves its final hour for evidence finalization/upload.
[ "$elapsed" -lt 14400 ] || { printf 'probe_gate,GHA_TIME_LIMIT_RISK,%s,less than 60 minute reserve\n' "$free" >> "$out"; exit 1; }
[ "$free" -ge 4294967296 ] || { printf 'probe_gate,GHA_STORAGE_BLOCKER,%s,less than 4 GiB free\n' "$free" >> "$out"; exit 1; }

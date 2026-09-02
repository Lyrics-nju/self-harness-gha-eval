#!/usr/bin/env bash
set -euo pipefail
mkdir -p work/diagnostic/jobs reports/harbor_diagnostic
job=gha-harbor-diagnostic-01
set +e
harbor run --path gha/synthetic-direct --agent oracle --env docker --n-concurrent 1 --n-attempts 1 --max-retries 0 --job-name "$job" --jobs-dir work/diagnostic/jobs --yes >work/diagnostic/harbor.stdout 2>work/diagnostic/harbor.stderr
rc=$?
set -e
trial=$(find "work/diagnostic/jobs/$job" -mindepth 1 -maxdepth 1 -type d | head -1 || true)
test -n "$trial"
python3 scripts/capture_harbor_diagnostic.py --trial "$trial" --stdout work/diagnostic/harbor.stdout --stderr work/diagnostic/harbor.stderr --exit "$rc" --out reports/harbor_diagnostic
printf '%s\n' "$rc" > reports/harbor_diagnostic/harbor_exit_code.txt

"""Probe-only 1536 MiB host-TSC feasibility diagnostics."""
from __future__ import annotations

import shlex

from .adapter import DshHarborAdapter

ARTIFACT_DIR = "/logs/artifacts/dsh-build-substage-forensics"
DIAGNOSTIC_NODE_OPTIONS = "--max-old-space-size=1536"
TSC_COMMAND = "pnpm exec tsc -b tsconfig.host.json"


def tsc_1536_wrapper(artifact_dir: str = ARTIFACT_DIR) -> str:
    directory = shlex.quote(artifact_dir)
    heap = shlex.quote(DIAGNOSTIC_NODE_OPTIONS)
    return f"""set +e
forensic_dir={directory}
mkdir -p "$forensic_dir"
if test "${{NODE_OPTIONS+x}}" = x; then
  printf 'classification=M1C_DSH_BUILD_NODE_OPTIONS_DRIFT\\ndiagnostic_complete=true\\ntsc_status=NOT_REACHED\\n' >"$forensic_dir/substage-summary.txt"
  exit 78
fi
printf '%s\\n' 'NODE_OPTIONS={DIAGNOSTIC_NODE_OPTIONS} {TSC_COMMAND}' >"$forensic_dir/tsc-1536-command.txt"
printf '%s\\n' '{DIAGNOSTIC_NODE_OPTIONS}' >"$forensic_dir/effective-node-options.txt"
effective_heap=$(env NODE_OPTIONS={heap} node -e 'console.log(require("v8").getHeapStatistics().heap_size_limit)' 2>/dev/null) || effective_heap=NOT_AVAILABLE
printf '%s\\n' "$effective_heap" >"$forensic_dir/effective-v8-heap-limit.txt"
snapshot() {{
  {{
    printf 'captured_at_utc='; date -u +%Y-%m-%dT%H:%M:%S.%NZ 2>/dev/null || printf 'NOT_AVAILABLE\\n'
    for path in /sys/fs/cgroup/memory.max /sys/fs/cgroup/memory.current /sys/fs/cgroup/memory.peak /sys/fs/cgroup/memory.events /sys/fs/cgroup/memory.swap.max /sys/fs/cgroup/memory.swap.current; do
      printf '%s=' "$path"; if test -r "$path"; then cat "$path"; else printf 'NOT_AVAILABLE\\n'; fi
    done
  }} >"$1" 2>&1 || true
}}
event_value() {{
  if test -r /sys/fs/cgroup/memory.events; then awk -v key="$1" '$1 == key {{print $2}}' /sys/fs/cgroup/memory.events; else printf 'NOT_AVAILABLE\\n'; fi
}}
sample_once() {{
  timestamp=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ 2>/dev/null || printf NOT_AVAILABLE)
  current=$(cat /sys/fs/cgroup/memory.current 2>/dev/null || printf NOT_AVAILABLE)
  swap=$(cat /sys/fs/cgroup/memory.swap.current 2>/dev/null || printf NOT_AVAILABLE)
  low=$(event_value low); high=$(event_value high); max=$(event_value max); oom=$(event_value oom); oom_kill=$(event_value oom_kill)
  anon=$(awk '$1=="anon" {{print $2}}' /sys/fs/cgroup/memory.stat 2>/dev/null || true)
  file=$(awk '$1=="file" {{print $2}}' /sys/fs/cgroup/memory.stat 2>/dev/null || true)
  shmem=$(awk '$1=="shmem" {{print $2}}' /sys/fs/cgroup/memory.stat 2>/dev/null || true)
  kernel=$(awk '$1=="kernel" {{print $2}}' /sys/fs/cgroup/memory.stat 2>/dev/null || true)
  printf '%s\\t%s\\t%s\\t%s\\t%s\\t%s\\t%s\\t%s\\t%s\\t%s\\t%s\\t%s\\n' "$timestamp" "$current" "$swap" "$low" "$high" "$max" "$oom" "$oom_kill" "${{anon:-NOT_AVAILABLE}}" "${{file:-NOT_AVAILABLE}}" "${{shmem:-NOT_AVAILABLE}}" "${{kernel:-NOT_AVAILABLE}}"
}}
before_oom=$(event_value oom); before_oom_kill=$(event_value oom_kill); before_max=$(event_value max)
snapshot "$forensic_dir/tsc-1536-resource-before.txt"
printf 'timestamp\\tmemory.current\\tmemory.swap.current\\tevents.low\\tevents.high\\tevents.max\\tevents.oom\\tevents.oom_kill\\tstat.anon\\tstat.file\\tstat.shmem\\tstat.kernel\\n' >"$forensic_dir/tsc-1536-memory-timeseries.tsv"
stop_file="$forensic_dir/.sampler-stop"; rm -f "$stop_file"
( while test ! -e "$stop_file"; do sample_once >>"$forensic_dir/tsc-1536-memory-timeseries.tsv" || true; sleep 0.25; done ) &
sampler_pid=$!
if test -x /usr/bin/time; then
  env NODE_OPTIONS={heap} /usr/bin/time -v -o "$forensic_dir/tsc-1536-time.txt" {TSC_COMMAND} >"$forensic_dir/tsc-1536.stdout" 2>"$forensic_dir/tsc-1536.stderr"
else
  printf 'NOT_AVAILABLE\\n' >"$forensic_dir/tsc-1536-time.txt"
  env NODE_OPTIONS={heap} {TSC_COMMAND} >"$forensic_dir/tsc-1536.stdout" 2>"$forensic_dir/tsc-1536.stderr"
fi
tsc_status=$?
touch "$stop_file"; wait "$sampler_pid" 2>/dev/null || true; rm -f "$stop_file"
sample_once >>"$forensic_dir/tsc-1536-memory-timeseries.tsv" || true
snapshot "$forensic_dir/tsc-1536-resource-after.txt"
after_oom=$(event_value oom); after_oom_kill=$(event_value oom_kill); after_max=$(event_value max)
printf '%s\\n' "$tsc_status" >"$forensic_dir/tsc-1536-exit.txt"
observed_current_max=$(awk -F '\\t' 'NR>1 && $2~/^[0-9]+$/ {{if($2>max)max=$2; found=1}} END {{if(found)print max; else print "NOT_AVAILABLE"}}' "$forensic_dir/tsc-1536-memory-timeseries.tsv")
observed_swap_max=$(awk -F '\\t' 'NR>1 && $3~/^[0-9]+$/ {{if($3>max)max=$3; found=1}} END {{if(found)print max; else print "NOT_AVAILABLE"}}' "$forensic_dir/tsc-1536-memory-timeseries.tsv")
if printf '%s %s %s %s %s %s' "$before_oom" "$after_oom" "$before_oom_kill" "$after_oom_kill" "$before_max" "$after_max" | grep -Eqv '^([0-9]+ ){{5}}[0-9]+$'; then
  oom_delta=NOT_AVAILABLE; oom_kill_delta=NOT_AVAILABLE; max_delta=NOT_AVAILABLE; classification=TSC_HOST_1536_RESULT_INDETERMINATE
else
  oom_delta=$((after_oom-before_oom)); oom_kill_delta=$((after_oom_kill-before_oom_kill)); max_delta=$((after_max-before_max))
  if test "$oom_delta" -gt 0 || test "$oom_kill_delta" -gt 0; then classification=TSC_HOST_1536_CGROUP_OOM
  elif grep -Fq 'Allocation failed - JavaScript heap out of memory' "$forensic_dir/tsc-1536.stderr"; then classification=V8_HEAP_EXHAUSTION_IN_TSC_HOST_AT_1536
  elif test "$tsc_status" -eq 0; then classification=TSC_HOST_1536_HEAP_FEASIBLE
  else classification=TSC_HOST_1536_NONZERO_OTHER
  fi
fi
printf 'classification=%s\\ndiagnostic_complete=true\\ntsc_status=%s\\neffective_node_options=%s\\neffective_heap_size_limit_bytes=%s\\nTSC_OBSERVED_MEMORY_CURRENT_MAX=%s\\nTSC_OBSERVED_SWAP_CURRENT_MAX=%s\\nmemory_events_oom_delta=%s\\nmemory_events_oom_kill_delta=%s\\nmemory_events_max_delta=%s\\n' "$classification" "$tsc_status" '{DIAGNOSTIC_NODE_OPTIONS}' "$effective_heap" "$observed_current_max" "$observed_swap_max" "$oom_delta" "$oom_kill_delta" "$max_delta" >"$forensic_dir/substage-summary.txt"
exit "$tsc_status"
"""


class DshHarborTsc1536FeasibilityProbe(DshHarborAdapter):
    """Replace only the final build with a diagnostic TSC-only experiment."""

    async def exec_as_root(self, environment, command, env=None, cwd=None, timeout_sec=None):
        suffix = self.BUILD_COMMAND
        if "pnpm install --frozen-lockfile; " + suffix in command and command.endswith(suffix):
            command = command[:-len(suffix)] + tsc_1536_wrapper()
        return await super().exec_as_root(environment, command=command, env=env, cwd=cwd, timeout_sec=timeout_sec)

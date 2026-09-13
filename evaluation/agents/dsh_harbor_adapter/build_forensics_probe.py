"""Probe-only full-fidelity diagnostics around the frozen production install."""
from __future__ import annotations

import shlex

from .adapter import DshHarborAdapter

ARTIFACT_DIR = "/logs/artifacts/dsh-build-forensics"
SUBSTAGE_ARTIFACT_DIR = "/logs/artifacts/dsh-build-substage-forensics"


def forensic_wrapper(command: str, artifact_dir: str = ARTIFACT_DIR) -> str:
    """Wrap *command* observationally and preserve its exact exit status."""
    directory = shlex.quote(artifact_dir)
    payload = shlex.quote(command)
    remote = shlex.quote(str(DshHarborAdapter.REMOTE))
    package_json = shlex.quote(str(DshHarborAdapter.REMOTE / "package.json"))
    heap_options = shlex.quote(DshHarborAdapter.BUILD_NODE_OPTIONS)
    return f"""set +e
forensic_dir={directory}
mkdir -p "$forensic_dir"
snapshot() {{
  label="$1"; output="$forensic_dir/resources-$label.txt"
  {{
    printf 'captured_at_utc='; date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || printf 'NOT_AVAILABLE\\n'
    for path in /sys/fs/cgroup/memory.max /sys/fs/cgroup/memory.current /sys/fs/cgroup/memory.peak /sys/fs/cgroup/memory.events /sys/fs/cgroup/memory.swap.max /sys/fs/cgroup/memory.swap.current; do
      printf '%s=' "$path"; if test -r "$path"; then cat "$path"; else printf 'NOT_AVAILABLE\\n'; fi
    done
    printf 'proc_meminfo_begin\\n'; test -r /proc/meminfo && cat /proc/meminfo || printf 'NOT_AVAILABLE\\n'; printf 'proc_meminfo_end\\n'
    printf 'free_begin\\n'; command -v free >/dev/null 2>&1 && free -b || printf 'NOT_AVAILABLE\\n'; printf 'free_end\\n'
    printf 'ulimit_a_begin\\n'; ulimit -a 2>/dev/null || printf 'NOT_AVAILABLE\\n'; printf 'ulimit_a_end\\n'
  }} >"$output" 2>&1 || true
}}
snapshot before
printf '%s\\n' {payload} >"$forensic_dir/exact-install-build-command.txt"
bash -o pipefail -c {payload} >"$forensic_dir/full-build.stdout" 2>"$forensic_dir/full-build.stderr"
child_status=$?
snapshot after
{{ printf 'shell_exit_status=%s\\n' "$child_status"; printf 'child_command_exit_status=%s\\n' "$child_status"; printf 'signal_evidence=NOT_AVAILABLE\\n'; }} >"$forensic_dir/exit-status.txt"
{{
  printf 'working_directory='; pwd 2>/dev/null || printf 'NOT_AVAILABLE\\n'
  printf 'node='; node --version 2>/dev/null || printf 'NOT_AVAILABLE\\n'
  printf 'pnpm='; (cd {remote} && pnpm --version) 2>/dev/null || printf 'NOT_AVAILABLE\\n'
  printf 'corepack='; corepack --version 2>/dev/null || printf 'NOT_AVAILABLE\\n'
  printf 'dsh_commit='; git -C {remote} rev-parse HEAD 2>/dev/null || printf 'NOT_AVAILABLE\\n'
  package_manager=$(sed -n 's/.*"packageManager"[[:space:]]*:[[:space:]]*"\\([^"]*\\)".*/\\1/p' {package_json} 2>/dev/null | head -n 1) || package_manager=''
  printf 'package_manager=%s\\n' "${{package_manager:-NOT_AVAILABLE}}"
  printf 'effective_heap_size_limit_bytes='; env NODE_OPTIONS={heap_options} node -e 'console.log(require("v8").getHeapStatistics().heap_size_limit)' 2>/dev/null || printf 'NOT_AVAILABLE\\n'
  printf 'kernel='; uname -a 2>/dev/null || printf 'NOT_AVAILABLE\\n'
  printf 'architecture='; uname -m 2>/dev/null || printf 'NOT_AVAILABLE\\n'
  printf 'libc_begin\\n'; ldd --version 2>&1 || printf 'NOT_AVAILABLE\\n'; printf 'libc_end\\n'
}} >"$forensic_dir/toolchain.txt" 2>&1 || true
exit "$child_status"
"""


class DshHarborBuildForensicsProbe(DshHarborAdapter):
    """Keep production install inherited; observe only its build-bearing exec."""

    async def exec_as_root(self, environment, command, env=None, cwd=None, timeout_sec=None):
        suffix = self.BUILD_COMMAND
        if "pnpm install --frozen-lockfile; " + suffix in command and command.endswith(suffix):
            # Keep the preceding production install chain byte-for-byte and
            # observationally wrap only its exact final build command.
            command = command[:-len(suffix)] + forensic_wrapper(suffix)
        return await super().exec_as_root(
            environment, command=command, env=env, cwd=cwd, timeout_sec=timeout_sec
        )


def substage_wrapper(artifact_dir: str = SUBSTAGE_ARTIFACT_DIR) -> str:
    """Run the two exact host-build children sequentially with full evidence."""
    directory = shlex.quote(artifact_dir)
    heap = shlex.quote(DshHarborAdapter.BUILD_NODE_OPTIONS)
    tsc = "pnpm exec tsc -b tsconfig.host.json"
    tsdown = "pnpm exec tsdown --env.DSH_BUILD_FACE host"
    return f"""set +e
forensic_dir={directory}
mkdir -p "$forensic_dir"
if test "${{NODE_OPTIONS+x}}" = x; then
  printf 'classification=M1C_DSH_BUILD_NODE_OPTIONS_DRIFT\\ndiagnostic_complete=true\\ntsc_status=NOT_REACHED\\ntsdown_status=NOT_REACHED\\n' >"$forensic_dir/substage-summary.txt"
  exit 78
fi
snapshot() {{
  label="$1"; output="$forensic_dir/resources-$label.txt"
  {{
    printf 'effective_heap_size_limit_bytes='; env NODE_OPTIONS={heap} node -e 'console.log(require("v8").getHeapStatistics().heap_size_limit)' 2>/dev/null || printf 'NOT_AVAILABLE\\n'
    for path in /sys/fs/cgroup/memory.max /sys/fs/cgroup/memory.current /sys/fs/cgroup/memory.peak /sys/fs/cgroup/memory.events /sys/fs/cgroup/memory.swap.max /sys/fs/cgroup/memory.swap.current; do
      printf '%s=' "$path"; if test -r "$path"; then cat "$path"; else printf 'NOT_AVAILABLE\\n'; fi
    done
    printf 'proc_meminfo_begin\\n'; test -r /proc/meminfo && cat /proc/meminfo || printf 'NOT_AVAILABLE\\n'; printf 'proc_meminfo_end\\n'
    printf 'free_begin\\n'; command -v free >/dev/null 2>&1 && free -b || printf 'NOT_AVAILABLE\\n'; printf 'free_end\\n'
  }} >"$output" 2>&1 || true
}}
printf '%s\\n' {shlex.quote(tsc)} >"$forensic_dir/tsc-host.command.txt"
printf '%s\\n' {shlex.quote(tsdown)} >"$forensic_dir/tsdown-host.command.txt"
snapshot TSC_BEFORE
NODE_OPTIONS={heap} {tsc} >"$forensic_dir/tsc-host.stdout" 2>"$forensic_dir/tsc-host.stderr"
tsc_status=$?
snapshot TSC_AFTER
if test "$tsc_status" -ne 0; then
  if grep -Fq 'Allocation failed - JavaScript heap out of memory' "$forensic_dir/tsc-host.stderr"; then classification=V8_HEAP_EXHAUSTION_IN_TSC_HOST; else classification=TSC_HOST_NONZERO; fi
  printf 'NOT_REACHED\\n' >"$forensic_dir/tsdown-host.status.txt"
  : >"$forensic_dir/tsdown-host.stdout"; : >"$forensic_dir/tsdown-host.stderr"
  printf 'classification=%s\\ndiagnostic_complete=true\\ntsc_status=%s\\ntsdown_status=NOT_REACHED\\n' "$classification" "$tsc_status" >"$forensic_dir/substage-summary.txt"
  exit "$tsc_status"
fi
snapshot TSDOWN_BEFORE
NODE_OPTIONS={heap} {tsdown} >"$forensic_dir/tsdown-host.stdout" 2>"$forensic_dir/tsdown-host.stderr"
tsdown_status=$?
snapshot TSDOWN_AFTER
if test "$tsdown_status" -ne 0; then
  if grep -Fq 'Allocation failed - JavaScript heap out of memory' "$forensic_dir/tsdown-host.stderr"; then classification=V8_HEAP_EXHAUSTION_IN_TSDOWN_HOST; else classification=TSDOWN_HOST_NONZERO; fi
else
  classification=SUBSTAGE_SEPARATION_DID_NOT_REPRODUCE_COMPOSITE_FAILURE
fi
printf 'classification=%s\\ndiagnostic_complete=true\\ntsc_status=%s\\ntsdown_status=%s\\n' "$classification" "$tsc_status" "$tsdown_status" >"$forensic_dir/substage-summary.txt"
exit "$tsdown_status"
"""


class DshHarborBuildSubstageForensicsProbe(DshHarborAdapter):
    """Replace only the final production build with diagnostic child isolation."""

    async def exec_as_root(self, environment, command, env=None, cwd=None, timeout_sec=None):
        suffix = self.BUILD_COMMAND
        if "pnpm install --frozen-lockfile; " + suffix in command and command.endswith(suffix):
            command = command[:-len(suffix)] + substage_wrapper()
        return await super().exec_as_root(
            environment, command=command, env=env, cwd=cwd, timeout_sec=timeout_sec
        )

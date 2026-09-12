"""Probe-only full-fidelity diagnostics around the frozen production install."""
from __future__ import annotations

import shlex

from .adapter import DshHarborAdapter

ARTIFACT_DIR = "/logs/artifacts/dsh-build-forensics"


def forensic_wrapper(command: str, artifact_dir: str = ARTIFACT_DIR) -> str:
    """Wrap *command* observationally and preserve its exact exit status."""
    directory = shlex.quote(artifact_dir)
    payload = shlex.quote(command)
    remote = shlex.quote(str(DshHarborAdapter.REMOTE))
    package_json = shlex.quote(str(DshHarborAdapter.REMOTE / "package.json"))
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
  printf 'kernel='; uname -a 2>/dev/null || printf 'NOT_AVAILABLE\\n'
  printf 'architecture='; uname -m 2>/dev/null || printf 'NOT_AVAILABLE\\n'
  printf 'libc_begin\\n'; ldd --version 2>&1 || printf 'NOT_AVAILABLE\\n'; printf 'libc_end\\n'
}} >"$forensic_dir/toolchain.txt" 2>&1 || true
exit "$child_status"
"""


class DshHarborBuildForensicsProbe(DshHarborAdapter):
    """Keep production install inherited; observe only its build-bearing exec."""

    async def exec_as_root(self, environment, command, env=None, cwd=None, timeout_sec=None):
        suffix = "pnpm run build"
        if "pnpm install --frozen-lockfile; pnpm run build" in command and command.endswith(suffix):
            # Keep the preceding production install chain byte-for-byte and
            # observationally wrap only its exact final build command.
            command = command[:-len(suffix)] + forensic_wrapper(suffix)
        return await super().exec_as_root(
            environment, command=command, env=env, cwd=cwd, timeout_sec=timeout_sec
        )

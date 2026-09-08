#!/usr/bin/env python3
"""No-model Harbor install-only qualification for the frozen DSH adapter."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

from scripts import gha_m1c1_live_controller as live
from scripts.m1c_postlive_observability import build_partial_manifest, capture_raw, discover_trial, write_json

JOB_NAME = "m1c1-container-build-probe"


def probe(root: Path) -> int:
    for marker in ("MODEL_EXPOSURE_START", "PROVIDER_PATH_REACHED", "PROVIDER_REQUEST_START"):
        if (root / "reports" / marker).exists():
            raise RuntimeError(f"forbidden marker present: {marker}")
    command = live.harbor_command(root) + ["--install-only"]
    environment = live.harbor_environment(root)
    profile = (root / "configs/model_profile_deepseek_v4_pro_v1.yaml").read_text()
    credential_name = next(line.split(":", 1)[1].strip() for line in profile.splitlines() if line.startswith("credential_environment_name:"))
    environment.pop(credential_name, None)
    metadata = {
        "schema_version": 1, "task_id": live.TASK_ID, "job_name": JOB_NAME,
        "workflow_commit": os.environ.get("GITHUB_SHA", "NOT_AVAILABLE"),
        "dsh_commit": live.DSH_COMMIT, "harbor_version": live.HARBOR_VERSION,
        "harbor_command": command, "install_only": True, "adapter_run_guard": "HARBOR_INSTALL_ONLY",
        "provider_request_status": "PROVEN_ZERO", "provider_path_reached": False,
        "node_options_state": "UNSET" if not environment.get("NODE_OPTIONS") else "SET_VALUE_NOT_RECORDED",
        "runner_node": subprocess.run(["node", "--version"], capture_output=True, text=True).stdout.strip(),
        "runner_pnpm": subprocess.run(["pnpm", "--version"], capture_output=True, text=True).stdout.strip(),
    }
    write_json(root / "reports/container-build-probe-metadata.json", metadata)
    stdout, stderr = root / "work/runtime/container-build-stdout.txt", root / "work/runtime/container-build-stderr.txt"
    start = time.monotonic()
    with stdout.open("wb") as out, stderr.open("wb") as err:
        process = subprocess.run(command, stdout=out, stderr=err, env=environment)
    capture_raw(root, JOB_NAME, "", credential_name)
    discovery = discover_trial(root / "work/jobs", JOB_NAME)
    result = None
    if discovery.get("result_path"):
        try: result = json.loads(Path(discovery["result_path"]).read_text())
        except (OSError, ValueError): pass
    exception = (result or {}).get("exception_info")
    install_only = bool(((result or {}).get("config") or {}).get("install_only"))
    success = process.returncode == 0 and result is not None and exception is None and install_only
    summary = {
        "classification": "M1C_GHA_CONTAINER_BUILD_QUALIFIED" if success else "M1C_CONTAINER_BUILD_PROBE_FAILED",
        "success": success, "task_id": live.TASK_ID, "harbor_process_exit": process.returncode,
        "wall_seconds": round(time.monotonic() - start, 3), "result_discovery": discovery,
        "trial_result_present": result is not None, "trial_exception": exception,
        "install_only": install_only, "adapter_run_invoked": False, "dsh_live_sessions": 0,
        "provider_path_reached": False, "provider_request_status": "PROVEN_ZERO", "provider_request_count": 0,
        "verifier_invoked": False,
    }
    write_json(root / "reports/container-build-probe-summary.json", summary)
    write_json(root / "reports/container-build-process.json", {"exit_code": process.returncode, "wall_seconds": summary["wall_seconds"]})
    return 0 if success else 1


def stage(root: Path) -> int:
    expected = {name: "reports/" + name for name in (
        "container-build-probe-metadata.json", "container-build-probe-summary.json",
        "container-build-process.json", "raw-capture-manifest.json", "raw-evidence",
        "harbor-resolution.json", "adapter-pth-qualification.json", "dataset-resolution.json")}
    build_partial_manifest(root, root / "container-build-artifact-stage", expected)
    return 0


if __name__ == "__main__":
    root = Path.cwd().resolve()
    raise SystemExit(stage(root) if len(sys.argv) > 1 and sys.argv[1] == "stage" else probe(root))

#!/usr/bin/env python3
"""No-model Harbor install-only qualification for the frozen DSH adapter."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from scripts import gha_m1c1_live_controller as live
from scripts.m1c_postlive_observability import build_partial_manifest, capture_raw, discover_trial, write_json


def optional_command_metadata(command: list[str], runner=None) -> dict[str, object]:
    """Capture host diagnostics without turning them into production dependencies."""
    runner = runner or subprocess.run
    try:
        completed = runner(command, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        return {"status": "ABSENT", "value": "NOT_AVAILABLE"}
    except OSError as exc:
        return {"status": "ERROR", "value": "NOT_AVAILABLE", "error_type": type(exc).__name__}
    value = completed.stdout.strip()
    if completed.returncode != 0:
        return {"status": "ERROR", "value": "NOT_AVAILABLE", "exit_code": completed.returncode}
    return {"status": "PRESENT", "value": value or "NOT_AVAILABLE"}


def optional_file_metadata(path: Path) -> dict[str, object]:
    """Capture optional runner filesystem metadata with an explicit status."""
    try:
        return {"status": "PRESENT", "value": path.read_text().strip() or "NOT_AVAILABLE"}
    except FileNotFoundError:
        return {"status": "ABSENT", "value": "NOT_AVAILABLE"}
    except OSError as exc:
        return {"status": "ERROR", "value": "NOT_AVAILABLE", "error_type": type(exc).__name__}


def authoritative_job_name(command: list[str]) -> str:
    values = [command[index + 1] for index, item in enumerate(command[:-1]) if item == "--job-name"]
    if len(values) != 1 or values[0] != live.JOB_NAME:
        raise RuntimeError("M1C_CONTAINER_BUILD_JOB_NAME_CONTRACT_MISMATCH")
    return live.JOB_NAME


def discover_intended_trial(jobs_dir: Path, job_name: str, task_id: str) -> dict:
    discovery = discover_trial(jobs_dir, job_name)
    discovery.update(job_name=job_name, task_id=task_id)
    trial_id = discovery.get("trial_id")
    task_slug = task_id.rsplit("/", 1)[-1]
    if discovery.get("status") == "PRESENT" and not (
        trial_id == task_slug or str(trial_id).startswith(task_slug + "__")
    ):
        return {
            "status": "PARSE_FAILED", "trial_dir": None, "trial_id": None,
            "result_path": None, "candidate_count": discovery.get("candidate_count", 0),
            "job_name": job_name, "task_id": task_id,
            "blocker": "M1C_HARBOR_TRIAL_TASK_MISMATCH",
        }
    return discovery


def probe(root: Path) -> int:
    for marker in ("MODEL_EXPOSURE_START", "PROVIDER_PATH_REACHED", "PROVIDER_REQUEST_START"):
        if (root / "reports" / marker).exists():
            raise RuntimeError(f"forbidden marker present: {marker}")
    command = live.harbor_command(root) + ["--install-only"]
    job_name = authoritative_job_name(command)
    environment = live.harbor_environment(root)
    profile = (root / "configs/model_profile_deepseek_v4_pro_v1.yaml").read_text()
    credential_name = next(line.split(":", 1)[1].strip() for line in profile.splitlines() if line.startswith("credential_environment_name:"))
    environment.pop(credential_name, None)
    metadata = {
        "schema_version": 1, "task_id": live.TASK_ID, "job_name": job_name,
        "workflow_commit": os.environ.get("GITHUB_SHA", "NOT_AVAILABLE"),
        "dsh_commit": live.DSH_COMMIT, "harbor_version": live.HARBOR_VERSION,
        "harbor_command": command, "install_only": True, "adapter_run_guard": "HARBOR_INSTALL_ONLY",
        "provider_request_status": "PROVEN_ZERO", "provider_path_reached": False,
        "node_options_state": "UNSET" if not environment.get("NODE_OPTIONS") else "SET_VALUE_NOT_RECORDED",
        "runner_node": optional_command_metadata(["node", "--version"]),
        "runner_pnpm": optional_command_metadata(["pnpm", "--version"]),
        "runner_cgroup_memory_max": optional_file_metadata(Path("/sys/fs/cgroup/memory.max")),
        "metadata_classification": {
            "runner_node": "OPTIONAL_DIAGNOSTIC_METADATA",
            "runner_pnpm": "OPTIONAL_DIAGNOSTIC_METADATA",
            "runner_cgroup_memory_max": "OPTIONAL_DIAGNOSTIC_METADATA",
            "harbor_install_only_command": "REQUIRED_FOR_PROBE_EXECUTION",
        },
    }
    write_json(root / "reports/container-build-probe-metadata.json", metadata)
    stdout, stderr = root / "work/runtime/container-build-stdout.txt", root / "work/runtime/container-build-stderr.txt"
    start = time.monotonic()
    with stdout.open("wb") as out, stderr.open("wb") as err:
        process = subprocess.run(command, stdout=out, stderr=err, env=environment)
    capture_raw(root, job_name, "", credential_name)
    discovery = discover_intended_trial(root / "work/jobs", job_name, live.TASK_ID)
    result = None
    if discovery.get("result_path"):
        try: result = json.loads(Path(discovery["result_path"]).read_text())
        except (OSError, ValueError): pass
    exception = (result or {}).get("exception_info")
    install_only = bool(((result or {}).get("config") or {}).get("install_only"))
    success = process.returncode == 0 and result is not None and exception is None and install_only
    summary = {
        "classification": "M1C_GHA_CONTAINER_BUILD_QUALIFIED" if success else "M1C_CONTAINER_BUILD_PROBE_FAILED",
        "success": success, "task_id": live.TASK_ID, "job_name": job_name,
        "harbor_process_exit": process.returncode,
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
    manifest = build_partial_manifest(root, root / "container-build-artifact-stage", expected)
    manifest["job_name"] = live.JOB_NAME
    write_json(root / "container-build-artifact-stage/EVIDENCE_MANIFEST.json", manifest)
    return 0


if __name__ == "__main__":
    root = Path.cwd().resolve()
    raise SystemExit(stage(root) if len(sys.argv) > 1 and sys.argv[1] == "stage" else probe(root))

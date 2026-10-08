#!/usr/bin/env python3
"""Local history/input gate and safe summary; no container operations."""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_PARENT = "1402698ce46653f24381baebca9588bae2b1ab1e"
FROZEN_SOURCE = "scripts/gha_m1c1_runtime_fingerprint.py"
SUITES = (
    "evaluation.tests.test_m1c_four_image_preflight",
    "evaluation.tests.test_m1c_four_image_loader_probe",
    "evaluation.tests.test_m1c_loader_identity",
    "evaluation.tests.test_m1c_runtime_fingerprint",
)


class GateError(Exception):
    def __init__(self, reason: str, exit_code: int = 1):
        self.reason = reason
        self.exit_code = exit_code


def git(root: Path, *args: str) -> bytes:
    result = subprocess.run(["git", *args], cwd=root, capture_output=True, check=False)
    if result.returncode:
        # Never propagate raw Git diagnostics into the safe lane.
        raise GateError("CHECKOUT_SHALLOW_HISTORY_PREFLIGHT_BLOCKER", result.returncode)
    return result.stdout.strip()


def validate_history(root: Path, expected_head: str) -> dict:
    if not re.fullmatch(r"[0-9a-f]{40}", expected_head):
        raise GateError("EXPECTED_HEAD_IDENTITY_INVALID")
    head = git(root, "rev-parse", "HEAD").decode()
    if head != expected_head:
        raise GateError("HEAD_IDENTITY_MISMATCH")
    for revision in (head, REQUIRED_PARENT):
        if git(root, "cat-file", "-t", revision) != b"commit":
            raise GateError("REQUIRED_GIT_OBJECT_NOT_COMMIT")
    parent = git(root, "rev-parse", "HEAD^").decode()
    if parent != REQUIRED_PARENT:
        raise GateError("DIRECT_PARENT_IDENTITY_MISMATCH")
    prior = subprocess.run(["git", "show", REQUIRED_PARENT + ":" + FROZEN_SOURCE],
                           cwd=root, capture_output=True, check=False)
    if prior.returncode:
        raise GateError("REQUIRED_HISTORY_FILE_UNAVAILABLE", prior.returncode)
    if prior.stdout != (root / FROZEN_SOURCE).read_bytes():
        raise GateError("FROZEN_CENSUS_SOURCE_DRIFT")
    return {"head_sha": head, "required_parent_sha": parent,
            "object_types": "commit", "required_history": "PASS"}


def validate_inputs() -> dict:
    spec = importlib.util.spec_from_file_location("preflight_four_probe", ROOT / "scripts/gha_m1c1_four_image_loader_probe.py")
    probe = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(probe)
    rows = probe.select_images()
    if tuple(row["task"] for row in rows) != probe.TASKS:
        raise GateError("FROZEN_SELECTION_IDENTITY_FAILURE")
    return {"tasks": list(probe.TASKS), "stable_pool_sha256": probe.rf.STABLE_POOL_SHA256,
            "snapshot_sha256": probe.rf.HISTORICAL_MAP_SHA256,
            "mapping_sha256": probe.rf.HISTORICAL_MAPPING_SHA256, "frozen_inputs": "PASS"}


def safe_id(value: str, pattern: str) -> str:
    return value if re.fullmatch(pattern, value) else "NOT_AVAILABLE"


def run_preflight(reports: Path, expected_head: str) -> dict:
    if reports.exists():
        raise GateError("PREFLIGHT_OUTPUT_ALREADY_EXISTS")
    reports.mkdir(parents=True)
    summary = {"schema_version": "m1c_four_image_preflight_v1",
               "classification": "FOUR_IMAGE_LOADER_IDENTITY_EVIDENCE_INDETERMINATE",
               "run_id": safe_id(os.environ.get("GITHUB_RUN_ID", ""), r"[0-9]+"),
               "run_attempt": safe_id(os.environ.get("GITHUB_RUN_ATTEMPT", ""), r"[0-9]+"),
               "expected_head_sha": safe_id(expected_head, r"[0-9a-f]{40}"),
               "required_parent_sha": REQUIRED_PARENT, "stage": "HISTORY",
               "preflight": "FAIL", "probe_status": "NOT_REACHED",
               "provider_requests": 0, "deepseek_requests": 0, "dsh_executions": 0,
               "benchmark_task_executions": 0, "oracle_executions": 0, "verifier_executions": 0}
    try:
        summary.update(validate_history(ROOT, expected_head))
        summary["stage"] = "FROZEN_INPUTS"
        summary.update(validate_inputs())
        summary["stage"] = "REGRESSION_TESTS"
        result = subprocess.run([sys.executable, "-m", "unittest", *SUITES, "-v"], cwd=ROOT, check=False)
        if result.returncode:
            raise GateError("PREFLIGHT_REGRESSION_FAILURE", result.returncode)
        summary["stage"] = "PUBLIC_SOURCE_SCAN"
        result = subprocess.run([sys.executable, "scripts/public_secret_scan.py", "."], cwd=ROOT, check=False)
        if result.returncode:
            raise GateError("PREFLIGHT_PUBLIC_SOURCE_SCAN_FAILURE", result.returncode)
        summary.update(stage="COMPLETED", preflight="PASS", exit_code=0, reason="NONE")
    except GateError as exc:
        summary.update(reason=exc.reason, exit_code=exc.exit_code)
    except Exception:
        # No exception message, arbitrary output, environment or credentials.
        summary.update(reason="PREFLIGHT_EVIDENCE_UNAVAILABLE", exit_code=1)
    (reports / "preflight-summary.json").write_text(json.dumps(summary, sort_keys=True, indent=2) + "\n")
    # Independent workflow scanner must accept this lane before upload.
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--reports", type=Path, required=True)
    args = parser.parse_args()
    result = run_preflight(args.reports, args.expected_head)
    print(json.dumps({"preflight": result["preflight"], "stage": result["stage"], "reason": result["reason"]}))
    return 0 if result["preflight"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Fail-closed controller for the single M1C.1 live integration smoke."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

try:
    from m1c_postlive_observability import (
        build_partial_manifest, build_safe_core, capture_raw, discover_trial, parse_result, provider_evidence, write_json,
    )
except ModuleNotFoundError:  # importlib-based repository tests
    from scripts.m1c_postlive_observability import (
        build_partial_manifest, build_safe_core, capture_raw, discover_trial, parse_result, provider_evidence, write_json,
    )

SELECTION_RECORD = Path(__file__).parents[1] / "configs/m1c_integration_task_v3.json"
TASK_ID = json.loads(SELECTION_RECORD.read_text())["selected_task_id"]
DATASET = "terminal-bench/terminal-bench-2-1@sha256:7d7bdc1cbedad549fc1140404bd4dc45e5fd0ea7c4186773687d177ad3a0699a"
DSH_COMMIT = "b150a551b8d465e31e418e1b2eaf5e79bbb7d28e"
PROFILE_SHA256 = "2102539e0c35c4168f2c91b2383f95e39042576a64612060e55a126a57bf7f4e"
HARBOR_VERSION = "0.21.0"
AGENT = "evaluation.agents.dsh_harbor_adapter.adapter:DshHarborAdapter"
JOB_NAME = "m1c1-live-single"
UNEXPOSED = "UNEXPOSED"
EXPOSED = "MODEL_EXPOSED_INTEGRATION_ONLY"
INDETERMINATE = "EXPOSURE_INDETERMINATE_AFTER_LIVE_ARTIFACT_LOSS"


def sanitize_text(text: str, credential: str) -> str:
    if credential:
        text = text.replace(credential, "[REDACTED]")
    return "\n".join(
        "[REDACTED AUTH HEADER]" if line.lower().lstrip().startswith("authoriz" + "ation:") else line
        for line in text.splitlines()
    ) + ("\n" if text.endswith("\n") else "")


def sanitize_value(value: object, credential: str) -> object:
    if isinstance(value, dict):
        return {key: sanitize_value(item, credential) for key, item in value.items() if key.lower() not in {"authoriz" + "ation", "coo" + "kie"}}
    if isinstance(value, list):
        return [sanitize_value(item, credential) for item in value]
    if isinstance(value, str):
        return sanitize_text(value, credential)
    return value


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def harbor_environment(root: Path) -> dict[str, str]:
    env = os.environ.copy()
    raw_source = env.get("ADAPTER_SOURCE_ROOT", "")
    source = Path(raw_source)
    expected = root.resolve()
    if not raw_source or not source.is_absolute() or source.resolve() != expected:
        raise RuntimeError("M1C_ADAPTER_SOURCE_ROOT_INVALID")
    if not (expected / "evaluation/agents/dsh_harbor_adapter/adapter.py").is_file():
        raise RuntimeError("M1C_ADAPTER_SOURCE_ROOT_MISSING")
    prior = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = str(expected) + (os.pathsep + prior if prior else "")
    return env


def exposure_classification(marker_present: bool, provider_request_count: int | None) -> str:
    if marker_present and isinstance(provider_request_count, int) and provider_request_count >= 1:
        return EXPOSED
    if marker_present and provider_request_count is None:
        return INDETERMINATE
    return UNEXPOSED


def harbor_command(root: Path) -> list[str]:
    candidate = json.loads((root / "work/candidate/adapter_smoke_h0/manifest.json").read_text())
    patch = (root / "work/candidate/adapter_smoke_h0/candidate.cordis.patch.yml").read_text()
    profile = (root / "configs/model_profile_deepseek_v4_pro_v1.yaml").read_text()
    credential_name = next(
        line.split(":", 1)[1].strip() for line in profile.splitlines()
        if line.startswith("credential_environment_name:")
    )
    config = json.dumps({
        "base_dsh_commit": DSH_COMMIT,
        "cordis_patch": patch,
        "credential_environment_name": credential_name,
        "timeout_sec": 1800,
    }, separators=(",", ":"))
    write_json(root / "reports/candidate-identity.json", candidate)
    return [
        "harbor", "run", "--dataset", DATASET,
        "--include-task-name", TASK_ID,
        "--agent", AGENT, "--agent-kwarg", f"config={config}",
        "--model", "deepseek-v4-pro", "--env", "docker",
        "--n-concurrent", "1", "--n-attempts", "1", "--max-retries", "0",
        "--job-name", JOB_NAME, "--jobs-dir", str(root / "work/jobs"), "--yes",
    ]


def preflight(root: Path) -> int:
    profile = root / "configs/model_profile_deepseek_v4_pro_v1.yaml"
    selection = json.loads((root / "configs/m1c_integration_task_v3.json").read_text())
    exclusions_path = root / "configs/experiment_task_exclusions_v1.json"
    exclusions = json.loads(exclusions_path.read_text())
    eligible = selection.get("eligible_task_ids", [])
    eligible_hash = hashlib.sha256(("\n".join(eligible) + "\n").encode()).hexdigest()
    excluded_ids = {entry.get("task_id") for entry in exclusions.get("exclusions", [])}
    actual_profile = sha256(profile)
    if actual_profile != PROFILE_SHA256:
        write_json(root / "reports/pre-model-gate.json", {"status": "FAIL", "classification": "M1C_MODEL_PROFILE_DRIFT", "actual": actual_profile, "expected": PROFILE_SHA256})
        return 2
    dsh = Path(os.environ["DSH_SOURCE"])
    adapter_source = Path(os.environ.get("ADAPTER_SOURCE_ROOT", ""))
    no_model = os.environ.get("M1C_NO_MODEL_PREFLIGHT") == "true"
    checks = {
        "runner": os.environ.get("ImageOS") == "ubuntu24",
        "harbor": subprocess.run(["harbor", "--version"], text=True, capture_output=True).stdout.strip() == HARBOR_VERSION,
        "dsh_commit": subprocess.run(["git", "-C", str(dsh), "rev-parse", "HEAD"], text=True, capture_output=True).stdout.strip() == DSH_COMMIT,
        "dsh_clean": not subprocess.run(["git", "-C", str(dsh), "status", "--porcelain", "--untracked-files=no"], text=True, capture_output=True).stdout.strip(),
        "profile_sha": True,
        "selection_task": selection.get("selected_task_id") == TASK_ID,
        "selection_count": selection.get("eligible_count") == 22 == len(eligible),
        "selection_order": eligible == sorted(eligible, key=lambda value: value.encode("utf-8")),
        "selection_order_sha": selection.get("eligible_order_sha256") == eligible_hash,
        "selection_exclusion_sha": selection.get("exclusion_config_sha") == sha256(exclusions_path),
        "selection_not_excluded": TASK_ID not in excluded_ids,
        "credential_contract": (
            os.environ.get("M1C_SECRET_AVAILABLE") == "true"
            if not no_model
            else not os.environ.get("DEEPSEEK_" + "API_KEY")
        ),
        "runtime_outside_dsh": dsh.resolve() not in (root / "work/runtime").resolve().parents,
        "adapter_source_absolute": adapter_source.is_absolute(),
        "adapter_source_exact": adapter_source.resolve() == root.resolve(),
        "adapter_source_present": (adapter_source / "evaluation/agents/dsh_harbor_adapter/adapter.py").is_file(),
    }
    try:
        from evaluation.agents.dsh_harbor_adapter import DshHarborAdapter
        checks["adapter_import"] = DshHarborAdapter.name() == "dsh-harbor-adapter-v1"
        checks["adapter_registration"] = bool(DshHarborAdapter.SUPPORTS_ATIF)
        command = harbor_command(root)
        checks["harness_materialization"] = (root / "work/candidate/adapter_smoke_h0/manifest.json").is_file()
        checks["single_task"] = command.count(TASK_ID) == 1
        checks["single_attempt"] = command[command.index("--n-attempts") + 1] == "1" and command[command.index("--max-retries") + 1] == "0"
    except Exception as exc:
        checks["adapter_or_materialization"] = False
        write_json(root / "reports/pre-model-gate-exception.json", {"type": type(exc).__name__, "message": str(exc)})
    ok = all(checks.values())
    write_json(root / "reports/pre-model-gate.json", {"status": "PASS" if ok else "FAIL", "mode": "NO_MODEL" if no_model else "LIVE", "checks": checks, "model_profile_sha256": actual_profile, "dsh_commit": DSH_COMMIT, "harbor_version": HARBOR_VERSION})
    if ok:
        (root / "reports/PRE_MODEL_GATE_COMPLETED").write_text("PRE_MODEL_GATE_COMPLETED\n")
    return 0 if ok else 1


def run_live(root: Path) -> int:
    gate = root / "reports/PRE_MODEL_GATE_COMPLETED"
    if not gate.is_file():
        raise SystemExit("pre-model gate marker absent")
    stdout = root / "work/runtime/stdout.txt"
    stderr = root / "work/runtime/stderr.txt"
    exposure = root / "reports/MODEL_EXPOSURE_START"
    exposure.write_text("MODEL_EXPOSURE_START\n")
    start = time.monotonic()
    with stdout.open("wb") as out, stderr.open("wb") as err:
        proc = subprocess.run(harbor_command(root), stdout=out, stderr=err, env=harbor_environment(root))
    profile = (root / "configs/model_profile_deepseek_v4_pro_v1.yaml").read_text()
    credential_name = next(line.split(":", 1)[1].strip() for line in profile.splitlines() if line.startswith("credential_environment_name:"))
    credential = os.environ.get(credential_name, "")
    # Raw-first: preserve the process streams and complete Harbor job tree before
    # any TrialResult parsing or normalization can fail.
    capture_raw(root, JOB_NAME, credential, credential_name)
    for source in (stdout, stderr):
        (root / "reports" / f"sanitized-{source.name}").write_text(sanitize_text(source.read_text(errors="replace"), credential))
    job = root / "work/jobs" / JOB_NAME
    trials = sorted(path for path in job.iterdir() if path.is_dir()) if job.is_dir() else []
    if len(trials) == 1 and (trials[0] / "result.json").is_file():
        try:
            raw_result = json.loads((trials[0] / "result.json").read_text())
            write_json(root / "reports/sanitized-trial-result.json", sanitize_value(raw_result, credential))
        except (OSError, ValueError):
            pass
        agent_logs = trials[0] / "agent"
        if agent_logs.is_dir():
            safe_events = root / "reports/sanitized-dsh-events"
            for source in sorted(path for path in agent_logs.rglob("*") if path.is_file() and path.stat().st_size <= 20_000_000):
                relative = source.relative_to(agent_logs)
                target = safe_events / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(sanitize_text(source.read_text(errors="replace"), credential))
    write_json(root / "reports/harbor-process.json", {"exit_code": proc.returncode, "wall_seconds": round(time.monotonic() - start, 3), "job_name": JOB_NAME})
    return proc.returncode


def normalize_trial(root: Path, trial: Path, runner=subprocess.run) -> tuple[dict | None, str]:
    normalized_path = root / "reports/normalizer-v2.json"
    try:
        completed = runner([sys.executable, str(root / "evaluation/normalize_outcome_v2.py"),
                            str(trial), "--output", str(normalized_path)], check=False)
        if completed.returncode != 0 or not normalized_path.is_file():
            return None, "PARSE_FAILED"
        value = json.loads(normalized_path.read_text())
        return (value, "PRESENT") if isinstance(value, dict) else (None, "PARSE_FAILED")
    except Exception as exc:
        write_json(root / "reports/normalizer-error.json", {"type": type(exc).__name__, "message": str(exc)})
        return None, "PARSE_FAILED"


def summarize(root: Path) -> int:
    process_path = root / "reports/harbor-process.json"
    process = json.loads(process_path.read_text()) if process_path.is_file() else {"exit_code": None, "wall_seconds": None}
    discovery = discover_trial(root / "work/jobs", JOB_NAME)
    trial = Path(discovery["trial_dir"]) if discovery.get("trial_dir") else None
    result, result_status = parse_result(discovery)
    normalized = None
    normalizer_status = "NOT_REACHED"
    if trial and result_status == "PRESENT":
        normalized, normalizer_status = normalize_trial(root, trial)
    verifier = result.get("verifier_result") if isinstance(result, dict) else None
    reward = (verifier.get("rewards") or {}).get("reward") if isinstance(verifier, dict) else None
    exception = result.get("exception_info") if isinstance(result, dict) else None
    request_evidence = provider_evidence(root / "reports/raw-evidence")
    summary = {
        "task_id": TASK_ID, "maximum_intended_trials": 1, "actual_trial_count": discovery.get("candidate_count", 0),
        "harbor_process_exit": process.get("exit_code"), "harbor_trial_id": trial.name if trial else None,
        "result_discovery": discovery, "trial_result_status": result_status,
        "trial_result_present": result is not None, "trial_exception_info": exception,
        "raw_reward": reward, "verifier_result_present": verifier is not None,
        "normalizer_status": normalizer_status,
        "normalizer_outcome": normalized.get("outcome") if normalized else None,
        "normalizer_reason": normalized.get("reason_code") if normalized else None,
        "dsh_session_id": ((result or {}).get("agent_info") or {}).get("session_id"),
        "dsh_process_exit": None, "dsh_event_log_status": "captured_if_present",
        "tool_event_count": None, "api_request_count": request_evidence["provider_request_count"],
        "provider_request_evidence": request_evidence, "token_usage": None,
        "wall_seconds": process.get("wall_seconds"), "timeout_evidence": None,
        "pre_model_gate_completed": (root / "reports/PRE_MODEL_GATE_COMPLETED").is_file(),
        "model_exposure_started": (root / "reports/MODEL_EXPOSURE_START").is_file(),
    }
    write_json(root / "reports/live-summary.json", summary)
    integration_green = discovery.get("candidate_count") == 1 and result is not None and verifier is not None and normalized and normalized.get("outcome") in {"PASS", "TASK_FAIL"} and not exception
    exposure = exposure_classification(bool(summary["model_exposure_started"]), summary["api_request_count"])
    write_json(root / "reports/post-live-decision.json", {
        "classification": "M1C_LIVE_TRIAL_GREEN" if integration_green else "M1C_LIVE_TRIAL_NOT_GREEN",
        "exposure_classification": exposure,
        "create_private_exclusion_after_authorized_retrieval": exposure == EXPOSED,
        "exclusion_classification": EXPOSED if exposure == EXPOSED else None,
        "adapter_freeze_allowed": integration_green,
    })
    return 0 if integration_green else 1


def stage(root: Path) -> int:
    expected = {
        name: "reports/" + name for name in (
            "runner.txt", "pre-model-gate.json", "PRE_MODEL_GATE_COMPLETED", "MODEL_EXPOSURE_START",
            "candidate-identity.json", "harbor-process.json", "raw-capture-manifest.json", "raw-evidence",
            "normalizer-v2.json", "normalizer-error.json", "live-summary.json", "post-live-decision.json",
            "frozen-evaluator", "evaluator-core.sha256", "adapter-source.sha256", "model-profile.sha256",
            "dataset-resolution.json", "harbor-resolution.json", "adapter-pth-qualification.json",
            "sanitized-stdout.txt", "sanitized-stderr.txt", "sanitized-trial-result.json",
            "sanitized-dsh-events",
        )
    }
    build_partial_manifest(root, root / "bulk-artifact-stage", expected)
    return 0


def safe_core(root: Path) -> int:
    build_safe_core(root, JOB_NAME, TASK_ID)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("preflight", "run-live", "summarize", "safe-core", "stage"))
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    root = args.root.resolve()
    return {"preflight": preflight, "run-live": run_live, "summarize": summarize,
            "safe-core": safe_core, "stage": stage}[args.action](root)


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Conservatively normalize one Harbor 0.21.0 trial outcome.

This controller-owned classifier never edits the input trial. It uses only
structured Harbor fields and a deliberately small set of explicit artifact
signatures backed by captured Milestone 1B evidence.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


CLASSIFIER_VERSION = "1.0.0"

AGENT_TIMEOUT_EXCEPTIONS = {"AgentTimeoutError"}
AGENT_ERROR_EXCEPTIONS = {
    "NonZeroAgentExitCodeError",
    "ApiError",
    "ApiRateLimitError",
    "ApiUsageLimitError",
    "ApiInternalServerError",
    "ApiOverloadedError",
    "ApiConnectionClosedError",
    "ApiResponseStalledError",
    "OutputTokenExceededError",
    "ContextWindowExceededError",
    "UnknownApiError",
    "ApiProviderResourceNotFoundError",
    "AgentSafetyRefusalError",
    "AgentAuthenticationError",
    "ModelNotFoundError",
    "NetworkConnectionError",
}
ENVIRONMENT_EXCEPTIONS = {"EnvironmentStartTimeoutError"}
CONTAINER_EXCEPTIONS = {"SandboxBuildFailedError", "HealthcheckError"}
VERIFIER_TIMEOUT_EXCEPTIONS = {"VerifierTimeoutError"}
VERIFIER_PROCESS_EXCEPTIONS = {
    "AddTestsDirError",
    "DownloadVerifierDirError",
    "RewardFileNotFoundError",
    "RewardFileEmptyError",
    "VerifierOutputParseError",
}

# This conjunction is intentionally specific to the captured regex-log event.
UV_NETWORK_SIGNATURES = (
    "downloading uv 0.9.5 x86_64-unknown-linux-gnu",
    "curl: (56) Failure when receiving data from the peer",
    "failed to download https://github.com/astral-sh/uv/releases/download/0.9.5/",
)


def _read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _raw_reward(result: dict[str, Any]) -> float | int | None:
    verifier_result = result.get("verifier_result")
    if not isinstance(verifier_result, dict):
        return None
    rewards = verifier_result.get("rewards")
    if not isinstance(rewards, dict):
        return None
    reward = rewards.get("reward")
    return reward if isinstance(reward, (int, float)) and not isinstance(reward, bool) else None


def _exception_type(exception_info: Any) -> str | None:
    if isinstance(exception_info, dict) and isinstance(exception_info.get("exception_type"), str):
        return exception_info["exception_type"]
    return None


def _evidence(path: Path) -> str:
    return str(path.resolve())


def _ctrf_summary(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        data = _read_json(path)
        summary = data["results"]["summary"]
    except (OSError, ValueError, KeyError, TypeError):
        return None
    return summary if isinstance(summary, dict) else None


def _reward_artifact(trial_dir: Path) -> tuple[float | int | None, Path | None]:
    json_path = trial_dir / "verifier" / "reward.json"
    text_path = trial_dir / "verifier" / "reward.txt"
    try:
        if json_path.is_file():
            data = _read_json(json_path)
            value = data.get("reward") if isinstance(data, dict) else None
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                return value, json_path
        if text_path.is_file():
            value = float(text_path.read_text(encoding="utf-8").strip())
            return value, text_path
    except (OSError, ValueError, TypeError):
        pass
    return None, None


def classify_trial(trial_dir: Path) -> dict[str, Any]:
    trial_dir = trial_dir.resolve()
    result_path = trial_dir / "result.json"
    if not result_path.is_file():
        raise FileNotFoundError(f"Harbor trial result not found: {result_path}")

    result = _read_json(result_path)
    if not isinstance(result, dict):
        raise ValueError("Harbor trial result must be a JSON object")

    reward = _raw_reward(result)
    exception_info = result.get("exception_info")
    exception_type = _exception_type(exception_info)
    evidence = [_evidence(result_path)]
    outcome = "UNCLASSIFIED"
    reason_code = "INSUFFICIENT_EVIDENCE"

    environment_type = (
        result.get("config", {}).get("environment", {}).get("type")
        if isinstance(result.get("config"), dict)
        else None
    )

    if exception_type in CONTAINER_EXCEPTIONS and environment_type == "docker":
        outcome, reason_code = "CONTAINER_ERROR", "EXPLICIT_DOCKER_ENVIRONMENT_EXCEPTION"
    elif exception_type in ENVIRONMENT_EXCEPTIONS or exception_type in CONTAINER_EXCEPTIONS:
        outcome, reason_code = "ENVIRONMENT_ERROR", "EXPLICIT_ENVIRONMENT_EXCEPTION"
    elif exception_type in AGENT_TIMEOUT_EXCEPTIONS:
        outcome, reason_code = "AGENT_TIMEOUT", "EXPLICIT_AGENT_TIMEOUT"
    elif exception_type in AGENT_ERROR_EXCEPTIONS:
        outcome, reason_code = "AGENT_ERROR", "EXPLICIT_AGENT_EXCEPTION"
    elif exception_type in VERIFIER_TIMEOUT_EXCEPTIONS:
        outcome, reason_code = "VERIFIER_INFRA_ERROR", "VERIFIER_TIMEOUT"
    elif exception_type in VERIFIER_PROCESS_EXCEPTIONS:
        outcome, reason_code = "VERIFIER_INFRA_ERROR", "VERIFIER_PROCESS_CRASH"
    else:
        verifier_stdout = trial_dir / "verifier" / "test-stdout.txt"
        stdout_text = ""
        if verifier_stdout.is_file():
            stdout_text = verifier_stdout.read_text(encoding="utf-8", errors="replace")

        if all(signature in stdout_text for signature in UV_NETWORK_SIGNATURES):
            outcome = "VERIFIER_INFRA_ERROR"
            reason_code = "VERIFIER_DEPENDENCY_NETWORK_FAILURE"
            evidence.append(_evidence(verifier_stdout))
        elif exception_type is None and reward == 1.0:
            artifact_reward, reward_path = _reward_artifact(trial_dir)
            if artifact_reward == reward and reward_path is not None:
                outcome, reason_code = "PASS", "VALID_VERIFIER_REWARD_SUCCESS"
                evidence.append(_evidence(reward_path))
        elif exception_type is None and reward == 0.0:
            ctrf_path = trial_dir / "verifier" / "ctrf.json"
            summary = _ctrf_summary(ctrf_path)
            failed = summary.get("failed") if summary else None
            tests = summary.get("tests") if summary else None
            if isinstance(failed, int) and failed > 0 and isinstance(tests, int) and tests > 0:
                outcome = "TASK_FAIL"
                reason_code = "VALID_VERIFIER_EXECUTION_TASK_INCORRECT"
                evidence.append(_evidence(ctrf_path))

    return {
        "outcome": outcome,
        "raw_reward": reward,
        "raw_exception_info": exception_info,
        "original_trial_path": str(trial_dir),
        "reason_code": reason_code,
        "evidence": evidence,
        "classifier_version": CLASSIFIER_VERSION,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trial_dir", type=Path)
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Output path outside the immutable Harbor trial directory",
    )
    args = parser.parse_args()

    trial_dir = args.trial_dir.resolve()
    output = args.output.resolve()
    if output == trial_dir or trial_dir in output.parents:
        parser.error("--output must be outside the immutable Harbor trial directory")

    normalized = classify_trial(trial_dir)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(normalized, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

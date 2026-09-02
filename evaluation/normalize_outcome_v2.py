#!/usr/bin/env python3
"""Outcome Normalizer v2: conservative verifier-owned network classification."""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
from pathlib import Path

CLASSIFIER_VERSION = "2.0.0"
NETWORK_REASON = "VERIFIER_DEPENDENCY_NETWORK_FAILURE"


def _load_v1():
    path = Path(__file__).with_name("normalize_outcome.py")
    spec = importlib.util.spec_from_file_location("normalize_outcome_v1", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load preserved v1: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _verifier_dependency_network_evidence(trial_dir: Path) -> Path | None:
    """Require both bootstrap/dependency context and a concrete network failure.

    Only verifier-owned regular files are inspected; agent/oracle artifacts are
    intentionally outside the evidence boundary.
    """
    verifier = trial_dir / "verifier"
    if not verifier.is_dir():
        return None
    bootstrap = re.compile(
        r"(?:downloading\s+uv\b|astral-sh/uv/releases/download|failed to download\s+https?://|"
        r"dependency|bootstrap|(?:pip|pip3|uv|apt(?:-get)?)\s+(?:install|sync))",
        re.I,
    )
    network = re.compile(
        r"(?:curl:\s*\((?:5|6|7|28|35|56)\)|couldn.t connect to server|"
        r"failed to connect to\s+[^\n]+port\s+443|network is unreachable|"
        r"temporary failure in name resolution|could not resolve host|"
        r"tls (?:connect )?error|ssl connect error|operation timed out|"
        r"connection (?:timed out|reset by peer)|failed to download\s+https?://)",
        re.I,
    )
    for path in sorted(verifier.rglob("*")):
        if not path.is_file() or path.stat().st_size > 20_000_000:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if bootstrap.search(text) and network.search(text):
            return path
    return None


def classify_trial(trial_dir: Path) -> dict:
    trial_dir = trial_dir.resolve()
    v1 = _load_v1()
    result = v1.classify_trial(trial_dir)
    evidence = _verifier_dependency_network_evidence(trial_dir)
    # A valid reward/CTRF is stronger evidence that verifier execution completed;
    # bootstrap warnings in that case are non-fatal and must not override PASS or
    # TASK_FAIL. V2 only resolves otherwise-insufficient evidence. V1's captured
    # regex-log rule already returns verifier infra and is preserved unchanged.
    if evidence is not None and result["outcome"] == "UNCLASSIFIED":
        result["outcome"] = "VERIFIER_INFRA_ERROR"
        result["reason_code"] = NETWORK_REASON
        resolved = str(evidence.resolve())
        if resolved not in result["evidence"]:
            result["evidence"].append(resolved)
    result["classifier_version"] = CLASSIFIER_VERSION
    result["base_classifier_version"] = v1.CLASSIFIER_VERSION
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trial_dir", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    trial = args.trial_dir.resolve()
    output = args.output.resolve()
    if output == trial or trial in output.parents:
        parser.error("--output must be outside the immutable Harbor trial directory")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(classify_trial(trial), indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Run frozen script-style evaluator regressions under their M1B contract."""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
import subprocess
import sys


class FrozenRegressionError(RuntimeError):
    pass


@dataclass(frozen=True)
class RegressionSpec:
    name: str
    path: str
    marker: str
    report: str


SPECS = (
    RegressionSpec("docker", "evaluation/tests/test_docker_endpoint_policy.py", "DOCKER_ENDPOINT_POLICY=7/7 PASS", "docker-policy-tests.txt"),
    RegressionSpec("harbor", "evaluation/tests/test_harbor_exception_policy.py", "HARBOR_EXCEPTION_POLICY=8/8 PASS", "harbor-policy-tests.txt"),
    RegressionSpec("normalizer", "evaluation/tests/test_normalizer_v2_public.py", "NORMALIZER_V2=9/9 PASS", "normalizer-v2-tests.txt"),
    RegressionSpec("tb21", "evaluation/tests/test_tb21_dataset_policy.py", "TB21_DATASET_POLICY=8/8 PASS", "tb21-dataset-policy-tests.txt"),
)


def direct_script_command(python: str, script: Path) -> list[str]:
    return [python, str(script)]


def validate_result(*, returncode: int, output: str, marker: str) -> None:
    if "Ran 0 tests" in output or "NO TESTS RAN" in output:
        raise FrozenRegressionError("unittest zero-test evidence is forbidden")
    if returncode != 0:
        raise FrozenRegressionError(f"frozen regression exited {returncode}")
    if marker not in output:
        raise FrozenRegressionError(f"expected frozen marker is missing: {marker}")


def run_one(
    spec: RegressionSpec,
    *,
    python: str = sys.executable,
    cwd: Path | None = None,
    output_dir: Path | None = None,
) -> str:
    root = cwd or Path.cwd()
    script = root / spec.path
    completed = subprocess.run(
        direct_script_command(python, script),
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    output = completed.stdout + completed.stderr
    if output_dir is not None:
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / spec.report).write_text(output)
    validate_result(returncode=completed.returncode, output=output, marker=spec.marker)
    return output


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        for spec in SPECS:
            output = run_one(spec, output_dir=args.output_dir)
            print(output, end="" if output.endswith("\n") else "\n")
    except (FrozenRegressionError, OSError) as error:
        print(f"FROZEN_EVALUATOR_REGRESSION_FAILED: {error}", file=sys.stderr)
        return 1
    print("FROZEN_EVALUATOR_REGRESSIONS=4/4 PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


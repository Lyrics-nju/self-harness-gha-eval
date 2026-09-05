#!/usr/bin/env python3
"""Install and verify fail-closed M1C adapter source registration."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path, PureWindowsPath
import subprocess
import sys

PTH_NAME = "self_harness_m1c_adapter_source.pth"
MODULE = "evaluation.agents.dsh_harbor_adapter.adapter"
CLASS = "DshHarborAdapter"


class WiringError(RuntimeError):
    pass


def validate_source_root(value: str, expected: Path) -> Path:
    if not value or PureWindowsPath(value).drive or "\\" in value:
        raise WiringError("M1C_SOURCE_ROOT_NOT_POSIX_ABSOLUTE")
    root = Path(value)
    if not root.is_absolute():
        raise WiringError("M1C_SOURCE_ROOT_NOT_ABSOLUTE")
    resolved = root.resolve(strict=True)
    if resolved != expected.resolve(strict=True):
        raise WiringError("M1C_SOURCE_ROOT_NOT_CURRENT_CHECKOUT")
    if "/research/self-harness-dsh" in resolved.as_posix():
        raise WiringError("M1C_PRIVATE_RESEARCH_ROOT_REJECTED")
    if not (resolved / "evaluation/agents/dsh_harbor_adapter/adapter.py").is_file():
        raise WiringError("M1C_ADAPTER_SOURCE_MISSING")
    return resolved


def harbor_site_packages(harbor_python: Path) -> Path:
    code = "import json,site; print(json.dumps(site.getsitepackages()))"
    proc = subprocess.run([str(harbor_python), "-c", code], text=True, capture_output=True)
    if proc.returncode:
        raise WiringError("M1C_HARBOR_SITE_PACKAGES_RESOLUTION_FAILED")
    candidates = [Path(item) for item in json.loads(proc.stdout)]
    owned = [item for item in candidates if item.is_dir() and harbor_python.parent.parent in item.parents]
    if len(owned) != 1:
        raise WiringError("M1C_HARBOR_SITE_PACKAGES_NOT_UNIQUE")
    return owned[0]


def install_pth(harbor_python: Path, source_root: Path) -> Path:
    destination = harbor_site_packages(harbor_python) / PTH_NAME
    destination.write_text(str(source_root) + "\n", encoding="utf-8")
    if destination.read_text(encoding="utf-8").splitlines() != [str(source_root)]:
        raise WiringError("M1C_PTH_CONTENT_INVALID")
    return destination


def probe(harbor_python: Path, source_root: Path, cwd: Path) -> dict[str, object]:
    code = r'''
import json, pathlib, sys
from harbor.agents.factory import AgentFactory
root = pathlib.Path(sys.argv[1])
assert str(root) in sys.path
import evaluation
from evaluation.agents.dsh_harbor_adapter.adapter import DshHarborAdapter
assert DshHarborAdapter.name() == "dsh-harbor-adapter-v1"
instance = AgentFactory.create_agent_from_import_path(
    "evaluation.agents.dsh_harbor_adapter.adapter:DshHarborAdapter",
    logs_dir=pathlib.Path("agent-logs"), model_name="no-model-import-probe", config={})
assert type(instance) is DshHarborAdapter
print(json.dumps({"sys_path": "PASS", "module_import": "PASS", "class_resolution": "PASS", "agentfactory_resolution": "PASS", "initialization_path": "PASS"}, sort_keys=True))
'''
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    proc = subprocess.run(
        [str(harbor_python), "-I", "-c", code, str(source_root)], cwd=cwd,
        env=env, text=True, capture_output=True,
    )
    if proc.returncode:
        raise WiringError("M1C_FRESH_HARBOR_IMPORT_PROBE_FAILED: " + proc.stderr[-500:])
    return json.loads(proc.stdout)


def qualify(harbor_python: Path, source_root: Path, workspace: Path) -> dict[str, object]:
    pth = install_pth(harbor_python, source_root)
    arbitrary = workspace / "work/import-probe/arbitrary"
    nested = workspace / "work/import-probe/jobs/job/trial/agent"
    arbitrary.mkdir(parents=True, exist_ok=True)
    nested.mkdir(parents=True, exist_ok=True)
    return {
        "harbor_python": str(harbor_python),
        "site_packages": str(pth.parent),
        "pth_file": str(pth),
        "pth_line_count": 1,
        "pth_executable_code": False,
        "source_root": str(source_root),
        "arbitrary_cwd": probe(harbor_python, source_root, arbitrary),
        "trial_like_cwd": probe(harbor_python, source_root, nested),
        "provider_requests": 0,
        "dsh_sessions": 0,
        "live_benchmark_trials": 0,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--harbor-python", type=Path, required=True)
    parser.add_argument("--source-root", required=True)
    parser.add_argument("--workspace", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = validate_source_root(args.source_root, args.workspace)
    result = qualify(args.harbor_python.absolute(), root, args.workspace.resolve())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print("M1C_HARBOR_PTH_QUALIFICATION_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

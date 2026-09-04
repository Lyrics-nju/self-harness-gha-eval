#!/usr/bin/env python3
"""Resolve and verify the Python interpreter belonging to a Harbor executable."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
from typing import Callable


class HarborResolutionError(RuntimeError):
    pass


def resolve_harbor_interpreter(
    command: str = "harbor",
    *,
    which: Callable[[str], str | None] = shutil.which,
) -> tuple[Path, Path]:
    executable = which(command)
    if not executable:
        raise HarborResolutionError("Harbor executable is missing")
    real_executable = Path(executable).resolve(strict=True)
    interpreter = real_executable.parent / "python"
    if not interpreter.is_file() or not os.access(interpreter, os.X_OK):
        raise HarborResolutionError(
            f"Python interpreter is missing beside resolved Harbor executable: {interpreter}"
        )
    # Keep the venv-local path. Resolving a venv's python symlink to the system
    # interpreter would discard the environment that owns the Harbor package.
    return real_executable, interpreter.absolute()


def verify_harbor_interpreter(
    interpreter: Path,
    *,
    expected_version: str,
    registration_import: str | None = None,
) -> dict[str, str]:
    probe = """
import importlib
import importlib.metadata
import json
import sys
import harbor
version = importlib.metadata.version('harbor')
registration = 'NOT_REQUESTED'
if sys.argv[1]:
    module = importlib.import_module(sys.argv[1])
    cls = getattr(module, 'DshHarborAdapter')
    assert cls.name() == 'dsh-harbor-adapter-v1'
    assert cls.SUPPORTS_ATIF
    registration = 'PASS'
print(json.dumps({'version': version, 'registration': registration}, sort_keys=True))
"""
    completed = subprocess.run(
        [str(interpreter), "-c", probe, registration_import or ""],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise HarborResolutionError(
            "Resolved Python cannot import Harbor or register the adapter"
        )
    try:
        result = json.loads(completed.stdout.strip())
    except (json.JSONDecodeError, AttributeError) as error:
        raise HarborResolutionError("Harbor interpreter probe returned malformed output") from error
    if result.get("version") != expected_version:
        raise HarborResolutionError(
            f"Harbor version mismatch: expected {expected_version}, got {result.get('version')}"
        )
    return result


def discover_and_verify(
    *, expected_version: str, registration_import: str | None = None
) -> dict[str, str]:
    executable, interpreter = resolve_harbor_interpreter()
    result = verify_harbor_interpreter(
        interpreter,
        expected_version=expected_version,
        registration_import=registration_import,
    )
    return {
        "executable": str(executable),
        "interpreter": str(interpreter),
        "version": result["version"],
        "registration": result["registration"],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--registration-import")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        result = discover_and_verify(
            expected_version=args.expected_version,
            registration_import=args.registration_import,
        )
    except (HarborResolutionError, OSError) as error:
        print(f"HARBOR_INTERPRETER_RESOLUTION_FAILED: {error}")
        return 1
    print(json.dumps(result, sort_keys=True) if args.json else result["interpreter"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

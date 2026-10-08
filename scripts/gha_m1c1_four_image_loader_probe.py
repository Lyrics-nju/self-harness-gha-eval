#!/usr/bin/env python3
"""Fixed four-image diagnostic; never a replacement for the 24-task census."""
from __future__ import annotations

import argparse
import base64
import gzip
import importlib.util
import json
import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("four_image_fingerprint", ROOT / "scripts/gha_m1c1_runtime_fingerprint.py")
rf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rf)
TASKS = tuple("terminal-bench/" + name for name in (
    "qemu-startup", "model-extraction-relu-logits", "fix-code-vulnerability", "configure-git-webserver"))
SNAPSHOT = ROOT / "evidence/m1c/runtime_fingerprint/historical_task_image_map_run_34972344189_v1.json"
POOL = ROOT / "splits/stable_task_pool_v3.json.gz.b64"
PASS = "FOUR_IMAGE_LOADER_IDENTITY_PROBE_PASS"
FAIL = "FOUR_IMAGE_LOADER_IDENTITY_PROBE_FAIL"
INFRA = "FOUR_IMAGE_LOADER_IDENTITY_INFRASTRUCTURE_BLOCKER"
UNKNOWN = "FOUR_IMAGE_LOADER_IDENTITY_EVIDENCE_INDETERMINATE"
SCHEMA = "m1c_four_image_loader_identity_v1"


def select_images() -> list[dict]:
    """No caller-controlled task/image selection or digest literals."""
    raw = gzip.decompress(base64.b64decode(POOL.read_bytes(), validate=False))
    with tempfile.TemporaryDirectory() as td:
        pool = Path(td) / "pool.json"
        pool.write_bytes(raw)
        ids = rf.load_stable_pool(pool)
    historical = rf.load_historical_task_image_map(SNAPSHOT, ids)
    if not all(task in ids for task in TASKS) or len(set(TASKS)) != 4:
        raise rf.QualificationError("FOUR_IMAGE_SELECTION_INVALID", "fixed membership must contain four tasks")
    return [dict(historical[task]) for task in TASKS]


def validate_elf(path: Path) -> dict:
    """Audit complete ELF header/program-file ranges, beyond the shared minimum."""
    digest = rf.hash_loader_binary(path)
    raw = path.read_bytes()
    if rf.sha256_bytes(raw) != digest:
        raise rf.QualificationError("LOADER_HASH_EVIDENCE_MISMATCH", "copied file changed during validation")
    ehsize, phentsize, phnum = struct.unpack_from("<HHH", raw, 52)
    phoff = struct.unpack_from("<Q", raw, 32)[0]
    if ehsize != 64 or phentsize != 56 or phnum == 0 or phoff < 64 or phoff + phnum * phentsize > len(raw):
        raise rf.QualificationError("LOADER_ELF_TRUNCATED_OR_INVALID", "invalid ELF program-header ranges")
    loads = 0
    for index in range(phnum):
        offset = phoff + index * phentsize
        p_type, _flags, p_offset, _vaddr, _paddr, filesz, memsz, _align = struct.unpack_from("<IIQQQQQQ", raw, offset)
        if p_offset + filesz > len(raw) or (p_type == 1 and filesz > memsz):
            raise rf.QualificationError("LOADER_ELF_TRUNCATED_OR_INVALID", "segment extends beyond copied file")
        if p_type == 1 and filesz:
            loads += 1
    if not loads:
        raise rf.QualificationError("LOADER_ELF_TRUNCATED_OR_INVALID", "no nonempty load segment")
    return {"magic": "7f454c46", "class": "ELF64", "endianness": "little", "type": "ET_DYN",
            "machine": "EM_X86_64", "platform": "linux/amd64", "file_size": len(raw),
            "program_headers": phnum, "nonempty_load_segments": loads, "sha256": digest, "valid": True}


def require_cleanup(raw_dir: Path) -> dict:
    evidence = {}
    for name in ("container-cleanup.json", "cleanup.json"):
        path = raw_dir / name
        if not path.is_file():
            raise rf.QualificationError("CLEANUP_EVIDENCE_MISSING", name)
        data = json.loads(path.read_text())
        evidence[name] = data
        if data.get("exit") != 0:
            raise rf.QualificationError("DIAGNOSTIC_CLEANUP_FAILURE", name)
    return evidence


def verify_row(selection: dict, fp: dict, raw_dir: Path, expected_config: str) -> dict:
    for name in ("fingerprint.stdout", "fingerprint.stderr", "fingerprint.exit", "pull.stdout", "pull.stderr",
                 "pull.exit", "fingerprint-container-state.json", "loader-identity-probes.json",
                 "registry-command.json", "registry.stdout", "registry.stderr", "registry.exit",
                 "manifest-resolution.json", "selected-manifest.json", "selection-binding.json"):
        if not (raw_dir / name).is_file():
            raise rf.QualificationError("REQUIRED_EXECUTION_EVIDENCE_MISSING", name)
    cleanup = require_cleanup(raw_dir)
    state = json.loads((raw_dir / "fingerprint-container-state.json").read_text())
    identity = json.loads((raw_dir / "loader-identity-probes.json").read_text())
    cid = state.get("container_id", "")
    if not rf.re.fullmatch(r"[0-9a-f]{64}", cid) or state.get("image") != expected_config or fp.get("docker_image_id") != expected_config:
        raise rf.QualificationError("DOCKER_COPY_SOURCE_BINDING_UNPROVEN", "container/image identity mismatch")
    if cleanup["container-cleanup.json"].get("container_id") != cid:
        raise rf.QualificationError("CLEANUP_CONTAINER_BINDING_UNPROVEN", "cleanup container differs from copy source")
    if fp.get("docker_os") != "linux" or fp.get("docker_architecture") != "amd64":
        raise rf.QualificationError("IMMUTABLE_PLATFORM_BINDING_UNPROVEN", "expected linux/amd64 config")
    if (state.get("state", {}).get("Running") is not False or state["state"].get("ExitCode") != 0
            or state.get("start_exit") != 0 or (raw_dir / "fingerprint.exit").read_text().strip() != "0"
            or (raw_dir / "pull.exit").read_text().strip() != "0"):
        raise rf.QualificationError("STOPPED_CONTAINER_STATE_UNPROVEN", "copy source must be stopped after diagnostic shell")
    runtime = fp["runtime"]
    realpath_probe = identity.get("probes", {}).get("realpath", {})
    if (runtime.get("dynamic_loader_path", rf.NOT_AVAILABLE) == rf.NOT_AVAILABLE
            or not realpath_probe.get("semantic_validity")
            or realpath_probe.get("value") != runtime.get("dynamic_loader_realpath")
            or realpath_probe.get("command") != ["readlink", "-f", "--", runtime.get("dynamic_loader_path")]):
        raise rf.QualificationError("LOADER_PATH_NOT_AVAILABLE", "loader path/realpath not validated")
    copy = identity.get("probes", {}).get("copy")
    if not isinstance(copy, dict):
        raise rf.QualificationError("LOADER_BINARY_EVIDENCE_MISSING", "copy evidence absent")
    if not all(key in copy for key in ("command", "exit_code", "stdout", "stderr", "semantic_validity")):
        raise rf.QualificationError("LOADER_BINARY_EVIDENCE_MISSING", "copy channels incomplete")
    expected_command = ["docker", "cp", "-L", f"{cid}:{runtime['dynamic_loader_realpath']}", str(raw_dir / "loader.binary")]
    if copy.get("command") != expected_command:
        raise rf.QualificationError("DOCKER_COPY_SOURCE_BINDING_UNPROVEN", "copy command binding mismatch")
    if copy.get("exit_code") != 0:
        raise rf.QualificationError("LOADER_BINARY_COPY_NONZERO", f"copy exit={copy.get('exit_code')}")
    if rf.re.search(r"error|cannot open|not found|usage:", str(copy.get("stderr", "")), rf.re.I):
        raise rf.QualificationError("LOADER_BINARY_COPY_DIAGNOSTIC", "copy emitted an error diagnostic")
    if not copy.get("semantic_validity") or runtime.get("loader_binary_identity_status") != "LOADER_BINARY_IDENTITY_VALID":
        raise rf.QualificationError("LOADER_BINARY_VALIDATION_FAILED", "copy did not establish binary identity")
    try:
        elf = validate_elf(raw_dir / "loader.binary")
        rf.write_json(raw_dir / "elf-validation.json", elf)
    except rf.QualificationError as exc:
        rf.write_json(raw_dir / "elf-validation.json", {"valid": False, "reason": exc.classification})
        raise
    if runtime.get("dynamic_loader_sha256") != elf["sha256"] or identity.get("identity", {}).get("dynamic_loader_sha256") != elf["sha256"]:
        raise rf.QualificationError("LOADER_HASH_EVIDENCE_MISMATCH", "copied bytes/hash mismatch")
    require_cleanup(raw_dir)
    record = {**selection, "immutable_image": selection["authoritative_image_ref"] + "@" + selection["historical_platform_digest"],
              "container_id": cid, "image_config_digest": expected_config, "platform": "linux/amd64",
              "diagnostic_shell_only": True, "benchmark_task_executed": False,
              "runtime": runtime, "elf_validation": elf, "cleanup": "PASS", "classification": PASS}
    rf.write_json(raw_dir / "four-image-binding.json", record)
    return record


def failure_class(reason: str) -> str:
    if reason in {"TASK_IMAGE_REGISTRY_RESOLUTION_INFRASTRUCTURE_BLOCKER", "TASK_IMAGE_PULL_FAILURE",
                  "RUNTIME_FINGERPRINT_DISK_SAFETY_STOP", "TASK_RUNTIME_FINGERPRINT_CONTAINER_FAILURE",
                  "DIAGNOSTIC_CLEANUP_FAILURE", "DOCKER_INFRASTRUCTURE_FAILURE"}:
        return INFRA
    if reason in {"LOADER_BINARY_COPY_NONZERO", "LOADER_BINARY_COPY_DIAGNOSTIC", "LOADER_BINARY_VALIDATION_FAILED", "LOADER_ELF_TRUNCATED_OR_INVALID",
                  "LOADER_BINARY_IDENTITY_NOT_AVAILABLE", "LOADER_PATH_NOT_AVAILABLE"}:
        return FAIL
    return UNKNOWN


def resolve_immutable(selection: dict, raw_dir: Path) -> tuple[dict, bytes]:
    """Inspect the historical platform manifest directly; never resolve a tag."""
    immutable = selection["authoritative_image_ref"] + "@" + selection["historical_platform_digest"]
    command = ["docker", "buildx", "imagetools", "inspect", "--raw", immutable]
    rf.write_json(raw_dir / "registry-command.json", {"command": command, "platform": "linux/amd64"})
    proc = subprocess.run(command, capture_output=True, check=False)
    raw = proc.stdout
    (raw_dir / "registry.stdout").write_bytes(raw)
    (raw_dir / "registry.stderr").write_bytes(proc.stderr)
    (raw_dir / "registry.exit").write_text(f"{proc.returncode}\n")
    if proc.returncode:
        raise rf.QualificationError("TASK_IMAGE_REGISTRY_RESOLUTION_INFRASTRUCTURE_BLOCKER", "immutable registry inspect nonzero")
    if rf.sha256_bytes(raw) != selection["historical_platform_digest"].split(":", 1)[1]:
        raise rf.QualificationError("IMMUTABLE_PLATFORM_DIGEST_MISMATCH", selection["task"])
    parsed = rf.parse_manifest(raw)
    if parsed["resolved_image_digest"] != selection["historical_platform_digest"]:
        raise rf.QualificationError("IMMUTABLE_PLATFORM_DIGEST_MISMATCH", "expected a single platform manifest")
    return rf.bind_selected_manifest(parsed, raw), raw


def manifest_verify(root: Path) -> None:
    lines = (root / "SHA256SUMS").read_text().splitlines()
    listed = set()
    for line in lines:
        digest, name = line.split("  ", 1)
        path = root / name
        if name in listed or not path.resolve().is_relative_to(root.resolve()) or rf.sha256_file(path) != digest:
            raise rf.QualificationError("ARTIFACT_INTEGRITY_FAILURE", "manifest/hash mismatch")
        listed.add(name)
    actual = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file() and p.name != "SHA256SUMS"}
    if listed != actual:
        raise rf.QualificationError("ARTIFACT_INTEGRITY_FAILURE", "incomplete manifest")


def seal(root: Path, summary: dict) -> dict:
    """A PASS is usable only after scanner and complete manifest verification."""
    summary_path = root / "four-image-loader-summary.json"
    rf.write_json(summary_path, summary)
    scan = subprocess.run([sys.executable, str(ROOT / "scripts/public_secret_scan.py"), "--artifact-mode", str(root)],
                          text=True, capture_output=True, check=False)
    (root / "secret-scan.txt").write_text(scan.stdout + scan.stderr)
    if scan.returncode:
        summary.update(classification=UNKNOWN, reason="ARTIFACT_SECRET_SCAN_FAILURE", secret_scan="FAIL")
    else:
        summary.update(secret_scan="PASS", sha256_integrity="PASS")
    rf.write_json(summary_path, summary)
    rf.content_manifest(root, root / "SHA256SUMS")
    try:
        manifest_verify(root)
    except Exception:
        summary.update(classification=UNKNOWN, reason="ARTIFACT_INTEGRITY_FAILURE", sha256_integrity="FAIL")
        rf.write_json(summary_path, summary)
        rf.content_manifest(root, root / "SHA256SUMS")
    return summary


def execute(reports: Path) -> dict:
    reports = reports.resolve()
    if reports.exists():
        raise rf.QualificationError("PROBE_OUTPUT_ALREADY_EXISTS", "use a new evidence directory")
    reports.mkdir(parents=True)
    summary = {"schema_version": SCHEMA, "classification": UNKNOWN, "images": [],
        "provider_requests": 0, "deepseek_requests": 0, "dsh_executions": 0, "dsh_builds": 0, "dsh_installs": 0,
        "oracle_executions": 0, "verifier_executions": 0, "benchmark_task_executions": 0,
        "task_runtime_fingerprint_qualified": False, "dsh_native_runtime_compatibility_qualified": False,
        "adapter_frozen": False, "head_sha": os.environ.get("GITHUB_SHA", rf.NOT_AVAILABLE),
        "run_id": os.environ.get("GITHUB_RUN_ID", rf.NOT_AVAILABLE), "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", rf.NOT_AVAILABLE)}
    try:
        selections = select_images()
        rf.write_json(reports / "selection.json", {"schema_version": SCHEMA, "tasks": selections,
            "snapshot_sha256": rf.HISTORICAL_MAP_SHA256, "mapping_sha256": rf.HISTORICAL_MAPPING_SHA256,
            "stable_pool_sha256": rf.STABLE_POOL_SHA256, "source_run_id": rf.HISTORICAL_RUN_ID})
        for index, selection in enumerate(selections, 1):
            summary["current_task"] = selection["task"]
            raw_dir = reports / f"{index:02d}-{selection['task'].split('/')[-1]}"
            raw_dir.mkdir()
            rf.write_json(raw_dir / "selection-binding.json", {**selection, "platform": "linux/amd64"})
            immutable = selection["authoritative_image_ref"] + "@" + selection["historical_platform_digest"]
            resolved, raw = resolve_immutable(selection, raw_dir)
            rf.write_json(raw_dir / "manifest-resolution.json", resolved)
            (raw_dir / "selected-manifest.json").write_bytes(raw)
            if resolved["resolved_image_digest"] != selection["historical_platform_digest"] or rf.sha256_bytes(raw) != selection["historical_platform_digest"].split(":", 1)[1]:
                raise rf.QualificationError("IMMUTABLE_PLATFORM_DIGEST_MISMATCH", selection["task"])
            try:
                fp = rf.fingerprint_one(selection["authoritative_image_ref"], selection["historical_platform_digest"], raw_dir)
            except Exception as exc:
                rf.write_json(raw_dir / "execution-failure.json", {"reason": getattr(exc, "classification", "DOCKER_INFRASTRUCTURE_FAILURE"),
                    "exception_type": type(exc).__name__})
                # Preserve and separately classify any reached cleanup failure.
                for name in ("container-cleanup.json", "cleanup.json"):
                    p = raw_dir / name
                    if p.is_file() and json.loads(p.read_text()).get("exit") != 0:
                        raise rf.QualificationError("DIAGNOSTIC_CLEANUP_FAILURE", name) from exc
                raise
            record = verify_row(selection, fp, raw_dir, resolved["image_config_digest"])
            summary["images"].append(record)
        if len(summary["images"]) != 4 or tuple(row["task"] for row in summary["images"]) != TASKS:
            raise rf.QualificationError("FOUR_IMAGE_SELECTION_INVALID", "completed task set mismatch")
        if len({row["container_id"] for row in summary["images"]}) != 4:
            raise rf.QualificationError("DIAGNOSTIC_CONTAINER_REUSED", "four distinct diagnostic containers required")
        summary["classification"] = PASS
    except Exception as exc:
        reason = getattr(exc, "classification", "DOCKER_INFRASTRUCTURE_FAILURE" if isinstance(exc, (OSError, subprocess.SubprocessError)) else "EXECUTION_EVIDENCE_INVALID")
        summary.update(classification=failure_class(reason), reason=reason, exception_type=type(exc).__name__)
    return seal(reports, summary)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reports", type=Path, required=True)
    args = parser.parse_args()
    summary = execute(args.reports)
    print(json.dumps({"classification": summary["classification"], "reason": summary.get("reason", "NONE")}, sort_keys=True))
    return 0 if summary["classification"] == PASS else 1


if __name__ == "__main__":
    raise SystemExit(main())

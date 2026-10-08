"""Offline validators only. No Docker, build, installer, task or provider calls.

Context identity is canonical JSON of explicit path/identity pairs. Binary inputs
are represented by independently pinned archive identities, not mutable paths.
Actual staged context must match this inventory; no undeclared files allowed.
The policy JSON uses canonicalization excluding ONLY context_sha256 (its own
derived digest); this avoids a self-hash cycle without omitting trusted inputs.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from pathlib import Path

from scripts import m1c_runtime_artifact as a

ROOT = Path(__file__).resolve().parents[1]
CONTEXT_FILES = ("gha/runtime-artifact-v1/Dockerfile", "scripts/m1c_runtime_identity.py",
                 "scripts/m1c_runtime_builder.py", "scripts/m1c_runtime_artifact.py",
                 "scripts/public_secret_scan.py")


def policy(root: Path = ROOT) -> dict:
    return json.loads((root / "configs/m1c_runtime_prebuild_v1.json").read_bytes())


def context_identity(p: dict, root: Path = ROOT) -> str:
    rows = {name: a.file_hash(root / name) for name in CONTEXT_FILES}
    rows.update({"inputs/node.tar.xz": p["node_archive_sha256"],
                 "inputs/corepack.tgz": p["corepack_integrity"],
                 "inputs/pnpm.tgz": p["pnpm_integrity"]})
    rows["configs/m1c_runtime_prebuild_v1.json"] = a.digest(a.canonical(
        {key: value for key, value in p.items() if key != "context_sha256"}))
    return a.digest(a.canonical(rows))


def validate_inputs(p: dict, root: Path = ROOT) -> str:
    a.require(bool(re.fullmatch(r"docker.io/library/python@sha256:[0-9a-f]{64}", p["base_image"])),
              "BUILDER_DIGEST_UNRESOLVED")
    for field in ("node_archive_sha256", "lockfile_sha256", "dockerfile_sha256", "context_sha256"):
        a.require(bool(a.HEX.fullmatch(p[field])), field.upper() + "_UNRESOLVED")
    pinned = policy(root)
    # Caller cannot substitute a different archive, toolchain, base or source.
    for field in ("base_image", "platform", "node_version", "node_architecture", "node_archive_sha256",
                  "corepack_version", "corepack_integrity", "pnpm", "pnpm_integrity", "source_commit",
                  "lockfile_sha256", "requested_resources", "minimum_glibc_target"):
        a.require(p[field] == pinned[field], "PREBUILD_INPUT_DRIFT:" + field)
    a.require(p["dockerfile_sha256"] == a.file_hash(root / CONTEXT_FILES[0]), "DOCKERFILE_DRIFT")
    a.require(p["builder_image"] == "BUILDER_IMAGE_NOT_YET_CREATED", "PREBUILD_IMAGE_FABRICATION")
    a.require(p["context_sha256"] == context_identity(p, root), "BUILD_CONTEXT_DRIFT")
    return "PREBUILD_INPUT_IDENTITIES_PINNED"


def verify_archives(inputs: Path, p: dict) -> None:
    a.require(a.file_hash(inputs / "node.tar.xz") == p["node_archive_sha256"], "NODE_ARCHIVE_CHECKSUM_MISMATCH")
    for name, field in (("corepack.tgz", "corepack_integrity"), ("pnpm.tgz", "pnpm_integrity")):
        expected = "sha512-" + base64.b64encode(hashlib.sha512((inputs / name).read_bytes()).digest()).decode()
        a.require(expected == p[field], "PACKAGE_INTEGRITY_MISMATCH:" + name)


def verify_staged_context(context: Path, p: dict) -> None:
    expected = set(CONTEXT_FILES) | {"inputs/node.tar.xz", "inputs/corepack.tgz", "inputs/pnpm.tgz",
                                   "configs/m1c_runtime_prebuild_v1.json"}
    paths = list(context.rglob("*"))
    a.require(not any(f.is_symlink() for f in paths), "BUILD_CONTEXT_SYMLINK")
    actual = {f.relative_to(context).as_posix() for f in paths if f.is_file()}
    a.require(actual == expected, "BUILD_CONTEXT_UNDECLARED_OR_MISSING_FILE")
    for name in CONTEXT_FILES:
        a.require(a.file_hash(context / name) == a.file_hash(ROOT / name), "BUILD_CONTEXT_FILE_DRIFT")
    a.require(json.loads((context / "configs/m1c_runtime_prebuild_v1.json").read_bytes()) == p,
              "STAGED_POLICY_DRIFT")
    verify_archives(context / "inputs", p)


def verify_image(record: dict | None, p: dict) -> str:
    a.require(record is not None, "BUILDER_IMAGE_NOT_YET_CREATED")
    a.require(record.get("image_id") != p["base_config_digest"], "BASE_IMAGE_IS_NOT_FINAL_BUILDER")
    a.require(set(record) == {"image_id", "platform", "os_release_sha256", "libc", "node_version",
                            "node_abi", "node_napi", "corepack", "pnpm", "input_context_sha256",
                            "base_image", "image_config_sha256", "container_image_id"}, "BUILDER_IMAGE_SCHEMA")
    a.require(bool(re.fullmatch(r"sha256:[0-9a-f]{64}", record["image_id"])) and
              record["container_image_id"] == record["image_id"] and
              record["image_config_sha256"] == record["image_id"].split(":")[1], "BUILDER_CONTENT_IDENTITY_DRIFT")
    for field, expected in (("platform", p["platform"]), ("node_version", p["node_version"]),
                            ("corepack", p["corepack_version"]), ("pnpm", p["pnpm"]),
                            ("input_context_sha256", p["context_sha256"]), ("base_image", p["base_image"])):
        a.require(record[field] == expected, "BUILDER_OBSERVED_IDENTITY_DRIFT:" + field)
    a.require(record["libc"] == "glibc 2.31" and bool(a.HEX.fullmatch(record["os_release_sha256"])) and
              all(isinstance(record[k], str) and record[k].isdigit() for k in ("node_abi", "node_napi")),
              "BUILDER_RUNTIME_IDENTITY_UNPROVEN")
    return "BUILDER_IMAGE_IDENTITY_VERIFIED"


def capacity_gate(observed: dict, p: dict, image: dict | None) -> str:
    verify_image(image, p)
    fields = {"host_cpus", "host_mem_available_bytes", "host_free_disk_bytes", "container_memory_max",
              "container_nano_cpus", "container_memory_swap", "memory_events", "measurement_id"}
    a.require(set(observed) == fields, "BUILDER_CAPACITY_EVIDENCE_MISSING")
    r = p["requested_resources"]
    a.require(all(type(observed[k]) is int for k in fields - {"memory_events", "measurement_id"}),
              "BUILDER_CAPACITY_NOT_MEASURED")
    a.require(observed["host_cpus"] >= r["cpus"] and
              observed["host_mem_available_bytes"] >= r["memory_bytes"] + r["host_memory_reserve_bytes"] and
              observed["host_free_disk_bytes"] >= r["free_disk_floor_bytes"] and
              observed["container_memory_max"] == r["memory_bytes"] and
              observed["container_nano_cpus"] == r["cpus"] * 10**9 and
              observed["container_memory_swap"] == r["memory_bytes"], "BUILDER_CAPACITY_INSUFFICIENT_OR_DRIFT")
    a.require(bool(a.HEX.fullmatch(observed["measurement_id"])) and
              set(observed["memory_events"]) >= {"oom", "oom_kill"} and
              observed["memory_events"]["oom"] == observed["memory_events"]["oom_kill"] == 0,
              "BUILDER_RESOURCE_EVIDENCE_UNPROVEN")
    return "BUILDER_CAPACITY_PREFLIGHT_PASS"


def dsh_build_gate(p: dict, image: dict | None, observed: dict, lock: Path, root: Path = ROOT) -> str:
    validate_inputs(p, root)
    capacity_gate(observed, p, image)
    a.require(a.file_hash(lock) == p["lockfile_sha256"], "FROZEN_LOCKFILE_DRIFT")
    return "DSH_BUILD_PERMITTED"


def validate_task_binding(task_file: Path, census: Path, root: Path = ROOT) -> dict:
    from scripts import m1c_runtime_qualification as q
    import tomllib
    binding = json.loads((root / "configs/m1c_runtime_task_binding_v1.json").read_bytes())
    a.require(a.file_hash(task_file) == binding["task_config_sha256"], "ORIGINAL_TASK_CONFIG_DRIFT")
    data = tomllib.loads(task_file.read_text())
    selected = q.fixed_image(root)
    rows = json.loads(census.read_bytes())
    # Census file itself must be trusted, not just an arbitrary matching row.
    a.require(a.file_hash(census) == binding["census_task_image_map_sha256"], "CENSUS_EVIDENCE_DRIFT")
    a.require(selected == binding["image_mapping"], "HISTORICAL_IMAGE_BINDING_DRIFT")
    env = data["environment"]
    a.require(env["docker_image"] == selected["authoritative_image_ref"] and
              {k: env[k] for k in ("cpus", "memory_mb", "storage_mb")} == binding["task_requested_resources"],
              "TASK_RESOURCE_CONFIG_DRIFT")
    matching = [r for r in rows["tasks"] if r["task_id"] == q.TASK]
    a.require(len(matching) == 1 and matching[0]["resolved_image_digest"] == selected["historical_platform_digest"]
              and matching[0]["authoritative_image_reference"] == selected["authoritative_image_ref"]
              and matching[0]["os"] == "linux" and matching[0]["architecture"] == "amd64", "CENSUS_TASK_DRIFT")
    return binding

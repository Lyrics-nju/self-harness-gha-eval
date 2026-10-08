#!/usr/bin/env python3
"""Deterministic, no-model task-image runtime fingerprint census."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tomllib
from collections import OrderedDict
from pathlib import Path
from typing import Any, Callable, Iterable

SCHEMA_VERSION = "runtime_fingerprint_v2"
SELECTOR_SCHEMA_VERSION = "artifact_class_selector_v2"
HISTORICAL_MAP_SCHEMA_VERSION = "m1c_runtime_fingerprint_historical_task_image_map_v1"
STABLE_POOL_SHA256 = "d3cf005c96355a618843982e47d3c130616766795d2b4f8a54bd9c1ace917fef"
DATASET_SHA256 = "7d7bdc1cbedad549fc1140404bd4dc45e5fd0ea7c4186773687d177ad3a0699a"
HISTORICAL_MAP_SHA256 = "16549c89b096aea3a635167b4a80e53d0628722d71df6346b9a20ca221b26f32"
HISTORICAL_MAPPING_SHA256 = "6962ffc8e2df29603c6ed3c2f7976f8c7b9a0e216d656142d93b2704f176efcb"
HISTORICAL_RUN_ID = 34972344189
HISTORICAL_RUN_ATTEMPT = 1
HISTORICAL_HEAD_SHA = "b47f1ba0da44707d035d300d01ba950ad7e51efc"
HISTORICAL_ARTIFACT_ID = 10397907660
STABLE_TASK_COUNT = 24
PLATFORM_OS = "linux"
PLATFORM_ARCH = "amd64"
NOT_AVAILABLE = "NOT_AVAILABLE"
CANONICAL_LAYOUT = "installed-agent-deepseek-harness-v1"
MIN_DISK_FREE_BYTES = 12 * 1024 * 1024 * 1024
INDEX_MEDIA_TYPES = {
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.index.v1+json",
}
DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")


class QualificationError(RuntimeError):
    def __init__(self, classification: str, detail: str):
        super().__init__(detail)
        self.classification = classification
        self.detail = detail


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_bytes(value))


def load_stable_pool(path: Path) -> list[str]:
    if sha256_file(path) != STABLE_POOL_SHA256:
        raise QualificationError("STABLE_POOL_IDENTITY_DRIFT", str(path))
    data = json.loads(path.read_text())
    tasks = data.get("tasks")
    if data.get("stable_count") != STABLE_TASK_COUNT or not isinstance(tasks, list) or len(tasks) != STABLE_TASK_COUNT:
        raise QualificationError("STABLE_POOL_TASK_COUNT_MISMATCH", f"expected {STABLE_TASK_COUNT}")
    ids = [item.get("task_id") for item in tasks if isinstance(item, dict)]
    if len(ids) != STABLE_TASK_COUNT or any(not isinstance(x, str) for x in ids) or len(set(ids)) != len(ids):
        raise QualificationError("STABLE_POOL_TASK_IDENTITY_INVALID", "task IDs must be 24 unique strings")
    return ids


def validate_dataset_identity(path: Path) -> None:
    data = json.loads(path.read_text())
    actual = data.get("resolved_content_hash") or data.get("dataset_version_content_hash")
    if actual != DATASET_SHA256 or data.get("identity_match_17g") is False:
        raise QualificationError("TB21_DATASET_IDENTITY_DRIFT", f"resolved={actual!r}")


def load_historical_task_image_map(
    path: Path,
    stable_task_ids: list[str],
    expected_snapshot_sha256: str = HISTORICAL_MAP_SHA256,
    expected_mapping_sha256: str = HISTORICAL_MAPPING_SHA256,
) -> dict[str, dict[str, str]]:
    raw = path.read_bytes()
    if sha256_bytes(raw) != expected_snapshot_sha256:
        raise QualificationError("HISTORICAL_TASK_IMAGE_MAP_IDENTITY_DRIFT", str(path))
    try:
        data = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise QualificationError("HISTORICAL_TASK_IMAGE_MAP_INVALID", str(exc)) from exc
    if raw != canonical_bytes(data):
        raise QualificationError("HISTORICAL_TASK_IMAGE_MAP_NONDETERMINISTIC", str(path))
    expected = {
        "schema_version": HISTORICAL_MAP_SCHEMA_VERSION,
        "source_run_id": HISTORICAL_RUN_ID,
        "source_run_attempt": HISTORICAL_RUN_ATTEMPT,
        "source_head_sha": HISTORICAL_HEAD_SHA,
        "source_artifact_id": HISTORICAL_ARTIFACT_ID,
        "stable_pool_sha256": STABLE_POOL_SHA256,
        "dataset_identity": f"sha256:{DATASET_SHA256}",
        "platform": f"{PLATFORM_OS}/{PLATFORM_ARCH}",
        "mapping_sha256": expected_mapping_sha256,
    }
    for field, value in expected.items():
        if data.get(field) != value:
            raise QualificationError("HISTORICAL_TASK_IMAGE_MAP_PROVENANCE_DRIFT", f"{field}: {data.get(field)!r}")
    mappings = data.get("mappings")
    if not isinstance(mappings, list) or len(mappings) != STABLE_TASK_COUNT:
        raise QualificationError("HISTORICAL_TASK_IMAGE_MAP_COUNT_MISMATCH", f"expected {STABLE_TASK_COUNT}")
    if sha256_bytes(canonical_bytes(mappings)) != data["mapping_sha256"]:
        raise QualificationError("HISTORICAL_TASK_IMAGE_MAPPING_IDENTITY_DRIFT", "mapping SHA mismatch")
    by_task: dict[str, dict[str, str]] = {}
    for item in mappings:
        if not isinstance(item, dict) or set(item) != {"task", "authoritative_image_ref", "historical_platform_digest"}:
            raise QualificationError("HISTORICAL_TASK_IMAGE_MAP_INVALID", "mapping fields")
        task = item["task"]
        reference = item["authoritative_image_ref"]
        digest = item["historical_platform_digest"]
        if not isinstance(task, str) or not isinstance(reference, str) or not reference:
            raise QualificationError("HISTORICAL_TASK_IMAGE_MAP_INVALID", "task/reference")
        if not isinstance(digest, str) or not DIGEST_PATTERN.fullmatch(digest):
            raise QualificationError("HISTORICAL_TASK_IMAGE_MAP_INVALID", f"{task}: digest")
        if task in by_task:
            raise QualificationError("HISTORICAL_TASK_IMAGE_MAP_DUPLICATE_TASK", task)
        by_task[task] = item
    if set(by_task) != set(stable_task_ids):
        raise QualificationError("HISTORICAL_CURRENT_TASK_SET_MISMATCH", "historical/stable task sets differ")
    return by_task


def compare_historical_task_image_map(
    historical: dict[str, dict[str, str]], current: list[dict[str, Any]],
) -> dict[str, Any]:
    current_by_task: dict[str, dict[str, Any]] = {}
    for item in current:
        task = item.get("task_id")
        digest = item.get("resolved_image_digest")
        reference = item.get("authoritative_image_reference")
        if not isinstance(task, str) or task in current_by_task:
            raise QualificationError("CURRENT_TASK_IMAGE_EVIDENCE_INVALID", str(task))
        if not isinstance(digest, str) or not DIGEST_PATTERN.fullmatch(digest):
            raise QualificationError("CURRENT_TASK_IMAGE_DIGEST_EVIDENCE_INCOMPLETE", task)
        if not isinstance(reference, str) or not reference:
            raise QualificationError("CURRENT_TASK_IMAGE_EVIDENCE_INVALID", task)
        current_by_task[task] = item
    if set(current_by_task) != set(historical):
        raise QualificationError("HISTORICAL_CURRENT_TASK_SET_MISMATCH", "historical/current task sets differ")
    rows = []
    for task in sorted(historical):
        old = historical[task]
        now = current_by_task[task]
        if now["authoritative_image_reference"] != old["authoritative_image_ref"]:
            raise QualificationError("HISTORICAL_CURRENT_IMAGE_REFERENCE_MISMATCH", task)
        matched = now["resolved_image_digest"] == old["historical_platform_digest"]
        rows.append({
            "authoritative_image_ref": old["authoritative_image_ref"],
            "current_platform_digest": now["resolved_image_digest"],
            "historical_platform_digest": old["historical_platform_digest"],
            "match": matched,
            "task": task,
        })
    drifted = [row for row in rows if not row["match"]]
    return {
        "schema_version": "m1c_runtime_fingerprint_inter_run_digest_comparison_v1",
        "classification": (
            "M1C_RUNTIME_FINGERPRINT_INTER_RUN_TAG_DRIFT_BLOCKER" if drifted else "INTER_RUN_TASK_IMAGE_DIGEST_IDENTITY_PASS"
        ),
        "historical_digest_matches": len(rows) - len(drifted),
        "drift_count": len(drifted),
        "drifted_tasks": [row["task"] for row in drifted],
        "comparisons": rows,
    }


def registry_of(reference: str) -> str:
    first = reference.split("/", 1)[0]
    return first if "." in first or ":" in first or first == "localhost" else "docker.io"


def resolve_task_image_map(task_ids: list[str], dataset_root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    allowed_dirs = {p.name for p in dataset_root.iterdir() if p.is_dir()}
    for ordinal, task_id in enumerate(task_ids, 1):
        prefix, sep, name = task_id.partition("/")
        if prefix != "terminal-bench" or not sep or not name or name not in allowed_dirs:
            raise QualificationError("STABLE_TASK_RESOLUTION_FAILURE", task_id)
        task_file = dataset_root / name / "task.toml"
        if not task_file.is_file():
            raise QualificationError("STABLE_TASK_RESOLUTION_FAILURE", f"{task_id}: missing task.toml")
        config = tomllib.loads(task_file.read_text())
        environment = config.get("environment")
        image = environment.get("docker_image") if isinstance(environment, dict) else None
        if not isinstance(image, str) or not image or "@" in image or ":" not in image.rsplit("/", 1)[-1]:
            raise QualificationError("TASK_IMAGE_DEFINITION_AMBIGUOUS", f"{task_id}: {image!r}")
        rows.append({
            "ordinal": ordinal,
            "task_id": task_id,
            "authoritative_image_reference": image,
            "registry": registry_of(image),
        })
    return rows


def parse_manifest(raw: bytes, os_name: str = PLATFORM_OS, architecture: str = PLATFORM_ARCH) -> dict[str, Any]:
    try:
        data = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise QualificationError("IMAGE_MANIFEST_INVALID", str(exc)) from exc
    media_type = data.get("mediaType", NOT_AVAILABLE)
    tag_digest = "sha256:" + sha256_bytes(raw)
    if media_type in INDEX_MEDIA_TYPES or isinstance(data.get("manifests"), list):
        matches = [
            item for item in data.get("manifests", [])
            if isinstance(item, dict)
            and item.get("platform", {}).get("os") == os_name
            and item.get("platform", {}).get("architecture") == architecture
            and item.get("platform", {}).get("variant") in (None, "")
        ]
        if len(matches) != 1:
            raise QualificationError(
                "IMAGE_PLATFORM_RESOLUTION_AMBIGUOUS",
                f"{os_name}/{architecture}: {len(matches)} matching manifests",
            )
        selected = matches[0]
        return {
            "tag_manifest_digest": tag_digest,
            "tag_manifest_media_type": media_type,
            "resolved_image_digest": selected["digest"],
            "manifest_media_type": selected.get("mediaType", NOT_AVAILABLE),
            "os": os_name,
            "architecture": architecture,
            "variant": selected.get("platform", {}).get("variant") or NOT_AVAILABLE,
        }
    config = data.get("config")
    if not isinstance(config, dict) or not isinstance(config.get("digest"), str):
        raise QualificationError("IMAGE_MANIFEST_INVALID", "single manifest has no config digest")
    return {
        "tag_manifest_digest": tag_digest,
        "tag_manifest_media_type": media_type,
        "resolved_image_digest": tag_digest,
        "manifest_media_type": media_type,
        "image_config_digest": config["digest"],
        "os": os_name,
        "architecture": architecture,
        "variant": NOT_AVAILABLE,
    }


def bind_selected_manifest(row: dict[str, Any], selected_raw: bytes) -> dict[str, Any]:
    data = json.loads(selected_raw)
    observed = "sha256:" + sha256_bytes(selected_raw)
    if observed != row["resolved_image_digest"]:
        raise QualificationError("TASK_IMAGE_DIGEST_MISMATCH", f"expected {row['resolved_image_digest']}, got {observed}")
    config = data.get("config")
    if not isinstance(config, dict) or not isinstance(config.get("digest"), str):
        raise QualificationError("IMAGE_MANIFEST_INVALID", "selected manifest has no config digest")
    result = dict(row)
    result["manifest_media_type"] = data.get("mediaType", result.get("manifest_media_type", NOT_AVAILABLE))
    result["image_config_digest"] = config["digest"]
    return result


def deduplicate_exact_digests(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    unique: OrderedDict[str, dict[str, Any]] = OrderedDict()
    for row in rows:
        digest = row["resolved_image_digest"]
        if digest not in unique:
            unique[digest] = {
                "resolved_image_digest": digest,
                "representative_image_reference": row["authoritative_image_reference"],
                "task_ids": [],
            }
        unique[digest]["task_ids"].append(row["task_id"])
    return list(unique.values())


def assert_no_tag_drift(before: dict[str, Any], after: dict[str, Any]) -> None:
    if any(before.get(field) != after.get(field) for field in ("tag_manifest_digest", "resolved_image_digest")):
        raise QualificationError("TASK_IMAGE_TAG_DRIFT", before["authoritative_image_reference"])


def run_checked(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, text=True, capture_output=True, check=True)


def resolve_remote(reference: str, runner: Callable[[list[str]], subprocess.CompletedProcess[str]] = run_checked) -> tuple[dict[str, Any], bytes]:
    if runner is run_checked:
        raw = subprocess.run(["docker", "buildx", "imagetools", "inspect", "--raw", reference], capture_output=True, check=True).stdout
    else:
        output = runner(["docker", "buildx", "imagetools", "inspect", "--raw", reference]).stdout
        raw = output.encode() if isinstance(output, str) else output
    result = parse_manifest(raw)
    selected_ref = f"{reference}@{result['resolved_image_digest']}"
    if runner is run_checked:
        selected_raw = subprocess.run(["docker", "buildx", "imagetools", "inspect", "--raw", selected_ref], capture_output=True, check=True).stdout
    else:
        output = runner(["docker", "buildx", "imagetools", "inspect", "--raw", selected_ref]).stdout
        selected_raw = output.encode() if isinstance(output, str) else output
    return bind_selected_manifest({"authoritative_image_reference": reference, **result}, selected_raw), selected_raw


def resolve_remote_fail_closed(
    reference: str,
    resolver: Callable[[str], tuple[dict[str, Any], bytes]] = resolve_remote,
) -> tuple[dict[str, Any], bytes]:
    """Keep registry/infrastructure failures distinct from proven digest drift."""
    try:
        return resolver(reference)
    except QualificationError:
        raise
    except (OSError, subprocess.SubprocessError) as exc:
        detail = f"{reference}: {type(exc).__name__}"
        if isinstance(exc, subprocess.CalledProcessError):
            detail += f" exit={exc.returncode}"
        raise QualificationError("TASK_IMAGE_REGISTRY_RESOLUTION_INFRASTRUCTURE_BLOCKER", detail) from exc


FINGERPRINT_SCRIPT = r"""
set -u
emit() { printf '%s\t%s\n' "$1" "$2"; }
na=NOT_AVAILABLE
probe() {
  probe_name=$1; shift
  probe_dir="$(mktemp -d)" || exit 1
  "$@" > "$probe_dir/stdout" 2> "$probe_dir/stderr"
  probe_exit=$?
  probe_stdout="$(cat "$probe_dir/stdout")"
  probe_stderr="$(cat "$probe_dir/stderr")"
  emit "${probe_name}_exit" "$probe_exit"
  emit "${probe_name}_stdout_b64" "$(base64 < "$probe_dir/stdout" | tr -d '\n')"
  emit "${probe_name}_stderr_b64" "$(base64 < "$probe_dir/stderr" | tr -d '\n')"
  rm -f "$probe_dir/stdout" "$probe_dir/stderr"; rmdir "$probe_dir"
}
probe release_getconf getconf GNU_LIBC_VERSION
probe release_ldd ldd --version
emit uname_s "$(uname -s 2>/dev/null || printf %s "$na")"
emit uname_m "$(uname -m 2>/dev/null || printf %s "$na")"
emit long_bit "$(getconf LONG_BIT 2>/dev/null || printf %s "$na")"
if test -r /etc/os-release; then emit os_release_b64 "$(base64 < /etc/os-release 2>/dev/null | tr -d '\n' || printf %s "$na")"; else emit os_release_b64 "$na"; fi
emit libc_getconf "$na"
emit ldd_version "$na"
libc_path="$(find /lib /lib64 /usr/lib -maxdepth 4 -type f -name 'libc.so.6' 2>/dev/null | sort | head -1)"
emit libc_path "${libc_path:-$na}"
if test -n "$libc_path"; then
  symbols="$(grep -aoE 'GLIBC_[0-9]+(\.[0-9]+)*' "$libc_path" 2>/dev/null | sort -Vu | tr '\n' ',' | sed 's/,$//' || true)"
  emit glibc_symbol_versions "${symbols:-$na}"
else emit glibc_symbol_versions "$na"; fi
loader=
loader_method=$na
loader_evidence=$na
probe_executable=
for candidate in /bin/sh /usr/bin/env /bin/ls; do
  if test -e "$candidate"; then probe_executable=$candidate; break; fi
done
emit loader_probe_executable "${probe_executable:-$na}"
if test -n "$probe_executable" && command -v readelf >/dev/null 2>&1; then
  probe path_readelf readelf -l "$probe_executable"
  interp=
  if test "$probe_exit" = 0 && test -z "$probe_stderr"; then
    interp="$(printf '%s\n' "$probe_stdout" | sed -n 's/.*Requesting program interpreter: \([^]]*\)].*/\1/p' | head -1)"
  fi
  if test -n "$interp" && test -e "$interp"; then
    loader=$interp
    loader_method=READELF_PT_INTERP
    loader_evidence="probe=$probe_executable;pt_interp=$interp"
  fi
fi
if test -z "$loader" && test -n "$probe_executable" && command -v ldd >/dev/null 2>&1; then
  probe path_ldd ldd "$probe_executable"
  interp=
  if test "$probe_exit" = 0 && test -z "$probe_stderr"; then
    interp="$(printf '%s\n' "$probe_stdout" | awk '{for(i=1;i<=NF;i++){v=$i; gsub(/[()]/,"",v); if(v ~ /^\// && v ~ /(ld-linux|ld-musl|\/ld-[^/]*\.so)/){print v; exit}}}')"
  fi
  if test -n "$interp" && test -e "$interp"; then
    loader=$interp
    loader_method=LDD_INTERPRETER_LINE
    loader_evidence="probe=$probe_executable;ldd_interpreter=$interp"
  fi
fi
if test -z "$loader"; then
  loader_candidates="$(find /lib /lib64 /usr/lib -maxdepth 4 \( -type f -o -type l \) \( -name 'ld-linux*.so*' -o -name 'ld-musl-*.so*' -o -name 'ld-*.so' \) -print 2>/dev/null | while IFS= read -r item; do test -e "$item" && readlink -f "$item"; done | sort -u)"
  loader_count="$(printf '%s\n' "$loader_candidates" | sed '/^$/d' | wc -l | tr -d ' ')"
  if test "$loader_count" = 1; then
    loader="$(printf '%s\n' "$loader_candidates" | sed '/^$/d')"
    loader_method=FILESYSTEM_UNIQUE_CANDIDATE
    loader_evidence="unique_candidate=$loader"
  elif test "$loader_count" -gt 1; then
    loader_method=FILESYSTEM_AMBIGUOUS
    loader_evidence="candidate_count=$loader_count"
  fi
fi
if test -n "$loader" && ! test -e "$loader"; then
  loader=
  loader_method=PATH_VALIDATION_FAILED
  loader_evidence=resolved_path_missing
fi
emit dynamic_loader_path "${loader:-$na}"
emit dynamic_loader_detection_method "$loader_method"
emit dynamic_loader_detection_evidence "$loader_evidence"
if test -n "$loader"; then
  probe loader_realpath readlink -f -- "$loader"
else emit loader_realpath_exit NOT_REACHED; fi
emit dynamic_loader_identity "$na"
emit uid "$(id -u 2>/dev/null || printf %s "$na")"
emit gid "$(id -g 2>/dev/null || printf %s "$na")"
emit user "$(id -un 2>/dev/null || printf %s "$na")"
emit cwd "$(pwd 2>/dev/null || printf %s "$na")"
emit default_shell "${SHELL:-$na}"
emit dev_pts "$(test -d /dev/pts && printf PRESENT || printf ABSENT)"
emit dev_ptmx "$(test -c /dev/ptmx && printf PRESENT || printf ABSENT)"
emit seccomp "$(awk '/^Seccomp:/{print $2}' /proc/1/status 2>/dev/null || printf %s "$na")"
emit no_new_privs "$(awk '/^NoNewPrivs:/{print $2}' /proc/1/status 2>/dev/null || printf %s "$na")"
emit landlock_securityfs "$(test -e /sys/kernel/security/landlock && printf PRESENT || printf "$na")"
if mkdir -p /installed-agent/.runtime-fingerprint 2>/dev/null; then rmdir /installed-agent/.runtime-fingerprint 2>/dev/null || true; emit installed_agent_writable PASS; else emit installed_agent_writable FAIL; fi
if touch /tmp/.runtime-fingerprint-write 2>/dev/null; then rm -f /tmp/.runtime-fingerprint-write; emit tmp_writable PASS; else emit tmp_writable FAIL; fi
if printf '#!/bin/sh\nexit 0\n' > /tmp/.runtime-fingerprint-exec && chmod 700 /tmp/.runtime-fingerprint-exec && /tmp/.runtime-fingerprint-exec; then rm -f /tmp/.runtime-fingerprint-exec; emit local_exec PASS; else rm -f /tmp/.runtime-fingerprint-exec; emit local_exec FAIL; fi
if command -v node >/dev/null 2>&1; then
  emit node_present yes
  emit node_version "$(node --version 2>/dev/null || printf %s "$na")"
  emit node_abi "$(node -p 'process.versions.modules' 2>/dev/null || printf %s "$na")"
  emit napi_version "$(node -p 'process.versions.napi' 2>/dev/null || printf %s "$na")"
else emit node_present no; emit node_version "$na"; emit node_abi "$na"; emit napi_version "$na"; fi
emit mount_root "$(awk '$2=="/"{print $3":"$4; found=1} END{if(!found)print "NOT_AVAILABLE"}' /proc/mounts 2>/dev/null)"
""".strip()


UNRESOLVED_SHELL_TOKEN = re.compile(r"\$(?:[A-Za-z_][A-Za-z0-9_]*|\{[^{}\r\n]+\})")


def contains_unresolved_shell_token(value: str) -> bool:
    return bool(UNRESOLVED_SHELL_TOKEN.search(value))


def normalize_fingerprint_value(field: str, value: str) -> str:
    normalized = value.strip()
    if not normalized:
        return NOT_AVAILABLE
    if contains_unresolved_shell_token(normalized):
        raise QualificationError("RUNTIME_FINGERPRINT_UNRESOLVED_SHELL_PLACEHOLDER", f"{field}: unresolved shell token")
    return normalized


def select_loader_candidate(
    authoritative_candidates: Iterable[tuple[str, str]],
    filesystem_candidates: Iterable[str],
    exists: Callable[[str], bool],
) -> tuple[str, str, str]:
    """Model the in-container deterministic loader selection for fixture tests."""
    for method, candidate in authoritative_candidates:
        if candidate and exists(candidate):
            return candidate, method, f"authoritative_path={candidate}"
    available = sorted({candidate for candidate in filesystem_candidates if candidate and exists(candidate)})
    if len(available) == 1:
        return available[0], "FILESYSTEM_UNIQUE_CANDIDATE", f"unique_candidate={available[0]}"
    if len(available) > 1:
        return NOT_AVAILABLE, "FILESYSTEM_AMBIGUOUS", f"candidate_count={len(available)}"
    return NOT_AVAILABLE, NOT_AVAILABLE, NOT_AVAILABLE


def parse_fingerprint(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in text.splitlines():
        key, sep, value = line.partition("\t")
        if sep and key:
            result[key] = normalize_fingerprint_value(key, value)
    for key in (
        "os_release_b64", "libc_getconf", "libc_path", "glibc_symbol_versions", "ldd_version", "dynamic_loader_path",
        "dynamic_loader_identity", "dynamic_loader_detection_method", "dynamic_loader_detection_evidence",
        "seccomp", "no_new_privs", "landlock_securityfs",
        "node_version", "node_abi", "napi_version", "mount_root",
    ):
        result.setdefault(key, NOT_AVAILABLE)
    return result


def candidate_runtime_key(fingerprint: dict[str, Any]) -> dict[str, str]:
    return {
        "kernel_family": fingerprint.get("uname_s", NOT_AVAILABLE),
        "architecture": fingerprint.get("uname_m", NOT_AVAILABLE),
        "libc_family_version": fingerprint.get("libc_getconf", NOT_AVAILABLE),
        "glibc_symbol_versions_sha256": (
            sha256_bytes(str(fingerprint["glibc_symbol_versions"]).encode())
            if fingerprint.get("glibc_symbol_versions", NOT_AVAILABLE) != NOT_AVAILABLE else NOT_AVAILABLE
        ),
        "loader_binary_sha256": fingerprint.get("dynamic_loader_sha256", NOT_AVAILABLE),
        "dynamic_loader_path": fingerprint.get("dynamic_loader_path", NOT_AVAILABLE),
        "kernel_security_contract": "|".join(str(fingerprint.get(key, NOT_AVAILABLE)) for key in ("seccomp", "no_new_privs", "landlock_securityfs", "dev_pts", "dev_ptmx")),
        "artifact_node_contract": "ARTIFACT_PROVIDED_NOT_YET_QUALIFIED",
        "canonical_runtime_layout": CANONICAL_LAYOUT,
    }


def classification_for(fingerprint: dict[str, Any]) -> str:
    required = (
        "uname_s", "uname_m", "libc_getconf", "dynamic_loader_path", "dynamic_loader_realpath",
        "dynamic_loader_detection_method", "dynamic_loader_detection_evidence",
    )
    capabilities = {
        "installed_agent_writable": "PASS", "tmp_writable": "PASS", "local_exec": "PASS",
        "dev_pts": "PRESENT", "dev_ptmx": "PRESENT",
    }
    digest = fingerprint.get("dynamic_loader_sha256", "")
    valid_binary = (isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest) is not None
                    and fingerprint.get("loader_binary_identity_status") == "LOADER_BINARY_IDENTITY_VALID"
                    and fingerprint.get("dynamic_loader_identity_method") == "HOST_SHA256_DOCKER_CP_RESOLVED_ELF")
    missing = not valid_binary or any(fingerprint.get(key, NOT_AVAILABLE) == NOT_AVAILABLE for key in required)
    incompatible = any(fingerprint.get(key, NOT_AVAILABLE) != value for key, value in capabilities.items())
    return "COMPATIBILITY_NOT_YET_PROVEN" if missing or incompatible else "TASK_RUNTIME_FINGERPRINT_QUALIFIED"


def validate_probe(method: str, command: list[str], exit_code: int | str, stdout: str, stderr: str) -> dict[str, Any]:
    """Only method-specific, successful stdout can supply semantic evidence."""
    value = stdout.strip()
    valid = exit_code == 0 and not stderr.strip() and not contains_unresolved_shell_token(value)
    if method == "GETCONF_GNU_LIBC_VERSION":
        valid = valid and command == ["getconf", "GNU_LIBC_VERSION"] and bool(re.fullmatch(r"glibc [0-9]+\.[0-9]+", value))
    elif method == "LDD_VERSION":
        valid = valid and command == ["ldd", "--version"] and bool(re.fullmatch(r"ldd \([^\n]+\) [0-9]+\.[0-9]+", value.splitlines()[0] if value else ""))
        valid = valid and not re.search(r"error|usage:|cannot open|not found", value, re.I)
    elif method == "READLINK_REALPATH":
        valid = valid and len(command) == 4 and command[:3] == ["readlink", "-f", "--"]
        valid = valid and value.startswith("/") and "\n" not in value and ".." not in Path(value).parts
    elif method in ("READELF_PT_INTERP", "LDD_INTERPRETER_LINE"):
        # Selection additionally requires the chosen path to exist in the container.
        valid = valid and bool(value) and not re.search(r"error|usage:|cannot open|not found", value, re.I)
        if method == "READELF_PT_INTERP":
            valid = valid and command[:2] == ["readelf", "-l"] and bool(re.search(r"Requesting program interpreter: /[^\]]+\]", value))
        else:
            valid = valid and command[:1] == ["ldd"] and bool(re.search(r"/(?:[^\s()]+/)*(?:ld-linux|ld-musl|ld-)[^\s()]+", value))
    else:
        valid = False
    return {"method": method, "command": command, "exit_code": exit_code, "stdout": stdout, "stderr": stderr,
            "semantic_validity": bool(valid), "value": value if valid else NOT_AVAILABLE,
            "status": "VALID" if valid else "LOADER_IDENTITY_PROBE_ERROR"}


def decode_probe(fp: dict[str, str], prefix: str, method: str, command: list[str]) -> dict[str, Any]:
    try:
        exit_code: int | str = int(fp[f"{prefix}_exit"])
        stdout = base64.b64decode("" if fp[f"{prefix}_stdout_b64"] == NOT_AVAILABLE else fp[f"{prefix}_stdout_b64"], validate=True).decode()
        stderr = base64.b64decode("" if fp[f"{prefix}_stderr_b64"] == NOT_AVAILABLE else fp[f"{prefix}_stderr_b64"], validate=True).decode()
    except (KeyError, ValueError, UnicodeError):
        return validate_probe(method, command, NOT_AVAILABLE, "", "probe evidence missing or invalid")
    return validate_probe(method, command, exit_code, stdout, stderr)


def hash_loader_binary(path: Path) -> str:
    """Hash copied regular ELF bytes, never symlink text or a pathname."""
    if path.is_symlink() or not path.is_file():
        raise QualificationError("LOADER_BINARY_IDENTITY_NOT_AVAILABLE", "copied loader is not a regular file")
    raw = path.read_bytes()
    if (len(raw) < 64 or raw[:6] != b"\x7fELF\x02\x01" or raw[16:20] != b"\x03\x00\x3e\x00"):
        raise QualificationError("LOADER_BINARY_IDENTITY_NOT_AVAILABLE", "expected amd64 little-endian ELF shared object")
    return sha256_bytes(raw)


def enrich_loader_identity(fp: dict[str, str], container_id: str, raw_dir: Path,
                           runner: Callable = subprocess.run) -> dict[str, Any]:
    path = fp.get("dynamic_loader_path", NOT_AVAILABLE)
    probes = {
        "realpath": decode_probe(fp, "loader_realpath", "READLINK_REALPATH", ["readlink", "-f", "--", path]),
        "getconf": decode_probe(fp, "release_getconf", "GETCONF_GNU_LIBC_VERSION", ["getconf", "GNU_LIBC_VERSION"]),
        "ldd": decode_probe(fp, "release_ldd", "LDD_VERSION", ["ldd", "--version"]),
        "path_readelf": decode_probe(fp, "path_readelf", "READELF_PT_INTERP", ["readelf", "-l", fp.get("loader_probe_executable", NOT_AVAILABLE)]),
        "path_ldd": decode_probe(fp, "path_ldd", "LDD_INTERPRETER_LINE", ["ldd", fp.get("loader_probe_executable", NOT_AVAILABLE)]),
    }
    result: dict[str, Any] = {**fp, "loader_binary_identity_status": "LOADER_BINARY_IDENTITY_NOT_AVAILABLE",
        "dynamic_loader_realpath": NOT_AVAILABLE, "dynamic_loader_sha256": NOT_AVAILABLE,
        "dynamic_loader_identity": NOT_AVAILABLE, "dynamic_loader_identity_method": NOT_AVAILABLE,
        "libc_version": probes["getconf"]["value"], "libc_getconf": probes["getconf"]["value"],
        "ldd_version": probes["ldd"]["value"], "dynamic_loader_release_metadata": NOT_AVAILABLE,
        "loader_release_metadata_status": "LOADER_RELEASE_METADATA_NOT_AVAILABLE"}
    if probes["ldd"]["semantic_validity"]:
        result["dynamic_loader_release_metadata"] = {"method": "LDD_VERSION", "value": probes["ldd"]["value"],
            "scope": "libc distribution release; not loader binary identity"}
        result["loader_release_metadata_status"] = "VALID"
    try:
        realpath = probes["realpath"]["value"]
        if path == NOT_AVAILABLE or not probes["realpath"]["semantic_validity"]:
            return result
        result["dynamic_loader_realpath"] = realpath
        target = raw_dir / "loader.binary"
        command = ["docker", "cp", "-L", f"{container_id}:{realpath}", str(target)]
        copied = runner(command, text=True, capture_output=True, check=False)
        probes["copy"] = {"method": "DOCKER_CP_FOLLOW_RESOLVED_TARGET", "command": command,
            "exit_code": copied.returncode, "stdout": copied.stdout, "stderr": copied.stderr, "semantic_validity": False}
        if copied.returncode:
            result["loader_binary_identity_status"] = "LOADER_IDENTITY_PROBE_ERROR"
            return result
        try:
            digest = hash_loader_binary(target)
        except QualificationError as exc:
            probes["copy"]["validation_error"] = exc.classification
            return result
        probes["copy"]["semantic_validity"] = True
        result.update(dynamic_loader_sha256=digest, dynamic_loader_identity=f"sha256:{digest}",
            dynamic_loader_identity_method="HOST_SHA256_DOCKER_CP_RESOLVED_ELF",
            loader_binary_identity_status="LOADER_BINARY_IDENTITY_VALID")
        return result
    finally:
        identity_fields = ("dynamic_loader_path", "dynamic_loader_realpath", "dynamic_loader_sha256",
            "dynamic_loader_identity", "dynamic_loader_identity_method", "loader_binary_identity_status",
            "libc_version", "dynamic_loader_release_metadata", "loader_release_metadata_status")
        write_json(raw_dir / "loader-identity-probes.json", {"schema_version": "loader_identity_evidence_v1",
            "probes": probes, "identity": {key: result[key] for key in identity_fields}})


def content_manifest(root: Path, output: Path) -> None:
    files = sorted(p for p in root.rglob("*") if p.is_file() and p != output)
    output.write_text("".join(f"{sha256_file(path)}  {path.relative_to(root).as_posix()}\n" for path in files))


def image_inspect(reference: str) -> dict[str, Any]:
    values = json.loads(run_checked(["docker", "image", "inspect", reference]).stdout)
    if not isinstance(values, list) or len(values) != 1:
        raise QualificationError("IMAGE_INSPECT_AMBIGUOUS", reference)
    item = values[0]
    config = item.get("Config") or {}
    return {
        "docker_image_id": item.get("Id", NOT_AVAILABLE),
        "docker_os": item.get("Os", NOT_AVAILABLE),
        "docker_architecture": item.get("Architecture", NOT_AVAILABLE),
        "docker_variant": item.get("Variant") or NOT_AVAILABLE,
        "default_user": config.get("User") or "root",
        "working_dir": config.get("WorkingDir") or "/",
        "entrypoint": config.get("Entrypoint") if config.get("Entrypoint") is not None else NOT_AVAILABLE,
        "cmd": config.get("Cmd") if config.get("Cmd") is not None else NOT_AVAILABLE,
        "shell": config.get("Shell") if config.get("Shell") is not None else ["/bin/sh", "-c"],
    }


def fingerprint_one(reference: str, digest: str, raw_dir: Path) -> dict[str, Any]:
    immutable = f"{reference}@{digest}"
    before = shutil.disk_usage("/").free
    if before < MIN_DISK_FREE_BYTES:
        raise QualificationError("RUNTIME_FINGERPRINT_DISK_SAFETY_STOP", f"free={before}")
    container_id = None
    try:
        pull = subprocess.run(["docker", "pull", "--platform", f"{PLATFORM_OS}/{PLATFORM_ARCH}", immutable], text=True, capture_output=True)
        (raw_dir / "pull.stdout").write_text(pull.stdout)
        (raw_dir / "pull.stderr").write_text(pull.stderr)
        (raw_dir / "pull.exit").write_text(f"{pull.returncode}\n")
        if pull.returncode:
            raise QualificationError("TASK_IMAGE_PULL_FAILURE", f"{immutable}: exit {pull.returncode}")
        inspect = image_inspect(immutable)
        created = run_checked(["docker", "create", "--entrypoint", "/bin/sh", immutable, "-c", FINGERPRINT_SCRIPT])
        container_id = created.stdout.strip()
        if not re.fullmatch(r"[0-9a-f]{64}", container_id):
            raise QualificationError("TASK_RUNTIME_FINGERPRINT_CONTAINER_FAILURE", "invalid container ID")
        proc = subprocess.run(["docker", "start", "-a", container_id], text=True, capture_output=True, check=False)
        (raw_dir / "fingerprint.stdout").write_text(proc.stdout)
        (raw_dir / "fingerprint.stderr").write_text(proc.stderr)
        state = json.loads(run_checked(["docker", "inspect", container_id]).stdout)[0]
        write_json(raw_dir / "fingerprint-container-state.json", {"container_id": container_id,
            "image": state["Image"], "state": state["State"], "start_exit": proc.returncode})
        child_exit = state["State"]["ExitCode"]
        (raw_dir / "fingerprint.exit").write_text(f"{child_exit}\n")
        if proc.returncode or state["State"]["Running"] or child_exit:
            raise QualificationError("TASK_RUNTIME_FINGERPRINT_CONTAINER_FAILURE", f"{immutable}: exit {proc.returncode}")
        if state["Image"] != inspect["docker_image_id"]:
            raise QualificationError("TASK_IMAGE_DIGEST_MISMATCH", "fingerprint container image mismatch")
        fp = parse_fingerprint(proc.stdout)
        fp = enrich_loader_identity(fp, container_id, raw_dir)
        if inspect["docker_os"] != PLATFORM_OS:
            raise QualificationError("TASK_IMAGE_OS_MISMATCH", immutable)
        if inspect["docker_architecture"] != PLATFORM_ARCH:
            raise QualificationError("TASK_IMAGE_ARCHITECTURE_MISMATCH", immutable)
        return {**inspect, "runtime": fp, "runtime_key_candidate": candidate_runtime_key(fp), "classification": classification_for(fp), "disk_free_before": before}
    finally:
        if container_id:
            cleanup = subprocess.run(["docker", "rm", "-f", container_id], text=True, capture_output=True)
            write_json(raw_dir / "container-cleanup.json", {"container_id": container_id, "exit": cleanup.returncode,
                "stdout": cleanup.stdout, "stderr": cleanup.stderr})
        removed = subprocess.run(["docker", "image", "rm", "-f", immutable], text=True, capture_output=True)
        write_json(raw_dir / "cleanup.json", {
            "attempted": True,
            "exit": removed.returncode,
            "stdout": removed.stdout,
            "stderr": removed.stderr,
            "disk_free_after": shutil.disk_usage("/").free,
        })


def census(args: argparse.Namespace) -> int:
    reports = args.reports.resolve()
    raw_root = reports / "per-digest"
    raw_root.mkdir(parents=True, exist_ok=True)
    try:
        task_ids = load_stable_pool(args.stable_pool)
        validate_dataset_identity(args.dataset_identity)
        historical = load_historical_task_image_map(args.historical_task_image_map, task_ids)
        mapping = resolve_task_image_map(task_ids, args.dataset_root)
        initial: dict[str, dict[str, Any]] = {}
        bound: list[dict[str, Any]] = []
        for row in mapping:
            reference = row["authoritative_image_reference"]
            resolved, selected_raw = resolve_remote_fail_closed(reference)
            merged = bind_selected_manifest({**row, **resolved}, selected_raw)
            if reference in initial:
                assert_no_tag_drift(initial[reference], merged)
            initial[reference] = merged
            bound.append(merged)
        write_json(reports / "task-image-map.json", {"schema_version": SCHEMA_VERSION, "tasks": bound})
        unique = deduplicate_exact_digests(bound)
        write_json(reports / "unique-image-digests.json", {"schema_version": SCHEMA_VERSION, "images": unique})
        confirmed: dict[str, tuple[dict[str, Any], bytes]] = {}
        for item in unique:
            reference = item["representative_image_reference"]
            again, selected_raw = resolve_remote_fail_closed(reference)
            again = bind_selected_manifest({**initial[reference], **again}, selected_raw)
            assert_no_tag_drift(initial[reference], again)
            confirmed[item["resolved_image_digest"]] = (again, selected_raw)
        comparison = compare_historical_task_image_map(historical, bound)
        write_json(reports / "inter-run-digest-comparison.json", comparison)
        if comparison["drift_count"]:
            raise QualificationError(
                "M1C_RUNTIME_FINGERPRINT_INTER_RUN_TAG_DRIFT_BLOCKER",
                ",".join(comparison["drifted_tasks"]),
            )
        fingerprints: list[dict[str, Any]] = []
        for index, item in enumerate(unique, 1):
            reference = item["representative_image_reference"]
            digest = item["resolved_image_digest"]
            again, selected_raw = confirmed[digest]
            raw_dir = raw_root / f"{index:02d}-{digest.replace(':', '-')}"
            raw_dir.mkdir(parents=True, exist_ok=True)
            write_json(raw_dir / "manifest-resolution.json", again)
            (raw_dir / "selected-manifest.json").write_bytes(selected_raw)
            fp = fingerprint_one(reference, digest, raw_dir)
            if fp["docker_image_id"] != again["image_config_digest"]:
                raise QualificationError("TASK_IMAGE_DIGEST_MISMATCH", f"{reference}: config mismatch")
            fingerprints.append({**item, **again, **fp})
        overall = "TASK_RUNTIME_FINGERPRINT_QUALIFIED" if fingerprints and all(item["classification"] == "TASK_RUNTIME_FINGERPRINT_QUALIFIED" for item in fingerprints) else "COMPATIBILITY_NOT_YET_PROVEN"
        class_rows = [{"resolved_image_digest": item["resolved_image_digest"], "runtime_key_candidate": item["runtime_key_candidate"], "task_ids": item["task_ids"]} for item in fingerprints]
        write_json(reports / "runtime-class-candidates.json", {"schema_version": SELECTOR_SCHEMA_VERSION, "candidates": class_rows})
        summary = {
            "schema_version": SCHEMA_VERSION,
            "classification": overall,
            "task_runtime_fingerprint_qualified": overall == "TASK_RUNTIME_FINGERPRINT_QUALIFIED",
            "dsh_native_runtime_compatibility_qualified": False,
            "stable_task_count": len(bound),
            "unique_immutable_image_digests": len(unique),
            "dataset_sha256": DATASET_SHA256,
            "stable_pool_sha256": STABLE_POOL_SHA256,
            "provider_requests": 0,
            "deepseek_requests": 0,
            "task_commands_executed": 0,
            "oracle_executions": 0,
            "verifier_executions": 0,
        }
        write_json(reports / "runtime-fingerprint-summary.json", summary)
        content_manifest(reports, reports / "SHA256SUMS")
        print(json.dumps(summary, sort_keys=True))
        return 0 if overall == "TASK_RUNTIME_FINGERPRINT_QUALIFIED" else 2
    except Exception as exc:
        classification = exc.classification if isinstance(exc, QualificationError) else "RUNTIME_FINGERPRINT_PREPARATION_FAILURE"
        failure = {
            "schema_version": SCHEMA_VERSION,
            "classification": classification,
            "detail": str(exc),
            "provider_requests": 0,
            "deepseek_requests": 0,
        }
        write_json(reports / "qualification-failure.json", failure)
        content_manifest(reports, reports / "SHA256SUMS")
        print(json.dumps(failure, sort_keys=True), file=sys.stderr)
        return 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stable-pool", type=Path, required=True)
    parser.add_argument("--dataset-root", type=Path, required=True)
    parser.add_argument("--dataset-identity", type=Path, required=True)
    parser.add_argument("--historical-task-image-map", type=Path, required=True)
    parser.add_argument("--reports", type=Path, required=True)
    return census(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())

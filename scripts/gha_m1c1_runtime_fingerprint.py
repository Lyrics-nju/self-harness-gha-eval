#!/usr/bin/env python3
"""Deterministic, no-model task-image runtime fingerprint census."""
from __future__ import annotations

import argparse
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

SCHEMA_VERSION = "runtime_fingerprint_v1"
SELECTOR_SCHEMA_VERSION = "artifact_class_selector_v1"
STABLE_POOL_SHA256 = "d3cf005c96355a618843982e47d3c130616766795d2b4f8a54bd9c1ace917fef"
DATASET_SHA256 = "7d7bdc1cbedad549fc1140404bd4dc45e5fd0ea7c4186773687d177ad3a0699a"
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


FINGERPRINT_SCRIPT = r"""
set -u
emit() { printf '%s\t%s\n' "$1" "$2"; }
na=NOT_AVAILABLE
emit uname_s "$(uname -s 2>/dev/null || printf %s "$na")"
emit uname_m "$(uname -m 2>/dev/null || printf %s "$na")"
emit long_bit "$(getconf LONG_BIT 2>/dev/null || printf %s "$na")"
if test -r /etc/os-release; then emit os_release_b64 "$(base64 < /etc/os-release 2>/dev/null | tr -d '\n' || printf %s "$na")"; else emit os_release_b64 "$na"; fi
emit libc_getconf "$(getconf GNU_LIBC_VERSION 2>/dev/null || printf %s "$na")"
emit ldd_version "$(ldd --version 2>&1 | head -1 || printf %s "$na")"
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
if test -n "$probe_executable" && command -v readelf >/dev/null 2>&1; then
  interp="$(readelf -l "$probe_executable" 2>/dev/null | sed -n 's/.*Requesting program interpreter: \([^]]*\)].*/\1/p' | head -1)"
  if test -n "$interp" && test -e "$interp"; then
    loader=$interp
    loader_method=READELF_PT_INTERP
    loader_evidence="probe=$probe_executable;pt_interp=$interp"
  fi
fi
if test -z "$loader" && test -n "$probe_executable" && command -v ldd >/dev/null 2>&1; then
  interp="$(ldd "$probe_executable" 2>/dev/null | awk '{for(i=1;i<=NF;i++){v=$i; gsub(/[()]/,"",v); if(v ~ /^\// && v ~ /(ld-linux|ld-musl|\/ld-[^/]*\.so)/){print v; exit}}}')"
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
  loader_identity="$("$loader" --version 2>&1 | head -1 || true)"
  emit dynamic_loader_identity "${loader_identity:-$na}"
else emit dynamic_loader_identity "$na"; fi
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
        "dynamic_loader_identity": fingerprint.get("dynamic_loader_identity", NOT_AVAILABLE),
        "dynamic_loader_path": fingerprint.get("dynamic_loader_path", NOT_AVAILABLE),
        "kernel_security_contract": "|".join(str(fingerprint.get(key, NOT_AVAILABLE)) for key in ("seccomp", "no_new_privs", "landlock_securityfs", "dev_pts", "dev_ptmx")),
        "artifact_node_contract": "ARTIFACT_PROVIDED_NOT_YET_QUALIFIED",
        "canonical_runtime_layout": CANONICAL_LAYOUT,
    }


def classification_for(fingerprint: dict[str, Any]) -> str:
    required = (
        "uname_s", "uname_m", "libc_getconf", "dynamic_loader_path", "dynamic_loader_identity",
        "dynamic_loader_detection_method", "dynamic_loader_detection_evidence",
    )
    capabilities = {
        "installed_agent_writable": "PASS", "tmp_writable": "PASS", "local_exec": "PASS",
        "dev_pts": "PRESENT", "dev_ptmx": "PRESENT",
    }
    missing = any(fingerprint.get(key, NOT_AVAILABLE) == NOT_AVAILABLE for key in required)
    incompatible = any(fingerprint.get(key, NOT_AVAILABLE) != value for key, value in capabilities.items())
    return "COMPATIBILITY_NOT_YET_PROVEN" if missing or incompatible else "TASK_RUNTIME_FINGERPRINT_QUALIFIED"


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
    try:
        pull = subprocess.run(["docker", "pull", "--platform", f"{PLATFORM_OS}/{PLATFORM_ARCH}", immutable], text=True, capture_output=True)
        (raw_dir / "pull.stdout").write_text(pull.stdout)
        (raw_dir / "pull.stderr").write_text(pull.stderr)
        (raw_dir / "pull.exit").write_text(f"{pull.returncode}\n")
        if pull.returncode:
            raise QualificationError("TASK_IMAGE_PULL_FAILURE", f"{immutable}: exit {pull.returncode}")
        inspect = image_inspect(immutable)
        proc = subprocess.run(["docker", "run", "--rm", "--entrypoint", "/bin/sh", immutable, "-c", FINGERPRINT_SCRIPT], text=True, capture_output=True, check=False)
        (raw_dir / "fingerprint.stdout").write_text(proc.stdout)
        (raw_dir / "fingerprint.stderr").write_text(proc.stderr)
        (raw_dir / "fingerprint.exit").write_text(f"{proc.returncode}\n")
        if proc.returncode:
            raise QualificationError("TASK_RUNTIME_FINGERPRINT_CONTAINER_FAILURE", f"{immutable}: exit {proc.returncode}")
        fp = parse_fingerprint(proc.stdout)
        if inspect["docker_os"] != PLATFORM_OS:
            raise QualificationError("TASK_IMAGE_OS_MISMATCH", immutable)
        if inspect["docker_architecture"] != PLATFORM_ARCH:
            raise QualificationError("TASK_IMAGE_ARCHITECTURE_MISMATCH", immutable)
        return {**inspect, "runtime": fp, "runtime_key_candidate": candidate_runtime_key(fp), "classification": classification_for(fp), "disk_free_before": before}
    finally:
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
        mapping = resolve_task_image_map(task_ids, args.dataset_root)
        initial: dict[str, dict[str, Any]] = {}
        bound: list[dict[str, Any]] = []
        for row in mapping:
            reference = row["authoritative_image_reference"]
            resolved, selected_raw = resolve_remote(reference)
            merged = bind_selected_manifest({**row, **resolved}, selected_raw)
            if reference in initial:
                assert_no_tag_drift(initial[reference], merged)
            initial[reference] = merged
            bound.append(merged)
        write_json(reports / "task-image-map.json", {"schema_version": SCHEMA_VERSION, "tasks": bound})
        unique = deduplicate_exact_digests(bound)
        write_json(reports / "unique-image-digests.json", {"schema_version": SCHEMA_VERSION, "images": unique})
        fingerprints: list[dict[str, Any]] = []
        for index, item in enumerate(unique, 1):
            reference = item["representative_image_reference"]
            again, selected_raw = resolve_remote(reference)
            again = bind_selected_manifest({**initial[reference], **again}, selected_raw)
            assert_no_tag_drift(initial[reference], again)
            digest = item["resolved_image_digest"]
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
    parser.add_argument("--reports", type=Path, required=True)
    return census(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())

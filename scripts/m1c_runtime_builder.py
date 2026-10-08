"""Fixed builder policy and conservative closure packer; no Docker invocation.

Prebuild metadata is pinned; the final builder image has not been created.
The local fixture suite does not grant permission to run a build.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from scripts import m1c_runtime_artifact as a
from scripts import m1c_runtime_identity as identity

POLICY = identity.policy()


def execution_gate(policy: dict, node_archive: Path, actual_commit: str) -> None:
    a.require(actual_commit == a.DSH_COMMIT and policy["source_commit"] == a.DSH_COMMIT, "SOURCE_COMMIT_DRIFT")
    a.require(policy["platform"] == "linux/amd64" and policy["pnpm"] == "11.7.0", "BUILDER_POLICY_DRIFT")
    a.require(bool(re.fullmatch(r"[a-z0-9./:_-]+@sha256:[0-9a-f]{64}", policy["base_image"])), "BUILDER_DIGEST_UNRESOLVED")
    a.require(bool(a.HEX.fullmatch(policy["node_archive_sha256"])), "NODE_CHECKSUM_UNRESOLVED")
    a.require(a.file_hash(node_archive) == policy["node_archive_sha256"], "NODE_ARCHIVE_CHECKSUM_MISMATCH")
    a.require(bool(re.fullmatch(r"v(?:22|24)\.[0-9]+\.[0-9]+", policy["node_version"])), "NODE_IDENTITY_UNRESOLVED")
    if policy["node_version"].startswith("v22."):
        a.require(tuple(map(int, policy["node_version"][1:].split("."))) >= (22, 19, 0), "NODE_UNSUPPORTED")
    a.require(bool(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", policy["corepack_version"])), "COREPACK_UNRESOLVED")
    a.require(type(policy["builder_memory"]) is int and policy["builder_memory"] > 2 * 1024**3,
              "BUILDER_RESOURCE_BUDGET_UNRESOLVED")


def builder_plan(node_archive: Path, actual_commit: str) -> list[str]:
    identity.validate_inputs(POLICY)
    a.require(node_archive.is_file(), "NODE_ARCHIVE_NOT_DOWNLOADED")
    execution_gate(POLICY, node_archive, actual_commit)
    identity.verify_archives(node_archive.parent, POLICY)
    context = node_archive.parent.parent
    identity.verify_staged_context(context, POLICY)
    return ["docker", "build", "--platform=linux/amd64", "--memory=" + str(POLICY["builder_memory"]),
            "--build-arg", "BASE_IMAGE=" + POLICY["base_image"], "--build-arg",
            "NODE_ARCHIVE_SHA256=" + POLICY["node_archive_sha256"], "--build-arg",
            "NODE_VERSION=" + POLICY["node_version"], "--build-arg",
            "COREPACK_INTEGRITY=" + POLICY["corepack_integrity"], "--build-arg",
            "PNPM_INTEGRITY=" + POLICY["pnpm_integrity"], "--file",
            str(context / "gha/runtime-artifact-v1/Dockerfile"), str(context)]


def command(argv: list[str], cwd: Path) -> str:
    result = subprocess.run(argv, cwd=cwd, check=True, capture_output=True, text=True)
    return result.stdout.strip()


def source_identity(source: Path, runner=command) -> tuple[str, str]:
    commit = runner(["git", "rev-parse", "HEAD"], source)
    a.require(commit == a.DSH_COMMIT, "SOURCE_COMMIT_DRIFT")
    a.require(not runner(["git", "status", "--porcelain"], source), "SOURCE_WORKTREE_DIRTY")
    tree = runner(["git", "rev-parse", "HEAD^{tree}"], source)
    a.require(bool(re.fullmatch(r"[0-9a-f]{40}", tree)), "SOURCE_TREE_UNRESOLVED")
    return commit, tree


def stage_workspace(source: Path, node_root: Path, destination: Path) -> None:
    """Keep workspace layout and installed dependency tree; never copy .git/cache.

    This conservative V1 also retains source/manifests in runtime package roots.
    It does not prune dev dependencies from the pnpm tree. No package installer
    runs here. Caches are excluded, unexpected state/credential paths fail closed.
    """
    a.require(not destination.exists(), "STAGING_EXISTS")
    destination.mkdir()

    def ignore(directory: str, names: list[str]) -> list[str]:
        excluded = []
        for name in names:
            if name in {".git", ".cache", ".pnpm-store", "__pycache__"} or name.endswith(a.CACHE_SUFFIXES):
                excluded.append(name)
            elif name in a.FORBIDDEN or name.startswith(".env.") or name.endswith((".pem", ".key")):
                raise a.ArtifactError("STATE_SECRET_CACHE_PATH")
        return excluded

    for root in a.ROOTS:
        origin = source / root
        a.require(origin.is_dir() and not origin.is_symlink(), "CLOSURE_ROOT_MISSING")
        shutil.copytree(origin, destination / root, symlinks=True, ignore=ignore)
    for name in a.ROOT_FILES:
        a.require((source / name).is_file() and not (source / name).is_symlink(), "CLOSURE_ROOT_MISSING")
        shutil.copy2(source / name, destination / name)
    node_path = destination / a.NODE
    node_path.parent.mkdir(parents=True)
    shutil.copy2(node_root / "bin/node", node_path)
    # Only the executable is required from the official Node carrier; ELF load
    # checks must prove all of its external libraries in the original task image.
    for name in ("LICENSE",):
        if (node_root / name).is_file():
            shutil.copy2(node_root / name, node_path.parent.parent / name)
    a.inventory(destination)


def main() -> int:
    a.require(len(sys.argv) == 6, "BUILDER_ARGUMENTS")
    source, node_root, output, identity_path, build_path = map(Path, sys.argv[1:])
    evidence = json.loads(identity_path.read_bytes())
    identity.dsh_build_gate(POLICY, evidence["image"], evidence["resources"], source / "pnpm-lock.yaml")
    build_record = json.loads(build_path.read_bytes())
    a.require(build_record == {"image_id": evidence["image"]["image_id"], "command": "pnpm run build",
                              "exit": 0, "lockfile_sha256": POLICY["lockfile_sha256"]}, "BUILD_NOT_PROVEN")
    # Re-check the frozen identities even inside Docker: bypassing the planning
    # helper must never turn unresolved policy into an accepted artifact.
    execution_gate(POLICY, Path("/inputs/node.tar.xz"), command(["git", "rev-parse", "HEAD"], source))
    commit, tree = source_identity(source)
    a.require("NODE_OPTIONS" not in os.environ, "BUILD_ENVIRONMENT_DRIFT")
    n = json.loads(command([str(node_root / "bin/node"), "-p",
                            "JSON.stringify({version:process.version,abi:process.versions.modules,napi:process.versions.napi})"], source))
    a.require(n["version"] == POLICY["node_version"], "NODE_IDENTITY_DRIFT")
    a.require(n["abi"] == evidence["image"]["node_abi"] and n["napi"] == evidence["image"]["node_napi"],
              "BUILDER_NODE_RUNTIME_DRIFT")
    n.update(archive_sha256=POLICY["node_archive_sha256"], binary_sha256=a.file_hash(node_root / "bin/node"))
    libc = command(["getconf", "GNU_LIBC_VERSION"], source)
    a.require(bool(re.fullmatch(r"glibc [0-9]+\.[0-9]+", libc)) and
              (2, 28) <= tuple(map(int, libc.split()[1].split("."))) <= (2, 31),
              "GENERIC_BUILDER_LIBC_BASELINE_DRIFT")
    corepack = command(["corepack", "--version"], source)
    pnpm = command(["pnpm", "--version"], source)
    a.require(corepack == POLICY["corepack_version"] and pnpm == POLICY["pnpm"], "TOOLCHAIN_DRIFT")
    a.require(libc == evidence["image"]["libc"], "BUILDER_LIBC_RUNTIME_DRIFT")
    provenance = {"source_commit": commit, "source_tree": tree, "lockfile_sha256": a.file_hash(source / "pnpm-lock.yaml"),
                  "builder_image": evidence["image"]["image_id"], "platform": POLICY["platform"], "libc": libc,
                  "node": n, "corepack": corepack, "pnpm": pnpm,
                  "builder_evidence": evidence,
                  "build": {"command": "pnpm run build", "environment": "CLEAN_BUILDER_NO_TASK_STATE", "exit": 0}}
    # Independent post-build receipts are required. This packer never builds.
    # Record/reject tracked source or lockfile modifications caused by the build.
    with tempfile.TemporaryDirectory() as temporary:
        stage = Path(temporary) / "closure"
        stage_workspace(source, node_root, stage)
        a.pack(stage, provenance, output)
        # Separate evidence lane, not an unversioned manifest-schema mutation.
        manifest = json.loads((output / "manifest.json").read_bytes())
        native = {}
        for row in manifest["native_inventory"]:
            inspected = subprocess.run(["readelf", "-h", "-d", "-V", str(stage / row["path"])],
                                       capture_output=True, text=True, check=False, timeout=30)
            a.require(inspected.returncode == 0, "NATIVE_ELF_INSPECTION_FAILED")
            machine = re.search(r"Machine:\s*(.+)", inspected.stdout)
            a.require(machine is not None, "NATIVE_ELF_MACHINE_MISSING")
            native[row["path"]] = {"sha256": row["sha256"], "readelf_exit": inspected.returncode,
                "machine": machine.group(1).strip(),
                "needed_libraries": re.findall(r"\(NEEDED\).*?\[([^\]]+)\]", inspected.stdout),
                "required_symbol_versions": sorted(set(re.findall(r"(?:GLIBC|GLIBCXX|CXXABI)_[0-9.]+", inspected.stdout))),
                "compatibility_status": "NOT_YET_QUALIFIED"}
        (output / "native-evidence.json").write_bytes(a.canonical(native))
        a.require(not a.scan_tree(output, artifact_mode=True), "ARTIFACT_SECRET_SCAN_REJECTED")
    return 0


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--preflight":
        source = Path(sys.argv[2])
        commit, _tree = source_identity(source)
        execution_gate(POLICY, Path("/inputs/node.tar.xz"), commit)
        identity.verify_archives(Path("/inputs"), POLICY)
        a.require(a.file_hash(source / "pnpm-lock.yaml") == POLICY["lockfile_sha256"], "FROZEN_LOCKFILE_DRIFT")
        a.require("NODE_OPTIONS" not in os.environ, "BUILD_ENVIRONMENT_DRIFT")
        # This legacy path proves input/archive identities only, never grants
        # build permission or fabricates a final image identity.
        identity.validate_inputs(POLICY)
        print("PREBUILD_INPUT_IDENTITIES_PINNED")
    else:
        raise SystemExit(main())

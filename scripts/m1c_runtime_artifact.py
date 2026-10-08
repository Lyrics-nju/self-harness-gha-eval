#!/usr/bin/env python3
"""V1 runtime archive: deterministic bytes, closed contents, offline extraction.

No build or runtime execution occurs on import. A receipt is an external trust
anchor: callers must pin its hash independently, not accept an archive's claims.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import posixpath
import re
import shutil
import stat
import tarfile
import tempfile
from pathlib import Path, PurePosixPath

from scripts.public_secret_scan import scan_tree

DSH_COMMIT = "b150a551b8d465e31e418e1b2eaf5e79bbb7d28e"
ADAPTER_SHA = "8ef6389565309ba208557923cced1e619a8a1b25549353f9b5f13e2313ad6070"
SCHEMA = "m1c_dsh_runtime_artifact_v1"
ENTRY = "apps/cli/lib/bin.js"
NODE = ".runtime-node/bin/node"
HEX = re.compile(r"[0-9a-f]{64}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
RESERVED = "ARTIFACT_MANIFEST.json"
FORBIDDEN = {".git", ".env", "DSH_HOME", "candidate.patch.yml", "sessions", "session-state",
             "agent-logs", "events", ".cache", ".pnpm-store", "__pycache__", ".npmrc", ".netrc",
             ".pypirc", ".ssh", ".aws", "credentials.json", "session.json", "events.jsonl"}
CACHE_SUFFIXES = (".tsbuildinfo", ".pyc")
ROOTS = ("apps", "packages", "vendor", "native/landlock-run/packages", "node_modules")
ROOT_FILES = ("package.json", "pnpm-lock.yaml", "pnpm-workspace.yaml")


class ArtifactError(RuntimeError):
    pass


def require(ok: bool, code: str) -> None:
    if not ok:
        raise ArtifactError(code)


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_hash(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def path_name(name: str) -> str:
    require(isinstance(name, str) and bool(name) and "\\" not in name and "\x00" not in name,
            "UNSAFE_PATH")
    parts = name.split("/")
    require(not name.startswith("/") and all(p not in ("", ".", "..") for p in parts), "UNSAFE_PATH")
    require(not any(p in FORBIDDEN or p.startswith(".env.") or p.endswith(CACHE_SUFFIXES)
                    or p.endswith((".pem", ".key")) for p in parts), "STATE_SECRET_CACHE_PATH")
    return name


def link_destination(name: str, target: str) -> str:
    require(isinstance(target, str) and bool(target) and not target.startswith("/")
            and "\\" not in target and "\x00" not in target, "UNSAFE_SYMLINK")
    resolved = posixpath.normpath(posixpath.join(posixpath.dirname(name), target))
    require(resolved != ".." and not resolved.startswith("../"), "SYMLINK_ESCAPE")
    return path_name(resolved)


def validate_links(entries: list[dict]) -> None:
    by_name = {item["path"]: item for item in entries}
    # A link cannot be an ancestor of another archive entry. This also prevents
    # extraction through a symlink directory; legitimate pnpm links are leaves.
    for name, item in by_name.items():
        for parent in PurePosixPath(name).parents:
            if str(parent) != ".":
                require(by_name.get(str(parent), {}).get("kind") == "dir", "UNDECLARED_OR_LINK_PARENT")
        if item["kind"] == "symlink":
            target = link_destination(name, item["target"])
            seen = {name}
            while by_name.get(target, {}).get("kind") == "symlink":
                require(target not in seen, "SYMLINK_CYCLE")
                seen.add(target)
                target = link_destination(target, by_name[target]["target"])
            require(target in by_name, "DANGLING_SYMLINK")


def inventory(tree: Path) -> list[dict]:
    require(tree.is_dir() and not tree.is_symlink(), "INVALID_PROGRAM_ROOT")
    entries = []
    for current, dirs, files in os.walk(tree, followlinks=False):
        for basename in sorted(dirs + files):
            path = Path(current) / basename
            name = path_name(path.relative_to(tree).as_posix())
            require(name != RESERVED, "RESERVED_MANIFEST_COLLISION")
            st = path.lstat()
            require(not st.st_mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX), "UNSAFE_MODE")
            mode = stat.S_IMODE(st.st_mode)
            if stat.S_ISLNK(st.st_mode):
                item = {"path": name, "kind": "symlink", "mode": 0o777, "target": os.readlink(path)}
            elif stat.S_ISDIR(st.st_mode):
                item = {"path": name, "kind": "dir", "mode": mode}
            elif stat.S_ISREG(st.st_mode):
                require(st.st_nlink == 1, "HARDLINK_NOT_SUPPORTED")
                item = {"path": name, "kind": "file", "mode": mode, "size": st.st_size,
                        "sha256": file_hash(path)}
            else:
                raise ArtifactError("UNSAFE_FILE_TYPE")
            entries.append(item)
    entries.sort(key=lambda item: item["path"])
    validate_links(entries)
    return entries


def validate_provenance(p: dict) -> None:
    require(set(p) == {"source_commit", "source_tree", "lockfile_sha256", "builder_image",
                      "platform", "libc", "node", "corepack", "pnpm", "build", "builder_evidence"}, "PROVENANCE_SCHEMA")
    require(p["source_commit"] == DSH_COMMIT, "SOURCE_COMMIT_DRIFT")
    require(bool(re.fullmatch(r"[0-9a-f]{40}", p["source_tree"])), "SOURCE_TREE_UNRESOLVED")
    require(bool(HEX.fullmatch(p["lockfile_sha256"])), "LOCKFILE_UNRESOLVED")
    require(bool(re.fullmatch(r"(?:[a-z0-9./:_-]+@)?sha256:[0-9a-f]{64}", p["builder_image"])),
            "BUILDER_DIGEST_UNRESOLVED")
    require(p["platform"] == "linux/amd64", "PLATFORM_DRIFT")
    require(bool(re.fullmatch(r"glibc [0-9]+\.[0-9]+", p["libc"])), "LIBC_UNRESOLVED")
    n = p["node"]
    require(set(n) == {"version", "abi", "napi", "archive_sha256", "binary_sha256"}, "NODE_SCHEMA")
    require(bool(re.fullmatch(r"v(?:22|24)\.[0-9]+\.[0-9]+", n["version"])), "NODE_UNSUPPORTED")
    if n["version"].startswith("v22."):
        require(tuple(map(int, n["version"][1:].split("."))) >= (22, 19, 0), "NODE_UNSUPPORTED")
    require(all(isinstance(n[k], str) and n[k].isdigit() for k in ("abi", "napi")), "NODE_ABI_UNRESOLVED")
    require(all(bool(HEX.fullmatch(n[k])) for k in ("archive_sha256", "binary_sha256")), "NODE_HASH_UNRESOLVED")
    require(bool(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", p["corepack"])), "COREPACK_UNRESOLVED")
    require(p["pnpm"] == "11.7.0", "PNPM_DRIFT")
    require(p["build"] == {"command": "pnpm run build", "environment": "CLEAN_BUILDER_NO_TASK_STATE",
                           "exit": 0}, "BUILD_NOT_PROVEN")
    from scripts import m1c_runtime_identity as identity
    evidence = p["builder_evidence"]
    require(set(evidence) == {"image", "resources"}, "BUILDER_EVIDENCE_SCHEMA")
    identity.capacity_gate(evidence["resources"], identity.policy(), evidence["image"])
    image = evidence["image"]
    require(p["builder_image"] == image["image_id"] and p["libc"] == image["libc"] and
            n["version"] == image["node_version"] and n["abi"] == image["node_abi"] and
            n["napi"] == image["node_napi"] and p["corepack"] == image["corepack"] and
            p["pnpm"] == image["pnpm"], "BUILDER_PROVENANCE_DRIFT")


def pack(tree: Path, provenance: dict, output: Path) -> dict:
    """Pack a controlled closure, not an arbitrary checkout or downloaded archive."""
    validate_provenance(provenance)
    require(not output.exists() and tree.resolve() not in output.resolve().parents, "OUTPUT_COLLISION")
    entries = inventory(tree)
    by_name = {item["path"]: item for item in entries}
    require(all(by_name.get(n, {}).get("kind") == "file" for n in (ENTRY, NODE, "apps/cli/package.json",
                                                                  "pnpm-lock.yaml")), "RUNTIME_INCOMPLETE")
    require(by_name[NODE]["mode"] & 0o111 != 0, "NODE_NOT_EXECUTABLE")
    require(by_name[NODE]["sha256"] == provenance["node"]["binary_sha256"], "NODE_BINARY_HASH_MISMATCH")
    require(by_name["pnpm-lock.yaml"]["sha256"] == provenance["lockfile_sha256"], "LOCKFILE_HASH_MISMATCH")
    require(not scan_tree(tree, artifact_mode=True), "ARTIFACT_SECRET_SCAN_REJECTED")
    def is_elf(item: dict) -> bool:
        with (tree / item["path"]).open("rb") as stream:
            return stream.read(4) == b"\x7fELF"

    native = [{"path": item["path"], "sha256": item["sha256"], "abi_status": "NOT_RUN",
               "needed_libraries": "NOT_RUN", "required_symbol_versions": "NOT_RUN"}
              for item in entries if item["kind"] == "file" and
              (is_elf(item) or item["path"].endswith(".node"))]
    manifest = {"schema_version": SCHEMA, "provenance": provenance, "entrypoint": ENTRY,
                "node_path": NODE, "entries": entries, "native_inventory": native,
                "secret_scan": "PASS", "relocation": "NOT_RUN", "compatibility": "NOT_RUN"}
    output.mkdir(parents=True)
    archive = output / "program.tar"
    with tarfile.open(archive, "w", format=tarfile.GNU_FORMAT) as tar:
        for item in entries:
            info = tarfile.TarInfo(item["path"])
            info.mode = item["mode"]
            if item["kind"] == "dir":
                info.type = tarfile.DIRTYPE
            elif item["kind"] == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = item["target"]
            else:
                info.size = item["size"]
            if item["kind"] == "file":
                with (tree / item["path"]).open("rb") as stream:
                    tar.addfile(info, stream)
            else:
                tar.addfile(info)
    # Manifest and receipt are intentionally outside the archive.
    (output / "manifest.json").write_bytes(canonical(manifest))
    receipt = {"schema_version": SCHEMA, "archive_sha256": file_hash(archive),
               "manifest_sha256": digest(canonical(manifest))}
    (output / "receipt.json").write_bytes(canonical(receipt))
    verify_archive(archive, manifest, receipt)
    return receipt


def validate_manifest(manifest: dict) -> None:
    require(set(manifest) == {"schema_version", "provenance", "entrypoint", "node_path", "entries",
                              "native_inventory", "secret_scan", "relocation", "compatibility"}, "MANIFEST_SCHEMA")
    require(manifest["schema_version"] == SCHEMA and manifest["entrypoint"] == ENTRY
            and manifest["node_path"] == NODE, "MANIFEST_IDENTITY")
    validate_provenance(manifest["provenance"])
    require(manifest["secret_scan"] == "PASS" and manifest["relocation"] == "NOT_RUN"
            and manifest["compatibility"] == "NOT_RUN", "QUALIFICATION_CLAIM_NOT_ALLOWED")
    entries = manifest["entries"]
    require(isinstance(entries, list) and bool(entries), "EMPTY_MANIFEST")
    require([e["path"] for e in entries] == sorted({e["path"] for e in entries}), "DUPLICATE_OR_UNSORTED")
    for e in entries:
        path_name(e["path"])
        kind = e["kind"]
        keys = {"path", "kind", "mode"} | ({"target"} if kind == "symlink" else
                                               {"size", "sha256"} if kind == "file" else set())
        require(set(e) == keys and kind in ("file", "dir", "symlink"), "ENTRY_SCHEMA")
        require(type(e["mode"]) is int and 0 <= e["mode"] <= 0o777, "UNSAFE_MODE")
        if kind == "file":
            require(type(e["size"]) is int and e["size"] >= 0 and bool(HEX.fullmatch(e["sha256"])), "FILE_SCHEMA")
    validate_links(entries)
    files = {e["path"]: e for e in entries if e["kind"] == "file"}
    require(all(n in files for n in (ENTRY, NODE, "apps/cli/package.json", "pnpm-lock.yaml")), "RUNTIME_INCOMPLETE")
    require(files[NODE]["mode"] & 0o111 != 0 and
            files[NODE]["sha256"] == manifest["provenance"]["node"]["binary_sha256"] and
            files["pnpm-lock.yaml"]["sha256"] == manifest["provenance"]["lockfile_sha256"], "RUNTIME_HASH_BINDING")
    expected_native_keys = {"path", "sha256", "abi_status", "needed_libraries", "required_symbol_versions"}
    seen = set()
    for n in manifest["native_inventory"]:
        require(set(n) == expected_native_keys and n["path"] in files and n["path"] not in seen
                and n["sha256"] == files[n["path"]]["sha256"] and
                all(n[k] == "NOT_RUN" for k in ("abi_status", "needed_libraries", "required_symbol_versions")), "NATIVE_SCHEMA")
        seen.add(n["path"])


def verify_archive(archive: Path, manifest: dict, receipt: dict) -> None:
    validate_manifest(manifest)
    require(set(receipt) == {"schema_version", "archive_sha256", "manifest_sha256"}
            and receipt["schema_version"] == SCHEMA, "RECEIPT_SCHEMA")
    require(file_hash(archive) == receipt["archive_sha256"] and
            digest(canonical(manifest)) == receipt["manifest_sha256"], "ARTIFACT_HASH_MISMATCH")
    expected = {e["path"]: e for e in manifest["entries"]}
    seen = set()
    native = set()
    with tarfile.open(archive, "r:") as tar:
        for member in tar:
            name = path_name(member.name.rstrip("/") if member.isdir() else member.name)
            require(name in expected and name not in seen, "UNDECLARED_OR_DUPLICATE_ENTRY")
            seen.add(name)
            e = expected[name]
            require(member.uid == member.gid == member.mtime == 0 and not member.pax_headers
                    and not member.uname and not member.gname and member.mode == e["mode"], "ARCHIVE_METADATA_DRIFT")
            if e["kind"] == "file":
                require(member.isfile() and member.size == e["size"], "UNSAFE_ARCHIVE_ENTRY")
                stream = tar.extractfile(member)
                require(stream is not None, "MISSING_ARCHIVE_CONTENT")
                h = hashlib.sha256()
                head = stream.read(4)
                h.update(head)
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    h.update(block)
                require(h.hexdigest() == e["sha256"], "FILE_HASH_MISMATCH")
                if head == b"\x7fELF" or name.endswith(".node"):
                    native.add(name)
            elif e["kind"] == "dir":
                require(member.isdir() and member.size == 0, "UNSAFE_ARCHIVE_ENTRY")
            else:
                require(member.issym() and member.linkname == e["target"] and member.size == 0, "UNSAFE_ARCHIVE_ENTRY")
    require(seen == set(expected), "MISSING_ARCHIVE_ENTRY")
    require(native == {n["path"] for n in manifest["native_inventory"]}, "NATIVE_INVENTORY_INCOMPLETE")


def verify_tree(tree: Path, manifest: dict) -> None:
    validate_manifest(manifest)
    require(inventory(tree) == manifest["entries"], "PROGRAM_TREE_MUTATION")
    require(not scan_tree(tree, artifact_mode=True), "ARTIFACT_SECRET_SCAN_REJECTED")


def load_bundle(bundle: Path, receipt_sha256: str) -> tuple[dict, dict]:
    raw_receipt = (bundle / "receipt.json").read_bytes()
    require(bool(HEX.fullmatch(receipt_sha256)) and digest(raw_receipt) == receipt_sha256,
            "RECEIPT_TRUST_ANCHOR_MISMATCH")
    receipt = json.loads(raw_receipt)
    raw_manifest = (bundle / "manifest.json").read_bytes()
    manifest = json.loads(raw_manifest)
    require(raw_receipt == canonical(receipt) and raw_manifest == canonical(manifest), "NONCANONICAL_METADATA")
    require(digest(raw_manifest) == receipt["manifest_sha256"], "MANIFEST_FILE_HASH_MISMATCH")
    verify_archive(bundle / "program.tar", manifest, receipt)
    return manifest, receipt


def materialize(archive: Path, manifest: dict, receipt: dict, destination: Path) -> None:
    """No extractall: validated regular entries first, leaf links last, atomic publish."""
    require(not destination.exists() and not destination.is_symlink(), "DESTINATION_EXISTS")
    require(destination.parent.is_dir(), "DESTINATION_PARENT_MISSING")
    require(destination.parent.resolve() == destination.parent.absolute(), "DESTINATION_PARENT_SYMLINK")
    verify_archive(archive, manifest, receipt)
    with tempfile.TemporaryDirectory(prefix=".dsh-materialize-", dir=destination.parent) as tmp:
        tree = Path(tmp) / "program"
        tree.mkdir()
        with tarfile.open(archive, "r:") as tar:
            members = {m.name.rstrip("/") if m.isdir() else m.name: m for m in tar}
            for item in sorted(manifest["entries"], key=lambda e: (len(PurePosixPath(e["path"]).parts), e["path"])):
                path = tree / item["path"]
                if item["kind"] == "dir":
                    path.mkdir(mode=0o700)
                elif item["kind"] == "file":
                    with tar.extractfile(members[item["path"]]) as source, path.open("xb") as target:
                        shutil.copyfileobj(source, target)
                    path.chmod(item["mode"])
            for item in manifest["entries"]:
                if item["kind"] == "symlink":
                    (tree / item["path"]).symlink_to(item["target"])
            for item in reversed(manifest["entries"]):
                if item["kind"] == "dir":
                    (tree / item["path"]).chmod(item["mode"])
        verify_tree(tree, manifest)
        tree.rename(destination)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("verify", "materialize"))
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--receipt-sha256", required=True)
    parser.add_argument("--destination", type=Path)
    args = parser.parse_args()
    manifest, receipt = load_bundle(args.bundle, args.receipt_sha256)
    archive = args.bundle / "program.tar"
    if args.operation == "materialize":
        require(args.destination is not None, "DESTINATION_REQUIRED")
        materialize(archive, manifest, receipt, args.destination)
    else:
        verify_archive(archive, manifest, receipt)
    print("ARTIFACT_INTEGRITY_PASS; RUNTIME_COMPATIBILITY_NOT_RUN")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

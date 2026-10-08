"""Synthetic bytes only: these tests never build or execute DSH/containers."""
import copy
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from scripts import m1c_runtime_artifact as a
from scripts import m1c_runtime_builder as b
from scripts import m1c_runtime_qualification as q
from scripts import m1c_runtime_identity as i


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.tree = self.root / "tree"
        self.tree.mkdir()
        for name, data in {a.ENTRY: b"// fixture only\n", "apps/cli/package.json": b'{"name":"fixture"}\n',
                           a.NODE: b"\x7fELFfake-node-never-executed", "pnpm-lock.yaml": b"fixture-lock\n",
                           "packages/test/lib/index.js": b"fixture\n"}.items():
            path = self.tree / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        (self.tree / a.NODE).chmod(0o755)
        (self.tree / "node_modules").mkdir()
        (self.tree / "node_modules/test").symlink_to("../packages/test", target_is_directory=True)
        self.provenance = {"source_commit": a.DSH_COMMIT, "source_tree": "f" * 40,
                           "lockfile_sha256": a.file_hash(self.tree / "pnpm-lock.yaml"),
                           "builder_image": "sha256:" + "a" * 64,
                           "platform": "linux/amd64", "libc": "glibc 2.31",
                           "node": {"version": "v24.0.0", "abi": "137", "napi": "10",
                                    "archive_sha256": "b" * 64, "binary_sha256": a.file_hash(self.tree / a.NODE)},
                           "corepack": "0.33.0", "pnpm": "11.7.0",
                           "build": {"command": "pnpm run build", "environment": "CLEAN_BUILDER_NO_TASK_STATE", "exit": 0}}
        self.provenance["builder_evidence"] = {
            "image": {"image_id": "sha256:" + "a" * 64, "container_image_id": "sha256:" + "a" * 64,
                      "image_config_sha256": "a" * 64, "platform": "linux/amd64", "libc": "glibc 2.31",
                      "os_release_sha256": "b" * 64, "node_version": "v24.0.0", "node_abi": "137", "node_napi": "10",
                      "corepack": "0.33.0", "pnpm": "11.7.0", "input_context_sha256": i.policy()["context_sha256"],
                      "base_image": i.policy()["base_image"]},
            "resources": {"host_cpus": 4, "host_mem_available_bytes": 12 * 1024**3,
                          "host_free_disk_bytes": 14 * 1024**3, "container_memory_max": 8 * 1024**3,
                          "container_nano_cpus": 2 * 10**9, "container_memory_swap": 8 * 1024**3,
                          "memory_events": {"oom": 0, "oom_kill": 0}, "measurement_id": "c" * 64}}
        self.bundle = self.root / "bundle"

    def packed(self):
        receipt = a.pack(self.tree, self.provenance, self.bundle)
        return json.loads((self.bundle / "manifest.json").read_bytes()), receipt

    def rejected(self, call, code):
        with self.assertRaisesRegex(a.ArtifactError, code):
            call()

    def rewrite_tar(self, manifest, receipt, mutate):
        archive = self.bundle / "program.tar"
        with tarfile.open(archive) as tar:
            rows = [(copy.copy(member), tar.extractfile(member).read() if member.isfile() else b"") for member in tar]
        mutate(rows)
        with tarfile.open(archive, "w", format=tarfile.GNU_FORMAT) as tar:
            for info, data in rows:
                tar.addfile(info, io.BytesIO(data) if info.isfile() else None)
        receipt["archive_sha256"] = a.file_hash(archive)
        return archive

    def test_01_deterministic_manifest_and_archive(self):
        manifest, receipt = self.packed()
        for path in self.tree.rglob("*"):
            if not path.is_symlink():
                os.utime(path, (100, 100))
        other = self.root / "other"
        self.assertEqual(receipt, a.pack(self.tree, self.provenance, other))
        self.assertEqual((self.bundle / "manifest.json").read_bytes(), (other / "manifest.json").read_bytes())

    def test_02_relocate_two_paths(self):
        manifest, receipt = self.packed()
        for name in ("destination-a", "destination-b"):
            dest = self.root / name
            a.materialize(self.bundle / "program.tar", manifest, receipt, dest)
            a.verify_tree(dest, manifest)
            self.assertEqual((dest / "node_modules/test").resolve(), dest / "packages/test")

    def test_03_permissions_preserved(self):
        manifest, receipt = self.packed()
        dest = self.root / "program"
        a.materialize(self.bundle / "program.tar", manifest, receipt, dest)
        self.assertEqual((dest / a.NODE).stat().st_mode & 0o777, 0o755)

    def test_04_archive_tamper(self):
        manifest, receipt = self.packed()
        (self.bundle / "program.tar").write_bytes(b"tampered")
        self.rejected(lambda: a.verify_archive(self.bundle / "program.tar", manifest, receipt), "HASH_MISMATCH")

    def test_05_manifest_tamper(self):
        manifest, receipt = self.packed()
        manifest["provenance"]["libc"] = "glibc 2.39"
        self.rejected(lambda: a.verify_archive(self.bundle / "program.tar", manifest, receipt), "BUILDER_PROVENANCE_DRIFT")

    def test_06_missing_archive_file(self):
        manifest, receipt = self.packed()
        archive = self.rewrite_tar(manifest, receipt, lambda rows: rows.pop())
        self.rejected(lambda: a.verify_archive(archive, manifest, receipt), "MISSING_ARCHIVE_ENTRY")

    def test_07_extra_archive_file(self):
        manifest, receipt = self.packed()
        info = tarfile.TarInfo("extra"); info.size = 1
        archive = self.rewrite_tar(manifest, receipt, lambda rows: rows.append((info, b"x")))
        self.rejected(lambda: a.verify_archive(archive, manifest, receipt), "UNDECLARED")

    def test_08_duplicate_archive_entry(self):
        manifest, receipt = self.packed()
        archive = self.rewrite_tar(manifest, receipt, lambda rows: rows.append(rows[0]))
        self.rejected(lambda: a.verify_archive(archive, manifest, receipt), "DUPLICATE")

    def test_09_unsafe_entry_types(self):
        for kind in (tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.FIFOTYPE):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as td:
                bundle = Path(td) / "bundle"
                receipt = a.pack(self.tree, self.provenance, bundle)
                previous = self.bundle; self.bundle = bundle
                manifest = json.loads((bundle / "manifest.json").read_bytes())
                def mutate(rows):
                    member = next(m for m, data in rows if m.isfile())
                    member.type = kind; member.linkname = "/outside"
                archive = self.rewrite_tar(manifest, receipt, mutate)
                self.rejected(lambda: a.verify_archive(archive, manifest, receipt), "UNSAFE_ARCHIVE_ENTRY")
                self.bundle = previous

    def test_10_path_traversal(self):
        for name in ("../escape", "/absolute", "a/../../escape", "a//b", "a/./b", "a\\b"):
            with self.subTest(name=name):
                self.rejected(lambda: a.path_name(name), "UNSAFE_PATH")

    def test_11_link_escape(self):
        for target in ("/etc/passwd", "../../outside", "..\\outside"):
            with self.subTest(target=target):
                self.rejected(lambda: a.link_destination("dir/link", target), "SYMLINK")

    def test_12_link_cycle(self):
        (self.tree / "cycle-a").symlink_to("cycle-b")
        (self.tree / "cycle-b").symlink_to("cycle-a")
        self.rejected(lambda: a.inventory(self.tree), "SYMLINK_CYCLE")

    def test_13_dangling_link(self):
        (self.tree / "dangling").symlink_to("missing")
        self.rejected(lambda: a.inventory(self.tree), "DANGLING_SYMLINK")

    def test_14_link_ancestor(self):
        entries = [{"path": "dir", "kind": "symlink", "mode": 0o777, "target": "file"},
                   {"path": "dir/child", "kind": "file", "mode": 0o644},
                   {"path": "file", "kind": "file", "mode": 0o644}]
        self.rejected(lambda: a.validate_links(entries), "LINK_PARENT")

    def test_15_program_mutation(self):
        manifest, _receipt = self.packed()
        (self.tree / a.ENTRY).write_bytes(b"changed")
        self.rejected(lambda: a.verify_tree(self.tree, manifest), "PROGRAM_TREE_MUTATION")

    def test_16_extra_extracted_file(self):
        manifest, _receipt = self.packed()
        (self.tree / "extra").write_text("extra")
        self.rejected(lambda: a.verify_tree(self.tree, manifest), "PROGRAM_TREE_MUTATION")

    def test_17_missing_extracted_file(self):
        manifest, _receipt = self.packed()
        (self.tree / a.ENTRY).unlink()
        self.rejected(lambda: a.verify_tree(self.tree, manifest), "PROGRAM_TREE_MUTATION")

    def test_18_state_cache_and_credentials(self):
        for name in (".git/config", "DSH_HOME/profile", "sessions/result", "candidate.patch.yml", ".env",
                     ".cache/file", "node_modules/.pnpm-store/cache", "source.tsbuildinfo", "test.pem",
                     ".npmrc", ".netrc", ".aws/credentials", "session.json", "events.jsonl"):
            with self.subTest(name=name):
                self.rejected(lambda: a.path_name(name), "STATE_SECRET_CACHE_PATH")

    def test_19_scanner_rejects_synthetic_value(self):
        (self.tree / "credential.json").write_text(json.dumps({"PASS" + "WORD": "synthetic-invalid-value"}))
        self.rejected(lambda: a.pack(self.tree, self.provenance, self.bundle), "SECRET_SCAN_REJECTED")

    def test_20_setuid_rejected(self):
        (self.tree / a.NODE).chmod(0o4755)
        self.rejected(lambda: a.inventory(self.tree), "UNSAFE_MODE")

    def test_21_hardlink_rejected(self):
        os.link(self.tree / a.ENTRY, self.tree / "hardlink")
        self.rejected(lambda: a.inventory(self.tree), "HARDLINK")

    def test_22_unqualified_native_inventory(self):
        manifest, receipt = self.packed()
        self.assertEqual(manifest["compatibility"], "NOT_RUN")
        self.assertEqual(manifest["relocation"], "NOT_RUN")
        self.assertEqual(manifest["native_inventory"][0]["abi_status"], "NOT_RUN")
        a.verify_archive(self.bundle / "program.tar", manifest, receipt)

    def test_23_forged_native_qualification(self):
        manifest, receipt = self.packed()
        manifest["native_inventory"][0]["abi_status"] = "PASS"
        self.rejected(lambda: a.validate_manifest(manifest), "NATIVE_SCHEMA")

    def test_24_incomplete_native_inventory(self):
        manifest, receipt = self.packed()
        manifest["native_inventory"] = []
        receipt["manifest_sha256"] = a.digest(a.canonical(manifest))
        self.rejected(lambda: a.verify_archive(self.bundle / "program.tar", manifest, receipt), "NATIVE_INVENTORY_INCOMPLETE")

    def test_25_provenance_exact_identity(self):
        self.provenance["source_commit"] = "0" * 40
        self.rejected(lambda: a.validate_provenance(self.provenance), "SOURCE_COMMIT_DRIFT")

    def test_26_missing_builder_digest(self):
        self.provenance["builder_image"] = "debian:bullseye"
        self.rejected(lambda: a.validate_provenance(self.provenance), "BUILDER_DIGEST_UNRESOLVED")

    def test_27_node_binary_binding(self):
        self.provenance["node"]["binary_sha256"] = "0" * 64
        self.rejected(lambda: a.pack(self.tree, self.provenance, self.bundle), "NODE_BINARY_HASH_MISMATCH")

    def test_28_lockfile_binding(self):
        self.provenance["lockfile_sha256"] = "0" * 64
        self.rejected(lambda: a.pack(self.tree, self.provenance, self.bundle), "LOCKFILE_HASH_MISMATCH")

    def test_29_unperformed_build_rejected(self):
        self.provenance["build"]["exit"] = 134
        self.rejected(lambda: a.validate_provenance(self.provenance), "BUILD_NOT_PROVEN")

    def test_30_destination_exists(self):
        manifest, receipt = self.packed()
        self.rejected(lambda: a.materialize(self.bundle / "program.tar", manifest, receipt, self.tree), "DESTINATION_EXISTS")

    def test_31_no_partial_publish(self):
        manifest, receipt = self.packed()
        receipt["archive_sha256"] = "0" * 64
        dest = self.root / "destination"
        self.rejected(lambda: a.materialize(self.bundle / "program.tar", manifest, receipt, dest), "HASH_MISMATCH")
        self.assertFalse(dest.exists())

    def test_32_symlink_destination_parent(self):
        manifest, receipt = self.packed()
        parent = self.root / "parent-link"; parent.symlink_to(self.tree, target_is_directory=True)
        self.rejected(lambda: a.materialize(self.bundle / "program.tar", manifest, receipt, parent / "dest"), "PARENT_SYMLINK")

    def test_33_actual_builder_boundary_closed(self):
        self.rejected(lambda: b.builder_plan(self.root / "not-downloaded", a.DSH_COMMIT), "NODE_ARCHIVE_NOT_DOWNLOADED")

    def test_34_node_archive_checksum(self):
        archive = self.root / "node.tar.xz"; archive.write_bytes(b"fixture")
        policy = dict(b.POLICY, base_image="generic@sha256:" + "a" * 64, node_version="v24.0.0",
                      corepack_version="0.33.0", builder_memory=8 * 1024**3, node_archive_sha256="0" * 64)
        self.rejected(lambda: b.execution_gate(policy, archive, a.DSH_COMMIT), "NODE_ARCHIVE_CHECKSUM_MISMATCH")
        policy["node_archive_sha256"] = a.file_hash(archive)
        b.execution_gate(policy, archive, a.DSH_COMMIT)

    def test_35_source_identity(self):
        def fake(argv, cwd):
            return {("git", "rev-parse", "HEAD"): a.DSH_COMMIT,
                    ("git", "status", "--porcelain"): "", ("git", "rev-parse", "HEAD^{tree}"): "f" * 40}[tuple(argv)]
        self.assertEqual(b.source_identity(self.tree, fake), (a.DSH_COMMIT, "f" * 40))
        self.rejected(lambda: b.source_identity(self.tree, lambda argv, cwd: "incorrect"), "SOURCE_COMMIT_DRIFT")

    def test_36_fixed_task_from_frozen_snapshot(self):
        selected = q.fixed_image()
        self.assertEqual(selected["task"], q.TASK)
        self.assertRegex(selected["historical_platform_digest"], r"^sha256:[0-9a-f]{64}$")

    def test_37_no_external_runtime_without_original_envelope(self):
        self.packed()
        class NeverTransport:
            def inspect(self):
                raise AssertionError("external runtime must not be reached")
        self.rejected(lambda: q.qualify(NeverTransport(), self.bundle, a.file_hash(self.bundle / "receipt.json")),
                      "ORIGINAL_HARBOR_SETUP_BINDING_UNRESOLVED")

    def test_38_commands_fixed_no_bootstrap(self):
        commands = q.probe_commands()
        self.assertEqual(len(commands), 3)
        self.assertEqual(commands[0][2:], ["--help"])
        self.assertEqual(commands[1][2:], ["--version"])
        for argv in commands:
            self.assertEqual(argv[0], q.PROGRAM + "/" + a.NODE)
            self.assertNotIn("pnpm", argv); self.assertNotIn("git", argv); self.assertNotIn("curl", argv)

    def test_39_qualification_boundary(self):
        envelope = {"memory_bytes": 2147483648, "nano_cpus": 2000000000,
                    "storage_options": {}, "memory_swap": 2147483648, "cpu_quota": 0, "cpu_period": 0,
                    "cpuset_cpus": "", "cpu_shares": 0, "memory_reservation": 0, "pids_limit": None}
        selected = q.fixed_image()
        actual = {"task_config_sha256": "f" * 64, "task_id": q.TASK, "harbor_version": "0.21.0",
                  "platform": "linux/amd64", "platform_digest": selected["historical_platform_digest"],
                  "image_reference": selected["authoritative_image_ref"], "resource_envelope": envelope,
                  "network_mode": "none", "credential_environment_names": [], "program_read_only": True,
                  "program_mount": q.PROGRAM, "program_archive_sha256": "a" * 64, "mounted_archive_sha256": "a" * 64}
        q.validate_container(actual, selected, envelope, "f" * 64)
        for key, value in (("network_mode", "bridge"), ("program_read_only", False),
                           ("platform_digest", "sha256:" + "0" * 64), ("resource_envelope", {})):
            with self.subTest(key=key):
                wrong = dict(actual); wrong[key] = value
                with self.assertRaises(a.ArtifactError):
                    q.validate_container(wrong, selected, envelope, "f" * 64)

    def test_40_production_and_formal_workflows_untouched(self):
        self.assertEqual(a.file_hash(ROOT / "evaluation/agents/dsh_harbor_adapter/adapter.py"), a.ADAPTER_SHA)
        self.assertNotIn("m1c_runtime_artifact", (ROOT / ".github/workflows/gha-m1c1-runtime-fingerprint.yml").read_text())
        self.assertNotIn("m1c_runtime_artifact", (ROOT / ".github/workflows/gha-m1c1-four-image-loader-probe.yml").read_text())

    def test_41_no_provider_session_or_task_execution(self):
        probe = q.PROBE.read_text()
        self.assertNotIn("process.env." + "DEEPSEEK" + "_API_KEY", probe)
        self.assertNotIn("fetch(", probe)
        self.assertNotIn(".run(", probe)
        self.assertNotIn("--profile", " ".join(" ".join(c) for c in q.probe_commands()))
        self.assertNotIn("DSH_HOME=", probe)
        self.assertIn("home-a", probe); self.assertIn("home-b", probe)

    def test_42_no_workflow_or_arbitrary_dispatch_inputs(self):
        workflow = (ROOT / ".github/workflows/gha-m1c1-runtime-artifact.yml").read_text()
        self.assertIn("workflow_dispatch:", workflow)
        self.assertNotIn("inputs:", workflow)
        self.assertNotIn("DEEPSEEK_API_KEY", workflow)
        recipe = (ROOT / "gha/runtime-artifact-v1/Dockerfile").read_text()
        self.assertNotIn("pnpm install --frozen-lockfile", recipe)
        self.assertNotIn("pnpm run build", recipe)
        self.assertNotIn("COPY source/", recipe)
        self.assertNotIn("apt-get", recipe); self.assertNotIn("curl", recipe)
        self.assertNotIn("NODE_OPTIONS=", recipe)

    def test_43_conservative_workspace_staging(self):
        for root in a.ROOTS:
            (self.tree / root).mkdir(parents=True, exist_ok=True)
        for name in a.ROOT_FILES:
            if not (self.tree / name).exists():
                (self.tree / name).write_text("fixture")
        (self.tree / "packages/test/.cache").mkdir()
        (self.tree / "packages/test/.cache/ignored").write_text("cache")
        (self.tree / "packages/test/build.tsbuildinfo").write_text("cache")
        node = self.root / "node"
        (node / "bin").mkdir(parents=True)
        (node / "bin/node").write_bytes(b"fixture-node")
        (node / "bin/node").chmod(0o755)
        destination = self.root / "staging"
        b.stage_workspace(self.tree, node, destination)
        self.assertFalse((destination / "packages/test/.cache").exists())
        self.assertFalse((destination / "packages/test/build.tsbuildinfo").exists())
        self.assertEqual((destination / "node_modules/test").resolve(), destination / "packages/test")
        self.assertEqual((destination / a.NODE).stat().st_mode & 0o777, 0o755)

    def test_44_long_pnpm_paths(self):
        name = "node_modules/.pnpm/" + "p" * 180 + "/node_modules/" + "q" * 100
        path = self.tree / name; path.parent.mkdir(parents=True); path.write_bytes(b"fixture")
        manifest, receipt = self.packed()
        a.materialize(self.bundle / "program.tar", manifest, receipt, self.root / "longpaths")

    def test_45_dirty_source_rejected(self):
        def fake(argv, cwd):
            return a.DSH_COMMIT if argv[-1] == "HEAD" else " M tracked"
        self.rejected(lambda: b.source_identity(self.tree, fake), "SOURCE_WORKTREE_DIRTY")

    def test_46_unsupported_node_rejected(self):
        self.provenance["node"]["version"] = "v22.18.0"
        self.rejected(lambda: a.validate_provenance(self.provenance), "NODE_UNSUPPORTED")

    def test_47_receipt_outside_archive(self):
        manifest, receipt = self.packed()
        with tarfile.open(self.bundle / "program.tar") as tar:
            names = tar.getnames()
        self.assertNotIn("receipt.json", names)
        self.assertNotIn("manifest.json", names)
        self.assertNotIn("archive_sha256", manifest)

    def test_48_missing_metadata_fails_closed(self):
        del self.provenance["node"]["abi"]
        self.rejected(lambda: a.validate_provenance(self.provenance), "NODE_SCHEMA")

    def test_49_fixture_controller_isolation_and_postverify(self):
        self.packed()
        selected = q.fixed_image()
        envelope = {"memory_bytes": 2147483648, "nano_cpus": 2000000000,
                    "storage_options": {}, "memory_swap": 2147483648, "cpu_quota": 0, "cpu_period": 0,
                    "cpuset_cpus": "", "cpu_shares": 0, "memory_reservation": 0, "pids_limit": None}
        receipt = json.loads((self.bundle / "receipt.json").read_bytes())
        facts = {"task_config_sha256": "f" * 64, "task_id": q.TASK, "harbor_version": "0.21.0",
                 "platform": "linux/amd64", "platform_digest": selected["historical_platform_digest"],
                 "image_reference": selected["authoritative_image_ref"], "resource_envelope": envelope,
                 "network_mode": "none", "credential_environment_names": [], "program_read_only": True,
                 "program_mount": q.PROGRAM, "program_archive_sha256": receipt["archive_sha256"],
                 "mounted_archive_sha256": receipt["archive_sha256"]}
        evidence = {name: "PASS" for name in ("profile_resolution", "plugin_resolution", "native_load", "pty",
                                              "filesystem", "sandbox", "isolation")}
        evidence.update(resolved_plugin_count=1, provider_path_reached=False, provider_requests=0, model_sessions=0)
        class FixtureTransport:
            def __init__(self):
                self.verifies = 0; self.executed = []; self.saved = False; self.bad = False
            def inspect(self):
                return copy.deepcopy(facts)
            def verify_program(self, manifest):
                self.verifies += 1
                return True
            def prepare_scratch(self, probe, scratch):
                self.probe = probe; self.scratch = scratch
            def exec_argv(self, argv, cwd, environment):
                assert environment == {} and cwd.startswith(q.SCRATCH)
                self.executed.append(argv)
                return {"exit": 1 if self.bad else 0, "stdout": json.dumps(evidence), "stderr": ""}
            def preserve_evidence(self, results, **kwargs):
                self.saved = True
        with patch.object(q, "RESOURCE_ENVELOPE", envelope), patch.object(q, "TASK_CONFIG_SHA256", "f" * 64):
            fake = FixtureTransport()
            result = q.qualify(fake, self.bundle, a.file_hash(self.bundle / "receipt.json"))
            self.assertEqual(result["compatibility_classes"], "NOT_QUALIFIED")
            self.assertEqual(fake.verifies, 2); self.assertEqual(len(fake.executed), 3); self.assertTrue(fake.saved)
            failure = FixtureTransport(); failure.bad = True
            self.rejected(lambda: q.qualify(failure, self.bundle, a.file_hash(self.bundle / "receipt.json")), "PROBE_FAILED")
            self.assertEqual(failure.verifies, 2); self.assertTrue(failure.saved)

    def test_50_scanner_strictness_not_modified(self):
        from scripts.public_secret_scan import scan_tree
        (self.tree / "unsafe.json").write_text(json.dumps({"AUTHOR" + "IZATION": "synthetic-unsafe-value"}))
        self.assertTrue(scan_tree(self.tree, artifact_mode=True))

    def test_51_independent_receipt_anchor(self):
        self.packed()
        self.rejected(lambda: a.load_bundle(self.bundle, "0" * 64), "RECEIPT_TRUST_ANCHOR_MISMATCH")
        a.load_bundle(self.bundle, a.file_hash(self.bundle / "receipt.json"))

    def test_52_noncanonical_manifest_rejected(self):
        self.packed()
        manifest = self.bundle / "manifest.json"
        manifest.write_bytes(manifest.read_bytes() + b" \n")
        self.rejected(lambda: a.load_bundle(self.bundle, a.file_hash(self.bundle / "receipt.json")), "NONCANONICAL_METADATA")

    def test_53_transport_rejects_arbitrary_exec(self):
        self.packed()
        class NeverRunner:
            def __call__(self, *args, **kwargs):
                raise AssertionError("arbitrary exec must not reach Docker")
        transport = q.DockerTransport("f" * 64, self.root / "task.toml", self.bundle,
                                      a.file_hash(self.bundle / "receipt.json"), self.root / "reports", NeverRunner())
        self.rejected(lambda: transport.exec_argv(["sh", "-c", "arbitrary"], q.SCRATCH + "/scratch", {}),
                      "PROBE_COMMAND_DRIFT")

    def test_54_safe_core_survives_bulk_scanner_rejection(self):
        self.packed()
        reports = self.root / "reports"
        transport = q.DockerTransport("f" * 64, self.root / "task.toml", self.bundle,
                                      a.file_hash(self.bundle / "receipt.json"), reports)
        candidate = "synthetic-unsafe-value"
        raw = "AUTHOR" + "IZATION: " + candidate
        self.rejected(lambda: transport.preserve_evidence([{"exit": 1, "stdout": raw, "stderr": ""}],
                                                         failure="ArtifactError", program_unchanged=True),
                      "BULK_SECRET_SCAN_REJECTED")
        self.assertFalse((reports / "bulk").exists())
        safe = (reports / "safe-core/summary.json").read_text()
        self.assertNotIn(candidate, safe)
        self.assertEqual(json.loads(safe)["bulk_status"], "BLOCKED")
        self.assertTrue((reports / "safe-core/SHA256SUMS").is_file())

    def test_55_transport_fixed_absolute_node_empty_env(self):
        self.packed()
        calls = []
        def fake_runner(argv, **kwargs):
            from types import SimpleNamespace
            calls.append(argv)
            return SimpleNamespace(returncode=0, stdout="fixture", stderr="")
        transport = q.DockerTransport("f" * 64, self.root / "task.toml", self.bundle,
                                      a.file_hash(self.bundle / "receipt.json"), self.root / "reports", fake_runner)
        transport.exec_argv(q.probe_commands()[0], q.SCRATCH + "/scratch", {})
        self.assertIn("/usr/bin/env", calls[0]); self.assertIn("-i", calls[0])
        self.assertNotIn("pull", calls[0]); self.assertNotIn("create", calls[0])

    def test_56_source_controlled_tooling_only(self):
        recipe = (ROOT / "gha/runtime-artifact-v1/Dockerfile").read_text()
        self.assertNotIn("COPY tooling/ /tooling/", recipe)
        self.assertIn("COPY scripts/ /tooling/scripts/", recipe)
        self.assertIn("scripts/public_secret_scan.py", i.CONTEXT_FILES)

    def test_57_transport_reads_real_identity_shape(self):
        self.packed()
        selected = q.fixed_image()
        ref = selected["authoritative_image_ref"].rsplit(":", 1)[0] + "@" + selected["historical_platform_digest"]
        config_file = self.root / "task.toml"; config_file.write_text("fixture only")
        state = {"Id": "f" * 64, "Image": "sha256:" + "b" * 64, "State": {"Running": True},
                 "Config": {"Image": ref, "Env": ["PATH=/usr/bin:/bin"],
                            "Labels": {"com.docker.compose.service": "main", "com.docker.compose.project": "fixture"}},
                 "Mounts": [{"Destination": q.PROGRAM, "Type": "bind", "RW": False, "Source": str(self.tree)}],
                 "HostConfig": {"Memory": 2147483648, "NanoCpus": 2000000000, "MemorySwap": 2147483648,
                                "StorageOpt": None, "CpuQuota": 0, "CpuPeriod": 0, "CpusetCpus": "", "CpuShares": 0,
                                "MemoryReservation": 0, "PidsLimit": None, "NetworkMode": "none", "Privileged": False,
                                "CapAdd": []}}
        image = {"Id": state["Image"], "RepoDigests": [ref], "Os": "linux", "Architecture": "amd64"}
        def runner(argv, **kwargs):
            from types import SimpleNamespace
            self.assertEqual(argv[:2], ["docker", "inspect"] if argv[1] == "inspect" else ["docker", "image"])
            return SimpleNamespace(returncode=0, stdout=json.dumps([state if argv[1] == "inspect" else image]), stderr="")
        transport = q.DockerTransport("f" * 64, config_file, self.bundle, a.file_hash(self.bundle / "receipt.json"),
                                      self.root / "reports", runner)
        with patch.object(q.importlib.metadata, "version", return_value="0.21.0"):
            actual = transport.inspect()
            self.assertEqual(set(actual["resource_envelope"]), q.ENVELOPE_FIELDS)
            self.assertEqual(actual["platform_digest"], selected["historical_platform_digest"])
            state["Config"]["Image"] = selected["authoritative_image_ref"]
            self.rejected(transport.inspect, "MUTABLE_TASK_IMAGE_SUBSTITUTION")


if __name__ == "__main__":
    unittest.main()

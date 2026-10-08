"""Identity/order fixture tests: no archive download, Docker or DSH execution."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import m1c_runtime_artifact as a
from scripts import m1c_runtime_identity as i


class IdentityTests(unittest.TestCase):
    def setUp(self):
        self.p = i.policy()
        self.image = {"image_id": "sha256:" + "a" * 64, "container_image_id": "sha256:" + "a" * 64,
                      "image_config_sha256": "a" * 64, "platform": "linux/amd64", "libc": "glibc 2.31",
                      "os_release_sha256": "b" * 64, "node_version": self.p["node_version"],
                      "node_abi": "137", "node_napi": "10", "corepack": self.p["corepack_version"],
                      "pnpm": self.p["pnpm"], "input_context_sha256": self.p["context_sha256"],
                      "base_image": self.p["base_image"]}
        self.resources = {"host_cpus": 4, "host_mem_available_bytes": 12 * 1024**3,
                          "host_free_disk_bytes": 14 * 1024**3, "container_memory_max": 8 * 1024**3,
                          "container_nano_cpus": 2 * 10**9, "container_memory_swap": 8 * 1024**3,
                          "memory_events": {"oom": 0, "oom_kill": 0}, "measurement_id": "c" * 64}

    def rejects(self, call, code):
        with self.assertRaisesRegex(a.ArtifactError, code): call()

    def test_pinned_input_metadata(self):
        self.assertEqual(i.validate_inputs(self.p), "PREBUILD_INPUT_IDENTITIES_PINNED")

    def test_missing_and_mutable_base(self):
        for base in ("UNRESOLVED", "python:3.11-bullseye"):
            with self.subTest(base=base):
                self.rejects(lambda: i.validate_inputs(dict(self.p, base_image=base)), "BUILDER_DIGEST_UNRESOLVED")

    def test_missing_node_hash(self):
        self.rejects(lambda: i.validate_inputs(dict(self.p, node_archive_sha256="UNRESOLVED")), "NODE_ARCHIVE_SHA256_UNRESOLVED")

    def test_wrong_node_hash(self):
        self.rejects(lambda: i.validate_inputs(dict(self.p, node_archive_sha256="0" * 64)), "PREBUILD_INPUT_DRIFT")

    def test_not_yet_created(self):
        self.assertEqual(self.p["builder_image"], "BUILDER_IMAGE_NOT_YET_CREATED")
        self.rejects(lambda: i.verify_image(None, self.p), "BUILDER_IMAGE_NOT_YET_CREATED")

    def test_no_fabricated_prebuild_image(self):
        self.rejects(lambda: i.validate_inputs(dict(self.p, builder_image=self.image["image_id"])), "PREBUILD_IMAGE_FABRICATION")

    def test_observed_image(self):
        self.assertEqual(i.verify_image(self.image, self.p), "BUILDER_IMAGE_IDENTITY_VERIFIED")
        for field in ("image_id", "node_version", "libc", "input_context_sha256", "platform"):
            with self.subTest(field=field):
                self.rejects(lambda: i.verify_image(dict(self.image, **{field: "wrong"}), self.p), "BUILDER_")

    def test_capacity_is_observed_not_requested(self):
        self.assertEqual(i.capacity_gate(self.resources, self.p, self.image), "BUILDER_CAPACITY_PREFLIGHT_PASS")
        self.rejects(lambda: i.capacity_gate(self.p["requested_resources"], self.p, self.image), "CAPACITY_EVIDENCE_MISSING")

    def test_capacity_shortfall_each_dimension(self):
        for key in ("host_cpus", "host_mem_available_bytes", "host_free_disk_bytes", "container_memory_max", "container_nano_cpus", "container_memory_swap"):
            with self.subTest(key=key):
                self.rejects(lambda: i.capacity_gate(dict(self.resources, **{key: 0}), self.p, self.image), "CAPACITY_INSUFFICIENT_OR_DRIFT")

    def test_unknown_observation_and_oom(self):
        self.rejects(lambda: i.capacity_gate(dict(self.resources, host_free_disk_bytes="NOT_MEASURED"), self.p, self.image), "CAPACITY_NOT_MEASURED")
        self.rejects(lambda: i.capacity_gate(dict(self.resources, memory_events={"oom": 1, "oom_kill": 0}), self.p, self.image), "RESOURCE_EVIDENCE_UNPROVEN")

    def test_build_blocked_before_image(self):
        self.rejects(lambda: i.dsh_build_gate(self.p, None, self.resources, Path("never-read")), "BUILDER_IMAGE_NOT_YET_CREATED")

    def test_build_blocked_before_capacity(self):
        self.rejects(lambda: i.dsh_build_gate(self.p, self.image, {}, Path("never-read")), "CAPACITY_EVIDENCE_MISSING")

    def test_lockfile_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            lock = Path(tmp) / "lock"; lock.write_bytes(b"fixture")
            self.rejects(lambda: i.dsh_build_gate(self.p, self.image, self.resources, lock), "FROZEN_LOCKFILE_DRIFT")
            with patch.object(a, "file_hash", wraps=a.file_hash) as hasher:
                # Only synthetic lock bytes are injected; source policy still validates.
                hasher.side_effect = lambda p: self.p["lockfile_sha256"] if p == lock else a.digest(p.read_bytes())
                self.assertEqual(i.dsh_build_gate(self.p, self.image, self.resources, lock), "DSH_BUILD_PERMITTED")

    def test_context_identity_changes(self):
        self.assertEqual(i.context_identity(self.p), self.p["context_sha256"])
        self.rejects(lambda: i.validate_inputs(dict(self.p, context_sha256="0" * 64)), "BUILD_CONTEXT_DRIFT")

    def test_task_binding_is_byte_hash_not_resource_proof(self):
        binding = json.loads((i.ROOT / "configs/m1c_runtime_task_binding_v1.json").read_bytes())
        self.assertEqual(binding["task_config_hash_mode"], "BYTE_LEVEL_SHA256")
        self.assertEqual(binding["task_requested_resources"], {"cpus": 1, "memory_mb": 2048, "storage_mb": 10240})
        self.assertEqual(binding["effective_resource_envelope"], "NOT_MEASURED")
        from scripts import m1c_runtime_qualification as q
        self.assertEqual(q.fixed_image(), binding["image_mapping"])
        self.assertEqual(q.TASK_CONFIG_SHA256, binding["task_config_sha256"])
        self.assertEqual(q.RESOURCE_ENVELOPE, "UNRESOLVED")

    def test_no_dsh_build_inside_image_creation(self):
        dockerfile = (i.ROOT / i.CONTEXT_FILES[0]).read_text()
        for forbidden in ("pnpm run build", "pnpm install", "COPY source/", "git clone", "apt-get", "NODE_OPTIONS"):
            self.assertNotIn(forbidden, dockerfile)

    def test_no_external_execution_in_validators(self):
        source = (i.ROOT / "scripts/m1c_runtime_identity.py").read_text()
        for forbidden in ("subprocess", "requests.", "urllib", "docker exec", "docker pull", "fetch(", "provider.run"):
            self.assertNotIn(forbidden, source)

    def test_context_refuses_extra_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.rejects(lambda: i.verify_staged_context(Path(tmp), self.p), "BUILD_CONTEXT_UNDECLARED_OR_MISSING_FILE")

    def test_base_image_is_not_final_image(self):
        self.rejects(lambda: i.verify_image(dict(self.image, image_id=self.p["base_config_digest"]), self.p),
                     "BASE_IMAGE_IS_NOT_FINAL_BUILDER")

    def test_byte_hash_determinism_and_line_ending_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "task.toml"; path.write_bytes(b"fixture\n")
            before = a.file_hash(path)
            self.assertEqual(before, a.file_hash(path))
            path.write_bytes(b"fixture\r\n")
            self.assertNotEqual(before, a.file_hash(path))

    def test_staged_context_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root / "untrusted").symlink_to("elsewhere")
            self.rejects(lambda: i.verify_staged_context(root, self.p), "BUILD_CONTEXT_SYMLINK")

    def test_corrupt_archive_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root / "node.tar.xz").write_bytes(b"never executed")
            self.rejects(lambda: i.verify_archives(root, self.p), "NODE_ARCHIVE_CHECKSUM_MISMATCH")

    def test_artifact_retains_image_and_capacity_evidence(self):
        from evaluation.tests.test_m1c_runtime_artifact import ArtifactTests
        fixture = ArtifactTests(); fixture.setUp()
        try:
            manifest, receipt = fixture.packed()
            self.assertEqual(manifest["provenance"]["builder_evidence"]["image"]["image_id"], manifest["provenance"]["builder_image"])
            manifest["provenance"]["builder_evidence"]["resources"]["container_memory_max"] = 1
            self.rejects(lambda: a.verify_archive(fixture.bundle / "program.tar", manifest, receipt), "CAPACITY_INSUFFICIENT_OR_DRIFT")
        finally: fixture.doCleanups()


if __name__ == "__main__": unittest.main()

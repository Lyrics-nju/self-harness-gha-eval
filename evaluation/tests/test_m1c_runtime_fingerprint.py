from __future__ import annotations

import hashlib
import importlib.util
import json
import base64
import gzip
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[2]
MODULE_PATH = ROOT / "scripts" / "gha_m1c1_runtime_fingerprint.py"
WORKFLOW = ROOT / ".github" / "workflows" / "gha-m1c1-runtime-fingerprint.yml"
POOL_PAYLOAD = ROOT / "splits" / "stable_task_pool_v3.json.gz.b64"
spec = importlib.util.spec_from_file_location("runtime_fingerprint", MODULE_PATH)
assert spec and spec.loader
rf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rf)


def single_manifest(config: str = "sha256:" + "c" * 64) -> bytes:
    return json.dumps({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"digest": config},
        "layers": [],
    }, separators=(",", ":")).encode()


class RuntimeFingerprintTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = WORKFLOW.read_text()
        cls.pool_bytes = gzip.decompress(base64.b64decode(POOL_PAYLOAD.read_bytes()))
        cls.tempdir = tempfile.TemporaryDirectory()
        cls.pool = Path(cls.tempdir.name) / "stable_task_pool_v3.json"
        cls.pool.write_bytes(cls.pool_bytes)
        cls.tasks = rf.load_stable_pool(cls.pool)

    @classmethod
    def tearDownClass(cls):
        cls.tempdir.cleanup()

    def test_01_stable_pool_exactly_24(self):
        self.assertEqual(len(self.tasks), 24)

    def test_02_stable_pool_sha_frozen(self):
        self.assertEqual(hashlib.sha256(self.pool_bytes).hexdigest(), rf.STABLE_POOL_SHA256)

    def test_03_only_authoritative_tasks_resolve(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaisesRegex(rf.QualificationError, "terminal-bench/not-authoritative"):
                rf.resolve_task_image_map(["terminal-bench/not-authoritative"], Path(td))

    def test_04_mapping_is_deterministic_and_ordered(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for name, image in (("b", "org/b:1"), ("a", "org/a:1")):
                directory = root / name
                directory.mkdir()
                (directory / "task.toml").write_text(f'[environment]\ndocker_image="{image}"\n')
            ids = ["terminal-bench/b", "terminal-bench/a"]
            first = rf.resolve_task_image_map(ids, root)
            self.assertEqual(first, rf.resolve_task_image_map(ids, root))
            self.assertEqual([item["task_id"] for item in first], ids)

    def test_05_tag_digest_is_recorded(self):
        raw = single_manifest()
        parsed = rf.parse_manifest(raw)
        self.assertEqual(parsed["tag_manifest_digest"], "sha256:" + hashlib.sha256(raw).hexdigest())

    def test_06_identical_digests_deduplicate(self):
        rows = [
            {"task_id": "terminal-bench/a", "authoritative_image_reference": "x/a:1", "resolved_image_digest": "sha256:x"},
            {"task_id": "terminal-bench/b", "authoritative_image_reference": "x/b:1", "resolved_image_digest": "sha256:x"},
        ]
        unique = rf.deduplicate_exact_digests(rows)
        self.assertEqual(len(unique), 1)
        self.assertEqual(unique[0]["task_ids"], ["terminal-bench/a", "terminal-bench/b"])

    def test_07_different_digests_never_deduplicate(self):
        rows = [
            {"task_id": "terminal-bench/a", "authoritative_image_reference": "x/a:1", "resolved_image_digest": "sha256:a"},
            {"task_id": "terminal-bench/b", "authoritative_image_reference": "x/b:1", "resolved_image_digest": "sha256:b"},
        ]
        self.assertEqual(len(rf.deduplicate_exact_digests(rows)), 2)

    def test_08_architecture_is_explicit(self):
        parsed = rf.parse_manifest(single_manifest())
        self.assertEqual((parsed["os"], parsed["architecture"]), ("linux", "amd64"))

    def test_09_unknown_libc_stays_not_available(self):
        self.assertEqual(rf.parse_fingerprint("uname_s\tLinux\n")["libc_getconf"], rf.NOT_AVAILABLE)

    def test_10_optional_command_absence_is_nonfatal(self):
        self.assertEqual(rf.parse_fingerprint("uname_s\tLinux\n")["dynamic_loader_identity"], rf.NOT_AVAILABLE)

    def test_11_missing_required_evidence_is_not_proven(self):
        self.assertEqual(rf.classification_for({"uname_s": "Linux"}), "COMPATIBILITY_NOT_YET_PROVEN")

    def test_12_complete_fingerprint_can_qualify(self):
        fp = {
            "uname_s": "Linux", "uname_m": "x86_64", "libc_getconf": "glibc 2.36",
            "dynamic_loader_path": "/lib64/ld-linux-x86-64.so.2", "dynamic_loader_identity": "ld.so 2.36",
            "installed_agent_writable": "PASS", "tmp_writable": "PASS", "local_exec": "PASS",
            "dev_pts": "PRESENT", "dev_ptmx": "PRESENT",
        }
        self.assertEqual(rf.classification_for(fp), "TASK_RUNTIME_FINGERPRINT_QUALIFIED")

    def test_13_canonical_json_is_deterministic(self):
        self.assertEqual(rf.canonical_bytes({"b": 1, "a": 2}), b'{"a":2,"b":1}\n')

    def test_14_manifest_covers_raw_and_structured(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "a.json").write_text("{}\n")
            (root / "raw").mkdir()
            (root / "raw" / "x.txt").write_text("x")
            rf.content_manifest(root, root / "SHA256SUMS")
            text = (root / "SHA256SUMS").read_text()
            self.assertIn("a.json", text)
            self.assertIn("raw/x.txt", text)

    def test_15_digest_mismatch_fails_closed(self):
        with self.assertRaisesRegex(rf.QualificationError, "expected"):
            rf.bind_selected_manifest({"resolved_image_digest": "sha256:" + "0" * 64}, single_manifest())

    def test_16_tag_drift_fails_closed(self):
        before = {"authoritative_image_reference": "x/y:1", "tag_manifest_digest": "sha256:a", "resolved_image_digest": "sha256:b"}
        after = {**before, "resolved_image_digest": "sha256:c"}
        with self.assertRaises(rf.QualificationError) as caught:
            rf.assert_no_tag_drift(before, after)
        self.assertEqual(caught.exception.classification, "TASK_IMAGE_TAG_DRIFT")

    def test_17_multiarch_selects_exact_platform(self):
        raw = json.dumps({"mediaType": "application/vnd.oci.image.index.v1+json", "manifests": [
            {"digest": "sha256:" + "a" * 64, "platform": {"os": "linux", "architecture": "arm64"}},
            {"digest": "sha256:" + "b" * 64, "platform": {"os": "linux", "architecture": "amd64"}},
        ]}, separators=(",", ":")).encode()
        self.assertEqual(rf.parse_manifest(raw)["resolved_image_digest"], "sha256:" + "b" * 64)

    def test_18_ambiguous_platform_fails_closed(self):
        item = {"digest": "sha256:" + "a" * 64, "platform": {"os": "linux", "architecture": "amd64"}}
        raw = json.dumps({"mediaType": "application/vnd.oci.image.index.v1+json", "manifests": [item, item]}).encode()
        with self.assertRaises(rf.QualificationError):
            rf.parse_manifest(raw)

    def test_19_cleanup_executes_in_finally(self):
        source = MODULE_PATH.read_text()
        self.assertIn("finally:", source)
        self.assertIn('"docker", "image", "rm", "-f"', source)

    def test_20_failure_evidence_survives(self):
        source = MODULE_PATH.read_text()
        self.assertIn('"qualification-failure.json"', source)
        self.assertIn("content_manifest(reports", source)

    def test_21_no_arbitrary_task_input(self):
        trigger = self.workflow.split("permissions:", 1)[0]
        self.assertIn("workflow_dispatch:", trigger)
        self.assertNotIn("inputs:", trigger)

    def test_22_no_agent_or_task_execution(self):
        lower = self.workflow.lower()
        for token in ("harbor run", "oracle", "verifier", "pnpm run build", "dsh session"):
            self.assertNotIn(token, lower)

    def test_23_no_provider_or_model_secret_surface(self):
        lower = self.workflow.lower()
        for token in ("deepseek_api_key", "secrets.", "provider request", "model session"):
            self.assertNotIn(token, lower)

    def test_24_secret_scan_is_fail_closed(self):
        self.assertIn("public_secret_scan.py --artifact-mode reports", self.workflow)
        self.assertIn("steps.scan.outcome == 'success'", self.workflow)

    def test_25_hash_manifest_is_verified(self):
        self.assertIn("sha256sum -c SHA256SUMS", self.workflow)

    def test_26_task_node_does_not_split_artifact_key(self):
        key = rf.candidate_runtime_key({})
        self.assertEqual(key["artifact_node_contract"], "ARTIFACT_PROVIDED_NOT_YET_QUALIFIED")
        self.assertNotIn("task_node_version", key)

    def test_27_dataset_drift_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "identity.json"
            path.write_text('{"resolved_content_hash":"wrong"}')
            with self.assertRaises(rf.QualificationError) as caught:
                rf.validate_dataset_identity(path)
            self.assertEqual(caught.exception.classification, "TB21_DATASET_IDENTITY_DRIFT")

    def test_28_registry_resolution_is_deterministic(self):
        self.assertEqual(rf.registry_of("alexgshaw/task:tag"), "docker.io")
        self.assertEqual(rf.registry_of("ghcr.io/org/task:tag"), "ghcr.io")

    def test_29_required_runtime_capability_failure_is_not_proven(self):
        fp = {
            "uname_s": "Linux", "uname_m": "x86_64", "libc_getconf": "glibc 2.36",
            "dynamic_loader_path": "/lib64/ld-linux-x86-64.so.2", "dynamic_loader_identity": "ld.so 2.36",
            "installed_agent_writable": "FAIL", "tmp_writable": "PASS", "local_exec": "PASS",
            "dev_pts": "PRESENT", "dev_ptmx": "PRESENT",
        }
        self.assertEqual(rf.classification_for(fp), "COMPATIBILITY_NOT_YET_PROVEN")

    def test_30_pull_failure_logs_before_failing(self):
        source = MODULE_PATH.read_text()
        self.assertLess(source.index('(raw_dir / "pull.stderr").write_text'), source.index('"TASK_IMAGE_PULL_FAILURE"'))

    def test_31_glibc_symbol_evidence_is_collected(self):
        self.assertIn("glibc_symbol_versions", rf.FINGERPRINT_SCRIPT)
        self.assertIn("glibc_symbol_versions_sha256", rf.candidate_runtime_key({}))

    def test_32_disk_safety_stop_precedes_pull(self):
        source = MODULE_PATH.read_text()
        self.assertLess(source.index("RUNTIME_FINGERPRINT_DISK_SAFETY_STOP"), source.index('["docker", "pull"'))

    def test_33_publication_manifest_covers_new_surface(self):
        manifest = (ROOT / "PUBLICATION_MANIFEST.txt").read_text().splitlines()
        for path in (
            ".github/workflows/gha-m1c1-runtime-fingerprint.yml",
            "evaluation/tests/test_m1c_runtime_fingerprint.py",
            "scripts/gha_m1c1_runtime_fingerprint.py",
            "splits/stable_task_pool_v3.json.gz.b64",
        ):
            self.assertEqual(manifest.count(path), 1)


if __name__ == "__main__":
    unittest.main()

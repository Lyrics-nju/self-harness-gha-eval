from __future__ import annotations

import hashlib
import importlib.util
import json
import base64
import gzip
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[2]
MODULE_PATH = ROOT / "scripts" / "gha_m1c1_runtime_fingerprint.py"
WORKFLOW = ROOT / ".github" / "workflows" / "gha-m1c1-runtime-fingerprint.yml"
POOL_PAYLOAD = ROOT / "splits" / "stable_task_pool_v3.json.gz.b64"
HISTORICAL_SNAPSHOT = ROOT / "evidence" / "m1c" / "runtime_fingerprint" / "historical_task_image_map_run_34972344189_v1.json"
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
            "dynamic_loader_detection_method": "READELF_PT_INTERP",
            "dynamic_loader_detection_evidence": "probe=/bin/sh;pt_interp=/lib64/ld-linux-x86-64.so.2",
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
            "dynamic_loader_detection_method": "READELF_PT_INTERP",
            "dynamic_loader_detection_evidence": "probe=/bin/sh;pt_interp=/lib64/ld-linux-x86-64.so.2",
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

    def test_34_shell_loader_variable_expands_before_emit(self):
        self.assertIn('emit dynamic_loader_path "${loader:-$na}"', rf.FINGERPRINT_SCRIPT)
        self.assertNotIn('emit dynamic_loader_path "\\${loader:-$na}"', rf.FINGERPRINT_SCRIPT)

    def test_35_observed_literal_fallback_is_rejected(self):
        with self.assertRaises(rf.QualificationError) as caught:
            rf.parse_fingerprint("dynamic_loader_path\t${loader:-NOT_AVAILABLE}\n")
        self.assertEqual(caught.exception.classification, "RUNTIME_FINGERPRINT_UNRESOLVED_SHELL_PLACEHOLDER")

    def test_36_simple_shell_variable_is_rejected(self):
        for value in ("$loader", "${loader}"):
            with self.subTest(value=value), self.assertRaises(rf.QualificationError):
                rf.parse_fingerprint(f"dynamic_loader_path\t{value}\n")

    def test_37_true_absence_is_exact_not_available(self):
        parsed = rf.parse_fingerprint("dynamic_loader_path\t\n")
        self.assertEqual(parsed["dynamic_loader_path"], rf.NOT_AVAILABLE)

    def test_38_readelf_pt_interp_is_authoritative(self):
        exists = lambda path: path in {"/bin/sh", "/lib64/ld-linux-x86-64.so.2"}
        selected = rf.select_loader_candidate(
            [("READELF_PT_INTERP", "/lib64/ld-linux-x86-64.so.2")],
            ["/lib/other-loader.so"], exists,
        )
        self.assertEqual(selected[:2], ("/lib64/ld-linux-x86-64.so.2", "READELF_PT_INTERP"))

    def test_39_ldd_fallback_when_readelf_unavailable(self):
        exists = lambda path: path == "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"
        selected = rf.select_loader_candidate(
            [("READELF_PT_INTERP", ""), ("LDD_INTERPRETER_LINE", "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2")],
            [], exists,
        )
        self.assertEqual(selected[1], "LDD_INTERPRETER_LINE")

    def test_40_loader_path_must_exist(self):
        selected = rf.select_loader_candidate(
            [("READELF_PT_INTERP", "/missing/ld.so")], [], lambda _path: False,
        )
        self.assertEqual(selected[0], rf.NOT_AVAILABLE)

    def test_41_loader_identity_is_independent(self):
        parsed = rf.parse_fingerprint(
            "dynamic_loader_path\t/lib/ld.so\n"
            "dynamic_loader_identity\tcustom loader version\n"
        )
        self.assertEqual(parsed["dynamic_loader_path"], "/lib/ld.so")
        self.assertEqual(parsed["dynamic_loader_identity"], "custom loader version")

    def test_42_ambiguous_filesystem_candidates_fail_closed(self):
        selected = rf.select_loader_candidate([], ["/lib/ld-a.so", "/lib/ld-b.so"], lambda _path: True)
        self.assertEqual(selected, (rf.NOT_AVAILABLE, "FILESYSTEM_AMBIGUOUS", "candidate_count=2"))

    def test_43_authoritative_source_disambiguates_filesystem(self):
        selected = rf.select_loader_candidate(
            [("READELF_PT_INTERP", "/lib/ld-b.so")], ["/lib/ld-a.so", "/lib/ld-b.so"], lambda _path: True,
        )
        self.assertEqual(selected[0], "/lib/ld-b.so")

    def _assert_generic_glibc_fixture(self, path: str, identity: str):
        fp = {
            "uname_s": "Linux", "uname_m": "x86_64", "libc_getconf": identity,
            "dynamic_loader_path": path, "dynamic_loader_identity": identity,
            "dynamic_loader_detection_method": "READELF_PT_INTERP",
            "dynamic_loader_detection_evidence": f"probe=/bin/sh;pt_interp={path}",
            "installed_agent_writable": "PASS", "tmp_writable": "PASS", "local_exec": "PASS",
            "dev_pts": "PRESENT", "dev_ptmx": "PRESENT",
        }
        self.assertEqual(rf.classification_for(fp), "TASK_RUNTIME_FINGERPRINT_QUALIFIED")

    def test_44_debian_bullseye_fixture_is_generic(self):
        self._assert_generic_glibc_fixture("/lib64/ld-linux-x86-64.so.2", "glibc 2.31")

    def test_45_ubuntu_glibc_fixture_is_generic(self):
        self._assert_generic_glibc_fixture("/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", "glibc 2.39")

    def test_46_debian_bookworm_fixture_is_generic(self):
        self._assert_generic_glibc_fixture("/lib64/ld-linux-x86-64.so.2", "glibc 2.36")

    def test_47_libc_version_does_not_substitute_for_loader(self):
        fp = {"uname_s": "Linux", "uname_m": "x86_64", "libc_getconf": "glibc 2.36"}
        self.assertEqual(rf.classification_for(fp), "COMPATIBILITY_NOT_YET_PROVEN")

    def test_48_missing_loader_identity_is_not_proven(self):
        fp = {
            "uname_s": "Linux", "uname_m": "x86_64", "libc_getconf": "glibc 2.31",
            "dynamic_loader_path": "/lib64/ld-linux-x86-64.so.2",
            "dynamic_loader_detection_method": "READELF_PT_INTERP",
            "dynamic_loader_detection_evidence": "probe=/bin/sh;pt_interp=/lib64/ld-linux-x86-64.so.2",
            "installed_agent_writable": "PASS", "tmp_writable": "PASS", "local_exec": "PASS",
            "dev_pts": "PRESENT", "dev_ptmx": "PRESENT",
        }
        self.assertEqual(rf.classification_for(fp), "COMPATIBILITY_NOT_YET_PROVEN")

    def test_49_no_qemu_task_special_case(self):
        self.assertNotIn("qemu-startup", MODULE_PATH.read_text())

    def test_50_detection_order_is_deterministic(self):
        source = rf.FINGERPRINT_SCRIPT
        self.assertLess(source.index("READELF_PT_INTERP"), source.index("LDD_INTERPRETER_LINE"))
        self.assertLess(source.index("LDD_INTERPRETER_LINE"), source.index("FILESYSTEM_UNIQUE_CANDIDATE"))

    def test_51_tag_digest_logic_unchanged(self):
        self.assertIn("assert_no_tag_drift(initial[reference], again)", MODULE_PATH.read_text())

    def test_52_exact_digest_dedup_policy_unchanged(self):
        self.assertEqual(len(rf.deduplicate_exact_digests([
            {"task_id": "a", "authoritative_image_reference": "same:tag", "resolved_image_digest": "sha256:a"},
            {"task_id": "b", "authoritative_image_reference": "same:tag", "resolved_image_digest": "sha256:b"},
        ])), 2)

    def test_53_cleanup_behavior_remains_finally_scoped(self):
        source = MODULE_PATH.read_text()
        self.assertLess(source.index("finally:"), source.index('["docker", "image", "rm", "-f"'))

    def test_54_no_dsh_execution_build_or_install(self):
        lower = self.workflow.lower()
        for token in ("dsh ", "pnpm run build", "dshharboradapter", "deepseek-harness"):
            self.assertNotIn(token, lower)

    def test_55_no_provider_or_evaluator_execution(self):
        lower = self.workflow.lower()
        for token in ("deepseek_api_key", "harbor run", "oracle", "verifier", "provider request"):
            self.assertNotIn(token, lower)

    def test_56_schema_includes_loader_detection_provenance(self):
        parsed = rf.parse_fingerprint("")
        self.assertEqual(parsed["dynamic_loader_detection_method"], rf.NOT_AVAILABLE)
        self.assertEqual(parsed["dynamic_loader_detection_evidence"], rf.NOT_AVAILABLE)

    def test_57_candidate_key_includes_validated_loader_path(self):
        key = rf.candidate_runtime_key({"dynamic_loader_path": "/lib/ld.so"})
        self.assertEqual(key["dynamic_loader_path"], "/lib/ld.so")

    def test_58_all_runtime_strings_reject_bug_class(self):
        for field in ("dynamic_loader_path", "default_shell", "mount_root"):
            with self.subTest(field=field), self.assertRaises(rf.QualificationError):
                rf.parse_fingerprint(f"{field}\tvalue-${{unexpanded}}\n")

    def test_59_whitespace_only_is_not_available(self):
        parsed = rf.parse_fingerprint("dynamic_loader_detection_evidence\t   \n")
        self.assertEqual(parsed["dynamic_loader_detection_evidence"], rf.NOT_AVAILABLE)

    def test_60_filesystem_fallback_is_unique_only(self):
        selected = rf.select_loader_candidate([], ["/lib/ld.so", "/lib/ld.so"], lambda _path: True)
        self.assertEqual(selected[1], "FILESYSTEM_UNIQUE_CANDIDATE")

    def test_61_identity_execution_is_read_only(self):
        self.assertIn('"$loader" --version', rf.FINGERPRINT_SCRIPT)

    def test_62_hash_and_secret_contract_unchanged(self):
        self.assertIn("sha256sum -c SHA256SUMS", self.workflow)
        self.assertIn("public_secret_scan.py --artifact-mode reports", self.workflow)

    def _modified_snapshot(self, mutate):
        data = json.loads(HISTORICAL_SNAPSHOT.read_text())
        mutate(data)
        mapping_sha = hashlib.sha256(rf.canonical_bytes(data["mappings"])).hexdigest()
        data["mapping_sha256"] = mapping_sha
        raw = rf.canonical_bytes(data)
        path = Path(self.tempdir.name) / (hashlib.sha256(raw).hexdigest() + ".json")
        path.write_bytes(raw)
        return path, hashlib.sha256(raw).hexdigest(), mapping_sha

    def test_63_verified_historical_snapshot_has_24_entries(self):
        loaded = rf.load_historical_task_image_map(HISTORICAL_SNAPSHOT, self.tasks)
        self.assertEqual(len(loaded), 24)

    def test_64_snapshot_provenance_is_deterministic(self):
        raw = HISTORICAL_SNAPSHOT.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), rf.HISTORICAL_MAP_SHA256)
        self.assertEqual(raw, rf.canonical_bytes(json.loads(raw)))

    def test_65_snapshot_stable_pool_mismatch_fails_closed(self):
        path, digest, mapping = self._modified_snapshot(lambda data: data.update(stable_pool_sha256="sha256:wrong"))
        with self.assertRaisesRegex(rf.QualificationError, "stable_pool_sha256"):
            rf.load_historical_task_image_map(path, self.tasks, digest, mapping)

    def test_66_snapshot_dataset_mismatch_fails_closed(self):
        path, digest, mapping = self._modified_snapshot(lambda data: data.update(dataset_identity="sha256:wrong"))
        with self.assertRaisesRegex(rf.QualificationError, "dataset_identity"):
            rf.load_historical_task_image_map(path, self.tasks, digest, mapping)

    def test_67_snapshot_count_mismatch_fails_closed(self):
        path, digest, mapping = self._modified_snapshot(lambda data: data["mappings"].pop())
        with self.assertRaises(rf.QualificationError) as caught:
            rf.load_historical_task_image_map(path, self.tasks, digest, mapping)
        self.assertEqual(caught.exception.classification, "HISTORICAL_TASK_IMAGE_MAP_COUNT_MISMATCH")

    def test_68_duplicate_historical_task_fails_closed(self):
        def mutate(data): data["mappings"][1]["task"] = data["mappings"][0]["task"]
        path, digest, mapping = self._modified_snapshot(mutate)
        with self.assertRaises(rf.QualificationError) as caught:
            rf.load_historical_task_image_map(path, self.tasks, digest, mapping)
        self.assertEqual(caught.exception.classification, "HISTORICAL_TASK_IMAGE_MAP_DUPLICATE_TASK")

    def test_69_missing_historical_digest_fails_closed(self):
        def mutate(data): data["mappings"][0]["historical_platform_digest"] = ""
        path, digest, mapping = self._modified_snapshot(mutate)
        with self.assertRaises(rf.QualificationError):
            rf.load_historical_task_image_map(path, self.tasks, digest, mapping)

    def test_70_malformed_historical_digest_fails_closed(self):
        def mutate(data): data["mappings"][0]["historical_platform_digest"] = "sha256:not-a-digest"
        path, digest, mapping = self._modified_snapshot(mutate)
        with self.assertRaises(rf.QualificationError):
            rf.load_historical_task_image_map(path, self.tasks, digest, mapping)

    def test_71_historical_current_task_set_mismatch_fails_closed(self):
        historical = rf.load_historical_task_image_map(HISTORICAL_SNAPSHOT, self.tasks)
        rows = self._current_rows(historical)[:-1]
        with self.assertRaises(rf.QualificationError) as caught:
            rf.compare_historical_task_image_map(historical, rows)
        self.assertEqual(caught.exception.classification, "HISTORICAL_CURRENT_TASK_SET_MISMATCH")

    def _current_rows(self, historical):
        return [{
            "task_id": task,
            "authoritative_image_reference": row["authoritative_image_ref"],
            "resolved_image_digest": row["historical_platform_digest"],
        } for task, row in historical.items()]

    def test_72_exact_24_of_24_match_permits_continuation(self):
        historical = rf.load_historical_task_image_map(HISTORICAL_SNAPSHOT, self.tasks)
        report = rf.compare_historical_task_image_map(historical, self._current_rows(historical))
        self.assertEqual((report["historical_digest_matches"], report["drift_count"]), (24, 0))
        self.assertEqual(report["classification"], "INTER_RUN_TASK_IMAGE_DIGEST_IDENTITY_PASS")

    def test_73_23_of_24_match_is_tag_drift_blocker(self):
        historical = rf.load_historical_task_image_map(HISTORICAL_SNAPSHOT, self.tasks)
        rows = self._current_rows(historical)
        rows[0]["resolved_image_digest"] = "sha256:" + "0" * 64
        report = rf.compare_historical_task_image_map(historical, rows)
        self.assertEqual(report["classification"], "M1C_RUNTIME_FINGERPRINT_INTER_RUN_TAG_DRIFT_BLOCKER")
        self.assertEqual((report["historical_digest_matches"], report["drift_count"]), (23, 1))

    def test_74_multiple_drifts_are_reported_deterministically(self):
        historical = rf.load_historical_task_image_map(HISTORICAL_SNAPSHOT, self.tasks)
        rows = self._current_rows(historical)
        rows[0]["resolved_image_digest"] = "sha256:" + "0" * 64
        rows[-1]["resolved_image_digest"] = "sha256:" + "1" * 64
        report = rf.compare_historical_task_image_map(historical, list(reversed(rows)))
        self.assertEqual(report["drift_count"], 2)
        self.assertEqual(report["drifted_tasks"], sorted(report["drifted_tasks"]))

    def test_75_registry_failure_is_not_tag_drift(self):
        source = MODULE_PATH.read_text()
        self.assertNotIn("M1C_RUNTIME_FINGERPRINT_INTER_RUN_TAG_DRIFT_BLOCKER", source[source.index("def resolve_remote"):source.index("FINGERPRINT_SCRIPT")])

    def test_76_unresolved_current_digest_is_not_tag_drift(self):
        historical = rf.load_historical_task_image_map(HISTORICAL_SNAPSHOT, self.tasks)
        rows = self._current_rows(historical)
        rows[0]["resolved_image_digest"] = rf.NOT_AVAILABLE
        with self.assertRaises(rf.QualificationError) as caught:
            rf.compare_historical_task_image_map(historical, rows)
        self.assertEqual(caught.exception.classification, "CURRENT_TASK_IMAGE_DIGEST_EVIDENCE_INCOMPLETE")

    def test_77_comparison_precedes_fingerprint_classification(self):
        source = MODULE_PATH.read_text()
        compare = source.index("compare_historical_task_image_map(historical, bound)")
        fingerprint = source.index("fp = fingerprint_one(reference, digest, raw_dir)")
        self.assertLess(compare, fingerprint)

    def test_78_drift_raise_precedes_fingerprint_execution(self):
        source = MODULE_PATH.read_text()
        drift = source.index('if comparison["drift_count"]')
        fingerprint = source.index("fp = fingerprint_one(reference, digest, raw_dir)")
        self.assertLess(drift, fingerprint)

    def test_79_controller_does_not_mutate_snapshot(self):
        before = HISTORICAL_SNAPSHOT.read_bytes()
        rf.load_historical_task_image_map(HISTORICAL_SNAPSHOT, self.tasks)
        self.assertEqual(HISTORICAL_SNAPSHOT.read_bytes(), before)

    def test_80_committed_snapshot_sha_is_validated(self):
        source = MODULE_PATH.read_text()
        self.assertIn("sha256_bytes(raw) != expected_snapshot_sha256", source)

    def test_81_snapshot_contains_identity_only(self):
        text = HISTORICAL_SNAPSHOT.read_text().lower()
        for token in ("api_key", "authorization", "task_output", "model_data", "/home/", "/mnt/"):
            self.assertNotIn(token, text)

    def test_82_benchmark_stable_pool_and_exclusions_not_mutated(self):
        changed = {"scripts/gha_m1c1_runtime_fingerprint.py", "evaluation/tests/test_m1c_runtime_fingerprint.py",
                   ".github/workflows/gha-m1c1-runtime-fingerprint.yml", "PUBLICATION_MANIFEST.txt",
                   "evidence/m1c/runtime_fingerprint/historical_task_image_map_run_34972344189_v1.json"}
        self.assertFalse(any(path.startswith(("configs/", "splits/stable_task_pool_v3.json")) for path in changed))

    def test_83_loader_correction_remains_intact(self):
        source = rf.FINGERPRINT_SCRIPT
        for token in ("READELF_PT_INTERP", "LDD_INTERPRETER_LINE", "FILESYSTEM_UNIQUE_CANDIDATE"):
            self.assertIn(token, source)

    def test_84_unresolved_loader_placeholder_remains_rejected(self):
        with self.assertRaises(rf.QualificationError):
            rf.parse_fingerprint("dynamic_loader_path\t${loader}\n")

    def test_85_workflow_supplies_immutable_snapshot(self):
        self.assertIn("--historical-task-image-map evidence/m1c/runtime_fingerprint/historical_task_image_map_run_34972344189_v1.json", self.workflow)

    def test_86_identity_gates_precede_registry_resolution(self):
        source = MODULE_PATH.read_text()
        self.assertLess(source.index("load_historical_task_image_map(args.historical_task_image_map"), source.index("resolved, selected_raw = resolve_remote_fail_closed(reference)"))

    def test_87_within_run_gate_precedes_inter_run_gate(self):
        source = MODULE_PATH.read_text()
        within = source.index("assert_no_tag_drift(initial[reference], again)")
        inter = source.index("compare_historical_task_image_map(historical, bound)")
        self.assertLess(within, inter)

    def test_88_snapshot_publication_manifest_coverage(self):
        manifest = (ROOT / "PUBLICATION_MANIFEST.txt").read_text().splitlines()
        self.assertEqual(manifest.count(HISTORICAL_SNAPSHOT.relative_to(ROOT).as_posix()), 1)

    def test_89_comparison_evidence_is_persisted(self):
        source = MODULE_PATH.read_text()
        self.assertIn('write_json(reports / "inter-run-digest-comparison.json", comparison)', source)

    def test_90_deterministic_comparison_ordering(self):
        historical = rf.load_historical_task_image_map(HISTORICAL_SNAPSHOT, self.tasks)
        rows = self._current_rows(historical)
        first = rf.compare_historical_task_image_map(historical, rows)
        second = rf.compare_historical_task_image_map(historical, list(reversed(rows)))
        self.assertEqual(rf.canonical_bytes(first), rf.canonical_bytes(second))

    def test_91_historical_mapping_sha_is_validated(self):
        source = MODULE_PATH.read_text()
        self.assertIn('sha256_bytes(canonical_bytes(mappings)) != data["mapping_sha256"]', source)

    def test_92_snapshot_provenance_fields_are_exact(self):
        data = json.loads(HISTORICAL_SNAPSHOT.read_text())
        self.assertEqual(data["source_run_id"], 34972344189)
        self.assertEqual(data["source_run_attempt"], 1)
        self.assertEqual(data["source_artifact_id"], 10397907660)

    def test_93_registry_transport_failure_has_explicit_non_drift_classification(self):
        def fail(_reference):
            raise subprocess.CalledProcessError(42, ["docker", "buildx"])

        with self.assertRaises(rf.QualificationError) as caught:
            rf.resolve_remote_fail_closed("example.invalid/image:tag", fail)
        self.assertEqual(
            caught.exception.classification,
            "TASK_IMAGE_REGISTRY_RESOLUTION_INFRASTRUCTURE_BLOCKER",
        )
        self.assertNotEqual(
            caught.exception.classification,
            "M1C_RUNTIME_FINGERPRINT_INTER_RUN_TAG_DRIFT_BLOCKER",
        )


if __name__ == "__main__":
    unittest.main()

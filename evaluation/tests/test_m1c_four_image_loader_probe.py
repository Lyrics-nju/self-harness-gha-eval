from __future__ import annotations

import hashlib
import importlib.util
import json
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).parents[2]
spec = importlib.util.spec_from_file_location("four_probe", ROOT / "scripts/gha_m1c1_four_image_loader_probe.py")
p = importlib.util.module_from_spec(spec); spec.loader.exec_module(p)


def elf_bytes():
    raw = bytearray(256)
    raw[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<HH", raw, 16, 3, 62)
    struct.pack_into("<Q", raw, 32, 64)
    struct.pack_into("<HHH", raw, 52, 64, 56, 1)
    struct.pack_into("<IIQQQQQQ", raw, 64, 1, 5, 0, 0, 0, 256, 256, 4096)
    return bytes(raw)


class FourImageTests(unittest.TestCase):
    def fixture(self, directory):
        raw = Path(directory); raw.mkdir(exist_ok=True)
        cid = "c" * 64; config = "sha256:" + "d" * 64
        selection = p.select_images()[0]
        for name in ("fingerprint.stdout", "fingerprint.stderr", "fingerprint.exit", "pull.stdout", "pull.stderr", "pull.exit"):
            (raw / name).write_text("0" if name.endswith("exit") else "diagnostic fixture")
        for name in ("registry-command.json", "registry.stdout", "registry.stderr", "registry.exit",
                     "manifest-resolution.json", "selected-manifest.json", "selection-binding.json"):
            if not (raw / name).exists():
                (raw / name).write_text("{}" if name.endswith("json") else "fixture")
        binary = raw / "loader.binary"; binary.write_bytes(elf_bytes())
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        runtime = {"dynamic_loader_path": "/lib64/ld-linux-x86-64.so.2", "dynamic_loader_realpath": "/lib/ld-real.so",
            "dynamic_loader_sha256": digest, "loader_binary_identity_status": "LOADER_BINARY_IDENTITY_VALID",
            "dynamic_loader_release_metadata": "NOT_AVAILABLE", "loader_release_metadata_status": "LOADER_RELEASE_METADATA_NOT_AVAILABLE"}
        p.rf.write_json(raw / "fingerprint-container-state.json", {"container_id": cid, "image": config,
            "state": {"Running": False, "ExitCode": 0}, "start_exit": 0})
        p.rf.write_json(raw / "loader-identity-probes.json", {"probes": {
            "realpath": {"semantic_validity": True, "value": runtime["dynamic_loader_realpath"],
                "command": ["readlink", "-f", "--", runtime["dynamic_loader_path"]]},
            "copy": {"command": ["docker", "cp", "-L", cid + ":/lib/ld-real.so", str(binary)],
                "exit_code": 0, "stdout": "", "stderr": "", "semantic_validity": True}},
            "identity": {"dynamic_loader_sha256": digest}})
        for name in ("container-cleanup.json", "cleanup.json"): p.rf.write_json(raw / name, {"exit": 0, "container_id": cid})
        return selection, {"docker_image_id": config, "docker_os": "linux", "docker_architecture": "amd64", "runtime": runtime}, config

    def mutate_json(self, path, action):
        data = json.loads(path.read_text()); action(data); p.rf.write_json(path, data)

    def test_01_fixed_selection_membership_order(self):
        rows = p.select_images()
        self.assertEqual(tuple(x["task"] for x in rows), p.TASKS)
        self.assertEqual(len(rows), 4)

    def test_02_historical_sha_provenance_enforced(self):
        with patch.object(p.rf, "HISTORICAL_MAP_SHA256", "invalid"):
            # Loader defaults are frozen at definition time; tamper bytes instead.
            with tempfile.TemporaryDirectory() as td:
                fake = Path(td) / "snapshot"; fake.write_text("{}")
                with patch.object(p, "SNAPSHOT", fake), self.assertRaises(p.rf.QualificationError): p.select_images()

    def test_03_registry_digest_mismatch(self):
        with tempfile.TemporaryDirectory() as td, patch.object(p.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, b"{}", b"")):
            with self.assertRaises(p.rf.QualificationError) as caught: p.resolve_immutable(p.select_images()[0], Path(td))
            self.assertEqual(caught.exception.classification, "IMMUTABLE_PLATFORM_DIGEST_MISMATCH")

    def test_04_arbitrary_cli_inputs_rejected(self):
        with patch.object(sys, "argv", ["probe", "--reports", "unused", "--task", "arbitrary"]), patch.object(p, "execute") as execute:
            with self.assertRaises(SystemExit): p.main()
            execute.assert_not_called()

    def test_05_stopped_copy_command(self):
        with tempfile.TemporaryDirectory() as td:
            selection, fp, config = self.fixture(td)
            self.assertEqual(p.verify_row(selection, fp, Path(td), config)["classification"], p.PASS)

    def test_06_symlink_text_is_not_elf(self):
        with tempfile.TemporaryDirectory() as td:
            file = Path(td) / "loader"; file.write_bytes(b"/lib/ld-real.so")
            with self.assertRaises(p.rf.QualificationError): p.validate_elf(file)

    def test_07_copy_source_binding(self):
        with tempfile.TemporaryDirectory() as td:
            s, fp, c = self.fixture(td)
            self.mutate_json(Path(td) / "loader-identity-probes.json", lambda d: d["probes"]["copy"]["command"].__setitem__(3, "other:/lib/ld-real.so"))
            with self.assertRaises(p.rf.QualificationError) as caught: p.verify_row(s, fp, Path(td), c)
            self.assertEqual(caught.exception.classification, "DOCKER_COPY_SOURCE_BINDING_UNPROVEN")

    def test_08_copy_nonzero(self):
        self.assert_row_copy_failure("exit_code", 1, "LOADER_BINARY_COPY_NONZERO")

    def assert_row_copy_failure(self, key, value, reason):
        with tempfile.TemporaryDirectory() as td:
            s, fp, c = self.fixture(td)
            self.mutate_json(Path(td) / "loader-identity-probes.json", lambda d: d["probes"]["copy"].__setitem__(key, value))
            with self.assertRaises(p.rf.QualificationError) as caught: p.verify_row(s, fp, Path(td), c)
            self.assertEqual(caught.exception.classification, reason)

    def test_09_copy_error_diagnostic(self):
        self.assert_row_copy_failure("stderr", "Error: copy failed", "LOADER_BINARY_COPY_DIAGNOSTIC")

    def test_10_empty_truncated_payload(self):
        for data in (b"", elf_bytes()[:64], elf_bytes()[:128]):
            with tempfile.TemporaryDirectory() as td:
                f = Path(td) / "elf"; f.write_bytes(data)
                with self.assertRaises(p.rf.QualificationError): p.validate_elf(f)

    def test_11_bad_magic(self):
        self.assert_bad_binary(b"HTML" + elf_bytes()[4:])

    def assert_bad_binary(self, data):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "elf"; f.write_bytes(data)
            with self.assertRaises(p.rf.QualificationError): p.validate_elf(f)

    def test_12_wrong_architecture(self):
        raw = bytearray(elf_bytes()); struct.pack_into("<H", raw, 18, 183)
        self.assert_bad_binary(raw)

    def test_13_sha_deterministic(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "elf"; f.write_bytes(elf_bytes())
            self.assertEqual(p.validate_elf(f), p.validate_elf(f))

    def test_14_hash_is_bytes_not_path(self):
        with tempfile.TemporaryDirectory() as td:
            a = Path(td) / "a"; b = Path(td) / "b"; a.write_bytes(elf_bytes()); b.write_bytes(elf_bytes())
            self.assertEqual(p.validate_elf(a)["sha256"], p.validate_elf(b)["sha256"])
            b.write_bytes(elf_bytes() + b"changed")
            self.assertNotEqual(p.validate_elf(a)["sha256"], p.validate_elf(b)["sha256"])

    def test_15_missing_release_allowed(self):
        with tempfile.TemporaryDirectory() as td:
            s, fp, c = self.fixture(td); self.assertEqual(p.verify_row(s, fp, Path(td), c)["classification"], p.PASS)

    def test_16_old_error_not_identity(self):
        error = "--version: error while loading shared libraries: --version: cannot open shared object file"
        self.assertFalse(p.rf.validate_probe("LDD_VERSION", ["ldd", "--version"], 0, error, "")["semantic_validity"])

    def test_17_generic_distribution_bytes(self):
        for version in ("2.31", "2.36", "2.41", "2.39"):
            self.assertTrue(p.rf.validate_probe("GETCONF_GNU_LIBC_VERSION", ["getconf", "GNU_LIBC_VERSION"], 0, "glibc " + version, "")["semantic_validity"])

    def test_18_no_task_specific_branch(self):
        source = (ROOT / "scripts/gha_m1c1_four_image_loader_probe.py").read_text()
        self.assertEqual(source.count("qemu-startup"), 1)

    def test_19_cleanup_success_required(self):
        with tempfile.TemporaryDirectory() as td:
            self.fixture(td); self.assertEqual(len(p.require_cleanup(Path(td))), 2)

    def test_20_failure_path_records_cleanup_reason(self):
        self.assertEqual(p.failure_class("DIAGNOSTIC_CLEANUP_FAILURE"), p.INFRA)
        source = (ROOT / "scripts/gha_m1c1_four_image_loader_probe.py").read_text()
        self.assertIn('"execution-failure.json"', source)

    def test_21_cleanup_failure_independent(self):
        with tempfile.TemporaryDirectory() as td:
            s, fp, c = self.fixture(td); p.rf.write_json(Path(td) / "container-cleanup.json", {"exit": 1})
            with self.assertRaises(p.rf.QualificationError) as caught: p.verify_row(s, fp, Path(td), c)
            self.assertEqual(caught.exception.classification, "DIAGNOSTIC_CLEANUP_FAILURE")

    def test_22_scan_failure_no_pass(self):
        with tempfile.TemporaryDirectory() as td, patch.object(p.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "SCAN_FAIL", "")):
            summary = p.seal(Path(td), {"classification": p.PASS})
            self.assertEqual(summary["classification"], p.UNKNOWN)

    def test_23_manifest_complete(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); (root / "a").write_text("a"); p.rf.content_manifest(root, root / "SHA256SUMS"); p.manifest_verify(root)
            (root / "unlisted").write_text("x")
            with self.assertRaises(p.rf.QualificationError): p.manifest_verify(root)

    def test_24_original_census_frozen(self):
        # Baseline advanced to the verified identical source at the corrective
        # commit's direct parent, so the GHA depth-2 contract is sufficient.
        prior = subprocess.check_output(["git", "show", "1402698ce46653f24381baebca9588bae2b1ab1e:scripts/gha_m1c1_runtime_fingerprint.py"], cwd=ROOT)
        self.assertEqual(prior, (ROOT / "scripts/gha_m1c1_runtime_fingerprint.py").read_bytes())

    def test_25_original_loader_order(self):
        s = p.rf.FINGERPRINT_SCRIPT
        self.assertLess(s.index("READELF_PT_INTERP"), s.index("LDD_INTERPRETER_LINE"))

    def test_26_no_dsh(self):
        s = (ROOT / ".github/workflows/gha-m1c1-four-image-loader-probe.yml").read_text().lower()
        for token in ("pnpm", "dshharboradapter", "deepseek-harness", "dsh session"): self.assertNotIn(token, s)

    def test_27_no_provider(self):
        s = (ROOT / ".github/workflows/gha-m1c1-four-image-loader-probe.yml").read_text().lower()
        for token in ("secrets.", "deepseek_api_key", "provider"): self.assertNotIn(token, s)

    def test_28_no_task_runner(self):
        s = (ROOT / ".github/workflows/gha-m1c1-four-image-loader-probe.yml").read_text().lower()
        for token in ("harbor run", "oracle", "verifier", "solve.sh"): self.assertNotIn(token, s)

    def test_29_no_fifth_or_arbitrary_input(self):
        w = (ROOT / ".github/workflows/gha-m1c1-four-image-loader-probe.yml").read_text()
        self.assertNotIn("inputs:", w); self.assertEqual(len(p.TASKS), 4)

    def test_30_no_promotion_to_census(self):
        self.assertNotEqual(p.PASS, "TASK_RUNTIME_FINGERPRINT_QUALIFIED")
        source = (ROOT / "scripts/gha_m1c1_four_image_loader_probe.py").read_text()
        self.assertIn('"task_runtime_fingerprint_qualified": False', source)

    def test_31_registry_failure_infrastructure(self):
        with tempfile.TemporaryDirectory() as td, patch.object(p.subprocess, "run", return_value=subprocess.CompletedProcess([], 7, b"", b"registry error")):
            with self.assertRaises(p.rf.QualificationError) as caught: p.resolve_immutable(p.select_images()[0], Path(td))
            self.assertEqual(p.failure_class(caught.exception.classification), p.INFRA)

    def test_32_registry_uses_single_immutable_reference(self):
        raw = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"digest": "sha256:" + "a" * 64}, "layers": []}).encode()
        selection = {"task": "fixture", "authoritative_image_ref": "example/image:1", "historical_platform_digest": "sha256:" + hashlib.sha256(raw).hexdigest()}
        with tempfile.TemporaryDirectory() as td, patch.object(p.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, raw, b"")) as run:
            p.resolve_immutable(selection, Path(td))
            self.assertEqual(run.call_args.args[0][-1], selection["authoritative_image_ref"] + "@" + selection["historical_platform_digest"])
            self.assertEqual(run.call_args.args[0][-1].count("@"), 1)

    def test_33_source_must_be_stopped(self):
        with tempfile.TemporaryDirectory() as td:
            s, fp, c = self.fixture(td)
            self.mutate_json(Path(td) / "fingerprint-container-state.json", lambda d: d["state"].__setitem__("Running", True))
            with self.assertRaises(p.rf.QualificationError): p.verify_row(s, fp, Path(td), c)

    def test_34_hash_mismatch_is_indeterminate(self):
        with tempfile.TemporaryDirectory() as td:
            s, fp, c = self.fixture(td); fp["runtime"]["dynamic_loader_sha256"] = "a" * 64
            with self.assertRaises(p.rf.QualificationError) as caught: p.verify_row(s, fp, Path(td), c)
            self.assertEqual(p.failure_class(caught.exception.classification), p.UNKNOWN)

    def test_35_missing_evidence_is_indeterminate(self):
        with tempfile.TemporaryDirectory() as td:
            s, fp, c = self.fixture(td); (Path(td) / "fingerprint.stdout").unlink()
            with self.assertRaises(p.rf.QualificationError) as caught: p.verify_row(s, fp, Path(td), c)
            self.assertEqual(p.failure_class(caught.exception.classification), p.UNKNOWN)

    def test_36_local_symlink_target_hash(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "target"; target.write_bytes(elf_bytes())
            link = Path(td) / "symlink"; link.symlink_to(target)
            self.assertEqual(p.validate_elf(link.resolve())["sha256"], hashlib.sha256(target.read_bytes()).hexdigest())
            with self.assertRaises(p.rf.QualificationError): p.validate_elf(link)

    def test_37_cleanup_binding(self):
        with tempfile.TemporaryDirectory() as td:
            s, fp, c = self.fixture(td)
            p.rf.write_json(Path(td) / "container-cleanup.json", {"exit": 0, "container_id": "different"})
            with self.assertRaises(p.rf.QualificationError): p.verify_row(s, fp, Path(td), c)

    def test_38_platform_config_binding(self):
        with tempfile.TemporaryDirectory() as td:
            s, fp, c = self.fixture(td); fp["docker_architecture"] = "arm64"
            with self.assertRaises(p.rf.QualificationError): p.verify_row(s, fp, Path(td), c)

    def test_39_manifest_tamper(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); f = root / "a"; f.write_text("a"); p.rf.content_manifest(root, root / "SHA256SUMS")
            f.write_text("tampered")
            with self.assertRaises(p.rf.QualificationError): p.manifest_verify(root)

    def test_40_full_four_image_flow_mocked(self):
        raw = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"digest": "sha256:" + "d" * 64}, "layers": []}).encode()
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        selections = [{"task": task, "authoritative_image_ref": "fixture/image:1", "historical_platform_digest": digest} for task in p.TASKS]
        counter = []
        def fake_fingerprint(reference, expected_digest, directory):
            _, fp, _ = self.fixture(directory)
            cid = str(len(counter) + 1).zfill(64); counter.append(cid)
            self.mutate_json(directory / "fingerprint-container-state.json", lambda d: d.__setitem__("container_id", cid))
            self.mutate_json(directory / "container-cleanup.json", lambda d: d.__setitem__("container_id", cid))
            self.mutate_json(directory / "loader-identity-probes.json", lambda d: d["probes"]["copy"]["command"].__setitem__(3, cid + ":/lib/ld-real.so"))
            return fp
        # All transport/container operations are mocks; scanner and manifest are real local gates.
        with tempfile.TemporaryDirectory() as td, patch.object(p, "select_images", return_value=selections), \
             patch.object(p, "resolve_immutable", return_value=({"resolved_image_digest": digest, "image_config_digest": "sha256:" + "d" * 64}, raw)), \
             patch.object(p.rf, "fingerprint_one", side_effect=fake_fingerprint):
            summary = p.execute(Path(td) / "new-output")
            self.assertEqual(summary["classification"], p.PASS)
            self.assertEqual(len(summary["images"]), 4)
            self.assertFalse(summary["task_runtime_fingerprint_qualified"])
            self.assertEqual(summary["secret_scan"], "PASS")

    def test_41_helper_failure_cleanup_preserved(self):
        selection = p.select_images()[0]
        raw = b"manifest fixture"
        selection["historical_platform_digest"] = "sha256:" + hashlib.sha256(raw).hexdigest()
        def fail(reference, digest, directory):
            p.rf.write_json(directory / "container-cleanup.json", {"exit": 1, "container_id": "c" * 64})
            p.rf.write_json(directory / "cleanup.json", {"exit": 0})
            raise p.rf.QualificationError("TASK_RUNTIME_FINGERPRINT_CONTAINER_FAILURE", "fixture failure")
        with tempfile.TemporaryDirectory() as td, patch.object(p, "select_images", return_value=[selection]), \
             patch.object(p, "resolve_immutable", return_value=({"resolved_image_digest": selection["historical_platform_digest"], "image_config_digest": "sha256:" + "d" * 64}, raw)), \
             patch.object(p.rf, "fingerprint_one", side_effect=fail):
            summary = p.execute(Path(td) / "new-output")
            self.assertEqual(summary["classification"], p.INFRA)
            self.assertEqual(summary["reason"], "DIAGNOSTIC_CLEANUP_FAILURE")
            self.assertEqual(summary["current_task"], selection["task"])


if __name__ == "__main__":
    unittest.main()

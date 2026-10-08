from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

ROOT = Path(__file__).parents[2]
spec = importlib.util.spec_from_file_location("loader_rf", ROOT / "scripts/gha_m1c1_runtime_fingerprint.py")
rf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rf)
ERROR = "--version: error while loading shared libraries: --version: cannot open shared object file"
ELF = b"\x7fELF\x02\x01" + b"\0" * 10 + b"\x03\x00\x3e\x00" + b"\0" * 100


def probe_fields(prefix, stdout, exit_code=0, stderr=""):
    return {prefix + "_exit": str(exit_code),
            prefix + "_stdout_b64": base64.b64encode(stdout.encode()).decode(),
            prefix + "_stderr_b64": base64.b64encode(stderr.encode()).decode()}


def fixture(version="2.31", release=True):
    fp = {"uname_s": "Linux", "uname_m": "x86_64", "dynamic_loader_path": "/lib64/ld-linux-x86-64.so.2",
          "dynamic_loader_detection_method": "LDD_INTERPRETER_LINE", "dynamic_loader_detection_evidence": "probe=/bin/sh",
          "installed_agent_writable": "PASS", "tmp_writable": "PASS", "local_exec": "PASS",
          "dev_pts": "PRESENT", "dev_ptmx": "PRESENT"}
    fp.update(probe_fields("loader_realpath", "/lib/x86_64-linux-gnu/ld-real.so\n"))
    fp.update(probe_fields("release_getconf", "glibc " + version + "\n"))
    fp.update(probe_fields("release_ldd", "ldd (GNU libc) " + version + "\n" if release else "", 0 if release else 127))
    return fp


class LoaderIdentityTests(unittest.TestCase):
    def enrich(self, fp=None, data=ELF, code=0):
        with tempfile.TemporaryDirectory() as td:
            def copy(command, **kwargs):
                self.assertEqual(command[:3], ["docker", "cp", "-L"])
                self.assertEqual(command[3], "c" * 64 + ":/lib/x86_64-linux-gnu/ld-real.so")
                if not code:
                    Path(command[4]).write_bytes(data)
                return subprocess.CompletedProcess(command, code, "", "copy failed" if code else "")
            result = rf.enrich_loader_identity(fp or fixture(), "c" * 64, Path(td), copy)
            evidence = json.loads((Path(td) / "loader-identity-probes.json").read_text())
            return result, evidence

    def test_01_nonzero_plausible_stdout_rejected(self):
        p = rf.validate_probe("LDD_VERSION", ["ldd", "--version"], 1, "ldd (GNU libc) 2.31", "")
        self.assertFalse(p["semantic_validity"])

    def test_02_stderr_is_not_identity(self):
        self.assertFalse(rf.validate_probe("LDD_VERSION", ["ldd", "--version"], 0, "", ERROR)["semantic_validity"])

    def test_03_exact_prior_error_rejected(self):
        self.assertFalse(rf.validate_probe("LDD_VERSION", ["ldd", "--version"], 0, ERROR, "")["semantic_validity"])

    def test_04_usage_rejected(self):
        for text in ("Usage: ld.so [OPTION]", "help: --version", "ldd (GNU libc) 2.31\nUsage: invalid"):
            self.assertFalse(rf.validate_probe("LDD_VERSION", ["ldd", "--version"], 0, text, "")["semantic_validity"])

    def test_05_hash_deterministic(self):
        a, _ = self.enrich(); b, _ = self.enrich()
        self.assertEqual(a["dynamic_loader_sha256"], b["dynamic_loader_sha256"])
        self.assertEqual(a["dynamic_loader_sha256"], hashlib.sha256(ELF).hexdigest())

    def test_06_symlink_target_bytes_and_not_link_text(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "target"; target.write_bytes(ELF)
            link = Path(td) / "ld.so"; link.symlink_to(target)
            fp = fixture(); fp.update(probe_fields("loader_realpath", str(target)))
            def follow(command, **kwargs):
                self.assertEqual(command[3], "c" * 64 + ":" + str(target))
                Path(command[4]).write_bytes(link.resolve().read_bytes())
                return subprocess.CompletedProcess(command, 0, "", "")
            result = rf.enrich_loader_identity(fp, "c" * 64, Path(td), follow)
            self.assertEqual(result["dynamic_loader_sha256"], hashlib.sha256(target.read_bytes()).hexdigest())

    def test_07_host_hash_no_image_sha256sum(self):
        result, _ = self.enrich()
        self.assertEqual(result["dynamic_loader_identity_method"], "HOST_SHA256_DOCKER_CP_RESOLVED_ELF")
        self.assertNotIn("sha256sum", rf.FINGERPRINT_SCRIPT)

    def test_08_missing_release_valid_binary(self):
        fp, _ = self.enrich(fixture(release=False))
        self.assertEqual(fp["loader_release_metadata_status"], "LOADER_RELEASE_METADATA_NOT_AVAILABLE")
        self.assertEqual(rf.classification_for(fp), "TASK_RUNTIME_FINGERPRINT_QUALIFIED")

    def test_09_missing_binary_fail_closed(self):
        fp, _ = self.enrich(code=1)
        self.assertEqual(fp["loader_binary_identity_status"], "LOADER_IDENTITY_PROBE_ERROR")
        self.assertEqual(rf.classification_for(fp), "COMPATIBILITY_NOT_YET_PROVEN")

    def test_10_debian11_generic(self):
        fp, _ = self.enrich(fixture("2.31")); self.assertEqual(rf.classification_for(fp), "TASK_RUNTIME_FINGERPRINT_QUALIFIED")

    def test_11_debian12_generic(self):
        fp, _ = self.enrich(fixture("2.36")); self.assertEqual(rf.classification_for(fp), "TASK_RUNTIME_FINGERPRINT_QUALIFIED")

    def test_12_ubuntu_generic(self):
        fp, _ = self.enrich(fixture("2.39")); self.assertEqual(rf.classification_for(fp), "TASK_RUNTIME_FINGERPRINT_QUALIFIED")

    def test_13_no_task_special_case(self):
        self.assertNotIn("qemu-startup", (ROOT / "scripts/gha_m1c1_runtime_fingerprint.py").read_text())

    def test_14_prior_path_detection_order(self):
        s = rf.FINGERPRINT_SCRIPT
        self.assertLess(s.index("READELF_PT_INTERP"), s.index("LDD_INTERPRETER_LINE"))
        self.assertLess(s.index("LDD_INTERPRETER_LINE"), s.index("FILESYSTEM_UNIQUE_CANDIDATE"))

    def test_15_placeholder_rejected(self):
        with self.assertRaises(rf.QualificationError):
            rf.parse_fingerprint("dynamic_loader_path\t${loader}\n")

    def test_16_old_text_identity_cannot_qualify(self):
        fp = fixture(); fp["dynamic_loader_identity"] = ERROR
        self.assertEqual(rf.classification_for(fp), "COMPATIBILITY_NOT_YET_PROVEN")

    def test_17_digest_match_semantics(self):
        hist = {"a": {"authoritative_image_ref": "x:1", "historical_platform_digest": "sha256:" + "a" * 64}}
        current = [{"task_id": "a", "authoritative_image_reference": "x:1", "resolved_image_digest": "sha256:" + "a" * 64}]
        self.assertEqual(rf.compare_historical_task_image_map(hist, current)["historical_digest_matches"], 1)
        current[0]["resolved_image_digest"] = "sha256:" + "b" * 64
        self.assertEqual(rf.compare_historical_task_image_map(hist, current)["drift_count"], 1)

    def test_18_registry_error_distinct(self):
        def fail(ref): raise subprocess.CalledProcessError(1, "inspect")
        with self.assertRaises(rf.QualificationError) as caught: rf.resolve_remote_fail_closed("x:1", fail)
        self.assertEqual(caught.exception.classification, "TASK_IMAGE_REGISTRY_RESOLUTION_INFRASTRUCTURE_BLOCKER")

    def test_19_no_execution_surfaces(self):
        s = (ROOT / ".github/workflows/gha-m1c1-runtime-fingerprint.yml").read_text().lower()
        for token in ("secrets.", "dsh session", "harbor run", "oracle", "verifier"):
            self.assertNotIn(token, s)

    def test_20_scan_and_hash_fail_closed(self):
        s = (ROOT / ".github/workflows/gha-m1c1-runtime-fingerprint.yml").read_text()
        self.assertIn("steps.scan.outcome == 'success'", s)
        self.assertIn("sha256sum -c SHA256SUMS", s)

    def test_21_copy_error_preserves_evidence(self):
        _, e = self.enrich(code=9)
        self.assertEqual(e["probes"]["copy"]["exit_code"], 9)
        self.assertEqual(e["probes"]["copy"]["stderr"], "copy failed")

    def test_22_non_elf_not_identity(self):
        fp, _ = self.enrich(data=b"/lib/ld-real.so")
        self.assertEqual(fp["loader_binary_identity_status"], "LOADER_BINARY_IDENTITY_NOT_AVAILABLE")

    def test_23_host_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "t"; target.write_bytes(ELF)
            link = Path(td) / "l"; link.symlink_to(target)
            with self.assertRaises(rf.QualificationError): rf.hash_loader_binary(link)

    def test_24_bad_realpath_prevents_copy(self):
        fp = fixture(); fp.update(probe_fields("loader_realpath", "/lib/ld.so", 1, "error"))
        with tempfile.TemporaryDirectory() as td:
            def forbidden(*args, **kwargs): self.fail("copy must not run")
            result = rf.enrich_loader_identity(fp, "c" * 64, Path(td), forbidden)
            self.assertEqual(result["dynamic_loader_sha256"], rf.NOT_AVAILABLE)

    def test_25_candidate_key_uses_binary_not_release(self):
        fp, _ = self.enrich(); key = rf.candidate_runtime_key(fp)
        self.assertEqual(key["loader_binary_sha256"], fp["dynamic_loader_sha256"])
        self.assertNotIn("dynamic_loader_identity", key)
        changed = {**fp, "dynamic_loader_release_metadata": "other"}
        self.assertEqual(key, rf.candidate_runtime_key(changed))

    def test_26_metadata_record_has_separate_channels(self):
        _, e = self.enrich()
        for p in e["probes"].values():
            for key in ("method", "command", "exit_code", "stdout", "stderr", "semantic_validity"):
                self.assertIn(key, p)

    def test_27_debian13_generic(self):
        fp, _ = self.enrich(fixture("2.41")); self.assertEqual(rf.classification_for(fp), "TASK_RUNTIME_FINGERPRINT_QUALIFIED")

    def test_28_empty_channels_survive_fingerprint_parser(self):
        raw = fixture()
        parsed = rf.parse_fingerprint("\n".join(k + "\t" + v for k, v in raw.items()))
        result, e = self.enrich(parsed)
        self.assertTrue(e["probes"]["getconf"]["semantic_validity"])
        self.assertEqual(result["loader_binary_identity_status"], "LOADER_BINARY_IDENTITY_VALID")

    def test_29_actual_shell_helper_preserves_exit_and_channels(self):
        helper = rf.FINGERPRINT_SCRIPT.split("probe release_getconf", 1)[0]
        proc = subprocess.run(["sh", "-c", helper + "\nprobe release_getconf sh -c 'printf stdout; printf stderr >&2; exit 7'"],
                              text=True, capture_output=True, check=True)
        fp = rf.parse_fingerprint(proc.stdout)
        p = rf.decode_probe(fp, "release_getconf", "GETCONF_GNU_LIBC_VERSION", ["getconf", "GNU_LIBC_VERSION"])
        self.assertEqual((p["exit_code"], p["stdout"], p["stderr"]), (7, "stdout", "stderr"))
        self.assertFalse(p["semantic_validity"])

    def test_30_malformed_base64_is_error(self):
        fp = fixture(); fp["loader_realpath_stdout_b64"] = "!invalid"
        result, e = self.enrich(fp)
        self.assertFalse(e["probes"]["realpath"]["semantic_validity"])
        self.assertEqual(result["dynamic_loader_sha256"], rf.NOT_AVAILABLE)

    def test_31_changed_bytes_change_exact_identity_only(self):
        a, _ = self.enrich(); b, _ = self.enrich(data=ELF + b"different")
        self.assertNotEqual(a["dynamic_loader_sha256"], b["dynamic_loader_sha256"])
        self.assertEqual(a["libc_version"], b["libc_version"])

    def test_32_container_binding_and_cleanup_mocked(self):
        cid = "c" * 64; image = "sha256:" + "d" * 64; seen = []
        def checked(command):
            seen.append(command)
            if command[1] == "create": out = cid
            elif command[1] == "inspect": out = json.dumps([{"Image": image, "State": {"ExitCode": 0, "Running": False}}])
            else: self.fail(str(command))
            return subprocess.CompletedProcess(command, 0, out, "")
        def run(command, **kwargs):
            seen.append(command)
            if command[1] == "start":
                return subprocess.CompletedProcess(command, 0, "uname_s\tLinux\n", "")
            return subprocess.CompletedProcess(command, 0, "", "")
        with tempfile.TemporaryDirectory() as td, patch.object(rf, "run_checked", checked), \
             patch.object(rf, "image_inspect", return_value={"docker_image_id": image, "docker_os": "linux", "docker_architecture": "amd64"}), \
             patch.object(rf.subprocess, "run", run), patch.object(rf.shutil, "disk_usage", return_value=type("Disk", (), {"free": rf.MIN_DISK_FREE_BYTES + 1})()), \
             patch.object(rf, "enrich_loader_identity", return_value={"uname_s": "Linux"}) as enrich:
            rf.fingerprint_one("example/image:1", "sha256:" + "a" * 64, Path(td))
            self.assertEqual(enrich.call_args.args[1], cid)
            self.assertIn(["docker", "start", "-a", cid], seen)
            self.assertIn(["docker", "rm", "-f", cid], seen)
            self.assertTrue((Path(td) / "container-cleanup.json").is_file())

    def test_33_getconf_bad_format_rejected(self):
        for text in ("glibc 2.31\nerror", "Usage: getconf", ERROR):
            self.assertFalse(rf.validate_probe("GETCONF_GNU_LIBC_VERSION", ["getconf", "GNU_LIBC_VERSION"], 0, text, "")["semantic_validity"])

    def test_34_release_cli_never_invokes_loader(self):
        self.assertNotIn('"$loader" --version', rf.FINGERPRINT_SCRIPT)

    def test_35_binary_status_without_digest_is_insufficient(self):
        fp, _ = self.enrich(); fp["dynamic_loader_sha256"] = "diagnostic"
        self.assertEqual(rf.classification_for(fp), "COMPATIBILITY_NOT_YET_PROVEN")

    def test_36_derived_binary_identity_is_preserved(self):
        fp, e = self.enrich()
        self.assertEqual(e["identity"]["dynamic_loader_sha256"], fp["dynamic_loader_sha256"])
        self.assertEqual(e["identity"]["dynamic_loader_realpath"], "/lib/x86_64-linux-gnu/ld-real.so")


if __name__ == "__main__":
    unittest.main()

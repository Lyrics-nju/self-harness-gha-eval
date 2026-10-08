from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("four_preflight", ROOT / "scripts/gha_m1c1_four_image_preflight.py")
h = importlib.util.module_from_spec(spec); spec.loader.exec_module(h)


class HistoryPreflightTests(unittest.TestCase):
    def command(self, root, *args):
        return subprocess.check_output(["git", *args], cwd=root, stderr=subprocess.DEVNULL).decode().strip()

    def repo(self, path):
        path.mkdir()
        self.command(path, "init", "-q")
        source = path / h.FROZEN_SOURCE
        source.parent.mkdir(parents=True)
        source.write_text("frozen census fixture\n")
        self.command(path, "add", ".")
        self.command(path, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "baseline")
        parent = self.command(path, "rev-parse", "HEAD")
        (path / "correction.txt").write_text("workflow-only correction\n")
        self.command(path, "add", ".")
        self.command(path, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "correction")
        head = self.command(path, "rev-parse", "HEAD")
        return parent, head

    def test_01_actual_depth_one_missing_parent_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            source = Path(td) / "source"; parent, head = self.repo(source)
            clone = Path(td) / "clone"
            self.command(Path(td), "clone", "-q", "--depth", "1", source.as_uri(), str(clone))
            with patch.object(h, "REQUIRED_PARENT", parent), self.assertRaises(h.GateError) as caught:
                h.validate_history(clone, head)
            self.assertEqual(caught.exception.reason, "CHECKOUT_SHALLOW_HISTORY_PREFLIGHT_BLOCKER")
            self.assertEqual(caught.exception.exit_code, 128)

    def test_02_actual_depth_two_reads_required_revision(self):
        with tempfile.TemporaryDirectory() as td:
            source = Path(td) / "source"; parent, head = self.repo(source)
            clone = Path(td) / "clone"
            self.command(Path(td), "clone", "-q", "--depth", "2", source.as_uri(), str(clone))
            with patch.object(h, "REQUIRED_PARENT", parent):
                row = h.validate_history(clone, head)
            self.assertEqual(row["required_history"], "PASS")
            self.assertEqual(row["required_parent_sha"], parent)

    def test_03_head_mismatch(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "r"; parent, _head = self.repo(root)
            with patch.object(h, "REQUIRED_PARENT", parent), self.assertRaises(h.GateError) as caught:
                h.validate_history(root, "a" * 40)
            self.assertEqual(caught.exception.reason, "HEAD_IDENTITY_MISMATCH")

    def test_04_missing_object(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "r"; _parent, head = self.repo(root)
            with patch.object(h, "REQUIRED_PARENT", "a" * 40), self.assertRaises(h.GateError):
                h.validate_history(root, head)

    def test_05_object_must_be_commit(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "r"; _parent, head = self.repo(root)
            blob = self.command(root, "rev-parse", "HEAD:" + h.FROZEN_SOURCE)
            with patch.object(h, "REQUIRED_PARENT", blob), self.assertRaises(h.GateError) as caught:
                h.validate_history(root, head)
            self.assertEqual(caught.exception.reason, "REQUIRED_GIT_OBJECT_NOT_COMMIT")

    def test_06_parent_mismatch(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "r"; _parent, head = self.repo(root)
            with patch.object(h, "REQUIRED_PARENT", head), self.assertRaises(h.GateError) as caught:
                h.validate_history(root, head)
            self.assertEqual(caught.exception.reason, "DIRECT_PARENT_IDENTITY_MISMATCH")

    def test_07_source_drift(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "r"; parent, head = self.repo(root)
            (root / h.FROZEN_SOURCE).write_text("drift\n")
            with patch.object(h, "REQUIRED_PARENT", parent), self.assertRaises(h.GateError) as caught:
                h.validate_history(root, head)
            self.assertEqual(caught.exception.reason, "FROZEN_CENSUS_SOURCE_DRIFT")

    def test_08_expected_head_syntax(self):
        with self.assertRaises(h.GateError): h.validate_history(ROOT, "HEAD")

    def failure(self, directory, error=None):
        with patch.object(h, "validate_history", side_effect=error or h.GateError("CHECKOUT_SHALLOW_HISTORY_PREFLIGHT_BLOCKER", 128)), \
             patch.object(h, "validate_inputs") as inputs, patch.object(h.subprocess, "run") as commands:
            row = h.run_preflight(Path(directory) / "lane", "a" * 40)
            inputs.assert_not_called(); commands.assert_not_called()
        return row

    def test_09_history_failure_has_no_probe_or_tests(self):
        with tempfile.TemporaryDirectory() as td:
            row = self.failure(td)
            self.assertEqual(row["probe_status"], "NOT_REACHED")
            self.assertEqual(row["exit_code"], 128)

    def test_10_history_failure_not_loader_incompatibility(self):
        with tempfile.TemporaryDirectory() as td:
            row = self.failure(td)
            self.assertEqual(row["classification"], "FOUR_IMAGE_LOADER_IDENTITY_EVIDENCE_INDETERMINATE")

    def test_11_safe_summary_never_saves_exception_or_environment(self):
        with tempfile.TemporaryDirectory() as td, patch.dict(h.os.environ, {"GITHUB_RUN_ID": "untrusted-value", "GITHUB_RUN_ATTEMPT": "untrusted-value"}):
            row = self.failure(td, RuntimeError("synthetic-sensitive-diagnostic-do-not-copy"))
            text = (Path(td) / "lane/preflight-summary.json").read_text()
            self.assertNotIn("synthetic-sensitive", text)
            self.assertNotIn("untrusted-value", text)
            self.assertEqual(row["reason"], "PREFLIGHT_EVIDENCE_UNAVAILABLE")
            self.assertEqual(list((Path(td) / "lane").iterdir()), [Path(td) / "lane/preflight-summary.json"])

    def test_12_safe_failure_summary_scans(self):
        with tempfile.TemporaryDirectory() as td:
            self.failure(td)
            p = subprocess.run(["python3", str(ROOT / "scripts/public_secret_scan.py"), "--artifact-mode", str(Path(td) / "lane")], capture_output=True)
            self.assertEqual(p.returncode, 0)

    def test_13_regressions_fail_closed(self):
        with tempfile.TemporaryDirectory() as td, patch.object(h, "validate_history", return_value={}), patch.object(h, "validate_inputs", return_value={}), \
             patch.object(h.subprocess, "run", return_value=subprocess.CompletedProcess([], 1)) as commands:
            row = h.run_preflight(Path(td) / "lane", "a" * 40)
            self.assertEqual(row["stage"], "REGRESSION_TESTS")
            self.assertEqual(row["preflight"], "FAIL"); self.assertEqual(commands.call_count, 1)

    def test_14_source_scanner_failure_not_bypassed(self):
        with tempfile.TemporaryDirectory() as td, patch.object(h, "validate_history", return_value={}), patch.object(h, "validate_inputs", return_value={}), \
             patch.object(h.subprocess, "run", side_effect=[subprocess.CompletedProcess([], 0), subprocess.CompletedProcess([], 1)]):
            row = h.run_preflight(Path(td) / "lane", "a" * 40)
            self.assertEqual(row["reason"], "PREFLIGHT_PUBLIC_SOURCE_SCAN_FAILURE")
            self.assertEqual(row["preflight"], "FAIL")

    def test_15_success_summary_is_not_qualification(self):
        with tempfile.TemporaryDirectory() as td, patch.object(h, "validate_history", return_value={}), patch.object(h, "validate_inputs", return_value={}), \
             patch.object(h.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)):
            row = h.run_preflight(Path(td) / "lane", "a" * 40)
            self.assertEqual(row["preflight"], "PASS")
            self.assertEqual(row["probe_status"], "NOT_REACHED")
            self.assertNotEqual(row["classification"], "FOUR_IMAGE_LOADER_IDENTITY_PROBE_PASS")

    def test_16_frozen_input_gate_real_local(self):
        row = h.validate_inputs()
        self.assertEqual(row["frozen_inputs"], "PASS")
        self.assertEqual(len(row["tasks"]), 4)

    def test_17_workflow_minimal_depth_and_pre_probe_order(self):
        w = (ROOT / ".github/workflows/gha-m1c1-four-image-loader-probe.yml").read_text()
        self.assertIn("fetch-depth: 2", w); self.assertNotIn("fetch-depth: 0", w)
        self.assertLess(w.index("gha_m1c1_four_image_preflight.py"), w.index("gha_m1c1_four_image_loader_probe.py"))
        self.assertIn('--expected-head "$GITHUB_SHA"', w)
        self.assertIn("if: always() && steps.preflight-evidence.outcome == 'success'", w)
        lane = w[w.index("Independent safe preflight evidence gate"):]
        self.assertLess(lane.index("public_secret_scan.py"), lane.index("actions/upload-artifact@v4"))
        self.assertNotIn("job.log", lane)

    def test_18_formal_workflow_and_gates_unchanged(self):
        for file in (".github/workflows/gha-m1c1-runtime-fingerprint.yml", h.FROZEN_SOURCE, "scripts/gha_m1c1_four_image_loader_probe.py"):
            prior = subprocess.check_output(["git", "show", h.REQUIRED_PARENT + ":" + file], cwd=ROOT)
            self.assertEqual(prior, (ROOT / file).read_bytes())

    def test_19_scanner_unchanged(self):
        name = "scripts/public_secret_scan.py"
        prior = subprocess.check_output(["git", "show", h.REQUIRED_PARENT + ":" + name], cwd=ROOT)
        self.assertEqual(hashlib.sha256(prior).hexdigest(), hashlib.sha256((ROOT / name).read_bytes()).hexdigest())

    def test_20_no_execution_path(self):
        source = (ROOT / "scripts/gha_m1c1_four_image_preflight.py").read_text()
        for forbidden in ('["docker"', "fingerprint_one(", "probe.execute(", "harbor run", "pnpm", "DshHarborAdapter", "DEEPSEEK_API_KEY", "secrets."):
            self.assertNotIn(forbidden, source)

    def test_21_output_reuse_fails(self):
        with tempfile.TemporaryDirectory() as td, self.assertRaises(h.GateError):
            h.run_preflight(Path(td), "a" * 40)

    def test_22_input_failure_precedes_child_commands(self):
        with tempfile.TemporaryDirectory() as td, patch.object(h, "validate_history", return_value={}), \
             patch.object(h, "validate_inputs", side_effect=ValueError("untrusted")), patch.object(h.subprocess, "run") as commands:
            row = h.run_preflight(Path(td) / "lane", "a" * 40)
            commands.assert_not_called()
            self.assertEqual(row["stage"], "FROZEN_INPUTS")
            self.assertEqual(row["probe_status"], "NOT_REACHED")


if __name__ == "__main__": unittest.main()

import importlib.util
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT = Path(__file__).parents[2]
LIVE = (ROOT / ".github/workflows/gha-m1c1-live.yml").read_text()
PROBE_PATH = ROOT / ".github/workflows/gha-m1c1-live-preflight-probe.yml"
PROBE = PROBE_PATH.read_text()
CONTROLLER_PATH = ROOT / "scripts/gha_m1c1_live_controller.py"
spec = importlib.util.spec_from_file_location("m1c_preflight_stage_controller", CONTROLLER_PATH)
controller = importlib.util.module_from_spec(spec); assert spec and spec.loader
spec.loader.exec_module(controller)


class PreflightOrderingTests(unittest.TestCase):
    def test_01_negative_before_pth(self):
        for text in (LIVE, PROBE):
            self.assertLess(text.index("Verify legacy no-wiring negatives"), text.index("Install and qualify interpreter-level"))

    def test_02_positive_after_pth(self):
        for text in (LIVE, PROBE):
            self.assertLess(text.index("scripts/m1c_adapter_pth.py"), text.index("Frozen pre-model regressions"))

    def test_03_gate_after_all_import_checks(self):
        for text in (LIVE, PROBE):
            self.assertLess(text.index("Frozen pre-model regressions"), text.index("pre-model hard gate"))

    def test_04_negative_semantics_preserved(self):
        negative = (ROOT / "evaluation/tests/test_m1c_custom_agent_import_contract.py").read_text()
        edge = (ROOT / "evaluation/tests/test_m1c_live_invocation_edges.py").read_text()
        self.assertIn("historical_nonrepo_import_failure_reproduced", negative)
        self.assertIn("assertNotEqual(proc.returncode, 0)", negative)
        self.assertIn("wrong_import_path_fails_preflight", edge)
        self.assertIn("assertEqual(proc.returncode, 1)", edge)

    def test_05_negative_tests_do_not_mutate_pth(self):
        combined = "".join((ROOT / p).read_text() for p in ("evaluation/tests/test_m1c_custom_agent_import_contract.py", "evaluation/tests/test_m1c_live_invocation_edges.py"))
        for token in ("self_harness_m1c_adapter_source.pth", ".unlink(", "site-packages"):
            self.assertNotIn(token, combined)

    def test_06_probe_dispatch_only(self):
        head = PROBE.split("permissions:", 1)[0]
        self.assertIn("workflow_dispatch:", head)
        for token in ("push:", "pull_request:", "schedule:", "matrix:"):
            self.assertNotIn(token, PROBE)

    def test_07_probe_model_path_unreachable(self):
        for token in ("DEEPSEEK_" + "API_KEY", "secrets.", "run-live", "harbor run"):
            self.assertNotIn(token, PROBE)
        self.assertEqual(PROBE.count("MODEL_EXPOSURE_START"), 1)
        self.assertIn("test ! -e reports/MODEL_EXPOSURE_START", PROBE)

    def test_08_probe_terminal_marker(self):
        self.assertIn("reports/PRE_MODEL_GATE_COMPLETED", PROBE)
        self.assertIn("test ! -e reports/MODEL_EXPOSURE_START", PROBE)

    def test_09_live_and_probe_share_pre_model_commands(self):
        for token in ("harbor==0.21.0", "scripts/resolve_harbor_python.py", "scripts/m1c_adapter_pth.py", "scripts/run_frozen_evaluator_regressions.py", "scripts/gha_m1c1_live_controller.py preflight"):
            self.assertIn(token, LIVE); self.assertIn(token, PROBE)

    def test_10_preflight_stage_is_initialized_before_first_copy(self):
        block = PROBE.split("- name: Prepare sanitized artifacts", 1)[1]
        self.assertLess(block.index("stage-preflight"), block.index("cp reports/full-pre-model-summary.json"))
        self.assertNotIn("gha_m1c1_live_controller.py stage\n", block)

    def test_11_fresh_missing_directory_is_created_repeatedly(self):
        for _ in range(2):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                reports = root / "reports"
                reports.mkdir()
                (reports / "full-pre-model-summary.json").write_text('{"provider_requests":0}\n')
                destination = root / "artifact-stage"
                self.assertFalse(destination.exists())
                self.assertEqual(controller.stage_preflight(root), 0)
                self.assertTrue(destination.is_dir())
                self.assertTrue((destination / "EVIDENCE_MANIFEST.json").is_file())
                scan = reports / "secret-scan.txt"
                scan.write_text("SECRET_SCAN_PASS\n")
                shutil.copy2(scan, destination / "secret-scan.txt")
                self.assertEqual((destination / "secret-scan.txt").read_text(), "SECRET_SCAN_PASS\n")

    def test_12_live_lanes_keep_independent_initializers_and_fail_closed_scan(self):
        self.assertIn('build_partial_manifest(root, root / "bulk-artifact-stage", expected)', CONTROLLER_PATH.read_text())
        self.assertIn('build_safe_core(root, JOB_NAME, TASK_ID)', CONTROLLER_PATH.read_text())
        self.assertIn("BLOCKED_BY_SECRET_SCAN", LIVE)
        self.assertIn("steps.safe_core.outputs.safe == 'true'", LIVE)
        self.assertIn("steps.bulk.outputs.safe == 'true'", LIVE)


if __name__ == "__main__": unittest.main()

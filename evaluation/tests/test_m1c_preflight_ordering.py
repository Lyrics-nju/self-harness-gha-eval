from pathlib import Path
import unittest

ROOT = Path(__file__).parents[2]
LIVE = (ROOT / ".github/workflows/gha-m1c1-live.yml").read_text()
PROBE_PATH = ROOT / ".github/workflows/gha-m1c1-live-preflight-probe.yml"
PROBE = PROBE_PATH.read_text()


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


if __name__ == "__main__": unittest.main()

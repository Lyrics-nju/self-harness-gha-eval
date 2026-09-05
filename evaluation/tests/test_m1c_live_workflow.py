import hashlib
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).parents[2]
WORKFLOW = ROOT / ".github/workflows/gha-m1c1-live.yml"
CONTROLLER = ROOT / "scripts/gha_m1c1_live_controller.py"
ADAPTER = ROOT / "evaluation/agents/dsh_harbor_adapter/adapter.py"
spec = importlib.util.spec_from_file_location("live_controller", CONTROLLER)
controller = importlib.util.module_from_spec(spec); spec.loader.exec_module(controller)

class LiveWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = WORKFLOW.read_text()
        cls.controller = CONTROLLER.read_text()

    def test_01_dedicated_workflow_exists(self): self.assertTrue(WORKFLOW.is_file())
    def test_02_dispatch_only(self):
        trigger = self.workflow.split("permissions:", 1)[0]
        self.assertIn("workflow_dispatch:", trigger); self.assertNotIn("push:", trigger); self.assertNotIn("pull_request:", trigger); self.assertNotIn("schedule:", trigger)
    def test_03_standard_runner(self): self.assertIn("runs-on: ubuntu-24.04", self.workflow)
    def test_04_no_matrix(self): self.assertNotIn("matrix:", self.workflow)
    def test_05_no_retry_logic(self): self.assertNotIn("retry", self.workflow.lower()); self.assertIn('"--max-retries", "0"', self.controller)
    def test_06_exact_fixed_task(self): self.assertEqual(controller.TASK_ID, "terminal-bench/caffe-cifar-10"); self.assertEqual(self.controller.count('TASK_ID = "terminal-bench/caffe-cifar-10"'), 1)
    def test_07_one_harbor_trial_path(self): self.assertEqual(self.controller.count('subprocess.run(harbor_command(root)'), 1)
    def test_08_no_arbitrary_task_input(self): self.assertNotIn("inputs:", self.workflow); self.assertNotIn("--task", self.controller)
    def test_09_required_secret_name_referenced(self): self.assertIn("secrets." + "DEEPSEEK_" + "API_KEY", self.workflow)
    def test_10_secret_not_printed(self):
        forbidden = ["echo $" + "DEEPSEEK_" + "API_KEY", "printenv", "Authoriz" + "ation:"]
        for token in forbidden: self.assertNotIn(token, self.workflow + self.controller)
        self.assertNotIn("\n          env\n", self.workflow)
        self.assertNotIn("env |", self.workflow)
    def test_11_no_shell_trace(self): self.assertNotIn("set -x", self.workflow)
    def test_12_profile_sha_frozen(self): self.assertEqual(controller.PROFILE_SHA256, "2102539e0c35c4168f2c91b2383f95e39042576a64612060e55a126a57bf7f4e")
    def test_13_dsh_commit_frozen(self): self.assertEqual(controller.DSH_COMMIT, "b150a551b8d465e31e418e1b2eaf5e79bbb7d28e")
    def test_14_harbor_version_frozen(self): self.assertEqual(controller.HARBOR_VERSION, "0.21.0"); self.assertIn("harbor==0.21.0", self.workflow)
    def test_15_gate_precedes_live(self): self.assertLess(self.workflow.index("Complete pre-model hard gate"), self.workflow.index("Execute exactly one fixed live Harbor trial"))
    def test_16_exposure_boundary_order(self): self.assertLess(self.controller.index("PRE_MODEL_GATE_COMPLETED"), self.controller.index("MODEL_EXPOSURE_START")); self.assertLess(self.controller.index("MODEL_EXPOSURE_START"), self.controller.index("subprocess.run(harbor_command(root)"))
    def test_17_artifact_always_run(self): self.assertIn("id: artifacts\n        if: always()", self.workflow)
    def test_18_scan_precedes_upload(self): self.assertLess(self.workflow.index("public_secret_scan.py --artifact-mode"), self.workflow.index("actions/upload-artifact@v4"))
    def test_19_tests_do_not_call_model(self): self.assertNotIn("import " + "subprocess", Path(__file__).read_text())
    def test_20_adapter_unchanged(self): self.assertEqual(hashlib.sha256(ADAPTER.read_bytes()).hexdigest(), "3086ed0919d182719195c8ee415bb89da2a035c2f2a923861efd09eb1c2e9d7c")

    def test_controller_interpreter_contracts(self):
        for action in ("preflight", "run-live", "summarize"):
            self.assertIn(f'PYTHONPATH="$ADAPTER_SOURCE_ROOT${{PYTHONPATH:+:$PYTHONPATH}}" "$HARBOR_PY" scripts/gha_m1c1_live_controller.py {action}', self.workflow)
        for duplicate in ('"$HARBOR_PY" python ', '"$HARBOR_PY" python3 ', '"$HARBOR_PY" /usr/bin/python3 '):
            self.assertNotIn(duplicate, self.workflow)
        self.assertIn("python3 scripts/run_frozen_evaluator_regressions.py", self.workflow)
        self.assertIn("ADAPTER_SOURCE_ROOT: ${{ github.workspace }}", self.workflow)

    def test_interpreter_level_wiring_precedes_live(self):
        self.assertIn("scripts/m1c_adapter_pth.py", self.workflow)
        self.assertIn("env -u PYTHONPATH", self.workflow)
        self.assertLess(self.workflow.index("scripts/m1c_adapter_pth.py"), self.workflow.index("Execute exactly one fixed live Harbor trial"))

    def test_import_wiring_evidence_is_failure_safe(self):
        self.assertIn('"harbor-resolution.json"', self.controller)
        self.assertIn('"adapter-pth-qualification.json"', self.controller)

if __name__ == "__main__": unittest.main()

import json
from pathlib import Path
import unittest
import yaml

ROOT = Path(__file__).parents[2]
WORKFLOW = ROOT / ".github/workflows/gha-m1c1-container-build-probe.yml"
SCRIPT = ROOT / "scripts/gha_m1c1_container_build_probe.py"


class ContainerBuildProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = WORKFLOW.read_text(); cls.script = SCRIPT.read_text()

    def test_01_dispatch_only_no_inputs(self):
        data=yaml.safe_load(self.workflow); self.assertEqual(data[True], {"workflow_dispatch": None})
        self.assertNotIn("inputs:", self.workflow)

    def test_02_no_model_secret_or_live_surface(self):
        for token in ("DEEPSEEK_"+"API_KEY", "secrets.", "run-live", "MODEL_EXPOSURE_START"):
            self.assertNotIn(token, self.workflow)

    def test_03_exact_production_install_only_path(self):
        self.assertIn("live.harbor_command(root) + [\"--install-only\"]", self.script)
        self.assertIn("evaluation.agents.dsh_harbor_adapter", (ROOT/"scripts/gha_m1c1_live_controller.py").read_text())

    def test_04_authoritative_v3_binding(self):
        record=json.loads((ROOT/"configs/m1c_integration_task_v3.json").read_text())
        self.assertEqual(record["selected_task_id"], "terminal-bench/configure-git-webserver")
        self.assertIn("live.TASK_ID", self.script)

    def test_05_run_guard_and_proven_zero(self):
        self.assertIn('"adapter_run_invoked": False', self.script)
        self.assertIn('"provider_request_status": "PROVEN_ZERO"', self.script)
        self.assertIn('"install_only": True', self.script)

    def test_06_failure_evidence_always_uploaded(self):
        self.assertIn("continue-on-error: true", self.workflow)
        self.assertIn("if: always()", self.workflow)
        self.assertLess(self.workflow.index("public_secret_scan.py"), self.workflow.index("actions/upload-artifact@v4"))
        self.assertIn("SHA256SUMS", self.workflow)

    def test_07_no_retry_or_second_task(self):
        self.assertIn('"--max-retries", "0"', (ROOT/"scripts/gha_m1c1_live_controller.py").read_text())
        self.assertNotIn("matrix:", self.workflow)


if __name__ == "__main__": unittest.main()

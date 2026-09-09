import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
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

    def test_08_materializer_owns_runtime_creation(self):
        from evaluation.agents.dsh_harbor_adapter.materializer import create_run
        with tempfile.TemporaryDirectory() as directory:
            work=Path(directory)/"work"; work.mkdir()
            runtime=work/"runtime"; self.assertFalse(runtime.exists())
            create_run(work,"runtime"); self.assertTrue(runtime.is_dir())

    def test_09_precreated_runtime_reproduces_collision(self):
        from evaluation.agents.dsh_harbor_adapter.materializer import create_run
        with tempfile.TemporaryDirectory() as directory:
            work=Path(directory)/"work"; (work/"runtime").mkdir(parents=True)
            with self.assertRaises(FileExistsError): create_run(work,"runtime")

    def test_10_workflow_leaves_runtime_absent(self):
        init=self.workflow.split("Initialize isolated probe runtime",1)[1].split("- name:",1)[0]
        self.assertNotIn("mkdir -p reports work/candidate work/jobs work/runtime",init)
        self.assertIn("test ! -e work/runtime",init)

    def test_11_arbitrary_cwd_stage_import_and_evidence(self):
        for _ in range(2):
            with tempfile.TemporaryDirectory() as directory:
                env=os.environ.copy(); env.pop("PYTHONPATH",None)
                proc=subprocess.run([sys.executable,str(SCRIPT),"stage"],cwd=directory,env=env,capture_output=True,text=True)
                self.assertEqual(proc.returncode,0,proc.stderr)
                stage=Path(directory)/"container-build-artifact-stage"
                self.assertTrue((stage/"EVIDENCE_MANIFEST.json").is_file())
                self.assertTrue((stage/"SHA256SUMS").is_file())

    def test_12_pre_harbor_missing_evidence_is_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            env=os.environ.copy(); env.pop("PYTHONPATH",None)
            subprocess.run([sys.executable,str(SCRIPT),"stage"],cwd=directory,env=env,check=True)
            manifest=json.loads((Path(directory)/"container-build-artifact-stage/EVIDENCE_MANIFEST.json").read_text())
            self.assertTrue(all(entry["status"]=="ABSENT" for entry in manifest["entries"]))

    def test_13_diagnostics_use_absolute_script_without_persistent_pythonpath(self):
        block=self.workflow.split("Prepare and scan diagnostics",1)[1]
        self.assertIn('env -u PYTHONPATH python3 "$GITHUB_WORKSPACE/scripts/gha_m1c1_container_build_probe.py" stage',block)

    def test_14_no_verifier_and_no_arbitrary_task(self):
        self.assertIn('"verifier_invoked": False',self.script)
        self.assertNotIn("inputs:",self.workflow)

    def test_15_scanner_and_checksums_are_fail_closed(self):
        block=self.workflow.split("Prepare and scan diagnostics",1)[1]
        self.assertIn("set -euo pipefail",block)
        self.assertIn("public_secret_scan.py --artifact-mode",block)
        self.assertIn("sha256sum > container-build-artifact-stage/SHA256SUMS",block)


if __name__ == "__main__": unittest.main()

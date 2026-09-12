import json
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock
import yaml

from scripts import gha_m1c1_container_build_probe as probe_module
from scripts.gha_m1c1_container_build_probe import (
    authoritative_job_name, discover_intended_trial, optional_command_metadata, optional_file_metadata,
)

ROOT = Path(__file__).parents[2]
WORKFLOW = ROOT / ".github/workflows/gha-m1c1-container-build-probe.yml"
SCRIPT = ROOT / "scripts/gha_m1c1_container_build_probe.py"
MATERIALIZER_SPEC = importlib.util.spec_from_file_location(
    "m1c_probe_materializer", ROOT / "evaluation/agents/dsh_harbor_adapter/materializer.py"
)
MATERIALIZER = importlib.util.module_from_spec(MATERIALIZER_SPEC)
MATERIALIZER_SPEC.loader.exec_module(MATERIALIZER)


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
        with tempfile.TemporaryDirectory() as directory:
            work=Path(directory)/"work"; work.mkdir()
            runtime=work/"runtime"; self.assertFalse(runtime.exists())
            MATERIALIZER.create_run(work,"runtime"); self.assertTrue(runtime.is_dir())

    def test_09_precreated_runtime_reproduces_collision(self):
        with tempfile.TemporaryDirectory() as directory:
            work=Path(directory)/"work"; (work/"runtime").mkdir(parents=True)
            with self.assertRaises(FileExistsError): MATERIALIZER.create_run(work,"runtime")

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

    def test_16_host_pnpm_absent_is_explicit_and_non_throwing(self):
        def absent(*args, **kwargs): raise FileNotFoundError("pnpm")
        self.assertEqual(optional_command_metadata(["pnpm", "--version"], absent),
                         {"status":"ABSENT", "value":"NOT_AVAILABLE"})

    def test_17_host_pnpm_present_version_is_recorded(self):
        runner=Mock(return_value=subprocess.CompletedProcess([],0,"10.15.1\n",""))
        self.assertEqual(optional_command_metadata(["pnpm", "--version"],runner),
                         {"status":"PRESENT", "value":"10.15.1"})

    def test_18_optional_command_error_is_not_success(self):
        runner=Mock(return_value=subprocess.CompletedProcess([],7,"","diagnostic failed"))
        self.assertEqual(optional_command_metadata(["pnpm", "--version"],runner),
                         {"status":"ERROR", "value":"NOT_AVAILABLE", "exit_code":7})

    def test_19_node_metadata_is_optional_and_stateful(self):
        self.assertIn('"runner_node": optional_command_metadata(["node", "--version"])',self.script)
        self.assertIn('"runner_node": "OPTIONAL_DIAGNOSTIC_METADATA"',self.script)

    def test_20_cgroup_absence_is_non_throwing(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(optional_file_metadata(Path(directory)/"missing"),
                             {"status":"ABSENT", "value":"NOT_AVAILABLE"})

    def test_21_cgroup_read_error_is_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(optional_file_metadata(Path(directory)),
                             {"status":"ERROR", "value":"NOT_AVAILABLE", "error_type":"IsADirectoryError"})

    def test_22_required_harbor_command_remains_fail_closed(self):
        self.assertIn("process = subprocess.run(command",self.script)
        self.assertNotIn("except Exception",self.script.split("process = subprocess.run(command",1)[1].split("capture_raw",1)[0])
        self.assertIn('"harbor_install_only_command": "REQUIRED_FOR_PROBE_EXECUTION"',self.script)

    def test_23_optional_metadata_precedes_required_probe(self):
        self.assertLess(self.script.index('"runner_pnpm": optional_command_metadata'),
                        self.script.index("process = subprocess.run(command"))
        self.assertIn('live.harbor_command(root) + ["--install-only"]',self.script)

    def test_24_metadata_failure_artifacts_and_absence_survive(self):
        self.test_06_failure_evidence_always_uploaded()
        self.test_12_pre_harbor_missing_evidence_is_explicit()

    def test_25_boundaries_and_binding_remain_frozen(self):
        self.assertIn('"adapter_run_invoked": False',self.script)
        self.assertIn('"provider_path_reached": False',self.script)
        self.assertIn('"verifier_invoked": False',self.script)
        self.assertNotIn("inputs:",self.workflow)
        self.assertNotIn("DEEPSEEK_"+"API_KEY",self.workflow)
        self.assertIn("configs/m1c_integration_task_v3.json",(ROOT/"scripts/gha_m1c1_live_controller.py").read_text())

    def test_26_command_and_evidence_share_authoritative_job_name(self):
        self.assertNotIn('JOB_NAME = "m1c1-container-build-probe"',self.script)
        self.assertIn("job_name = authoritative_job_name(command)",self.script)
        self.assertIn("capture_raw(root, job_name",self.script)
        self.assertIn("discover_intended_trial(root / \"work/jobs\", job_name",self.script)

    def test_27_command_contract_tracks_authoritative_value(self):
        old=probe_module.live.JOB_NAME
        try:
            probe_module.live.JOB_NAME="changed-authoritative-job"
            command=["harbor","run","--job-name","changed-authoritative-job","--yes"]
            self.assertEqual(authoritative_job_name(command),"changed-authoritative-job")
        finally: probe_module.live.JOB_NAME=old

    def test_28_command_contract_rejects_missing_duplicate_or_divergent(self):
        with self.assertRaises(RuntimeError): authoritative_job_name(["harbor","run"])
        with self.assertRaises(RuntimeError): authoritative_job_name(["--job-name","wrong"])
        with self.assertRaises(RuntimeError): authoritative_job_name(
            ["--job-name",probe_module.live.JOB_NAME,"--job-name",probe_module.live.JOB_NAME])

    def _trial(self,root,name,result=True):
        trial=root/"jobs"/probe_module.live.JOB_NAME/name; trial.mkdir(parents=True)
        (trial/"config.json").write_text("{}")
        if result: (trial/"result.json").write_text("{}")
        return trial

    def test_29_exact_job_root_and_dynamic_suffix(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); self._trial(root,"configure-git-webserver__Dynamic9")
            found=discover_intended_trial(root/"jobs",probe_module.live.JOB_NAME,
                                          "terminal-bench/configure-git-webserver")
            self.assertEqual(found["status"],"PRESENT")
            self.assertEqual(found["trial_id"],"configure-git-webserver__Dynamic9")

    def test_30_zero_and_multiple_matches_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            absent=discover_intended_trial(root/"jobs",probe_module.live.JOB_NAME,
                                           "terminal-bench/configure-git-webserver")
            self.assertEqual(absent["blocker"],"M1C_HARBOR_TRIAL_NOT_FOUND")
            self._trial(root,"configure-git-webserver__a")
            self._trial(root,"configure-git-webserver__b")
            ambiguous=discover_intended_trial(root/"jobs",probe_module.live.JOB_NAME,
                                              "terminal-bench/configure-git-webserver")
            self.assertEqual(ambiguous["blocker"],"M1C_HARBOR_TRIAL_AMBIGUOUS")

    def test_31_single_wrong_task_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); self._trial(root,"other-task__Dynamic9")
            found=discover_intended_trial(root/"jobs",probe_module.live.JOB_NAME,
                                          "terminal-bench/configure-git-webserver")
            self.assertEqual(found["blocker"],"M1C_HARBOR_TRIAL_TASK_MISMATCH")

    def test_32_summary_and_manifest_record_authoritative_job_name(self):
        self.assertIn('"job_name": job_name',self.script)
        self.assertIn('manifest["job_name"] = live.JOB_NAME',self.script)

    def test_33_exit_zero_without_result_is_not_success(self):
        self.assertIn("process.returncode == 0 and result is not None",self.script)


if __name__ == "__main__": unittest.main()

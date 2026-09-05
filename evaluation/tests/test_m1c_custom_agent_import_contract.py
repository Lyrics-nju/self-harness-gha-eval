from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).parents[2]
MODULE = "evaluation.agents.dsh_harbor_adapter.adapter:DshHarborAdapter"
ADAPTER = ROOT / "evaluation/agents/dsh_harbor_adapter/adapter.py"
CONTROLLER_PATH = ROOT / "scripts/gha_m1c1_live_controller.py"
SPEC = importlib.util.spec_from_file_location("m1c_live_controller_import_tests", CONTROLLER_PATH)
controller = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(controller)


class CustomAgentImportContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.harbor_python = os.environ.get("HARBOR_PY", "")
        if not cls.harbor_python or not Path(cls.harbor_python).is_file():
            raise unittest.SkipTest("HARBOR_PY must name the runtime-resolved Harbor interpreter")

    def env(self, source: Path | None = ROOT) -> dict[str, str]:
        env = os.environ.copy()
        env.pop("PYTHONPATH", None)
        if source is not None:
            env["PYTHONPATH"] = str(source.resolve())
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        return env

    def import_process(self, cwd: Path, source: Path | None = ROOT, module: str = MODULE):
        code = f"from harbor.agents.factory import AgentFactory; AgentFactory.create_agent_from_import_path({module!r}, logs_dir=__import__('pathlib').Path('logs'), model_name='deepseek-v4-pro', config={{}})"
        return subprocess.run([self.harbor_python, "-c", code], cwd=cwd, env=self.env(source), text=True, capture_output=True)

    def test_01_current_namespace_package_contract(self):
        self.assertFalse((ROOT / "evaluation/__init__.py").exists())
        self.assertFalse((ROOT / "evaluation/agents/__init__.py").exists())
        self.assertTrue((ROOT / "evaluation/agents/dsh_harbor_adapter/__init__.py").is_file())
        self.assertTrue(ADAPTER.is_file())

    def test_02_historical_nonrepo_import_failure_reproduced(self):
        with tempfile.TemporaryDirectory() as td:
            proc = self.import_process(Path(td), source=None)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("No module named 'evaluation'", proc.stderr)

    def test_03_repository_root_import_passes(self):
        proc = self.import_process(ROOT)
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_04_arbitrary_cwd_import_passes_with_absolute_root(self):
        with tempfile.TemporaryDirectory() as td:
            proc = self.import_process(Path(td))
            self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_05_trial_like_nested_cwd_import_passes(self):
        with tempfile.TemporaryDirectory() as td:
            nested = Path(td) / "jobs/job/trial/agent"; nested.mkdir(parents=True)
            proc = self.import_process(nested)
            self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_06_resolved_harbor_python_import_passes(self):
        proc = subprocess.run([self.harbor_python, "-c", "import harbor; import evaluation.agents.dsh_harbor_adapter.adapter"], cwd=Path("/tmp"), env=self.env(), text=True, capture_output=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_07_system_python_is_not_production_importer(self):
        workflow = (ROOT / ".github/workflows/gha-m1c1-live.yml").read_text()
        self.assertIn('"$HARBOR_PY" scripts/gha_m1c1_live_controller.py run-live', workflow)
        self.assertNotIn("python3 scripts/gha_m1c1_live_controller.py run-live", workflow)

    def test_08_missing_adapter_source_fails_closed(self):
        with mock.patch.dict(os.environ, {"ADAPTER_SOURCE_ROOT": ""}, clear=False):
            with self.assertRaisesRegex(RuntimeError, "M1C_ADAPTER_SOURCE_ROOT_INVALID"):
                controller.harbor_environment(ROOT)

    def test_09_wrong_adapter_source_fails_closed(self):
        with tempfile.TemporaryDirectory() as td, mock.patch.dict(os.environ, {"ADAPTER_SOURCE_ROOT": td}, clear=False):
            with self.assertRaisesRegex(RuntimeError, "M1C_ADAPTER_SOURCE_ROOT_INVALID"):
                controller.harbor_environment(ROOT)

    def test_10_incorrect_module_name_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            proc = self.import_process(Path(td), module="evaluation.missing:Missing")
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("Failed to import module", proc.stderr)

    def test_11_actual_agentfactory_initialization_path_passes(self):
        with tempfile.TemporaryDirectory() as td:
            proc = self.import_process(Path(td))
            self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_12_adapter_source_hash_unchanged(self):
        self.assertEqual(hashlib.sha256(ADAPTER.read_bytes()).hexdigest(), "3086ed0919d182719195c8ee415bb89da2a035c2f2a923861efd09eb1c2e9d7c")

    def test_13_marker_without_provider_request_is_unexposed(self):
        self.assertEqual(controller.exposure_classification(True, 0), controller.UNEXPOSED)
        self.assertEqual(controller.exposure_classification(True, None), controller.UNEXPOSED)

    def test_14_provider_request_after_marker_is_exposed(self):
        self.assertEqual(controller.exposure_classification(True, 1), controller.EXPOSED)
        self.assertEqual(controller.exposure_classification(True, 7), controller.EXPOSED)


if __name__ == "__main__":
    unittest.main()

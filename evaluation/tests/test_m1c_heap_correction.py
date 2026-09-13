import inspect
import os
import subprocess
import unittest
from pathlib import Path

from evaluation.agents.dsh_harbor_adapter.adapter import DshHarborAdapter
from evaluation.agents.dsh_harbor_adapter.build_forensics_probe import DshHarborBuildForensicsProbe


ROOT = Path(__file__).parents[2]
ADAPTER = ROOT / "evaluation/agents/dsh_harbor_adapter/adapter.py"
PROBE = ROOT / "evaluation/agents/dsh_harbor_adapter/build_forensics_probe.py"


class M1cHeapCorrectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.adapter = ADAPTER.read_text()
        cls.probe = PROBE.read_text()

    def test_01_exact_heap_value(self):
        self.assertEqual(DshHarborAdapter.BUILD_NODE_OPTIONS, "--max-old-space-size=1280")

    def test_02_assignment_is_command_scoped(self):
        self.assertTrue(DshHarborAdapter.BUILD_COMMAND.endswith(
            "NODE_OPTIONS=--max-old-space-size=1280 pnpm run build"))
        self.assertNotIn("export NODE_OPTIONS", self.adapter)

    def test_03_unexpected_node_options_fails_closed(self):
        self.assertIn('test "${NODE_OPTIONS+x}" = x', DshHarborAdapter.BUILD_COMMAND)
        self.assertIn("M1C_DSH_BUILD_NODE_OPTIONS_DRIFT", DshHarborAdapter.BUILD_COMMAND)
        self.assertIn("exit 78", DshHarborAdapter.BUILD_COMMAND)

    def test_03b_drift_guard_executes_before_build(self):
        environment = os.environ.copy()
        environment["NODE_OPTIONS"] = "--trace-warnings"
        result = subprocess.run(
            ["bash", "-c", DshHarborAdapter.BUILD_COMMAND],
            env=environment, text=True, capture_output=True,
        )
        self.assertEqual(result.returncode, 78)
        self.assertIn("M1C_DSH_BUILD_NODE_OPTIONS_DRIFT", result.stderr)

    def test_04_run_has_no_node_options(self):
        run_source = inspect.getsource(DshHarborAdapter.run)
        self.assertNotIn("NODE_OPTIONS", run_source)

    def test_05_pinned_dsh_unchanged(self):
        self.assertEqual(DshHarborAdapter.DSH_COMMIT,
                         "b150a551b8d465e31e418e1b2eaf5e79bbb7d28e")

    def test_06_install_order_unchanged(self):
        install = inspect.getsource(DshHarborAdapter.install)
        ordered = ["git clone", "checkout --detach", "corepack enable",
                   "pnpm install --frozen-lockfile", "self.BUILD_COMMAND"]
        positions = [install.index(token) for token in ordered]
        self.assertEqual(positions, sorted(positions))

    def test_07_versions_and_memory_not_modified(self):
        self.assertIn("setup_24.x", self.adapter)
        self.assertNotIn("memory.max", self.adapter)
        self.assertEqual(self.adapter.count("--max-old-space-size=1280"), 1)

    def test_08_forensics_uses_authoritative_build_command(self):
        self.assertIn("suffix = self.BUILD_COMMAND", self.probe)
        self.assertNotIn('suffix = "pnpm run build"', self.probe)

    def test_09_forensics_reports_effective_heap_limit(self):
        self.assertIn("effective_heap_size_limit_bytes", self.probe)
        self.assertIn("DshHarborAdapter.BUILD_NODE_OPTIONS", self.probe)

    def test_10_production_install_is_inherited(self):
        self.assertIs(DshHarborBuildForensicsProbe.install, DshHarborAdapter.install)

    def test_11_no_model_or_provider_surface(self):
        self.assertNotIn("DEEPSEEK_" + "API_KEY", self.probe)
        self.assertNotIn("def run(", self.probe)

    def test_12_no_dsh_build_config_changes(self):
        changed = {"evaluation/agents/dsh_harbor_adapter/adapter.py",
                   "evaluation/agents/dsh_harbor_adapter/build_forensics_probe.py",
                   "evaluation/tests/test_m1c_heap_correction.py"}
        self.assertFalse(any(name.endswith(("package.json", "pnpm-lock.yaml", "tsconfig.json")) for name in changed))


if __name__ == "__main__":
    unittest.main()

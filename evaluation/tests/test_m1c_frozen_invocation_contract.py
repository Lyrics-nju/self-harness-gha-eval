import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).parents[2]
SCRIPT = ROOT / "scripts" / "run_frozen_evaluator_regressions.py"
SPEC = importlib.util.spec_from_file_location("run_frozen_evaluator_regressions", SCRIPT)
runner = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = runner
SPEC.loader.exec_module(runner)


class FrozenInvocationContractTests(unittest.TestCase):
    def test_01_script_command_is_direct(self):
        command = runner.direct_script_command("python3", Path("frozen.py"))
        self.assertEqual(command, ["python3", "frozen.py"])
        self.assertNotIn("unittest", command)

    def test_02_zero_test_discovery_rejected(self):
        with self.assertRaises(runner.FrozenRegressionError):
            runner.validate_result(returncode=5, output="Ran 0 tests\nNO TESTS RAN\n", marker="X=1/1 PASS")

    def test_03_count_mismatch_rejected(self):
        with self.assertRaises(runner.FrozenRegressionError):
            runner.validate_result(returncode=0, output="X=6/7 PASS\n", marker="X=7/7 PASS")

    def test_04_nonzero_with_marker_rejected(self):
        with self.assertRaises(runner.FrozenRegressionError):
            runner.validate_result(returncode=9, output="X=7/7 PASS\n", marker="X=7/7 PASS")

    def test_05_direct_script_and_marker_pass(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            script = root / "check.py"
            script.write_text("print('X=7/7 PASS')\n")
            spec = runner.RegressionSpec("fixture", "check.py", "X=7/7 PASS", "fixture.txt")
            output = runner.run_one(spec, python=sys.executable, cwd=root, output_dir=root / "reports")
            self.assertIn("X=7/7 PASS", output)
            self.assertTrue((root / "reports" / "fixture.txt").is_file())

    def test_06_workflow_uses_controller_not_unittest(self):
        workflow = (ROOT / ".github" / "workflows" / "gha-m1c1-no-model.yml").read_text()
        self.assertIn("scripts/run_frozen_evaluator_regressions.py", workflow)
        self.assertNotIn("-m unittest evaluation.tests.test_docker_endpoint_policy", workflow)

    def test_07_always_run_artifacts_preserved(self):
        workflow = (ROOT / ".github" / "workflows" / "gha-m1c1-no-model.yml").read_text()
        self.assertIn("id: diagnostics\n        if: always()", workflow)
        self.assertIn("if: always() && steps.diagnostics.outputs.safe == 'true'", workflow)


if __name__ == "__main__":
    unittest.main()


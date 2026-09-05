from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).parents[2]
CONTROLLER = ROOT / "scripts/gha_m1c1_live_controller.py"
PROFILE = ROOT / "configs/model_profile_deepseek_v4_pro_v1.yaml"
DSH_COMMIT = "b150a551b8d465e31e418e1b2eaf5e79bbb7d28e"


class InvocationEdgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.harbor_python = os.environ.get("HARBOR_PY", "")
        if not cls.harbor_python or not Path(cls.harbor_python).is_file():
            raise unittest.SkipTest("HARBOR_PY must name the runtime-resolved Harbor interpreter")

    def fixture(self, root: Path) -> tuple[Path, dict[str, str]]:
        (root / "configs").mkdir()
        (root / "reports").mkdir()
        candidate = root / "work/candidate/adapter_smoke_h0"
        candidate.mkdir(parents=True)
        shutil.copy2(PROFILE, root / "configs/model_profile_deepseek_v4_pro_v1.yaml")
        (candidate / "manifest.json").write_text('{"candidate_id":"adapter_smoke_h0"}\n')
        (candidate / "candidate.cordis.patch.yml").write_text("plugins: []\n")
        dsh = root / "dsh-source"; dsh.mkdir()
        fake_bin = root / "fake-bin"; fake_bin.mkdir()
        harbor = fake_bin / "harbor"
        harbor.write_text("#!/bin/sh\nprintf '0.21.0\\n'\n")
        git = fake_bin / "git"
        git.write_text(f'''#!/bin/sh
case "$*" in
  *"rev-parse HEAD"*) printf '{DSH_COMMIT}\\n' ;;
  *"status --porcelain"*) : ;;
  *) exit 3 ;;
esac
''')
        harbor.chmod(0o755); git.chmod(0o755)
        env = os.environ.copy()
        env.update({
            "PATH": f"{fake_bin}:{env['PATH']}",
            "PYTHONPATH": str(ROOT),
            "ImageOS": "ubuntu24",
            "M1C_SECRET_AVAILABLE": "true",
            "DSH_SOURCE": str(dsh),
            "PYTHONDONTWRITEBYTECODE": "1",
        })
        return root, env

    def test_01_resolved_harbor_python_starts_preflight_successfully(self):
        with tempfile.TemporaryDirectory() as td:
            root, env = self.fixture(Path(td))
            proc = subprocess.run([self.harbor_python, str(CONTROLLER), "preflight", "--root", str(root)], cwd=ROOT, env=env, text=True, capture_output=True)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertTrue((root / "reports/PRE_MODEL_GATE_COMPLETED").is_file())

    def test_02_historical_duplicate_interpreter_form_is_rejected(self):
        proc = subprocess.run([self.harbor_python, "python3", str(CONTROLLER), "preflight"], cwd=ROOT, text=True, capture_output=True)
        self.assertEqual(proc.returncode, 2)
        self.assertIn("python3", proc.stderr)

    def test_03_exact_controller_argv_is_accepted(self):
        proc = subprocess.run([self.harbor_python, str(CONTROLLER), "--help"], cwd=ROOT, text=True, capture_output=True)
        self.assertEqual(proc.returncode, 0)
        for action in ("preflight", "run-live", "summarize", "stage"):
            self.assertIn(action, proc.stdout)

    def test_04_missing_controller_file_fails_closed(self):
        missing = ROOT / "scripts/does-not-exist-controller.py"
        proc = subprocess.run([self.harbor_python, str(missing), "preflight"], cwd=ROOT, text=True, capture_output=True)
        self.assertEqual(proc.returncode, 2)
        self.assertIn("can't open file", proc.stderr)

    def test_05_wrong_import_path_fails_preflight(self):
        with tempfile.TemporaryDirectory() as td:
            root, env = self.fixture(Path(td))
            env["PYTHONPATH"] = ""
            proc = subprocess.run([self.harbor_python, str(CONTROLLER), "preflight", "--root", str(root)], cwd=root, env=env, text=True, capture_output=True)
            self.assertEqual(proc.returncode, 1)
            report = json.loads((root / "reports/pre-model-gate.json").read_text())
            self.assertFalse(report["checks"]["adapter_or_materialization"])

    def test_06_system_python_lacks_harbor_context(self):
        proc = subprocess.run([sys.executable, "-I", "-c", "import harbor"], text=True, capture_output=True)
        self.assertNotEqual(proc.returncode, 0)

    def test_07_resolved_harbor_python_context_is_valid(self):
        proc = subprocess.run([self.harbor_python, "-c", "import importlib.metadata,harbor; assert importlib.metadata.version('harbor')=='0.21.0'"], text=True, capture_output=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_08_frozen_evaluator_remains_system_python(self):
        workflow = (ROOT / ".github/workflows/gha-m1c1-live.yml").read_text()
        self.assertIn("python3 scripts/run_frozen_evaluator_regressions.py", workflow)
        self.assertNotIn('"$HARBOR_PY" scripts/run_frozen_evaluator_regressions.py', workflow)


if __name__ == "__main__":
    unittest.main()

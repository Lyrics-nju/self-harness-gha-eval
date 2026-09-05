from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).parents[2]
HELPER = ROOT / "scripts/m1c_adapter_pth.py"
PROBE = ROOT / ".github/workflows/gha-m1c1-agent-import-probe.yml"
LIVE = ROOT / ".github/workflows/gha-m1c1-live.yml"
ADAPTER = ROOT / "evaluation/agents/dsh_harbor_adapter/adapter.py"
SPEC = importlib.util.spec_from_file_location("m1c_adapter_pth", HELPER)
wiring = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(wiring)


class AdapterPthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.harbor_python = Path(os.environ.get("HARBOR_PY", ""))
        if not cls.harbor_python.is_file():
            raise unittest.SkipTest("HARBOR_PY required")

    @classmethod
    def tearDownClass(cls):
        candidate = wiring.harbor_site_packages(cls.harbor_python) / wiring.PTH_NAME
        candidate.unlink(missing_ok=True)

    def test_01_destination_is_runtime_resolved(self):
        site = wiring.harbor_site_packages(self.harbor_python)
        self.assertIn(self.harbor_python.parent.parent, site.parents)

    def test_02_pth_exactly_one_non_executable_line(self):
        pth = wiring.install_pth(self.harbor_python, ROOT.resolve())
        self.assertEqual(pth.read_text().splitlines(), [str(ROOT.resolve())])
        self.assertNotIn("import ", pth.read_text())

    def test_03_arbitrary_cwd_fresh_process(self):
        wiring.install_pth(self.harbor_python, ROOT.resolve())
        with tempfile.TemporaryDirectory() as td:
            result = wiring.probe(self.harbor_python, ROOT.resolve(), Path(td))
        self.assertEqual(set(result.values()), {"PASS"})

    def test_04_trial_like_cwd_fresh_process(self):
        wiring.install_pth(self.harbor_python, ROOT.resolve())
        with tempfile.TemporaryDirectory() as td:
            nested = Path(td) / "jobs/job/trial/agent"; nested.mkdir(parents=True)
            result = wiring.probe(self.harbor_python, ROOT.resolve(), nested)
        self.assertEqual(result["agentfactory_resolution"], "PASS")

    def test_05_missing_root_fails_closed(self):
        with self.assertRaises(wiring.WiringError): wiring.validate_source_root("", ROOT)

    def test_06_wrong_root_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(wiring.WiringError): wiring.validate_source_root(td, ROOT)

    def test_07_relative_root_rejected(self):
        with self.assertRaises(wiring.WiringError): wiring.validate_source_root(".", ROOT)

    def test_08_private_research_path_rejected(self):
        with mock.patch.object(Path, "resolve", return_value=Path("/home/u/research/self-harness-dsh")):
            with self.assertRaises(wiring.WiringError): wiring.validate_source_root("/home/u/research/self-harness-dsh", ROOT)

    def test_09_windows_path_rejected(self):
        with self.assertRaises(wiring.WiringError): wiring.validate_source_root("C:\\repo", ROOT)

    def test_10_adapter_hash_unchanged(self):
        self.assertEqual(hashlib.sha256(ADAPTER.read_bytes()).hexdigest(), "3086ed0919d182719195c8ee415bb89da2a035c2f2a923861efd09eb1c2e9d7c")

    def test_11_probe_dispatch_only_and_no_matrix(self):
        text = PROBE.read_text(); trigger = text.split("permissions:", 1)[0]
        self.assertIn("workflow_dispatch:", trigger)
        for token in ("push:", "pull_request:", "schedule:", "matrix:"): self.assertNotIn(token, text)

    def test_12_probe_has_no_model_secret_or_provider(self):
        text = PROBE.read_text()
        for token in ("DEEPSEEK_" + "API_KEY", "secrets.", "run-live", "harbor run", "DSH_SOURCE"):
            self.assertNotIn(token, text)

    def test_13_probe_uses_no_transient_pythonpath(self):
        text = PROBE.read_text()
        self.assertIn("env -u PYTHONPATH", text)
        self.assertNotIn("PYTHONPATH=.", text)

    def test_14_live_and_probe_equivalent_wiring(self):
        for text in (PROBE.read_text(), LIVE.read_text()):
            self.assertIn("scripts/m1c_adapter_pth.py", text)
            self.assertIn("--source-root \"$ADAPTER_SOURCE_ROOT\"", text)


if __name__ == "__main__": unittest.main()

import hashlib
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

from evaluation.agents.dsh_harbor_adapter.adapter import DshHarborAdapter
from evaluation.agents.dsh_harbor_adapter.tsc_1536_probe import DIAGNOSTIC_NODE_OPTIONS, tsc_1536_wrapper

ROOT = Path(__file__).parents[2]
ADAPTER = ROOT / "evaluation/agents/dsh_harbor_adapter/adapter.py"
WORKFLOW = ROOT / ".github/workflows/gha-m1c1-tsc-1536-feasibility-probe.yml"
EXPECTED_ADAPTER_SHA = "8ef6389565309ba208557923cced1e619a8a1b25549353f9b5f13e2313ad6070"


class Tsc1536ProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.wrapper = tsc_1536_wrapper("/tmp/tsc-1536")
        cls.workflow = WORKFLOW.read_text()

    def test_01_heap_exact(self): self.assertEqual(DIAGNOSTIC_NODE_OPTIONS, "--max-old-space-size=1536")
    def test_02_production_heap(self): self.assertEqual(DshHarborAdapter.BUILD_NODE_OPTIONS, "--max-old-space-size=1280")
    def test_03_adapter_sha(self): self.assertEqual(hashlib.sha256(ADAPTER.read_bytes()).hexdigest(), EXPECTED_ADAPTER_SHA)
    def test_04_exact_tsc(self): self.assertIn("pnpm exec tsc -b tsconfig.host.json", self.wrapper)
    def test_05_no_tsdown(self): self.assertNotIn("tsdown", self.wrapper)
    def test_06_no_extra_flags(self): self.assertNotIn("--extendedDiagnostics", self.wrapper)
    def test_07_effective_options(self): self.assertIn("effective-v8-heap-limit.txt", self.wrapper)
    def test_08_drift_fails_closed(self): self.assertIn("M1C_DSH_BUILD_NODE_OPTIONS_DRIFT", self.wrapper)
    def test_09_sampler_before_tsc(self): self.assertLess(self.wrapper.index("sampler_pid=$!"), self.wrapper.index("/usr/bin/time -v"))
    def test_10_sampler_stops(self): self.assertLess(self.wrapper.index("tsc_status=$?"), self.wrapper.index('touch "$stop_file"'))
    def test_11_sampler_nonmasking(self): self.assertIn('wait "$sampler_pid" 2>/dev/null || true', self.wrapper)
    def test_12_logs_on_nonzero(self):
        for name in ("tsc-1536.stdout", "tsc-1536.stderr", "tsc-1536-exit.txt", "tsc-1536-resource-before.txt", "tsc-1536-resource-after.txt", "substage-summary.txt"): self.assertIn(name, self.wrapper)
    def test_13_timeseries_checksum(self):
        self.assertIn("tsc-1536-memory-timeseries.tsv", self.wrapper); self.assertIn("SHA256SUMS", self.workflow)
    def test_14_oom_deltas(self): self.assertIn('test "$oom_delta" -gt 0 || test "$oom_kill_delta" -gt 0', self.wrapper)
    def test_15_max_not_oom(self):
        condition=self.wrapper.split("TSC_HOST_1536_CGROUP_OOM",1)[0].rsplit("if ",1)[-1]; self.assertNotIn("max_delta", condition)
    def test_16_time_optional(self): self.assertIn("if test -x /usr/bin/time", self.wrapper)
    def test_17_no_model(self):
        for token in ("DEEPSEEK_"+"API_KEY", "MODEL_EXPOSURE_START", "gha-m1c1-live.yml"): self.assertNotIn(token, self.workflow)
    def test_18_third_task(self): self.assertIn("terminal-bench/configure-git-webserver", (ROOT/"configs/m1c_integration_task_v2.json").read_text())
    def test_19_no_fourth_task(self):
        self.assertEqual(yaml.safe_load(self.workflow)[True], {"workflow_dispatch": None}); self.assertNotIn("matrix:", self.workflow)

    def test_20_nonzero_runtime_preserves_logs_and_sampler(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pnpm = root / "pnpm"
            pnpm.write_text("#!/bin/sh\nprintf 'synthetic stdout\\n'\nprintf 'synthetic stderr\\n' >&2\nexit 37\n")
            pnpm.chmod(0o755)
            artifacts = root / "artifacts"
            environment = os.environ.copy()
            environment.pop("NODE_OPTIONS", None)
            environment["PATH"] = str(root) + os.pathsep + environment["PATH"]
            result = subprocess.run(["bash", "-c", tsc_1536_wrapper(str(artifacts))], env=environment, cwd=root)
            self.assertEqual(result.returncode, 37)
            self.assertEqual((artifacts / "tsc-1536-exit.txt").read_text().strip(), "37")
            self.assertIn("synthetic stdout", (artifacts / "tsc-1536.stdout").read_text())
            self.assertIn("synthetic stderr", (artifacts / "tsc-1536.stderr").read_text())
            self.assertGreaterEqual(len((artifacts / "tsc-1536-memory-timeseries.tsv").read_text().splitlines()), 2)
            self.assertIn("classification=TSC_HOST_1536_RESULT_INDETERMINATE", (artifacts / "substage-summary.txt").read_text())


if __name__ == "__main__": unittest.main()

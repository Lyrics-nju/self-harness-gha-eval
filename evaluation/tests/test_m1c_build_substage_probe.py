import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

from evaluation.agents.dsh_harbor_adapter.adapter import DshHarborAdapter
from evaluation.agents.dsh_harbor_adapter.build_forensics_probe import substage_wrapper

ROOT = Path(__file__).parents[2]
WORKFLOW = ROOT / ".github/workflows/gha-m1c1-build-substage-probe.yml"


class BuildSubstageProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (ROOT / "evaluation/agents/dsh_harbor_adapter/build_forensics_probe.py").read_text()
        cls.workflow = WORKFLOW.read_text()

    def test_01_exact_local_binary_commands(self):
        wrapper = substage_wrapper("/tmp/substage-test")
        self.assertIn("pnpm exec tsc -b tsconfig.host.json", wrapper)
        self.assertIn("pnpm exec tsdown --env.DSH_BUILD_FACE host", wrapper)

    def test_02_tsc_precedes_tsdown(self):
        wrapper = substage_wrapper("/tmp/substage-test")
        self.assertLess(wrapper.index("NODE_OPTIONS=" + DshHarborAdapter.BUILD_NODE_OPTIONS + " pnpm exec tsc"),
                        wrapper.index("NODE_OPTIONS=" + DshHarborAdapter.BUILD_NODE_OPTIONS + " pnpm exec tsdown"))

    def test_03_tsdown_not_reached_on_tsc_failure(self):
        wrapper = substage_wrapper("/tmp/substage-test")
        self.assertIn("tsdown_status=NOT_REACHED", wrapper)
        self.assertIn("exit \"$tsc_status\"", wrapper)

    def test_04_identical_heap_policy(self):
        wrapper = substage_wrapper("/tmp/substage-test")
        self.assertEqual(wrapper.count("NODE_OPTIONS=--max-old-space-size=1280 pnpm exec"), 2)

    def test_05_full_logs_and_status_paths(self):
        wrapper = substage_wrapper("/tmp/substage-test")
        for name in ("tsc-host.stdout", "tsc-host.stderr", "tsdown-host.stdout",
                     "tsdown-host.stderr", "substage-summary.txt"):
            self.assertIn(name, wrapper)

    def test_06_per_stage_snapshots(self):
        wrapper = substage_wrapper("/tmp/substage-test")
        for label in ("TSC_BEFORE", "TSC_AFTER", "TSDOWN_BEFORE", "TSDOWN_AFTER"):
            self.assertIn("snapshot " + label, wrapper)

    def test_07_optional_resource_absence_nonfatal(self):
        wrapper = substage_wrapper("/tmp/substage-test")
        self.assertIn("NOT_AVAILABLE", wrapper)
        self.assertIn("|| true", wrapper)

    def test_08_nonzero_tsc_preserves_log_and_skips_tsdown(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "pnpm"
            binary.write_text("#!/bin/sh\nprintf '%035000d' 0\nprintf '%s\\n' 'Allocation failed - JavaScript heap out of memory' >&2\nexit 37\n")
            binary.chmod(0o755)
            artifacts = root / "artifacts"
            environment = os.environ.copy()
            environment.pop("NODE_OPTIONS", None)
            environment["PATH"] = str(root) + os.pathsep + environment["PATH"]
            result = subprocess.run(["bash", "-c", substage_wrapper(str(artifacts))],
                                    env=environment, cwd=root)
            self.assertEqual(result.returncode, 37)
            self.assertEqual(len((artifacts / "tsc-host.stdout").read_text()), 35000)
            self.assertIn("Allocation failed", (artifacts / "tsc-host.stderr").read_text())
            self.assertEqual((artifacts / "tsdown-host.status.txt").read_text().strip(), "NOT_REACHED")
            summary = (artifacts / "substage-summary.txt").read_text()
            self.assertIn("classification=V8_HEAP_EXHAUSTION_IN_TSC_HOST", summary)
            self.assertIn("tsc_status=37", summary)

    def test_09_production_adapter_unchanged_by_probe(self):
        self.assertNotIn("def run(", self.source)
        self.assertIn("suffix = self.BUILD_COMMAND", self.source)

    def test_10_no_model_secret_or_live_workflow(self):
        for token in ("DEEPSEEK_" + "API_KEY", "secrets.", "MODEL_EXPOSURE_START", "gha-m1c1-live.yml"):
            self.assertNotIn(token, self.workflow)

    def test_11_dispatch_only_and_single_task(self):
        data = yaml.safe_load(self.workflow)
        self.assertEqual(data[True], {"workflow_dispatch": None})
        self.assertNotIn("matrix:", self.workflow)

    def test_12_diagnostic_not_production_qualification(self):
        self.assertIn("gha_m1c1_container_build_probe.py substage", self.workflow)
        self.assertIn("diagnostic_complete", self.workflow)


if __name__ == "__main__": unittest.main()

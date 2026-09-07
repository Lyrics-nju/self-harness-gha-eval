from __future__ import annotations

import importlib.util
import json
import tempfile
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).parents[2]
def load(name, path):
    spec=importlib.util.spec_from_file_location(name,path); mod=importlib.util.module_from_spec(spec)
    assert spec and spec.loader; sys.modules[name]=mod; spec.loader.exec_module(mod); return mod
obs=load("evidence_obs", ROOT/"scripts/m1c_postlive_observability.py")
scanner=load("evidence_scan", ROOT/"scripts/public_secret_scan.py")


class EvidenceSafetyTests(unittest.TestCase):
    def setUp(self):
        self.t=tempfile.TemporaryDirectory(); self.root=Path(self.t.name)
        (self.root/"reports/raw-evidence").mkdir(parents=True)
        (self.root/"reports/PRE_MODEL_GATE_COMPLETED").write_text("PASS\n")
    def tearDown(self): self.t.cleanup()
    def safe(self): return obs.build_safe_core(self.root,"m1c1-live-single","terminal-bench/synthetic")
    def test_01_both_lanes_uploadable(self):
        self.safe(); (self.root/"bulk").mkdir(); (self.root/"bulk/a.json").write_text('{"DEEPSEEK_API_KEY":"REDACTED"}')
        self.assertFalse(scanner.scan_tree(self.root/"safe-core-stage",True)); self.assertFalse(scanner.scan_tree(self.root/"bulk",True))
    def test_02_bulk_fail_safe_core_survives(self):
        self.safe(); (self.root/"bulk").mkdir(); (self.root/"bulk/a.json").write_text('{"DEEPSEEK_API_KEY":"synthetic-unsafe-fixture"}')
        self.assertTrue(scanner.scan_tree(self.root/"bulk",True)); self.assertFalse(scanner.scan_tree(self.root/"safe-core-stage",True))
    def test_03_normalizer_missing_safe_core(self): self.assertEqual(self.safe()["normalizer_status"],"NOT_AVAILABLE")
    def test_04_trial_missing_safe_core(self): self.assertEqual(self.safe()["trial_result_status"],"ABSENT")
    def test_05_event_missing_safe_core(self): self.assertEqual(self.safe()["dsh_event_log_status"],"NOT_AVAILABLE")
    def test_06_provider_indeterminate(self):
        (self.root/"reports/MODEL_EXPOSURE_START").write_text("START\n")
        self.assertEqual(self.safe()["provider_request_status"],"INDETERMINATE")
    def test_07_safe_core_scan_fail_blocks(self):
        self.safe(); (self.root/"safe-core-stage/unsafe.txt").write_text("Authoriz" + "ation: Bearer synthetic-token")
        self.assertTrue(scanner.scan_tree(self.root/"safe-core-stage",True))
    def test_08_explicit_zero(self):
        (self.root/"reports/raw-evidence/event.jsonl").write_text(json.dumps({"provider_request_count":0})+"\n")
        self.assertEqual(self.safe()["provider_request_status"],"PROVEN_ZERO")
    def test_09_explicit_nonzero(self):
        (self.root/"reports/MODEL_EXPOSURE_START").write_text("START\n")
        (self.root/"reports/raw-evidence/event.jsonl").write_text(json.dumps({"type":"provider_request_started"})+"\n")
        self.assertEqual(self.safe()["provider_request_status"],"PROVEN_NONZERO")


if __name__ == "__main__": unittest.main()

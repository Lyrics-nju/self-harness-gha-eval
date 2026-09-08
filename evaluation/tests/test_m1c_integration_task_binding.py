from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).parents[2]
V2 = ROOT / "configs/m1c_integration_task_v2.json"
V3 = ROOT / "configs/m1c_integration_task_v3.json"
EXCLUSIONS = ROOT / "configs/experiment_task_exclusions_v1.json"
CONTROLLER = ROOT / "scripts/gha_m1c1_live_controller.py"
RESOLVER = ROOT / "scripts/gha_tb21_resolve_m1c1.py"
LIVE = ROOT / ".github/workflows/gha-m1c1-live.yml"
PREFLIGHT = ROOT / ".github/workflows/gha-m1c1-live-preflight-probe.yml"


class IntegrationTaskBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v2 = json.loads(V2.read_text())
        cls.v3 = json.loads(V3.read_text())
        cls.exclusions = json.loads(EXCLUSIONS.read_text())
        spec = importlib.util.spec_from_file_location("m1c_binding_controller", CONTROLLER)
        cls.controller = importlib.util.module_from_spec(spec); assert spec and spec.loader
        spec.loader.exec_module(cls.controller)

    def test_01_v2_historical_record_preserved(self):
        self.assertEqual(hashlib.sha256(V2.read_bytes()).hexdigest(), "1e87728903d983cdf33e910113345cdd85fba91e5af3e9adb813752b50f5474c")
        self.assertEqual(self.v2["selected_task_id"], "terminal-bench/chess-best-move")

    def test_02_counts_and_quarantines(self):
        self.assertEqual(len(self.exclusions["exclusions"]), 2)
        self.assertEqual(self.v3["eligible_count"], 22)
        self.assertEqual(len(self.v3["eligible_task_ids"]), 22)
        excluded = {entry["task_id"] for entry in self.exclusions["exclusions"]}
        self.assertTrue(excluded.isdisjoint(self.v3["eligible_task_ids"]))

    def test_03_selection_is_bytewise_lexicographic_first(self):
        ordered = self.v3["eligible_task_ids"]
        self.assertEqual(ordered, sorted(ordered, key=lambda value: value.encode("utf-8")))
        self.assertEqual(self.v3["selected_task_id"], ordered[0])
        self.assertEqual(self.v3["selection_rule"].split(":", 1)[0], "M1C_INTEGRATION_TASK_LEXICOGRAPHIC_FIRST_V1")

    def test_04_order_hash_reproducible(self):
        payload = ("\n".join(self.v3["eligible_task_ids"]) + "\n").encode()
        self.assertEqual(hashlib.sha256(payload).hexdigest(), self.v3["eligible_order_sha256"])
        self.assertEqual(self.v3["eligible_order_sha256"], "918319a8317b4608c6cdaeb334070e3b950c97ac3f72fea164d2f5dcb1ffccbe")

    def test_05_selected_is_member_and_not_excluded(self):
        selected = self.v3["selected_task_id"]
        excluded = {entry["task_id"] for entry in self.exclusions["exclusions"]}
        self.assertIn(selected, self.v3["eligible_task_ids"])
        self.assertNotIn(selected, excluded)

    def test_06_live_preflight_v3_identity(self):
        selected = self.v3["selected_task_id"]
        self.assertEqual(self.controller.TASK_ID, selected)
        resolver = RESOLVER.read_text()
        self.assertIn("configs/m1c_integration_task_v3.json", resolver)
        self.assertIn('["selected_task_id"]', resolver)
        for workflow in (LIVE, PREFLIGHT):
            self.assertIn("scripts/gha_tb21_resolve_m1c1.py", workflow.read_text())
            self.assertIn("scripts/gha_m1c1_live_controller.py preflight", workflow.read_text())

    def test_07_exactly_one_authoritative_binding_no_input(self):
        self.assertEqual(CONTROLLER.read_text().count("configs/m1c_integration_task_v3.json"), 2)
        self.assertEqual(RESOLVER.read_text().count("configs/m1c_integration_task_v3.json"), 1)
        self.assertNotIn("terminal-bench/configure-git-webserver", CONTROLLER.read_text())
        self.assertNotIn("terminal-bench/configure-git-webserver", RESOLVER.read_text())
        self.assertNotIn("inputs:", LIVE.read_text())
        self.assertNotIn("inputs:", PREFLIGHT.read_text())

    def test_08_v3_identity_and_stage(self):
        self.assertEqual(self.v3["source_stable_pool_sha"], "d3cf005c96355a618843982e47d3c130616766795d2b4f8a54bd9c1ace917fef")
        self.assertEqual(self.v3["exclusion_config_sha"], "4791ea562b79392618c0da2dfd01ae7054267505124753d913c07e4a604e6e6b")
        self.assertEqual(self.v3["classification"], "M1C_INTEGRATION_ONLY_PENDING_EXPOSURE")
        self.assertEqual(self.v3["selected_at_stage"], "M1C_PRE_FORMAL_SPLIT")
        self.assertEqual(self.v3["previous_selection_record"], "configs/m1c_integration_task_v2.json")

    def test_09_both_quarantines_are_permanent(self):
        by_id = {entry["task_id"]: entry for entry in self.exclusions["exclusions"]}
        for task in ("terminal-bench/caffe-cifar-10", "terminal-bench/chess-best-move"):
            self.assertEqual(by_id[task]["classification"], "EXPOSURE_INDETERMINATE_AFTER_LIVE_ARTIFACT_LOSS")
            self.assertFalse(by_id[task]["eligible_for_D_mine"])
            self.assertFalse(by_id[task]["eligible_for_D_gate"])
            self.assertFalse(by_id[task]["eligible_for_D_sealed"])


if __name__ == "__main__": unittest.main()

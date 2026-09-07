from __future__ import annotations

import hashlib
import importlib.util
import json
import ast
from pathlib import Path
import unittest

ROOT = Path(__file__).parents[2]
RECORD = ROOT / "configs/m1c_integration_task_v2.json"
EXCLUSIONS = ROOT / "configs/experiment_task_exclusions_v1.json"
CONTROLLER = ROOT / "scripts/gha_m1c1_live_controller.py"
RESOLVER = ROOT / "scripts/gha_tb21_resolve_m1c1.py"
LIVE = ROOT / ".github/workflows/gha-m1c1-live.yml"
PREFLIGHT = ROOT / ".github/workflows/gha-m1c1-live-preflight-probe.yml"


class IntegrationTaskBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.record = json.loads(RECORD.read_text())
        cls.exclusions = json.loads(EXCLUSIONS.read_text())
        spec = importlib.util.spec_from_file_location("m1c_binding_controller", CONTROLLER)
        cls.controller = importlib.util.module_from_spec(spec); spec.loader.exec_module(cls.controller)
        tree = ast.parse(RESOLVER.read_text())
        cls.resolver_task = next(
            node.value.value for node in tree.body
            if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "TASK" for t in node.targets)
        )

    def test_01_historical_selection_record_is_unchanged(self):
        self.assertEqual(self.record["eligible_count"], 23)
        self.assertEqual(len(self.record["eligible_task_ids"]), 23)

    def test_02_old_quarantine_absent_from_eligible(self):
        self.assertNotIn("terminal-bench/caffe-cifar-10", self.record["eligible_task_ids"])
        self.assertEqual(self.exclusions["exclusions"][0]["classification"],
                         "EXPOSURE_INDETERMINATE_AFTER_LIVE_ARTIFACT_LOSS")

    def test_03_selection_is_lexicographic_first(self):
        ordered = self.record["eligible_task_ids"]
        self.assertEqual(ordered, sorted(ordered, key=lambda value: value.encode("utf-8")))
        self.assertEqual(self.record["selected_task_id"], ordered[0])

    def test_04_order_hash_reproducible(self):
        payload = ("\n".join(self.record["eligible_task_ids"]) + "\n").encode()
        self.assertEqual(hashlib.sha256(payload).hexdigest(), self.record["eligible_order_sha256"])

    def test_05_selected_is_now_quarantined_without_rebinding(self):
        selected = self.record["selected_task_id"]
        excluded = {entry["task_id"] for entry in self.exclusions["exclusions"]}
        self.assertIn(selected, self.record["eligible_task_ids"])
        self.assertIn(selected, excluded)
        self.assertEqual(selected, "terminal-bench/chess-best-move")

    def test_05b_remaining_formal_eligible_count(self):
        excluded = {entry["task_id"] for entry in self.exclusions["exclusions"]}
        remaining = [task for task in self.record["eligible_task_ids"] if task not in excluded]
        self.assertEqual(len(remaining), 22)
        self.assertNotIn("terminal-bench/caffe-cifar-10", remaining)
        self.assertNotIn("terminal-bench/chess-best-move", remaining)

    def test_06_live_preflight_record_identity(self):
        selected = self.record["selected_task_id"]
        self.assertEqual(self.controller.TASK_ID, selected)
        self.assertEqual(self.resolver_task, selected)
        self.assertIn("scripts/gha_tb21_resolve_m1c1.py", LIVE.read_text())
        self.assertIn("scripts/gha_tb21_resolve_m1c1.py", PREFLIGHT.read_text())

    def test_07_exactly_one_fixed_task_no_input(self):
        selected = self.record["selected_task_id"]
        self.assertEqual(CONTROLLER.read_text().count(f'TASK_ID = "{selected}"'), 1)
        self.assertEqual(RESOLVER.read_text().count(f'TASK = "{selected}"'), 1)
        self.assertNotIn("inputs:", LIVE.read_text())
        self.assertNotIn("inputs:", PREFLIGHT.read_text())

    def test_08_record_identity_and_stage(self):
        self.assertEqual(self.record["source_stable_pool_sha"],
                         "d3cf005c96355a618843982e47d3c130616766795d2b4f8a54bd9c1ace917fef")
        self.assertEqual(self.record["exclusion_config_sha"],
                         "7624f87b86ecc227fd79415b9440aaf39d888c3fa6da520413aed179d69dc4e3")
        self.assertEqual(self.record["classification"], "M1C_INTEGRATION_ONLY_PENDING_EXPOSURE")
        self.assertEqual(self.record["selected_at_stage"], "M1C_PRE_FORMAL_SPLIT")

    def test_09_both_quarantines_are_permanent(self):
        by_id = {entry["task_id"]: entry for entry in self.exclusions["exclusions"]}
        for task in ("terminal-bench/caffe-cifar-10", "terminal-bench/chess-best-move"):
            self.assertEqual(by_id[task]["classification"], "EXPOSURE_INDETERMINATE_AFTER_LIVE_ARTIFACT_LOSS")
            self.assertFalse(by_id[task]["eligible_for_D_mine"])
            self.assertFalse(by_id[task]["eligible_for_D_gate"])
            self.assertFalse(by_id[task]["eligible_for_D_sealed"])


if __name__ == "__main__":
    unittest.main()

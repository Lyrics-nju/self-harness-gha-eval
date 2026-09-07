from __future__ import annotations

import importlib.util
import json
import tempfile
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).parents[2]


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


obs = load("m1c_postlive_observability", ROOT / "scripts/m1c_postlive_observability.py")
normalizer = load("normalizer_v2", ROOT / "evaluation/normalize_outcome_v2.py")


class PostLiveObservabilityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "reports").mkdir()
        (self.root / "work/runtime").mkdir(parents=True)
        (self.root / "work/runtime/stdout.txt").write_text("harbor stdout\n")
        (self.root / "work/runtime/stderr.txt").write_text("harbor stderr\n")

    def tearDown(self):
        self.temp.cleanup()

    def trial(self, name="caffe-cifar-10__Dynamic7", *, reward=1.0, malformed=False,
              result=True, ctrf=False, event=True):
        trial = self.root / "work/jobs/m1c1-live-single" / name
        (trial / "verifier").mkdir(parents=True)
        (trial / "agent/dsh-home/sessions").mkdir(parents=True)
        (trial / "config.json").write_text("{}")
        if result:
            if malformed:
                (trial / "result.json").write_text("{bad")
            else:
                value = {"exception_info": None, "agent_info": {"name": "dsh-harbor-adapter-v1"},
                         "verifier_result": {"rewards": {"reward": reward}},
                         "config": {"environment": {"type": "docker"}}}
                (trial / "result.json").write_text(json.dumps(value))
                if reward == 1.0:
                    (trial / "verifier/reward.txt").write_text("1")
                if ctrf:
                    (trial / "verifier/ctrf.json").write_text(
                        json.dumps({"results": {"summary": {"tests": 1, "failed": 1}}}))
        if event:
            (trial / "agent/dsh-home/sessions/events.jsonl").write_text(
                json.dumps({"type": "session_created", "session_id": "fixture-session"}) + "\n")
        return trial

    def capture_and_stage(self):
        manifest = obs.capture_raw(self.root, "m1c1-live-single")
        staged = obs.build_partial_manifest(self.root, self.root / "artifact-stage", {
            "raw": "reports/raw-evidence", "normalizer": "reports/normalizer-v2.json",
            "summary": "reports/live-summary.json"})
        self.assertEqual(manifest["raw_capture"], "PASS")
        self.assertTrue((self.root / "artifact-stage/SHA256SUMS").is_file())
        return staged

    def test_01_complete_pass_raw_normalize_artifacts(self):
        trial = self.trial()
        self.assertEqual(normalizer.classify_trial(trial)["outcome"], "PASS")
        self.capture_and_stage()

    def test_02_task_fail_raw_normalize_artifacts(self):
        trial = self.trial(reward=0.0, ctrf=True)
        self.assertEqual(normalizer.classify_trial(trial)["outcome"], "TASK_FAIL")
        self.capture_and_stage()

    def test_03_result_absent_raw_survives(self):
        self.trial(result=False)
        capture = obs.capture_raw(self.root, "m1c1-live-single")
        self.assertEqual(capture["result_discovery"]["blocker"], "M1C_TRIAL_RESULT_ABSENT")
        staged = self.capture_and_stage()
        self.assertIn("ABSENT", {entry["status"] for entry in staged["entries"]})

    def test_04_malformed_result_is_parse_failed_and_raw_survives(self):
        self.trial(malformed=True)
        capture = obs.capture_raw(self.root, "m1c1-live-single")
        result, status = obs.parse_result(capture["result_discovery"])
        self.assertIsNone(result); self.assertEqual(status, "PARSE_FAILED")
        self.capture_and_stage()

    def test_05_normalizer_throw_does_not_remove_raw(self):
        trial = self.trial()
        obs.capture_raw(self.root, "m1c1-live-single")
        def throwing(*args, **kwargs):
            raise RuntimeError("fixture normalizer crash")
        controller = load("live_controller_fixture", ROOT / "scripts/gha_m1c1_live_controller.py")
        value, status = controller.normalize_trial(self.root, trial, runner=throwing)
        self.assertIsNone(value); self.assertEqual(status, "PARSE_FAILED")
        self.assertTrue((self.root / "reports/raw-evidence/harbor-job/caffe-cifar-10__Dynamic7/result.json").is_file())
        self.capture_and_stage()

    def test_06_dsh_event_absent_is_explicit(self):
        self.trial(event=False)
        capture = obs.capture_raw(self.root, "m1c1-live-single")
        files = capture["sources"]["harbor-job"]
        self.assertFalse(any("events.jsonl" in item["path"] for item in files))
        self.assertEqual(capture["scientific_evidence"]["dsh_event_or_session_evidence"], "ABSENT")
        self.capture_and_stage()

    def test_07_usage_absent_is_not_available(self):
        self.trial()
        obs.capture_raw(self.root, "m1c1-live-single")
        evidence = obs.provider_evidence(self.root / "reports/raw-evidence")
        self.assertEqual(evidence["status"], "NOT_AVAILABLE")

    def test_08_partial_trial_copied_with_manifest(self):
        trial = self.trial(result=False)
        (trial / "agent/partial.log").write_text("partial")
        self.capture_and_stage()
        self.assertTrue((self.root / "artifact-stage/reports/raw-evidence/harbor-job/caffe-cifar-10__Dynamic7/agent/partial.log").is_file())

    def test_09_dynamic_trial_id_discovered(self):
        self.trial(name="caffe-cifar-10__xYz987")
        found = obs.discover_trial(self.root / "work/jobs", "m1c1-live-single")
        self.assertEqual(found["trial_id"], "caffe-cifar-10__xYz987")

    def test_10_no_candidate_is_deterministic_and_diagnostic(self):
        found = obs.capture_raw(self.root, "m1c1-live-single")["result_discovery"]
        self.assertEqual(found["blocker"], "M1C_HARBOR_TRIAL_NOT_FOUND")
        self.capture_and_stage()
        self.assertTrue((self.root / "artifact-stage/EVIDENCE_MANIFEST.json").is_file())

    def test_11_explicit_request_event_is_detected(self):
        trial = self.trial()
        (trial / "agent/dsh-home/sessions/events.jsonl").write_text(
            json.dumps({"type": "provider_request_started"}) + "\n")
        obs.capture_raw(self.root, "m1c1-live-single")
        evidence = obs.provider_evidence(self.root / "reports/raw-evidence")
        self.assertEqual(evidence["provider_request_count"], 1)

    def test_12_credential_value_and_name_are_redacted_before_staging(self):
        trial = self.trial()
        (trial / "agent/private.txt").write_text("secret-value credential-variable")
        obs.capture_raw(self.root, "m1c1-live-single", "secret-value", "credential-variable")
        copied = (self.root / "reports/raw-evidence/harbor-job/caffe-cifar-10__Dynamic7/agent/private.txt").read_text()
        self.assertNotIn("secret-value", copied)
        self.assertNotIn("credential-variable", copied)


if __name__ == "__main__":
    unittest.main()

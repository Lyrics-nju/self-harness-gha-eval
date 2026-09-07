from pathlib import Path
import unittest

ROOT = Path(__file__).parents[2]
WORKFLOW = ROOT / ".github/workflows/gha-m1c1-postlive-observability-probe.yml"
LIVE = ROOT / ".github/workflows/gha-m1c1-live.yml"


class PostLiveWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = WORKFLOW.read_text()
        cls.live = LIVE.read_text()

    def test_dispatch_only(self):
        trigger = self.text.split("permissions:", 1)[0]
        self.assertIn("workflow_dispatch:", trigger)
        for forbidden in ("push:", "pull_request:", "schedule:"):
            self.assertNotIn(forbidden, trigger)

    def test_standard_read_only_single_job(self):
        self.assertIn("runs-on: ubuntu-24.04", self.text)
        self.assertIn("contents: read", self.text)
        self.assertNotIn("matrix:", self.text)

    def test_no_model_or_live_surface(self):
        joined = self.text.lower()
        self.assertNotIn("api_key", joined)
        self.assertNotIn("run-live", joined)
        self.assertNotIn("harbor run", joined)
        self.assertNotIn("dsh session", joined)

    def test_no_retry_or_automatic_trigger(self):
        self.assertNotIn("retry", self.text.lower())

    def test_exact_production_code_is_exercised(self):
        self.assertIn("test_m1c_postlive_observability", self.text)
        self.assertIn("gha_m1c1_live_controller.py stage", self.text)

    def test_secret_scan_hash_and_upload(self):
        self.assertLess(self.text.index("public_secret_scan.py"), self.text.index("actions/upload-artifact@v4"))
        self.assertIn("sha256sum -c", self.text)

    def test_live_raw_capture_precedes_summary(self):
        self.assertLess(self.live.index("Execute exactly one fixed live Harbor trial"),
                        self.live.index("Normalize and classify live result"))
        self.assertIn("raw-capture-manifest.json", (ROOT / "scripts/gha_m1c1_live_controller.py").read_text())


if __name__ == "__main__":
    unittest.main()

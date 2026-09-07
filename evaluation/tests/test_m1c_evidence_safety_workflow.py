from pathlib import Path
import unittest

ROOT=Path(__file__).parents[2]
WORKFLOW=ROOT/".github/workflows/gha-m1c1-evidence-safety-probe.yml"


class EvidenceSafetyWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.text=WORKFLOW.read_text()
    def test_01_dispatch_only(self):
        trigger=self.text.split("permissions:",1)[0]
        self.assertIn("workflow_dispatch:",trigger)
        for value in ("push:","pull_request:","schedule:"): self.assertNotIn(value,trigger)
    def test_02_standard_read_only_single_job(self):
        self.assertIn("runs-on: ubuntu-24.04",self.text); self.assertIn("contents: read",self.text); self.assertNotIn("matrix:",self.text)
    def test_03_no_model_surface(self):
        lower=self.text.lower()
        for value in ("api_key","run-live","harbor run","dsh session","retry"): self.assertNotIn(value,lower)
    def test_04_production_code_and_hashes(self):
        self.assertIn("m1c_evidence_safety_probe.py",self.text); self.assertIn("public_secret_scan.py",self.text); self.assertIn("sha256sum -c",self.text)
    def test_05_unsafe_bulk_not_uploaded(self): self.assertNotIn("unsafe-bulk",self.text)


if __name__ == "__main__": unittest.main()

from __future__ import annotations

import importlib.util
import json
import tempfile
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).parents[2]
spec = importlib.util.spec_from_file_location("public_secret_scan", ROOT / "scripts/public_secret_scan.py")
scanner = importlib.util.module_from_spec(spec); assert spec and spec.loader
sys.modules["public_secret_scan"] = scanner
spec.loader.exec_module(scanner)


class StructuredSecretScannerTests(unittest.TestCase):
    key = "DEEPSEEK_" + "API_KEY"
    auth_header_name = "Authoriz" + "ation"
    def scan(self, name: str, content: str):
        with tempfile.TemporaryDirectory() as td:
            Path(td, name).write_text(content)
            return scanner.scan_tree(Path(td), artifact_mode=True)

    def test_01_json_redacted(self): self.assertFalse(self.scan("a.json", json.dumps({self.key: "REDACTED"})))
    def test_02_json_stars(self): self.assertFalse(self.scan("a.json", json.dumps({self.key: "***"})))
    def test_03_json_fake_value_fails(self): self.assertTrue(self.scan("a.json", json.dumps({self.key: "sk-synthetic-fixture-123456789"})))
    def test_04_identifier_only(self): self.assertFalse(self.scan("a.txt", self.key + "\n"))
    def test_05_redacted_assignment(self): self.assertFalse(self.scan("a.txt", self.key + "=REDACTED\n"))
    def test_06_fake_assignment_fails(self): self.assertTrue(self.scan("a.txt", self.key + "=synthetic-not-a-secret-123\n"))
    def test_07_authorization_name_only(self): self.assertFalse(self.scan("a.txt", self.auth_header_name + "\n"))
    def test_08_bearer_fixture_fails(self): self.assertTrue(self.scan("a.txt", self.auth_header_name + ": Bearer synthetic-token-value\n"))
    def test_09_cloud_identifier_redacted(self): self.assertFalse(self.scan("a.json", json.dumps({"AWS_SECRET_ACCESS_KEY": "MASKED"})))
    def test_10_private_key_fixture_fails(self): self.assertTrue(self.scan("a.txt", "-----BEGIN RSA " + "PRIVATE KEY-----\nsynthetic\n"))
    def test_11_diagnostic_omits_candidate(self):
        candidate = "synthetic-private-value-987654"
        finding = self.scan("a.txt", self.key + "=" + candidate)[0]
        self.assertNotIn(candidate, finding.diagnostic())
        self.assertIn("candidate_length=", finding.diagnostic())
    def test_12_diagnostic_rule_and_path(self):
        diagnostic = self.scan("fixture.json", json.dumps({"GITHUB_TOKEN": "synthetic-value"}))[0].diagnostic()
        self.assertIn("fixture.json", diagnostic); self.assertIn("SENSITIVE_FIELD_UNREDACTED", diagnostic)


if __name__ == "__main__": unittest.main()

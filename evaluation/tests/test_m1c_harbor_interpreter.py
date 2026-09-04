import importlib.util
from pathlib import Path
import stat
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).parents[2] / "scripts" / "resolve_harbor_python.py"
SPEC = importlib.util.spec_from_file_location("resolve_harbor_python", SCRIPT)
resolver = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(resolver)


class HarborInterpreterResolverTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def layout(self, manager):
        real_bin = self.root / manager / "tools" / "harbor" / "bin"
        real_bin.mkdir(parents=True)
        harbor = real_bin / "harbor"
        harbor.write_text("#!/bin/sh\nexit 0\n")
        harbor.chmod(harbor.stat().st_mode | stat.S_IXUSR)
        (real_bin / "python").symlink_to(sys.executable)
        exposed = self.root / ".local" / "bin" / "harbor"
        exposed.parent.mkdir(parents=True, exist_ok=True)
        exposed.symlink_to(harbor)
        return exposed, harbor.resolve(), (real_bin / "python").absolute()

    def test_01_pipx_layout(self):
        exposed, harbor, python = self.layout("pipx")
        self.assertEqual(resolver.resolve_harbor_interpreter(which=lambda _: str(exposed)), (harbor, python))

    def test_02_uv_tool_layout(self):
        exposed, harbor, python = self.layout("uv")
        self.assertEqual(resolver.resolve_harbor_interpreter(which=lambda _: str(exposed)), (harbor, python))

    def test_03_missing_harbor(self):
        with self.assertRaises(resolver.HarborResolutionError):
            resolver.resolve_harbor_interpreter(which=lambda _: None)

    def test_04_missing_python(self):
        harbor = self.root / "bin" / "harbor"
        harbor.parent.mkdir()
        harbor.write_text("#!/bin/sh\n")
        harbor.chmod(0o755)
        with self.assertRaises(resolver.HarborResolutionError):
            resolver.resolve_harbor_interpreter(which=lambda _: str(harbor))

    def fake_python(self, body):
        path = self.root / "python-fixture"
        path.write_text("#!/bin/sh\n" + body + "\n")
        path.chmod(0o755)
        return path

    def test_05_cannot_import_harbor(self):
        python = self.fake_python("exit 7")
        with self.assertRaises(resolver.HarborResolutionError):
            resolver.verify_harbor_interpreter(python, expected_version="0.21.0")

    def test_06_wrong_version(self):
        python = self.fake_python("echo '{\"version\":\"0.20.0\",\"registration\":\"NOT_REQUESTED\"}'")
        with self.assertRaises(resolver.HarborResolutionError):
            resolver.verify_harbor_interpreter(python, expected_version="0.21.0")

    def test_07_adapter_registration(self):
        result = resolver.verify_harbor_interpreter(
            Path(sys.executable),
            expected_version="0.21.0",
            registration_import="evaluation.agents.dsh_harbor_adapter",
        )
        self.assertEqual(result["registration"], "PASS")


if __name__ == "__main__":
    unittest.main()

"""Offline unit tests for the deterministic review engine (no network)."""
import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('security_agents', ROOT / 'security_agents.py')
module = importlib.util.module_from_spec(spec)
import sys
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class AgentTests(unittest.TestCase):
    def test_all_15_modules_registered(self):
        self.assertEqual(len(module.CHECKS), 15)

    def test_training_shell_execution_detected(self):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            (base / 'practice_lab').mkdir()
            (base / 'practice_lab' / 'insecure.py').write_text('import os\nos.system(input("command:"))\n')
            ctx = module.load_context(base)
            findings = module.check_shell(ctx)
            self.assertEqual(len(findings), 1)
            self.assertTrue(findings[0].training_only)

    def test_scanner_source_not_mistaken_for_private_key(self):
        ctx = module.load_context(ROOT)
        self.assertFalse(any(f.file == 'security_agents.py' for f in module.check_private_keys(ctx)))

    def test_no_network_scanning_enabled(self):
        self.assertFalse(__import__('json').loads((ROOT / 'scope-config.json').read_text())['external_scanning'])


if __name__ == '__main__':
    unittest.main()

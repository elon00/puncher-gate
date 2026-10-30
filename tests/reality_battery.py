"""Legacy test path retained without corrupt bytes or fabricated PQC assertions.

The genuine offline parser regressions live in test_stun_binding.py.
"""

from pathlib import Path
import unittest


class LegacyEntryPointTests(unittest.TestCase):
    def test_implementation_and_regressions_present(self):
        root = Path(__file__).resolve().parents[1]
        self.assertTrue((root / "src" / "stun_binding.py").is_file())
        self.assertTrue((root / "tests" / "test_stun_binding.py").is_file())

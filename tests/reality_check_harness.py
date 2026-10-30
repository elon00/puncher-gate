"""Backward-compatible entrypoint: run the real offline parser test suite."""

import sys
import unittest
from pathlib import Path


if __name__ == "__main__":
    tests = unittest.defaultTestLoader.discover(str(Path(__file__).parent), pattern="test_*.py")
    result = unittest.TextTestRunner(verbosity=2).run(tests)
    sys.exit(0 if result.wasSuccessful() and result.testsRun > 0 else 1)

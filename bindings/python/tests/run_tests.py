"""Runs every binding test module."""

from __future__ import annotations

import os
import sys
import unittest

import support

MODULES = [
    "concurrency_test",
    "corpus_test",
    "docs_test",
    "engine_test",
    "native_test",
    "thread_stack_test",
]


class InterpreterTest(unittest.TestCase):
    def test_interpreter_version(self) -> None:
        self.assertEqual(support.python_version(), os.environ["RUSTLEAKS_TEST_PYTHON"])
        # The tests run on standard builds, which have the GIL.
        if hasattr(sys, "_is_gil_enabled"):
            self.assertTrue(sys._is_gil_enabled())


def main() -> int:
    loader = unittest.TestLoader()
    suite = unittest.TestSuite([loader.loadTestsFromTestCase(InterpreterTest)])
    for name in MODULES:
        suite.addTests(loader.loadTestsFromName(name))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())

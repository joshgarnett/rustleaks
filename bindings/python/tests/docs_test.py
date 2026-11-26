"""Runs the examples in the docstrings, the README and the Python guide."""

from __future__ import annotations

import doctest
import os
import re
import unittest

import support

import rustleaks
from rustleaks import _engine, _errors, _types

FENCE = re.compile(r"^```python\n(.*?)^```$", re.M | re.S)


def python_blocks(path: str) -> list[str]:
    with open(path, encoding="utf-8") as file:
        return FENCE.findall(file.read())


class DocsTest(unittest.TestCase):
    def test_docstrings(self) -> None:
        for module in (rustleaks, _engine, _errors, _types):
            with self.subTest(module.__name__):
                result = doctest.testmod(module, optionflags=doctest.ELLIPSIS)
                self.assertEqual(result.failed, 0)
        self.assertGreater(doctest.testmod(rustleaks).attempted, 0)

    def test_markdown_examples(self) -> None:
        paths = support.doc_paths()
        self.assertEqual(
            sorted(os.path.basename(path) for path in paths), ["README.md", "python.md"]
        )
        total = 0
        for path in paths:
            for index, block in enumerate(python_blocks(path)):
                total += 1
                with self.subTest(f"{os.path.basename(path)} example {index + 1}"):
                    code = compile(block, f"{path} example {index + 1}", "exec")
                    exec(code, {"__name__": "__example__"})  # noqa: S102
        self.assertGreater(total, 5)


if __name__ == "__main__":
    unittest.main()

"""Prints the path of the CPython interpreter that Bazel selected.

The binding dry run creates its virtual environments from this interpreter.
On Windows, rules_python's own interpreter target is not available, so the
dry run runs this program instead.
"""

import sys

print(getattr(sys, "_base_executable", sys.executable))

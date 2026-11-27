"""Prints the path of the CPython interpreter that Bazel selected.

The binding dry run creates its virtual environments from this interpreter.
On Windows, rules_python's own interpreter target is not available, so the
dry run runs this program instead.

The path is resolved past runfiles links, because the dry run runs this
program once per Python version and Bazel replaces the runfiles each time.
"""

import os
import sys

print(os.path.realpath(getattr(sys, "_base_executable", sys.executable)))

"""Shared helpers of the binding tests.

Importing this module points the package at the library that Bazel built.
Key-shaped test values are built at run time, because the CI self-scan runs
every built-in rule over the repository.
"""

from __future__ import annotations

import os
import sys

import rustleaks
from rustleaks import _native

LIBRARY_SUFFIXES = (".so", ".dylib", ".dll")


def runfile(path: str) -> str:
    """The absolute path of a runfile given as an rlocation path."""
    root = os.environ.get("RUNFILES_DIR") or os.environ["TEST_SRCDIR"]
    return os.path.join(root, *path.split("/"))


def runfiles(variable: str) -> list[str]:
    """The absolute paths of the runfiles listed in an environment variable."""
    return [runfile(path) for path in os.environ[variable].split()]


def library_path() -> str:
    for path in runfiles("RUSTLEAKS_TEST_LIBRARY"):
        if path.endswith(LIBRARY_SUFFIXES) and os.path.isfile(path):
            return path
    raise RuntimeError("no shared library in RUSTLEAKS_TEST_LIBRARY")


def corpus_file(name: str) -> str:
    """The absolute path of a file in testdata/bindings."""
    for path in runfiles("RUSTLEAKS_TEST_CORPUS"):
        if path.replace(os.sep, "/").endswith("testdata/bindings/" + name):
            return path
    raise RuntimeError(f"no {name} in RUSTLEAKS_TEST_CORPUS")


def header_path() -> str:
    return runfile(os.environ["RUSTLEAKS_TEST_HEADER"])


def doc_paths() -> list[str]:
    return runfiles("RUSTLEAKS_TEST_DOCS")


_native.set_library_path(library_path())

# A synthetic marker that a test scans. Tests check that it never appears in
# a repr, a message or a traceback.
MARKER_SECRET = "QZXW"
MARKER_CONFIG = """
[[rules]]
id = "synthetic-marker"
description = "A synthetic marker"
regex = '''MARK-([A-Z]{4})'''
secretGroup = 1
keywords = ["mark-"]
tags = ["synthetic"]
"""


def marker_input() -> bytes:
    return b"name = MARK-" + MARKER_SECRET.encode() + b"\n"


def aws_key() -> bytes:
    """A synthetic AWS access key ID that the built-in rules find."""
    return b"AKIA" + b"LALEMEL33243OLIB"


def slow_input(engine: rustleaks.Engine, size: int = 40_000_000) -> bytes:
    """An input of about ``size`` bytes that holds every keyword of the
    engine's rules many times, so that a scan of it takes seconds even in an
    optimized build. Tests cancel or time out these scans; none waits for
    one to finish."""
    block = b"".join(
        keyword.encode() + b' = "x0x0x0x0x0x0"\n'
        for rule in engine.rules()
        for keyword in rule.keywords
    )
    return block * max(1, size // len(block))


def slow_engine(**options: object) -> rustleaks.Engine:
    """An engine with every built-in rule, no input limit and no finding
    record limit, for slow scans."""
    return rustleaks.Engine(
        max_input_bytes=rustleaks.UNLIMITED,
        budget=rustleaks.Budget(finding_records=rustleaks.UNLIMITED),
        **options,  # type: ignore[arg-type]
    )


def python_version() -> str:
    return f"{sys.version_info.major}.{sys.version_info.minor}"

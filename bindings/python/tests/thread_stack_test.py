"""Builds engines and scans from threading.Thread threads with small stacks.

A rule with 200 nested groups compiles on the thread that builds the engine
or searches, and needs more than 128 KiB of stack in an unoptimized build.
Threads on musl, and threads that set threading.stack_size, can be that
small. The library builds and scans on its own threads with an 8 MiB stack,
so these scans pass on any thread.

Each case runs in a child process, so a stack overflow fails one test with
its output instead of ending the whole run.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import unittest

# Importing support points the package at the library that Bazel built, in
# the test process and in the child.
import support  # noqa: F401

import rustleaks

DEEP_PATTERN = "(" * 200 + "a" + ")" * 200
DEEP_CONFIG = f"[[rules]]\nid = \"deep\"\nregex = '''{DEEP_PATTERN}'''\n"


def keyword_input(engine: rustleaks.Engine) -> bytes:
    """Every keyword of every rule, so the scan compiles every pattern."""
    return b"".join(
        keyword.encode() + b' = "x"\n' for rule in engine.rules() for keyword in rule.keywords
    )


def work() -> dict[str, object]:
    with rustleaks.Engine(config=DEEP_CONFIG) as engine:
        deep = [finding.match.decode() for finding in engine.scan(b"xax")]
    with rustleaks.Engine() as engine:
        findings = engine.scan(keyword_input(engine), path="config/app.env", decode_depth=5)
    return {"deep": deep, "builtin_scan_returned": isinstance(findings, list)}


def child(stack_kib: int) -> int:
    """Runs ``work`` on a new thread and prints the result as JSON."""
    if stack_kib:
        threading.stack_size(stack_kib * 1024)
    result: dict[str, object] = {}

    def target() -> None:
        try:
            result.update(work())
        except BaseException as error:  # noqa: BLE001
            result["error"] = f"{type(error).__name__}: {error}"

    thread = threading.Thread(target=target)
    thread.start()
    thread.join()
    print(json.dumps(result))
    return 0


def child_command(stack_kib: int) -> list[str]:
    tests = os.path.dirname(os.path.abspath(__file__))
    package = os.path.dirname(os.path.dirname(os.path.abspath(rustleaks.__file__)))
    code = (
        "import sys\n"
        f"sys.path[:0] = [{tests!r}, {package!r}]\n"
        "import thread_stack_test\n"
        f"sys.exit(thread_stack_test.child({stack_kib}))\n"
    )
    return [sys.executable, "-c", code]


class ThreadStackTest(unittest.TestCase):
    def check(self, stack_kib: int) -> None:
        process = subprocess.run(
            child_command(stack_kib),
            capture_output=True,
            text=True,
            check=False,
            timeout=600,
        )
        output = process.stdout.strip().splitlines()
        self.assertEqual(process.returncode, 0, process.stderr[-2000:])
        self.assertTrue(output, process.stderr[-2000:])
        result = json.loads(output[-1])
        self.assertNotIn("error", result)
        self.assertEqual(result["deep"], ["a"])
        self.assertTrue(result["builtin_scan_returned"])

    def test_default_thread_stack(self) -> None:
        self.check(0)

    def test_256_kib_thread_stack(self) -> None:
        self.check(256)

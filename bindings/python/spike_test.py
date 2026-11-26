"""Smoke test for loading the spike shared library with ctypes."""

import ctypes
import os
import subprocess
import sys
import threading
import unittest

# Maps a probe size in KiB to the value spike_stack returns.
EXPECTED_STACK_SUMS = {64: 120, 256: 2016, 1024: 32640}

SUFFIXES = (".so", ".dylib", ".dll")


def library_path():
    """Returns the absolute path of the shared library in the runfiles."""
    root = os.environ.get("RUNFILES_DIR") or os.environ["TEST_SRCDIR"]
    for path in os.environ["RUSTLEAKS_SPIKE_LIBRARY"].split():
        if path.endswith(SUFFIXES):
            return os.path.join(root, *path.split("/"))
    raise RuntimeError("no shared library in RUSTLEAKS_SPIKE_LIBRARY")


def load():
    library = ctypes.CDLL(library_path())
    library.spike_add.argtypes = (ctypes.c_uint64, ctypes.c_uint64)
    library.spike_add.restype = ctypes.c_uint64
    library.spike_sum.argtypes = (ctypes.c_char_p, ctypes.c_size_t)
    library.spike_sum.restype = ctypes.c_uint64
    library.spike_stack.argtypes = (ctypes.c_uint32,)
    library.spike_stack.restype = ctypes.c_uint64
    return library


def run_stack_child(kib):
    """Runs one stack probe on a new threading.Thread and prints the result."""
    library = load()
    result = {}

    def probe():
        result["value"] = library.spike_stack(kib)

    thread = threading.Thread(target=probe)
    thread.start()
    thread.join()
    value = result.get("value")
    if value != EXPECTED_STACK_SUMS[kib]:
        print(f"wrong result {value}")
        return 1
    print(f"ok (thread stack size setting {threading.stack_size()})")
    return 0


class SpikeTest(unittest.TestCase):
    def test_interpreter_version(self):
        expected = os.environ["RUSTLEAKS_SPIKE_PYTHON"]
        actual = f"{sys.version_info.major}.{sys.version_info.minor}"
        self.assertEqual(actual, expected)
        print(f"SPIKE-PYTHON {sys.version.split()[0]} {sys.platform} {sys.executable}")

    def test_add(self):
        library = load()
        self.assertEqual(library.spike_add(2, 40), 42)
        self.assertEqual(library.spike_add(2**64 - 1, 2), 1)

    def test_sum(self):
        library = load()
        self.assertEqual(library.spike_sum(None, 0), 0)
        data = b"\xff" * (1 << 20)
        self.assertEqual(library.spike_sum(data, len(data)), 0xFF << 20)

    def test_stack_probe(self):
        """Records how much native stack a threading.Thread can use.

        It prints the result and does not fail, because the spike only
        measures it.
        """
        for kib in sorted(EXPECTED_STACK_SUMS):
            child = subprocess.run(
                [sys.executable, os.path.abspath(__file__), "--stack-child", str(kib)],
                capture_output=True,
                text=True,
                check=False,
            )
            output = (child.stdout + child.stderr).strip().splitlines()
            detail = output[-1] if output else ""
            status = "ok" if child.returncode == 0 else f"failed (exit {child.returncode})"
            print(
                f"SPIKE-STACK python {sys.version_info.major}.{sys.version_info.minor} "
                f"{sys.platform} {kib} KiB: {status}: {detail}"
            )


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--stack-child":
        sys.exit(run_stack_child(int(sys.argv[2])))
    unittest.main()

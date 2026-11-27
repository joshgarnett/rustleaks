"""Threads, close, cancel, timeouts, fork and interrupts.

Most tests hold scans in flight with a test hook that runs after a scan
holds a worker and before the native call, so no assertion depends on how
long a scan takes. Only the GIL test needs a scan that is inside the native
library. It uses an input full of rule keywords, which takes far longer to
scan than a small input. No assertion compares clock readings.
"""

from __future__ import annotations

import _thread
import gc
import json
import os
import random
import signal
import threading
import time
import unittest
import warnings
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any

from support import MARKER_CONFIG, MARKER_SECRET, marker_input, slow_engine, slow_input

import rustleaks
from rustleaks import _engine

WAIT_SECONDS = 120


def wait_until(condition: Callable[[], bool]) -> None:
    deadline = time.monotonic() + WAIT_SECONDS
    while not condition():
        if time.monotonic() > deadline:
            raise AssertionError("the condition did not hold in time")
        time.sleep(0.005)


class Outcome:
    """The result or exception of a call on another thread."""

    def __init__(self) -> None:
        self.value: Any = None
        self.error: BaseException | None = None
        self.done = threading.Event()


def start(call: Callable[[], Any]) -> tuple[threading.Thread, Outcome]:
    outcome = Outcome()

    def target() -> None:
        try:
            outcome.value = call()
        except BaseException as error:  # noqa: BLE001
            outcome.error = error
        outcome.done.set()

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    return thread, outcome


def join(thread: threading.Thread) -> None:
    thread.join(WAIT_SECONDS)
    if thread.is_alive():
        raise AssertionError("the thread did not finish in time")


@contextmanager
def before_native(action: Callable[[rustleaks.Engine], None]) -> Iterator[None]:
    """Runs ``action`` in every scan after it holds a worker and before the
    native call."""
    _engine._test_hook_before_native = action
    try:
        yield
    finally:
        _engine._test_hook_before_native = None


class Gate:
    """Holds the scans of one engine before their native call until opened."""

    def __init__(self, engine: rustleaks.Engine) -> None:
        self.engine = engine
        self.opened = threading.Event()

    def __call__(self, engine: rustleaks.Engine) -> None:
        if engine is self.engine and not self.opened.wait(WAIT_SECONDS):
            raise AssertionError("the gate was not opened in time")

    def open(self) -> None:
        self.opened.set()


def small_input() -> bytes:
    return b"nothing to find here\n"


class GilTest(unittest.TestCase):
    def test_scans_overlap_with_the_gil_released(self) -> None:
        # If a native call held the GIL, this thread could not run the second
        # scan until the first one returned.
        engine = slow_engine(workers=2)
        self.addCleanup(engine.close)
        token = rustleaks.CancelToken()
        data = slow_input(engine)
        thread, slow = start(lambda: engine.scan(data, cancel=token))
        wait_until(lambda: engine._in_flight == 1)
        self.assertEqual(engine.scan(small_input()), [])
        self.assertFalse(slow.done.is_set(), "the slow scan ended before the small one")
        token.cancel()
        join(thread)
        # The slow scan is cancelled, or complete if it ended first.
        if slow.error is not None:
            self.assertIsInstance(slow.error, rustleaks.ScanCancelledError)
        else:
            self.assertIsInstance(slow.value, list)


class CancelAndTimeoutTest(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = rustleaks.Engine(config=MARKER_CONFIG, workers=2)
        self.addCleanup(self.engine.close)

    def test_cancel_reaches_the_native_scan(self) -> None:
        # The token is cancelled after the checks in Python, so only the
        # library can stop the scan.
        token = rustleaks.CancelToken()
        with before_native(lambda engine: token.cancel()):
            with self.assertRaises(rustleaks.ScanCancelledError) as caught:
                self.engine.scan(marker_input(), cancel=token)
        error = caught.exception
        self.assertEqual(error.termination, "cancelled")
        self.assertEqual(str(error), "the scan was cancelled")
        self.assertIsNone(error.budget)
        self.assertIsNone(error.limit)

    def test_cancel_before_a_scan(self) -> None:
        token = rustleaks.CancelToken()
        token.cancel()
        with self.assertRaises(rustleaks.ScanCancelledError) as caught:
            self.engine.scan(marker_input(), cancel=token)
        self.assertIn("before it started", str(caught.exception))
        # A cancelled token stays cancelled.
        with self.assertRaises(rustleaks.ScanCancelledError):
            self.engine.scan_text("text", cancel=token)

    def test_one_token_cancels_many_scans(self) -> None:
        # Two scans hold the workers and two wait. One cancel stops all four:
        # the waiting ones in Python and the held ones in the library.
        token = rustleaks.CancelToken()
        gate = Gate(self.engine)
        with before_native(gate):
            started = [
                start(lambda: self.engine.scan(marker_input(), cancel=token)) for _ in range(4)
            ]
            wait_until(lambda: self.engine._in_flight == 2)
            token.cancel()
            gate.open()
            for thread, outcome in started:
                join(thread)
                self.assertIsInstance(outcome.error, rustleaks.ScanCancelledError)

    def test_timeout_reaches_the_native_scan(self) -> None:
        # A worker is free, so the scan starts with a deadline that has
        # already passed, and the library stops it at its first check.
        with self.assertRaises(rustleaks.ScanTimeoutError) as caught:
            self.engine.scan(marker_input(), timeout=0)
        self.assertEqual(caught.exception.termination, "timeout")
        self.assertIn("before the scan finished", str(caught.exception))

    def test_timeout_and_cancel_while_waiting_for_a_worker(self) -> None:
        gate = Gate(self.engine)
        with before_native(gate):
            busy = [start(lambda: self.engine.scan(small_input())) for _ in range(2)]
            wait_until(lambda: self.engine._in_flight == 2)
            with self.assertRaises(rustleaks.ScanTimeoutError) as caught:
                self.engine.scan(small_input(), timeout=0)
            self.assertIn("waited for a worker", str(caught.exception))
            waiting_token = rustleaks.CancelToken()
            thread, outcome = start(
                lambda: self.engine.scan(small_input(), cancel=waiting_token)
            )
            waiting_token.cancel()
            join(thread)
            self.assertIsInstance(outcome.error, rustleaks.ScanCancelledError)
            gate.open()
            for thread, outcome in busy:
                join(thread)
                self.assertEqual(outcome.value, [])

    def test_a_scan_that_finishes_in_time_returns_findings(self) -> None:
        findings = self.engine.scan(marker_input(), timeout=60)
        self.assertEqual(len(findings), 1)


class CloseTest(unittest.TestCase):
    def test_close_waits_and_does_not_cancel(self) -> None:
        engine = rustleaks.Engine(config=MARKER_CONFIG, workers=1)
        gate = Gate(engine)
        with before_native(gate):
            scanner, scanned = start(lambda: engine.scan(marker_input() * 3))
            wait_until(lambda: engine._in_flight == 1)
            # This scan waits for the only worker and sees the engine close.
            waiter, waited = start(lambda: engine.scan(b"x"))
            closer, closed = start(engine.close)
            wait_until(lambda: engine.closed)
            join(waiter)
            self.assertIsInstance(waited.error, rustleaks.ClosedError)
            with self.assertRaises(rustleaks.ClosedError):
                engine.scan(b"x")
            # The held scan cannot leave, so close is still waiting.
            self.assertFalse(closed.done.is_set())
            self.assertTrue(engine._handle)
            gate.open()
            join(scanner)
            join(closer)
        # The scan that ran during close is complete.
        self.assertIsNone(scanned.error)
        self.assertEqual(len(scanned.value), 3)
        self.assertIsNone(closed.error)
        self.assertFalse(engine._handle)

    def test_close_inside_a_scan_on_the_same_thread(self) -> None:
        # As from a signal handler that runs during a scan: close would wait
        # for its own thread, so it raises instead.
        engine = rustleaks.Engine(config=MARKER_CONFIG)
        errors: list[RuntimeError] = []

        def close_here(scanning: rustleaks.Engine) -> None:
            try:
                scanning.close()
            except RuntimeError as error:
                errors.append(error)

        with before_native(close_here):
            findings = engine.scan(marker_input())
        self.assertEqual(len(findings), 1)
        self.assertEqual(len(errors), 1)
        self.assertIn("inside a scan", str(errors[0]))
        self.assertFalse(engine.closed)
        engine.close()
        self.assertTrue(engine.closed)

    def test_many_threads_share_an_engine(self) -> None:
        with rustleaks.Engine(config=MARKER_CONFIG, workers=2) as engine:
            started = [
                start(lambda: [engine.scan(marker_input() * 50) for _ in range(20)])
                for _ in range(8)
            ]
            for thread, outcome in started:
                join(thread)
                self.assertIsNone(outcome.error)
                for findings in outcome.value:
                    self.assertEqual(len(findings), 50)
                    self.assertEqual(findings[0].secret, MARKER_SECRET.encode())


class InterruptTest(unittest.TestCase):
    def setUp(self) -> None:
        self.previous = signal.signal(signal.SIGINT, signal.default_int_handler)

    def tearDown(self) -> None:
        signal.signal(signal.SIGINT, self.previous)

    def test_interrupt_while_close_waits(self) -> None:
        engine = rustleaks.Engine(config=MARKER_CONFIG, workers=1)
        gate = Gate(engine)
        with before_native(gate):
            scanner, scanned = start(lambda: engine.scan(marker_input()))
            wait_until(lambda: engine._in_flight == 1)
            # The scan is held, so close waits until the interrupt.
            timer = threading.Timer(0.05, _thread.interrupt_main)
            timer.start()
            with self.assertRaises(KeyboardInterrupt):
                engine.close()
            timer.join()
            # The engine stays closed, and the held scan keeps its engine.
            self.assertTrue(engine.closed)
            self.assertTrue(engine._handle)
            with self.assertRaises(rustleaks.ClosedError):
                engine.scan(b"x")
            gate.open()
            join(scanner)
        self.assertEqual(len(scanned.value), 1)
        engine.close()
        self.assertFalse(engine._handle)

    @unittest.skipUnless(hasattr(signal, "setitimer"), "this platform has no interval timer")
    def test_timer_interrupts_never_leak_the_lock_or_a_worker(self) -> None:
        # A timer signal interrupts the scan loop at any bytecode, including
        # the Python code around the native call, unlike interrupt_main,
        # which only lands where the main thread gives up the GIL. After each
        # interrupt the lock must be free and no scan registered; otherwise
        # the next scan would wait forever.
        def handler(signum: int, frame: object) -> None:
            raise KeyboardInterrupt

        previous = signal.signal(signal.SIGALRM, handler)
        engine = rustleaks.Engine(config=MARKER_CONFIG, workers=1)
        delays = random.Random(0)
        try:
            for _ in range(1500):
                try:
                    signal.setitimer(signal.ITIMER_REAL, 0.0002 + delays.random() * 0.002)
                    while True:
                        engine.scan(marker_input(), timeout=60)
                except KeyboardInterrupt:
                    signal.setitimer(signal.ITIMER_REAL, 0)
                self.assertFalse(engine._lock.locked())
                self.assertEqual(engine._in_flight, 0)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)
        self.assertEqual(len(engine.scan(marker_input(), timeout=60)), 1)
        engine.close()
        self.assertFalse(engine._handle)

    def test_interrupts_during_scans_release_the_worker(self) -> None:
        # An interrupt can arrive at any step of a scan. With one worker, a
        # lost worker slot would make the next scan time out, and a scan that
        # stayed registered would make close wait forever.
        engine = rustleaks.Engine(config=MARKER_CONFIG, workers=1)
        data = marker_input() * 100
        for delay in (0.0, 0.0005, 0.001, 0.002, 0.005, 0.01):
            with self.subTest(delay=delay):
                timer = threading.Timer(delay, _thread.interrupt_main)
                deadline = time.monotonic() + 10
                try:
                    timer.start()
                    while time.monotonic() < deadline:
                        engine.scan(data, timeout=60)
                except KeyboardInterrupt:
                    pass
                finally:
                    timer.join()
                self.assertEqual(engine._in_flight, 0)
                self.assertEqual(len(engine.scan(data, timeout=60)), 100)
        closer, closed = start(engine.close)
        join(closer)
        self.assertIsNone(closed.error)
        self.assertTrue(engine.closed)

    def test_interrupts_around_construction_never_free_twice(self) -> None:
        library = rustleaks._native.library()
        counts = {"new": 0, "free": 0}
        new = library.rustleaks_engine_new
        free = library.rustleaks_engine_free

        def counting_new(*args: Any) -> int:
            status = new(*args)
            if status == rustleaks._native.OK:
                counts["new"] += 1
            return status

        def counting_free(handle: Any) -> int:
            if handle:
                counts["free"] += 1
            return free(handle)

        library.rustleaks_engine_new = counting_new
        library.rustleaks_engine_free = counting_free
        try:
            for delay in (0.0, 0.001, 0.005, 0.02, 0.05):
                with self.subTest(delay=delay):
                    timer = threading.Timer(delay, _thread.interrupt_main)
                    before = dict(counts)
                    deadline = time.monotonic() + 10
                    try:
                        timer.start()
                        while time.monotonic() < deadline:
                            engine = rustleaks.Engine(config=MARKER_CONFIG)
                            engine.scan(marker_input())
                            engine.close()
                    except KeyboardInterrupt:
                        pass
                    finally:
                        timer.join()
                    engine = None
                    gc.collect()
                    made = counts["new"] - before["new"]
                    freed = counts["free"] - before["free"]
                    # Each round has one interrupt. It can leak one engine,
                    # between clearing a handle and freeing it, or skip one
                    # count in these wrappers. A handle freed twice or many
                    # leaked handles would differ by more.
                    self.assertLessEqual(abs(made - freed), 1)
        finally:
            library.rustleaks_engine_new = new
            library.rustleaks_engine_free = free
        with rustleaks.Engine(config=MARKER_CONFIG) as engine:
            self.assertEqual(len(engine.scan(marker_input())), 1)


def fork_child_checks(engine: rustleaks.Engine, token: rustleaks.CancelToken) -> dict[str, Any]:
    report: dict[str, Any] = {"closed": engine.closed}
    try:
        engine.scan(marker_input())
        report["old_scan"] = "returned"
    except rustleaks.ClosedError:
        report["old_scan"] = "ClosedError"
    engine.close()
    report["old_close"] = "returned"
    with rustleaks.Engine(config=MARKER_CONFIG) as fresh:
        report["new_findings"] = len(fresh.scan(marker_input()))
        try:
            fresh.scan(marker_input(), cancel=token)
            report["parent_token"] = "not cancelled"
        except rustleaks.ScanCancelledError:
            report["parent_token"] = "cancelled"
    return report


@unittest.skipUnless(hasattr(os, "fork"), "this platform has no fork")
class ForkTest(unittest.TestCase):
    def test_fork_closes_engines_of_the_parent(self) -> None:
        # This thread waits for a scan before the fork, as a server that
        # scans and then forks workers would.
        with rustleaks.Engine(config=MARKER_CONFIG) as warm:
            self.assertEqual(len(warm.scan(marker_input())), 1)
        engine = rustleaks.Engine(config=MARKER_CONFIG, workers=2)
        gate = Gate(engine)
        with before_native(gate):
            scanner, scanned = start(lambda: engine.scan(marker_input()))
            # Fork while a scan holds a worker, so the child inherits a busy
            # engine. The gate lets the child's own engine through.
            wait_until(lambda: engine._in_flight == 1)
            child_token = rustleaks.CancelToken()
            child_token.cancel()
            read_end, write_end = os.pipe()
            with warnings.catch_warnings():
                # Python warns about fork in a process with threads.
                warnings.simplefilter("ignore", DeprecationWarning)
                pid = os.fork()
            if pid == 0:
                code = 1
                try:
                    os.close(read_end)
                    report = fork_child_checks(engine, child_token)
                    os.write(write_end, json.dumps(report).encode())
                    code = 0
                finally:
                    os._exit(code)
            os.close(write_end)
            chunks = []
            while chunk := os.read(read_end, 65536):
                chunks.append(chunk)
            os.close(read_end)
            _, status = os.waitpid(pid, 0)
            gate.open()
            join(scanner)
        engine.close()
        self.assertEqual(os.waitstatus_to_exitcode(status), 0)
        self.assertEqual(
            json.loads(b"".join(chunks)),
            {
                "closed": True,
                "old_scan": "ClosedError",
                "old_close": "returned",
                "new_findings": 1,
                "parent_token": "cancelled",
            },
        )
        self.assertEqual(len(scanned.value), 1)


if __name__ == "__main__":
    unittest.main()

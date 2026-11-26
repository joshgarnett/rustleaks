"""Threads, close, cancel, timeouts, fork and interrupts.

Slow scans use an input full of rule keywords, which takes seconds even in an
optimized build. Every slow scan in these tests is cancelled or times out;
no assertion needs a scan to finish within a time.
"""

from __future__ import annotations

import _thread
import gc
import json
import os
import signal
import threading
import time
import unittest
import warnings
from collections.abc import Callable
from typing import Any

from support import MARKER_CONFIG, MARKER_SECRET, marker_input, slow_engine, slow_input

import rustleaks

WAIT_SECONDS = 120


def wait_until(condition: Callable[[], bool]) -> None:
    deadline = time.monotonic() + WAIT_SECONDS
    while not condition():
        if time.monotonic() > deadline:
            raise AssertionError("the condition did not hold in time")
        time.sleep(0.005)


class Outcome:
    """The result or exception of a call on another thread, with times."""

    def __init__(self) -> None:
        self.value: Any = None
        self.error: BaseException | None = None
        self.started = 0.0
        self.ended = 0.0


def start(call: Callable[[], Any]) -> tuple[threading.Thread, Outcome]:
    outcome = Outcome()

    def target() -> None:
        outcome.started = time.monotonic()
        try:
            outcome.value = call()
        except BaseException as error:  # noqa: BLE001
            outcome.error = error
        outcome.ended = time.monotonic()

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    return thread, outcome


def join(thread: threading.Thread) -> None:
    thread.join(WAIT_SECONDS)
    if thread.is_alive():
        raise AssertionError("the thread did not finish in time")


class SlowScanTest(unittest.TestCase):
    """Tests that share one engine with every built-in rule."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.engine = slow_engine(workers=2)
        cls.data = slow_input(cls.engine)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.engine.close()

    def test_scans_overlap_with_the_gil_released(self) -> None:
        # If a native call held the GIL, the second scan could not start and
        # this thread could not cancel until the first scan finished.
        tokens = [rustleaks.CancelToken(), rustleaks.CancelToken()]
        started = [
            start(lambda token=token: self.engine.scan(self.data, cancel=token))
            for token in tokens
        ]
        wait_until(lambda: self.engine._in_flight == 2)
        for token in tokens:
            token.cancel()
        for thread, outcome in started:
            join(thread)
            self.assertIsInstance(outcome.error, rustleaks.ScanCancelledError)
        first, second = (outcome for _, outcome in started)
        self.assertLess(max(first.started, second.started), min(first.ended, second.ended))

    def test_cancel_during_a_scan(self) -> None:
        token = rustleaks.CancelToken()
        thread, outcome = start(lambda: self.engine.scan(self.data, cancel=token))
        wait_until(lambda: self.engine._in_flight == 1)
        token.cancel()
        join(thread)
        self.assertIsInstance(outcome.error, rustleaks.ScanCancelledError)
        self.assertEqual(outcome.error.termination, "cancelled")
        self.assertIsNone(outcome.error.budget)
        self.assertIsNone(outcome.error.limit)

    def test_cancel_before_a_scan(self) -> None:
        token = rustleaks.CancelToken()
        token.cancel()
        with self.assertRaises(rustleaks.ScanCancelledError):
            self.engine.scan(self.data, cancel=token)
        # A cancelled token stays cancelled.
        with self.assertRaises(rustleaks.ScanCancelledError):
            self.engine.scan_text("text", cancel=token)

    def test_one_token_cancels_many_scans(self) -> None:
        token = rustleaks.CancelToken()
        started = [start(lambda: self.engine.scan(self.data, cancel=token)) for _ in range(4)]
        wait_until(lambda: self.engine._in_flight == 2)
        token.cancel()
        for thread, outcome in started:
            join(thread)
            self.assertIsInstance(outcome.error, rustleaks.ScanCancelledError)

    def test_timeout_during_a_scan(self) -> None:
        with self.assertRaises(rustleaks.ScanTimeoutError) as caught:
            self.engine.scan(self.data, timeout=0.2)
        self.assertEqual(caught.exception.termination, "timeout")

    def test_timeout_and_cancel_while_waiting_for_a_worker(self) -> None:
        # Both workers are busy, so these scans wait.
        token = rustleaks.CancelToken()
        busy = [start(lambda: self.engine.scan(self.data, cancel=token)) for _ in range(2)]
        wait_until(lambda: self.engine._in_flight == 2)
        with self.assertRaises(rustleaks.ScanTimeoutError):
            self.engine.scan(rustleaks_input(), timeout=0.1)
        waiting_token = rustleaks.CancelToken()
        thread, outcome = start(lambda: self.engine.scan(rustleaks_input(), cancel=waiting_token))
        waiting_token.cancel()
        join(thread)
        self.assertIsInstance(outcome.error, rustleaks.ScanCancelledError)
        token.cancel()
        for thread, _ in busy:
            join(thread)

    def test_a_scan_that_finishes_in_time_returns_findings(self) -> None:
        findings = self.engine.scan(rustleaks_input(), timeout=60)
        self.assertEqual(findings, [])


def rustleaks_input() -> bytes:
    return b"nothing to find here\n"


class CloseTest(unittest.TestCase):
    def test_close_waits_and_does_not_cancel(self) -> None:
        unlimited = rustleaks.Budget(finding_records=rustleaks.UNLIMITED)
        engine = rustleaks.Engine(config=MARKER_CONFIG, budget=unlimited)
        data = marker_input() * 200_000
        thread, outcome = start(lambda: engine.scan(data))
        wait_until(lambda: engine._in_flight == 1)
        engine.close()
        self.assertFalse(engine._handle)
        join(thread)
        # The scan that ran during close is complete.
        self.assertIsNone(outcome.error)
        self.assertEqual(len(outcome.value), 200_000)
        with self.assertRaises(rustleaks.ClosedError):
            engine.scan(marker_input())

    def test_close_while_scanning(self) -> None:
        engine = slow_engine(workers=1)
        data = slow_input(engine)
        token = rustleaks.CancelToken()
        scanner, scanned = start(lambda: engine.scan(data, cancel=token))
        wait_until(lambda: engine._in_flight == 1)
        # This scan waits for the only worker and sees the engine close.
        waiter, waited = start(lambda: engine.scan(b"x"))
        closer, closed = start(engine.close)
        wait_until(lambda: engine.closed)
        join(waiter)
        self.assertIsInstance(waited.error, rustleaks.ClosedError)
        with self.assertRaises(rustleaks.ClosedError):
            engine.scan(b"x")
        # close waits for the running scan.
        closer.join(0.2)
        self.assertTrue(closer.is_alive())
        token.cancel()
        join(scanner)
        join(closer)
        self.assertIsInstance(scanned.error, rustleaks.ScanCancelledError)
        self.assertIsNone(closed.error)
        self.assertFalse(engine._handle)

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
        engine = slow_engine(workers=1)
        data = slow_input(engine)
        token = rustleaks.CancelToken()
        scanner, scanned = start(lambda: engine.scan(data, cancel=token))
        wait_until(lambda: engine._in_flight == 1)
        timer = threading.Timer(0.2, _thread.interrupt_main)
        timer.start()
        with self.assertRaises(KeyboardInterrupt):
            engine.close()
        timer.join()
        # The engine stays closed, and the running scan keeps its engine.
        self.assertTrue(engine.closed)
        with self.assertRaises(rustleaks.ClosedError):
            engine.scan(b"x")
        token.cancel()
        join(scanner)
        self.assertIsInstance(scanned.error, rustleaks.ScanCancelledError)
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
                self.assertEqual(len(engine.scan(data, timeout=5)), 100)
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
        engine = slow_engine(workers=2)
        data = slow_input(engine)
        token = rustleaks.CancelToken()
        scanner, scanned = start(lambda: engine.scan(data, cancel=token))
        # Fork while a scan runs, so the child inherits a busy engine.
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
        token.cancel()
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
        self.assertIsInstance(scanned.error, rustleaks.ScanCancelledError)


if __name__ == "__main__":
    unittest.main()

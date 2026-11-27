"""Tests of the engine API: options, inputs, findings and errors."""

from __future__ import annotations

import array
import base64
import copy
import dataclasses
import gc
import pathlib
import pickle
import sys
import traceback
import unittest

from support import MARKER_CONFIG, MARKER_SECRET, aws_key, marker_input

import rustleaks
from rustleaks import _engine, _native


def exception_text(error: BaseException) -> str:
    """Everything that printing or logging the exception can show."""
    parts = [str(error), repr(error), "".join(traceback.format_exception(error))]
    parts.extend(repr(value) for value in vars(error).values())
    return "\n".join(parts)


class BuiltinRulesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.engine = rustleaks.Engine()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.engine.close()

    def test_every_builtin_rule_by_default(self) -> None:
        rules = self.engine.rules()
        ids = [rule.id for rule in rules]
        self.assertGreater(len(rules), 200)
        self.assertEqual(len(ids), len(set(ids)))
        self.assertIn("aws-access-token", ids)
        self.assertIn("pkcs12-file", ids)
        for rule in rules:
            self.assertIsInstance(rule, rustleaks.Rule)
            self.assertIsInstance(rule.id, str)
            self.assertIsInstance(rule.description, str)
            self.assertIsInstance(rule.tags, tuple)
            self.assertIsInstance(rule.keywords, tuple)
        self.assertIsNot(self.engine.rules(), self.engine.rules())

    def test_builtin_finding(self) -> None:
        data = b'aws = "' + aws_key() + b'"\n'
        findings = self.engine.scan(data, path="config/app.env")
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "aws-access-token")
        self.assertTrue(finding.description)
        self.assertEqual(finding.secret, aws_key())
        self.assertEqual(finding.match, aws_key())
        self.assertEqual(finding.line, data[:-1])
        self.assertEqual(
            (finding.start_line, finding.end_line, finding.start_column, finding.end_column),
            (1, 1, 8, 27),
        )
        self.assertEqual(finding.secret_range, range(7, 27))
        self.assertEqual(finding.match_range, range(7, 27))
        self.assertIsInstance(finding.entropy, float)
        self.assertGreater(finding.entropy, 0)
        self.assertEqual(finding.path, "config/app.env")
        self.assertEqual(finding.tags, ())

    def test_workers(self) -> None:
        self.assertGreaterEqual(self.engine.workers, 1)
        self.assertLessEqual(self.engine.workers, 12)


class OptionsTest(unittest.TestCase):
    def test_rule_selection(self) -> None:
        with rustleaks.Engine(rules=["aws-access-token"]) as engine:
            self.assertEqual([rule.id for rule in engine.rules()], ["aws-access-token"])
        with rustleaks.Engine(rules=iter(["pkcs12-file"])) as engine:
            self.assertEqual([rule.id for rule in engine.rules()], ["pkcs12-file"])

    def test_config_replaces_the_builtin_rules(self) -> None:
        for config in (MARKER_CONFIG, MARKER_CONFIG.encode()):
            with rustleaks.Engine(config=config) as engine:
                self.assertEqual([rule.id for rule in engine.rules()], ["synthetic-marker"])
                rule = engine.rules()[0]
                self.assertEqual(rule.tags, ("synthetic",))
                self.assertEqual(rule.keywords, ("mark-",))
                self.assertEqual(rule.description, "A synthetic marker")

    def test_config_extends_the_builtin_rules(self) -> None:
        config = "[extend]\nuseDefault = true\n" + MARKER_CONFIG
        with rustleaks.Engine(config=config) as engine:
            ids = {rule.id for rule in engine.rules()}
            self.assertIn("synthetic-marker", ids)
            self.assertIn("aws-access-token", ids)
            findings = engine.scan(marker_input() + b"aws = " + aws_key() + b"\n")
            self.assertEqual(
                sorted(finding.rule_id for finding in findings),
                ["aws-access-token", "synthetic-marker"],
            )

    def test_config_errors(self) -> None:
        cases = {
            "extend path": '[extend]\npath = "base.toml"\n',
            "bad pattern": "[[rules]]\nid = \"x\"\nregex = '''(unclosed'''\n",
            "bad TOML": "[[rules]\n",
            "not UTF-8": b"[[rules]]\nid = \"\xff\"\n",
        }
        for name, config in cases.items():
            with self.subTest(name), self.assertRaises(rustleaks.ConfigError) as caught:
                rustleaks.Engine(config=config)
            self.assertEqual(caught.exception.kind, "config")
            self.assertTrue(str(caught.exception))

    def test_lone_surrogates_in_engine_text(self) -> None:
        for options in ({"config": MARKER_CONFIG + "#\ud800\n"}, {"rules": ["\ud800"]}):
            with self.subTest(options), self.assertRaises(rustleaks.TextEncodingError) as caught:
                rustleaks.Engine(**options)  # type: ignore[arg-type]
            self.assertIsNone(caught.exception.__context__)

    def test_unknown_rule_is_a_selection_error(self) -> None:
        with self.assertRaises(rustleaks.ConfigError) as caught:
            rustleaks.Engine(config=MARKER_CONFIG, rules=["no-such-rule"])
        self.assertEqual(caught.exception.kind, "rule_selection")

    def test_input_limit_comes_from_the_library(self) -> None:
        with rustleaks.Engine(config=MARKER_CONFIG) as engine:
            self.assertEqual(engine.max_input_bytes, 10_000_000)
            self.assertEqual(len(engine.scan(bytes(10_000_000))), 0)
            with self.assertRaises(rustleaks.InputTooLargeError) as caught:
                engine.scan(bytes(10_000_001))
            self.assertEqual(caught.exception.limit, 10_000_000)
        for limit in (0, 64, rustleaks.UNLIMITED):
            with rustleaks.Engine(config=MARKER_CONFIG, max_input_bytes=limit) as engine:
                self.assertEqual(engine.max_input_bytes, limit)

    def test_workers_option(self) -> None:
        with rustleaks.Engine(config=MARKER_CONFIG, workers=3) as engine:
            self.assertEqual(engine.workers, 3)

    def test_bad_engine_options(self) -> None:
        cases = [
            ({"workers": 0}, ValueError),
            ({"workers": 257}, ValueError),
            ({"workers": True}, TypeError),
            ({"workers": 2.0}, TypeError),
            ({"workers": "2"}, TypeError),
            ({"max_input_bytes": -1}, ValueError),
            ({"max_input_bytes": 2**64}, ValueError),
            ({"max_input_bytes": False}, TypeError),
            ({"decode_depth": -1}, ValueError),
            ({"decode_depth": True}, TypeError),
            ({"allow_comments": 1}, TypeError),
            ({"allow_comments": "yes"}, TypeError),
            ({"base64_mode": "other"}, ValueError),
            ({"base64_mode": 1}, TypeError),
            ({"redaction": 101}, ValueError),
            ({"redaction": -1}, ValueError),
            ({"redaction": True}, TypeError),
            ({"budget": {"work_units": 1}}, TypeError),
            ({"rules": "aws-access-token"}, TypeError),
            ({"rules": [1]}, TypeError),
            ({"rules": []}, ValueError),
            ({"config": 1}, TypeError),
            ({"config": pathlib.Path("rules.toml")}, TypeError),
        ]
        for options, error in cases:
            with self.subTest(options), self.assertRaises(error):
                rustleaks.Engine(**options)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            rustleaks.Engine(MARKER_CONFIG)  # type: ignore[misc]

    def test_bad_budgets(self) -> None:
        with self.assertRaises(TypeError):
            rustleaks.Budget(work_units=True)
        with self.assertRaises(TypeError):
            rustleaks.Budget(work_units=1.0)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            rustleaks.Budget(work_units=-1)
        with self.assertRaises(ValueError):
            rustleaks.Budget(work_units=2**64)
        self.assertEqual(rustleaks.Budget(work_units=rustleaks.UNLIMITED).work_units, 2**64 - 1)

    def test_detection_options(self) -> None:
        encoded = b"value = " + base64.b64encode(b"token MARK-" + MARKER_SECRET.encode()) + b"\n"
        allowed = marker_input().rstrip(b"\n") + b" # rustleaks:allow\n"
        with rustleaks.Engine(config=MARKER_CONFIG) as engine:
            self.assertEqual(engine.scan(encoded), [])
            self.assertEqual(engine.scan(allowed), [])
        options = {
            "decode_depth": 1,
            "allow_comments": False,
            "redaction": 100,
            "base64_mode": "extended",
        }
        with rustleaks.Engine(config=MARKER_CONFIG, **options) as engine:  # type: ignore[arg-type]
            (decoded,) = engine.scan(encoded)
            self.assertIn("decoded:base64", decoded.tags)
            self.assertIsNone(decoded.secret_range)
            self.assertIsNone(decoded.match_range)
            (finding,) = engine.scan(allowed)
            self.assertEqual(finding.secret, b"REDACTED")

    def test_redaction(self) -> None:
        secret = MARKER_SECRET.encode()
        half = secret[:2] + b"..."
        encoded = b"value = " + base64.b64encode(b"token MARK-" + secret) + b"\n"
        with rustleaks.Engine(config=MARKER_CONFIG) as engine:
            for percent, replacement in ((100, b"REDACTED"), (50, half)):
                with self.subTest(percent=percent):
                    (finding,) = engine.scan(marker_input(), redaction=percent)
                    # The secret is replaced in the secret, the match and
                    # the line.
                    self.assertEqual(finding.secret, replacement)
                    self.assertEqual(finding.match, b"MARK-" + replacement)
                    self.assertEqual(finding.line, b"name = MARK-" + replacement)
                    self.assertEqual(finding.secret_range, range(12, 16))
            (decoded,) = engine.scan(encoded, decode_depth=1, redaction=100)
            # The line of a decoded finding holds the secret in encoded
            # form, so the whole line is replaced.
            self.assertEqual(decoded.secret, b"REDACTED")
            self.assertEqual(decoded.line, b"REDACTED")
            self.assertNotIn(secret, decoded.match)
            (unredacted,) = engine.scan(marker_input())
            self.assertEqual(unredacted.line, b"name = MARK-" + secret)

    def test_scan_overrides(self) -> None:
        encoded = b"value = " + base64.b64encode(b"token MARK-" + MARKER_SECRET.encode()) + b"\n"
        allowed = marker_input().rstrip(b"\n") + b" # gitleaks:allow\n"
        two = marker_input() * 2
        with rustleaks.Engine(config=MARKER_CONFIG) as engine:
            self.assertEqual(len(engine.scan(encoded, decode_depth=1)), 1)
            self.assertEqual(len(engine.scan(encoded, decode_depth=1, base64_mode="extended")), 1)
            self.assertEqual(len(engine.scan(allowed, allow_comments=False)), 1)
            with self.assertRaises(rustleaks.BudgetExceededError):
                engine.scan(two, budget=rustleaks.Budget(finding_records=1))
        # The engine's budget applies unless a scan overrides it.
        budget = rustleaks.Budget(finding_records=1)
        with rustleaks.Engine(config=MARKER_CONFIG, budget=budget) as engine:
            with self.assertRaises(rustleaks.BudgetExceededError):
                engine.scan(two)
            unlimited = rustleaks.Budget(finding_records=rustleaks.UNLIMITED)
            self.assertEqual(len(engine.scan(two, budget=unlimited)), 2)
            with self.assertRaises(rustleaks.BudgetExceededError):
                engine.scan(two, budget=rustleaks.Budget())

    def test_budget_error(self) -> None:
        with rustleaks.Engine(config=MARKER_CONFIG) as engine:
            with self.assertRaises(rustleaks.BudgetExceededError) as caught:
                engine.scan(marker_input() * 3, budget=rustleaks.Budget(finding_records=2))
        error = caught.exception
        self.assertIsInstance(error, rustleaks.IncompleteScanError)
        self.assertEqual(error.termination, "budget")
        self.assertEqual(error.budget, "finding_records")
        self.assertEqual(error.limit, 2)
        self.assertIsInstance(error.consumed, int)
        self.assertIsInstance(error.requested, int)
        self.assertIsInstance(error.usage, rustleaks.Usage)
        self.assertGreater(error.usage.work_units, 0)
        self.assertNotIn(MARKER_SECRET, exception_text(error))

    def test_very_long_timeouts(self) -> None:
        # Longer than the library's nanosecond deadline holds; the scan runs
        # as without a timeout.
        with rustleaks.Engine(config=MARKER_CONFIG) as engine:
            for timeout in (sys.float_info.max, 10**400, 2**64):
                with self.subTest(timeout=timeout):
                    self.assertEqual(len(engine.scan(marker_input(), timeout=timeout)), 1)

    def test_bad_scan_arguments(self) -> None:
        cases = [
            ({"path": 1}, TypeError),
            ({"path": b"config/app.env"}, TypeError),
            ({"timeout": -1}, ValueError),
            ({"timeout": float("nan")}, ValueError),
            ({"timeout": float("inf")}, ValueError),
            ({"timeout": True}, TypeError),
            ({"timeout": "1"}, TypeError),
            ({"cancel": object()}, TypeError),
            ({"decode_depth": True}, TypeError),
            ({"allow_comments": 0}, TypeError),
            ({"redaction": 1000}, ValueError),
            ({"base64_mode": "x"}, ValueError),
            ({"budget": 5}, TypeError),
        ]
        with rustleaks.Engine(config=MARKER_CONFIG) as engine:
            for options, error in cases:
                with self.subTest(options), self.assertRaises(error):
                    engine.scan(b"", **options)  # type: ignore[arg-type]
                with self.subTest(options, text=True), self.assertRaises(error):
                    engine.scan_text("", **options)  # type: ignore[arg-type]
            for data in ("text", 1, None, [1, 2]):
                with self.subTest(data=data), self.assertRaises(TypeError):
                    engine.scan(data)  # type: ignore[arg-type]
            for text in (b"bytes", 1, None):
                with self.subTest(text=text), self.assertRaises(TypeError):
                    engine.scan_text(text)  # type: ignore[arg-type]


class InputTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.engine = rustleaks.Engine(config=MARKER_CONFIG, max_input_bytes=64)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.engine.close()

    def secrets(self, findings: list[rustleaks.Finding]) -> list[bytes]:
        return [finding.secret for finding in findings]

    def test_bytes_like_inputs(self) -> None:
        data = marker_input()

        class Subclass(bytes):
            pass

        inputs = {
            "bytes": data,
            "bytearray": bytearray(data),
            "memoryview": memoryview(data),
            "slice": memoryview(b"xx" + data + b"yy")[2:-2],
            "subclass": Subclass(data),
            "array": array.array("B", data),
            "strided": memoryview(bytes(b for byte in data for b in (byte, 0)))[::2],
        }
        expected = self.engine.scan(data)
        self.assertEqual(len(expected), 1)
        for name, value in inputs.items():
            with self.subTest(name):
                self.assertEqual(self.engine.scan(value), expected)

    def test_buffer_is_released_and_copied(self) -> None:
        buffer = bytearray(marker_input())
        (finding,) = self.engine.scan(buffer)
        # A held export would make the resize fail.
        buffer.extend(b"more")
        buffer[:] = b"x" * len(buffer)
        self.assertEqual(finding.secret, MARKER_SECRET.encode())

    def test_input_limit(self) -> None:
        at_limit = marker_input().ljust(64, b" ")
        self.assertEqual(len(self.engine.scan(at_limit)), 1)
        for value in (at_limit + b" ", bytearray(65), memoryview(bytes(1000))):
            with self.subTest(type(value).__name__):
                with self.assertRaises(rustleaks.InputTooLargeError) as caught:
                    self.engine.scan(value)
                self.assertEqual(caught.exception.limit, 64)
                self.assertGreater(caught.exception.size, 64)

    def test_text(self) -> None:
        (finding,) = self.engine.scan_text("é name = MARK-" + MARKER_SECRET)
        # Offsets and columns count UTF-8 bytes; "é" takes two.
        self.assertEqual(finding.secret_range, range(15, 19))
        self.assertEqual(finding.start_column, 11)
        self.assertEqual(finding.secret, MARKER_SECRET.encode())

    def test_text_limit(self) -> None:
        with self.assertRaises(rustleaks.InputTooLargeError) as caught:
            self.engine.scan_text("x" * 65)
        self.assertEqual(caught.exception.size, 65)
        # 40 characters, 80 bytes.
        with self.assertRaises(rustleaks.InputTooLargeError) as caught:
            self.engine.scan_text("é" * 40)
        self.assertEqual(caught.exception.size, 80)
        self.assertEqual(len(self.engine.scan_text("é" * 32)), 0)

    def test_lone_surrogate(self) -> None:
        text = "MARK-" + MARKER_SECRET + " \ud800 tail"
        with self.assertRaises(rustleaks.TextEncodingError) as caught:
            self.engine.scan_text(text)
        error = caught.exception
        self.assertEqual(error.position, 10)
        self.assertIsNone(error.__cause__)
        self.assertIsNone(error.__context__)
        self.assertNotIn(MARKER_SECRET, exception_text(error))
        self.assertNotIn("tail", exception_text(error))

    def test_paths(self) -> None:
        cases = {
            "config/app.env": "config/app.env",
            "": None,
            "config\\app.env": "config\\app.env",
            "é/app.env": "é/app.env",
        }
        for path, expected in cases.items():
            with self.subTest(path):
                (finding,) = self.engine.scan(marker_input(), path=path)
                self.assertEqual(finding.path, expected)
        (finding,) = self.engine.scan(marker_input(), path=pathlib.PurePosixPath("a/b.env"))
        self.assertEqual(finding.path, "a/b.env")
        (finding,) = self.engine.scan(marker_input())
        self.assertIsNone(finding.path)
        with self.assertRaises(rustleaks.TextEncodingError):
            self.engine.scan(marker_input(), path="\udc80.env")

    def test_path_rule_with_a_windows_path(self) -> None:
        with rustleaks.Engine(rules=["pkcs12-file"]) as engine:
            (finding,) = engine.scan(b"", path="certs\\site.p12")
        self.assertEqual(finding.path, "certs\\site.p12")
        self.assertEqual((finding.start_line, finding.start_column), (0, 0))
        self.assertIsNone(finding.secret_range)

    def test_equal_lines_share_one_object(self) -> None:
        # The library shares one copy of a long line between its findings.
        line = b"MARK-AAAA " + b"x" * 5000 + b" MARK-BBBB\n"
        with rustleaks.Engine(config=MARKER_CONFIG) as engine:
            first, second = engine.scan(line)
        self.assertEqual(first.line, line[:-1])
        self.assertIs(first.line, second.line)
        self.assertIs(first.tags, second.tags)
        self.assertIs(first.rule_id, second.rule_id)


class FindingTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        with rustleaks.Engine(config=MARKER_CONFIG) as engine:
            (cls.finding,) = engine.scan(marker_input(), path="config/app.env")

    def test_repr_leaves_out_secret_bytes(self) -> None:
        for text in (repr(self.finding), str(self.finding), repr([self.finding])):
            self.assertNotIn(MARKER_SECRET, text)
            self.assertIn("synthetic-marker", text)
            self.assertIn("start_line=1", text)

    def test_frozen_and_comparable(self) -> None:
        with self.assertRaises(dataclasses.FrozenInstanceError):
            self.finding.secret = b""  # type: ignore[misc]
        same = dataclasses.replace(self.finding)
        self.assertEqual(same, self.finding)
        self.assertEqual(hash(same), hash(self.finding))
        self.assertNotEqual(dataclasses.replace(self.finding, secret=b"x"), self.finding)

    def test_cannot_be_pickled(self) -> None:
        for protocol in range(pickle.HIGHEST_PROTOCOL + 1):
            with self.subTest(protocol), self.assertRaises(TypeError):
                pickle.dumps(self.finding, protocol)

    def test_copies(self) -> None:
        self.assertIs(copy.copy(self.finding), self.finding)
        self.assertIs(copy.deepcopy(self.finding), self.finding)

    def test_types(self) -> None:
        finding = self.finding
        self.assertIsInstance(finding.secret, bytes)
        self.assertIsInstance(finding.match, bytes)
        self.assertIsInstance(finding.line, bytes)
        self.assertIsInstance(finding.tags, tuple)
        self.assertEqual(finding.match, b"MARK-" + MARKER_SECRET.encode())
        self.assertEqual(finding.match_range, range(7, 16))
        self.assertEqual(finding.secret_range, range(12, 16))


class LifecycleTest(unittest.TestCase):
    def test_close(self) -> None:
        engine = rustleaks.Engine(config=MARKER_CONFIG)
        self.assertFalse(engine.closed)
        self.assertIn("open", repr(engine))
        engine.close()
        engine.close()
        self.assertTrue(engine.closed)
        self.assertIn("closed", repr(engine))
        with self.assertRaises(rustleaks.ClosedError):
            engine.scan(marker_input())
        with self.assertRaises(rustleaks.ClosedError):
            engine.scan_text("text")
        with self.assertRaises(rustleaks.ClosedError):
            with engine:
                pass
        self.assertEqual([rule.id for rule in engine.rules()], ["synthetic-marker"])

    def test_context_manager(self) -> None:
        with rustleaks.Engine(config=MARKER_CONFIG) as engine:
            self.assertEqual(len(engine.scan(marker_input())), 1)
        self.assertTrue(engine.closed)

    def test_garbage_collected_engine_is_freed(self) -> None:
        library = _native.library()
        free = library.rustleaks_engine_free
        freed: list[int] = []

        def counting_free(handle: object) -> int:
            if handle:
                freed.append(1)
            return free(handle)

        library.rustleaks_engine_free = counting_free
        try:
            engine = rustleaks.Engine(config=MARKER_CONFIG)
            engine.scan(marker_input())
            del engine
            gc.collect()
            self.assertEqual(len(freed), 1)
            # A closed engine is freed by close, not again when collected.
            engine = rustleaks.Engine(config=MARKER_CONFIG)
            engine.close()
            del engine
            gc.collect()
            self.assertEqual(len(freed), 2)
        finally:
            library.rustleaks_engine_free = free

    def test_engines_and_tokens_cannot_be_pickled_or_copied(self) -> None:
        with rustleaks.Engine(config=MARKER_CONFIG) as engine:
            token = rustleaks.CancelToken()
            for value in (engine, token):
                with self.subTest(type(value).__name__):
                    name = type(value).__name__
                    for protocol in range(pickle.HIGHEST_PROTOCOL + 1):
                        with self.assertRaisesRegex(TypeError, f"^cannot pickle a rustleaks {name}$"):
                            pickle.dumps(value, protocol)
                    with self.assertRaisesRegex(TypeError, f"^cannot copy a rustleaks {name}$"):
                        copy.copy(value)
                    with self.assertRaisesRegex(TypeError, f"^cannot copy a rustleaks {name}$"):
                        copy.deepcopy(value)

    def test_token(self) -> None:
        token = rustleaks.CancelToken()
        self.assertFalse(token.cancelled)
        self.assertIn("not cancelled", repr(token))
        token.cancel()
        token.cancel()
        self.assertTrue(token.cancelled)
        self.assertNotIn("not", repr(token))


class ErrorTest(unittest.TestCase):
    def test_hierarchy(self) -> None:
        for error in (
            rustleaks.ConfigError,
            rustleaks.IncompleteScanError,
            rustleaks.InputTooLargeError,
            rustleaks.ClosedError,
            rustleaks.LibraryError,
            rustleaks.TextEncodingError,
        ):
            self.assertTrue(issubclass(error, rustleaks.Error))
        for error in (
            rustleaks.ScanCancelledError,
            rustleaks.ScanTimeoutError,
            rustleaks.BudgetExceededError,
        ):
            self.assertTrue(issubclass(error, rustleaks.IncompleteScanError))
        self.assertTrue(issubclass(rustleaks.Error, Exception))

    def test_errors_hold_no_scanned_bytes(self) -> None:
        errors: list[BaseException] = []
        with rustleaks.Engine(config=MARKER_CONFIG, max_input_bytes=20) as engine:
            for call in (
                lambda: engine.scan(marker_input() * 3),
                lambda: engine.scan_text(marker_input().decode() * 3),
                lambda: engine.scan(marker_input(), budget=rustleaks.Budget(finding_records=0)),
                lambda: engine.scan_text(marker_input().decode() + "\ud800"),
            ):
                try:
                    call()
                except rustleaks.Error as error:
                    errors.append(error)
            token = rustleaks.CancelToken()
            token.cancel()
            try:
                engine.scan(marker_input(), cancel=token)
            except rustleaks.Error as error:
                errors.append(error)
        try:
            engine.scan(marker_input())
        except rustleaks.Error as error:
            errors.append(error)
        self.assertEqual(
            [type(error) for error in errors],
            [
                rustleaks.InputTooLargeError,
                rustleaks.InputTooLargeError,
                rustleaks.BudgetExceededError,
                rustleaks.TextEncodingError,
                rustleaks.ScanCancelledError,
                rustleaks.ClosedError,
            ],
        )
        for error in errors:
            with self.subTest(type(error).__name__):
                self.assertNotIn(MARKER_SECRET, exception_text(error))
                self.assertIsNone(error.__cause__)
                self.assertIsNone(error.__context__)

    def test_native_error_kinds(self) -> None:
        cases = {
            _native.ERROR_CONFIG: (rustleaks.ConfigError, "config"),
            _native.ERROR_RULE_SELECTION: (rustleaks.ConfigError, "rule_selection"),
            _native.ERROR_ABI_MISMATCH: (rustleaks.LibraryError, "version"),
            _native.ERROR_ENGINE: (rustleaks.LibraryError, "engine"),
            _native.ERROR_PANIC: (rustleaks.LibraryError, "panic"),
        }
        for status, (error_type, kind) in cases.items():
            with self.subTest(status=status):
                error = _engine._status_error(status, "message")
                self.assertIs(type(error), error_type)
                self.assertEqual(error.kind, kind)  # type: ignore[attr-defined]
                with self.assertRaises(error_type):
                    _engine._check(status, "call")
        self.assertIs(type(_engine._status_error(_native.ERROR_INVALID_ARGUMENT, "m")), rustleaks.Error)

    def test_errors_can_be_pickled(self) -> None:
        original = rustleaks.BudgetExceededError(
            "budget",
            termination="budget",
            usage=rustleaks.Usage(work_units=3),
            budget="work_units",
            limit=1,
            consumed=1,
            requested=2,
        )
        copied = pickle.loads(pickle.dumps(original))
        self.assertIs(type(copied), rustleaks.BudgetExceededError)
        self.assertEqual(str(copied), "budget")
        self.assertEqual(copied.usage, original.usage)
        self.assertEqual((copied.limit, copied.consumed, copied.requested), (1, 1, 2))
        config = pickle.loads(pickle.dumps(rustleaks.ConfigError("bad", "rule_selection")))
        self.assertEqual(config.kind, "rule_selection")
        library = pickle.loads(pickle.dumps(rustleaks.LibraryError("bad", "panic")))
        self.assertEqual(library.kind, "panic")


if __name__ == "__main__":
    unittest.main()

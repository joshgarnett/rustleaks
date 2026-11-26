"""Runs every case of the shared binding corpus in testdata/bindings/.

The Rust test of the C ABI and the Go tests read the same cases. The
expected values are fixed by hand; a difference is a bug in the package or
the library, never a reason to change a case.
"""

from __future__ import annotations

import json
import unittest
from typing import Any

import support

import rustleaks

# Corpus error names and the exception that each one stands for.
ERRORS: dict[str, type[rustleaks.Error]] = {
    "config": rustleaks.ConfigError,
    "rule_selection": rustleaks.ConfigError,
    "input_too_large": rustleaks.InputTooLargeError,
    "budget_exceeded": rustleaks.BudgetExceededError,
}


def segments(value: list[Any]) -> bytes:
    """Joins corpus segments: strings are UTF-8 text, {"hex": ...} raw bytes."""
    parts = []
    for segment in value:
        if isinstance(segment, str):
            parts.append(segment.encode("utf-8"))
        else:
            if set(segment) != {"hex"} or len(segment["hex"]) % 2:
                raise ValueError(f"not a segment: {segment!r}")
            parts.append(bytes.fromhex(segment["hex"]))
    return b"".join(parts)


def engine_options(spec: dict[str, Any]) -> dict[str, Any]:
    options: dict[str, Any] = {}
    if spec["config"] is not None:
        with open(support.corpus_file(spec["config"]), "rb") as file:
            options["config"] = file.read()
    if spec["rules"] is not None:
        options["rules"] = spec["rules"]
    if "allow_comments" in spec:
        options["allow_comments"] = spec["allow_comments"]
    if "decode_depth" in spec:
        options["decode_depth"] = spec["decode_depth"]
    if "max_input_bytes" in spec:
        options["max_input_bytes"] = spec["max_input_bytes"]
    if "max_finding_records" in spec:
        options["budget"] = rustleaks.Budget(finding_records=spec["max_finding_records"])
    return options


class CorpusTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        with open(support.corpus_file("cases.json"), encoding="utf-8") as file:
            cls.cases = json.load(file)["cases"]
        # Building the built-in rules is slow in an unoptimized build, so
        # cases with the same engine share one.
        cls.engines: dict[str, rustleaks.Engine] = {}

    @classmethod
    def tearDownClass(cls) -> None:
        for engine in cls.engines.values():
            engine.close()

    def engine(self, spec: dict[str, Any]) -> rustleaks.Engine:
        key = json.dumps(spec, sort_keys=True)
        engine = self.engines.get(key)
        if engine is None:
            engine = self.engines[key] = rustleaks.Engine(**engine_options(spec))
        return engine

    def run_case(self, case: dict[str, Any]) -> list[rustleaks.Finding]:
        engine = self.engine(case["engine"])
        scan = case["scan"]
        return engine.scan(segments(scan["input"]), path=scan.get("path"))

    def test_corpus_is_well_formed(self) -> None:
        names = [case["name"] for case in self.cases]
        self.assertGreaterEqual(len(names), 30)
        self.assertEqual(len(names), len(set(names)))
        for case in self.cases:
            if case["expect"]["error"] is not None:
                self.assertEqual(case["expect"]["findings"], [], case["name"])

    def test_every_case(self) -> None:
        for case in self.cases:
            with self.subTest(case["name"]):
                self.check_case(case)

    def check_case(self, case: dict[str, Any]) -> None:
        expect = case["expect"]
        error = expect["error"]
        if error is not None:
            with self.assertRaises(ERRORS[error]) as caught:
                self.run_case(case)
            if isinstance(caught.exception, rustleaks.ConfigError):
                self.assertEqual(caught.exception.kind, error)
            self.assertTrue(str(caught.exception))
            return
        findings = self.run_case(case)
        self.assertEqual(len(findings), len(expect["findings"]), "finding count")
        path = case["scan"].get("path")
        for index, (actual, wanted) in enumerate(zip(findings, expect["findings"])):
            with self.subTest(finding=index):
                self.check_finding(actual, wanted, path)

    def check_finding(
        self, actual: rustleaks.Finding, wanted: dict[str, Any], path: str | None
    ) -> None:
        self.assertEqual(actual.rule_id, wanted["rule_id"])
        self.assertEqual(actual.secret, segments(wanted["secret"]))
        self.assertEqual(actual.match, segments(wanted["match"]))
        if "line" in wanted:
            self.assertEqual(actual.line, segments(wanted["line"]))
        self.assertEqual(
            (actual.start_line, actual.end_line, actual.start_column, actual.end_column),
            (
                wanted["start_line"],
                wanted["end_line"],
                wanted["start_column"],
                wanted["end_column"],
            ),
        )
        expected_range = wanted["secret_range"]
        if expected_range is None:
            self.assertIsNone(actual.secret_range)
        else:
            self.assertEqual(actual.secret_range, range(*expected_range))
        self.assertEqual(actual.path, path)


if __name__ == "__main__":
    unittest.main()

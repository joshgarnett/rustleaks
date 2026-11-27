"""Compares the package with rustleaks-core on a fixed set of files.

//crates/rustleaks-eval:binding_reference writes, at build time, the
findings that rustleaks-core reports for each file. This test scans the same
files through the package and requires the same findings in the same order.
It compares two implementations; it stores no expected values.
"""

from __future__ import annotations

import dataclasses
import json
import sys
import time
import unittest
from typing import Any

import support

import rustleaks


def reference_path() -> str:
    for path in support.runfiles("RUSTLEAKS_TEST_REFERENCE"):
        if path.endswith("binding-reference.json"):
            return path
    raise RuntimeError("no binding-reference.json in RUSTLEAKS_TEST_REFERENCE")


def repo_file(path: str) -> str:
    return support.runfile("_main/" + path)


def content(data: bytes, variant: str) -> bytes:
    """The scanned form of a file, as the reference tool makes it."""
    if variant == "file":
        return data
    if variant == "crlf":
        return data.replace(b"\n", b"\r\n")
    if variant == "no-final-newline":
        if not data.endswith(b"\n"):
            raise ValueError("no final line break to remove")
        return data[:-1]
    raise ValueError(f"unknown variant {variant!r}")


def as_range(value: list[int] | None) -> range | None:
    return None if value is None else range(value[0], value[1])


def compare(got: list[rustleaks.Finding], want: list[dict[str, Any]], path: str) -> list[str]:
    """The differences between the package findings and the core findings."""
    out = []
    if len(got) != len(want):
        out.append(f"{len(got)} findings, core reported {len(want)}")
    for index, (g, w) in enumerate(zip(got, want)):
        fields = {
            "rule_id": (g.rule_id, w["rule_id"]),
            "description": (g.description, w["description"]),
            "tags": (g.tags, tuple(w["tags"])),
            "secret": (g.secret, bytes.fromhex(w["secret"])),
            "match": (g.match, bytes.fromhex(w["match"])),
            "line": (g.line, bytes.fromhex(w["line"])),
            "start_line": (g.start_line, w["start_line"]),
            "end_line": (g.end_line, w["end_line"]),
            "start_column": (g.start_column, w["start_column"]),
            "end_column": (g.end_column, w["end_column"]),
            "secret_range": (g.secret_range, as_range(w["secret_range"])),
            "match_range": (g.match_range, as_range(w["match_range"])),
            "entropy": (g.entropy, w["entropy"]),
            "path": (g.path, path),
        }
        for name, (got_value, want_value) in fields.items():
            if type(got_value) is not type(want_value) or got_value != want_value:
                out.append(f"finding {index} {name} = {got_value!r}, core {want_value!r}")
        if out:
            # Later findings usually differ for the same reason.
            break
    return out


class ReferenceTest(unittest.TestCase):
    def test_findings_match_core(self) -> None:
        with open(reference_path(), encoding="utf-8") as file:
            inputs = json.load(file)["inputs"]
        self.assertTrue(inputs)
        files: dict[str, bytes] = {}
        for item in inputs:
            if item["path"] not in files:
                with open(repo_file(item["path"]), "rb") as file:
                    files[item["path"]] = file.read()
        started = time.monotonic()
        failures = []
        findings = 0
        rules: set[str] = set()
        with rustleaks.Engine() as engine:
            rule_count = len(engine.rules())
            for item in inputs:
                data = content(files[item["path"]], item["variant"])
                got = engine.scan(data, path=item["path"])
                difference = compare(got, item["findings"], item["path"])
                if difference:
                    failures.append(f"{item['path']} ({item['variant']}): {difference}")
                findings += len(item["findings"])
                rules.update(finding["rule_id"] for finding in item["findings"])
        self.assertFalse(
            failures,
            f"{len(failures)} of {len(inputs)} inputs differ from core:\n" + "\n".join(failures[:10]),
        )
        self.assertGreater(findings, 0)
        print(
            f"{len(inputs)} inputs from {len(files)} files, {findings} findings,"
            f" {len(rules)} of {rule_count} rules, {time.monotonic() - started:.1f} s",
            file=sys.stderr,
        )

    def test_compare_reports_each_field(self) -> None:
        want = {
            "rule_id": "rule",
            "description": "d",
            "tags": ["t"],
            "secret": b"s".hex(),
            "match": b"m".hex(),
            "line": b"l".hex(),
            "start_line": 1,
            "end_line": 1,
            "start_column": 2,
            "end_column": 3,
            "secret_range": [1, 2],
            "match_range": None,
            "entropy": 0.5,
        }
        same = rustleaks.Finding(
            rule_id="rule",
            description="d",
            tags=("t",),
            secret=b"s",
            match=b"m",
            line=b"l",
            start_line=1,
            end_line=1,
            start_column=2,
            end_column=3,
            secret_range=range(1, 2),
            match_range=None,
            entropy=0.5,
            path="p",
        )
        self.assertEqual(compare([same], [want], "p"), [])
        for name, value in {
            "tags": (),
            "secret": b"x",
            "line": b"l\r",
            "end_column": 4,
            "match_range": range(0, 0),
            "entropy": 0.25,
            "path": "q",
        }.items():
            changed = dataclasses.replace(same, **{name: value})
            self.assertNotEqual(compare([changed], [want], "p"), [], name)
        self.assertNotEqual(compare([], [want], "p"), [])


if __name__ == "__main__":
    unittest.main()

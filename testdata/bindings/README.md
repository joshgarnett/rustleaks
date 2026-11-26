# Binding contract cases

This folder holds the cases that every language binding must pass: the Rust
test of the C ABI, and the Go and Python package tests. Each binding builds
an engine and scans as a case says, and compares the result with the
expected error or findings.

| File | Contents | Read by |
| --- | --- | --- |
| `cases.json` | The cases | `//crates/rustleaks-ffi:contract_test`, the Go and Python binding tests |
| `configs/*.toml` | Synthetic configurations that cases name | The same tests |

The expected values are written by hand from the documented behavior in
[Line and column numbers](../../docs/user/reports.md#line-and-column-numbers),
[Configuration](../../docs/user/configuration.md) and
[Using rustleaks-core](../../docs/user/library.md). Never copy program
output into them. Every value is synthetic.

## Format

`cases.json` is an object with one key, `cases`, a list of cases. Each case
has:

- `name`: a unique, stable name.
- `engine`: how to build the engine.
  - `config`: a path relative to this folder, or `null` for every built-in
    rule.
  - `rules`: a list of rule IDs to select, or `null` for every rule.
  - `allow_comments` (optional, default `true`), `decode_depth` (optional,
    default 0), `max_input_bytes` (optional, default 10,000,000) and
    `max_finding_records` (optional, default 100,000): engine options.
- `scan`: one scan with the engine.
  - `input`: the scanned bytes, as a list of segments.
  - `path` (optional): the path given to the scan, as a string.
- `expect`: the result.
  - `error`: `null`, or the kind of error that building the engine or the
    scan returns: `config`, `rule_selection` or `input_too_large`.
    `budget_exceeded` means that the scan stopped because a budget ran
    out; a binding reports that as its incomplete scan error.
  - `findings`: the findings in order. Empty when `error` is not `null`.

A finding has `rule_id`; `secret`, `match` and `line` as lists of segments;
and `start_line`, `end_line`, `start_column` and `end_column`. `line` is
optional, and a runner checks it only when it is present. It also has `secret_range`, the `[start, end]` byte offsets of
the secret in the input. It is `null` when the secret has no exact range, as
for decoded text and path-only rules. Every finding of a case has the case's
`path`.

The cases `unterminated-last-line` and `match-over-the-last-line-end` leave
out `line`. When a match starts on, or runs to, a last line that has no line
break, core currently reports the text from the start of the input as the
line, not the last line alone. The intended `line` is the last line, so
these cases do not pin the current value. Add `line` back when core reports
the last line.

A segment is a JSON string, which stands for its UTF-8 bytes, or an object
`{"hex": "..."}` with an even number of hex digits, which stands for those
bytes. A list of segments stands for their bytes joined in order. Segments
keep NUL, invalid UTF-8 and line ends exact.

## Changing a case

The CI self-scan runs every built-in rule over this folder. Never write a
value that a rule finds as one literal. Split it across segments, as the
cases with `AKIA` do, so that the file holds no complete key.

A new or changed case follows [Rules for
tests](../../docs/dev/testing.md#rules-for-tests). The three binding tests
read the same file, so a change runs in all of them.

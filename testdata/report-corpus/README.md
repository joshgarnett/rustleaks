# Report corpus

These cases cover report output: the exact bytes of JSON, CSV, JUnit and
SARIF reports, redaction, SARIF rule order, links and symlink paths, writer
errors, an unknown format, and Go templates.

## Files

- `requests-v1.jsonl`: 49 cases. `format` is `json` (13 cases), `csv` (7),
  `junit` (6), `sarif` (7), `template` (15) or `yaml` (1, an unknown
  format). `findings` lists the findings to write, with byte fields in
  base64. Optional fields set `redact_percent`, `ordered_rules` (the SARIF
  rule list), `fail_after_bytes` (the writer fails after this many bytes),
  and `template_base64` with `template_mode` for templates.
- `outcomes-v1.jsonl`: the expected result of each case. `output_base64` is
  the exact report. `error` is `null`, or an object whose `class` names the
  error, such as `writer` or `format`.
- `coverage-v1.json` and `native-windows-v1.json`: coverage notes and
  Windows hashes from when the cases were recorded. No test reads them.

JUnit and SARIF outcomes name the tool `gitleaks`. The test replaces that
name with the Rustleaks name, version and repository before it compares; see
`crates/rustleaks-report/tests/support/tool_identity.rs`.

## Tests

`//crates/rustleaks-report:report_corpus_test` writes each JSON, CSV, JUnit
and SARIF case and compares the bytes with `output_base64`. It lists by ID
the cases that it does not compare byte for byte (malformed requests, a nil
tag list and the JUnit writer error) and the 15 `template` cases.
`//crates/rustleaks-report:template_test` lists the same 15 template IDs and
covers them with its own inputs.

Because the comparison is byte for byte, these cases also fix JSON key order
and CSV column order.

## Origin and changes

The cases were recorded from Gitleaks at commit `b58d3f1` (MIT, see
[`NOTICE`](../../NOTICE)). See [Changing a case](../README.md#changing-a-case).

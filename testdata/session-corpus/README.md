# Session corpus

These cases cover what happens to findings after detection. They test
fingerprints and the order in which findings are collected. They test
`.gitleaksignore` files: global and commit entries, comments, blank and
malformed lines, duplicates and path separators. They also test baselines:
which fields are compared and which are ignored, invalid and missing files,
and redaction.

## Files

- `requests-v1.jsonl`: 45 cases. `findings` lists the findings of the scan.
  `ignore_file` and `baseline_file` are `null` or a file with `name`,
  `content_base64` and `missing` (true when the file does not exist).
  `redact_percent` sets redaction.
- `outcomes-v1.jsonl`: the expected result of each case. `ignore` and
  `baseline` describe the loaded files. `decisions` has one entry per input
  finding, with its fingerprints, whether the ignore file or the baseline
  removes it, and its `disposition`. `collected_findings` lists the kept
  findings in collection order, and `canonical_findings` in sorted order.
  `error.class` is `ignore-open`, `baseline-open` or `baseline-format` when
  a file cannot be read.
- `coverage-v1.json`, `negative-controls-v1.json` and `manifest-v1.json`:
  coverage notes, counts and hashes from when the cases were recorded. No
  test reads them.

## Tests

`//crates/rustleaks-core:session_corpus_test` replays every case and checks
that there are 45.

## Origin and changes

The cases were recorded from Gitleaks at commit `b58d3f1` (MIT, see
[`NOTICE`](../../NOTICE)). See [Changing a case](../README.md#changing-a-case).

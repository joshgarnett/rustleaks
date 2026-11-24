# Regex corpus

These cases cover the Go regular expression syntax that rules use: which
patterns compile, capture groups, and every non-overlapping match in an
input, including empty matches and invalid UTF-8. A malformed UTF-8 byte
counts as one character, and all positions are byte offsets.

## Files

- `requests-v1.jsonl`: 3,618 cases. Each case has an `id`, a pattern in
  `pattern_base64` and an input in `input_base64`.
- `outcomes-v1.jsonl`: the expected result of each case, in the same order.
  `compile.success` says whether the pattern compiles, with
  `capture_count` and `capture_names`. `matches` lists each match as a
  `span` (start and end byte) and its `captures`. Capture 0 is the whole
  match, and a capture that did not take part is `[-1, -1]`. In 37 cases
  the pattern does not compile.
- `manifest-v1.json`: counts. The test reads `request_count` and
  `compile_error_count`, so update them when you add or remove a case.
- `expressions-v1.jsonl`: the patterns that the cases were built from, one
  line for each of the 436 places where a pattern appears in the Gitleaks
  default configuration or the configuration fixtures. No test reads it.
- `request-metadata-v1.jsonl`: the category and hashes of each case. No test
  reads it.

## Tests

`//crates/rustleaks-core:rustleaks_core_unit_test` reads the corpus in
`src/regex/mod.rs`, which compares every outcome, and in the regex
validation, literal prefilter and differential tests, which use the
patterns and inputs. The comparison in `src/regex/mod.rs` allows only the
differences that it lists by case ID (two cases for the character
`U+105C0`).

The `go_regex` fuzz target takes its seeds from `requests-v1.jsonl`. See
[the core fuzz targets](../../crates/rustleaks-core/fuzz/README.md).

## Origin and changes

The cases were recorded from Gitleaks at commit `b58d3f1` (MIT, see
[`NOTICE`](../../NOTICE)). See [Changing a case](../README.md#changing-a-case).

# Composite corpus

These cases cover required (composite) rules, the suppression of generic
findings by more specific rules, and redaction. They include missing and
repeated required findings, proximity limits, cycles in required rules, and
redaction percentages.

## Files

- `requests-v1.jsonl`: 182 cases. `operation` is one of:
  - `detect` (143 cases): scan `fragment` with `options` and the
    configuration in `config_base64`, in `config_fixture` (a file under
    `../fixtures/upstream/testdata/config/`), or in `config_files` (a set of
    files for `[extend]` paths, where `config_entry` names the file to load).
  - `redact` (29 cases): redact the finding in `redaction` by
    `redact_percent`.
  - `mask_secret` (4 cases) and `filter_probe` (5 cases): call the internal
    secret mask and final finding filter directly.
  - `probe_missing_required` (1 case): a required rule that names a missing
    rule.
- `outcomes-v1.jsonl`: the expected result of each case. `findings` lists the
  expected findings, each with its `required_findings`. For `redact`,
  `original` and `redacted` are the finding before and after redaction.
  `mask_secret_base64` is the expected mask.
- `coverage-v1.json`, `negative-controls-v1.json` and `manifest-v1.json`:
  coverage notes, counts and hashes from when the cases were recorded. No
  test reads them.

## Tests

- `//crates/rustleaks-core:composite_corpus_test` replays the `detect` and
  `redact` cases. It skips cases with a negative `start_line`, which
  Rustleaks cannot represent, and six large `resource-*` cases, and it
  lists the skipped case IDs. Separate tests in the same file replay five of
  the `resource-*` cases only when the `RUSTLEAKS_BOUNDED_RESOURCE_TEST`
  environment variable names the test.
- `//crates/rustleaks-core:rustleaks_core_unit_test` replays the
  `filter_probe` cases (in `src/engine/tests.rs`) and the `mask_secret`
  cases (in `src/model.rs`).

## Origin and changes

The cases were recorded from Gitleaks at commit
`b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b` (MIT, see the repository
[`NOTICE`](../../NOTICE)). The outcomes are the expected Rustleaks behavior.
To change a case, edit the JSONL by hand or with a small script in a
reviewed change, keep byte fields in base64, and write the expected value
from the intended behavior. See [Changing a case](../README.md#changing-a-case).

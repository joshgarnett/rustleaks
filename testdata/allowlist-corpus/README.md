# Allowlist corpus

These cases cover allowlists: validation, the commit, path, regex and stop
word checks, `condition = "OR"` and `"AND"`, regex targets (secret, match and
line), global and rule allowlists, and allowlists from extended
configurations.

## Files

- `requests-v1.jsonl`: 188 cases. `operation` is `method` (127 cases) or
  `detect` (61 cases).
  - A `method` case calls one allowlist check. `method` names the check
    (`commit`, `path`, `regex` or `stopword`), `allowlist` holds the
    allowlist fields, and `input_base64` is the value to check. `validate`
    says whether the allowlist is validated first.
  - A `detect` case scans `fragment` with the configuration in
    `config_base64`, or with `config_fixture`, a file under
    `../fixtures/upstream/testdata/config/`. `config_files` adds extra files
    for `[extend]` paths.
- `outcomes-v1.jsonl`: the expected result of each case. `validation` is the
  validation result, `normalized` is the allowlist after validation,
  `method_result` is the result of the check, and `findings` lists the
  expected findings of a `detect` case.
- `coverage-v1.json`: behavior notes. No test reads it.
- `request-metadata-v1.jsonl` and `manifest-v1.json`: counts and hashes from
  when the cases were recorded. No test reads them.

## Tests

`//crates/rustleaks-core:allowlist_test` replays the corpus. It runs every
`detect` case and every validated `method` case. Rustleaks cannot build the
other `method` cases (for example an allowlist that was never validated), so
the test counts them and checks the totals. The test also checks the number
of cases of each kind, so update those counts when you add or remove a case.

## Origin and changes

The cases were recorded from Gitleaks at commit `b58d3f1` (MIT, see
[`NOTICE`](../../NOTICE)). See [Changing a case](../README.md#changing-a-case).

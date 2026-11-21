# Configuration corpus

These cases cover configuration loading: the default configuration, the 50
configuration fixtures under `../fixtures/upstream/testdata/config/`, and
focused cases for parsing, validation, aliases, required rules, allowlists
and `[extend]`.

## Files

- `requests-v1.jsonl`: 112 cases. `source.kind` says how the configuration
  is loaded:
  - `default`: load the default configuration.
  - `inline`: load the TOML in `source.config_base64`.
  - `path` and `origin`: load `source.config_base64` as if it came from
    `source.path` or `source.origin`, so that relative `[extend]` paths
    resolve against it.
- `inputs-v1.jsonl`: 66 configuration files that `[extend]` paths can name,
  with `path` and the file in `config_base64`. 50 are the upstream fixtures
  and 16 are extra files for the focused cases.
- `outcomes-v1.jsonl`: the expected result of each case. 75 cases load:
  `effective` is the loaded configuration, with rules in order, keywords,
  allowlists and the `[extend]` settings. 37 cases fail: `error.class`
  names the error, such as `parse`, `unmarshal`, `rule`, `allowlist`,
  `required-rule`, `extension` or `panic` (an invalid regular expression).
  `diagnostics` lists log messages; the test does not compare them.
- `default-gitleaks.toml`: the Gitleaks default configuration at the commit
  below. The test uses it as the default configuration for these cases. It
  is not the shipped default rule set, which is
  `../../crates/rustleaks-core/default/gitleaks.toml`.
- `schema-v1.json` and `manifest-v1.json`: the record layout, counts and
  hashes from when the cases were recorded. No test reads them.

## Tests

`//crates/rustleaks-core:config_test` replays every case and checks that 112
cases ran. For `allowlist`, `rule` and `required-rule` errors it also
compares `error.message` with the Rustleaks error text.

## Origin and changes

The cases and `default-gitleaks.toml` were recorded from Gitleaks at commit
`b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b` (MIT, see the repository
[`NOTICE`](../../NOTICE)). Keep `default-gitleaks.toml` byte for byte. The
outcomes are the expected Rustleaks behavior. To change a case, edit the
JSONL by hand or with a small script in a reviewed change, keep byte fields
in base64, and write the expected value from the intended behavior. See
[Changing a case](../README.md#changing-a-case).

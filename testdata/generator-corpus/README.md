# Generator corpus

`samples-v1.jsonl` holds 6,770 positive and negative samples for 220 default
rules. Each sample is one input for one rule, with the findings that the rule
must report on it. The samples come from the sample checks in the Gitleaks
rule generator (`cmd/generate`). They are synthetic test values, not live
credentials.

## Fields

- `case_id`: the stable name of the sample.
- `rule_id`: the rule to run. The test runs only this rule.
- `polarity` and `contract`:
  - `ordinary_true` (6,368 samples), contract `at_least_one`;
  - `ordinary_false` (342 samples), contract `zero`;
  - `path_true` (28 samples), contract `exactly_one`;
  - `path_false` (32 samples), contract `zero`.
- `input_base64`: the scanned text.
- `path_present` and `path_base64`: the file path of a path sample.
  `path_base64` is `null` when no path is given.
- `oracle_observed_count` and `findings`: the expected number of findings,
  and the expected `match_base64` and `secret_base64` of each finding, in
  order.

The other fields record where the sample came from in the generator source
(`constructor`, `helper`, `source_file`, line numbers, `template_key`) and
its hashes. The tests do not read them. Duplicate samples stay as separate
rows.

## Tests

- `//crates/rustleaks-core:default_rule_corpus_test` runs each sample with
  its rule from the shipped default rules and checks the count, the
  contract, and the match and secret of each finding. It also checks the
  totals above.
- `//crates/rustleaks-core:default_rule_cases_test` and
  `//crates/rustleaks-core:rule_precedence_test` use the positive samples as
  inputs for other checks.
- `//crates/rustleaks-core:rustleaks_core_unit_test` uses the samples in the
  regular expression and literal prefilter tests.

`cargo xtask compare-workloads` also reads the samples as scan inputs.

## Origin and changes

The samples were recorded from Gitleaks at commit `b58d3f1` (MIT, see
[`NOTICE`](../../NOTICE)). See [Changing a case](../README.md#changing-a-case).

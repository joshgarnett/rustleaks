# Synthetic detection quality corpus

This corpus measures detection and exact secret locations on a small set of
synthetic examples written for Rustleaks. The labels are written from the
intended input, not from detector output. Unlike the other corpora in
`testdata/`, none of its cases come from Gitleaks. It does not estimate
precision on real repositories, check that a value is a valid provider
format, or check whether a credential works.

`crates/rustleaks-eval/src/evaluation/generator.rs` generates
`cases-v1.json`, using the separate case catalog in `native_cases.rs`. The evaluator
writes `baseline-v1.json`. Both files are generated; do not edit them by
hand. All material in this corpus is covered by the repository's MIT license.
It contains no live credentials and no external data.

## Generate and replay

Format the generator and evaluator, then run from the repository root:

```sh
bazelisk run //crates/rustleaks-eval:rustleaks_quality -- generate
bazelisk run //crates/rustleaks-eval:rustleaks_quality -- baseline
bazelisk run //crates/rustleaks-eval:rustleaks_quality -- check
bazelisk run //crates/rustleaks-eval:rustleaks_quality -- check-baseline
```

`just quality-eval` checks the corpus and prints the current report. The
`rustleaks-eval` unit tests check that the corpus regenerates exactly, that
the baseline replays, and that the metrics match hand-calculated controls.
Regeneration can change source fingerprints without changing counts. Review
counts and labels on their own. Never change a label to improve a detector's
result.

## Labels

Each input byte belongs to exactly one of three kinds of region:

- a positive: one secret occurrence. Its label holds the decoded secret
  bytes, the exact source range, the family and the expected rule IDs. These
  bytes are test inputs, not active credentials.
- a reviewed negative: bytes that must not produce a finding.
- an unknown region: bytes that are not scored.

For an encoded secret, the source range names the fixture bytes. It does not
mean that the engine can map the decoded value back to an exact range.

## Cases

The corpus has 72 cases: 19 base cases and 53 cases for the
`rustleaks-extra-v1` pack (from `native_cases.rs`).

The base cases cover provider patterns, generic assignments, provider and
generic rules on the same value, repeated values, paired fields, invalid
UTF-8, percent encoding, multiline private-key-shaped text, documentation and
vendor paths, harmless identifiers, near misses, placeholders and unknown
labels. One case has an `api_key` field with a harmless generated identifier,
to test false alerts. The key-shaped block is not a usable key.

The pack cases cover the pack's three families: Azure Service Bus keys, Azure
App Configuration keys (both with connection string fields in different
orders), and MongoDB passwords (with raw and percent-encoded user names and
passwords). They include encoded values, repeated
values, invalid bytes, templates, malformed near misses, and known gaps for
sovereign cloud endpoints and IPv6 hosts. The pack's format references and
decisions are in
[`rustleaks-extra-v1.md`](../../crates/rustleaks-core/default/rustleaks-extra-v1.md).

Each case is in one of two splits: `tune` or `holdout`. Related cases share a
group (`leakage_group`), and a group stays in one split. All cases from one
pack family share a split. Validation rejects a group, an identical input or
an intended secret value that appears in both splits. These checks cannot
find every near duplicate. The cases are written from provider
specifications, so `holdout` does not mean unseen real-world data. The corpus
is small and is not a sample of real repositories.

## Assessments

Two assessments score every positive on the same inputs:

- `all-default-rules` uses every built-in rule, as a scan does by default:
  `gitleaks.toml` and the `rustleaks-extra-v1`, `rustleaks-providers-v1` and
  `rustleaks-connections-v1` rule files.
- `gitleaks-toml-rules` uses the rules in `gitleaks.toml` alone. It shows
  what the Rustleaks rule files add.

Neither assessment changes a rule.

A single-rule assessment selects one rule from the built-in rules and
scores only the positives that expect that rule.
Other positives become unknown regions for that assessment, so a provider
rule is not penalized for other providers' secrets.
`scored_positive_indices` refers to the positions of the positives in the
original case.

## Metrics

An observed occurrence is one exact source range with one secret value. More
alerts for the same occurrence count as duplicate alerts. Attribution is
correct if any alert for the occurrence names an expected rule. Alert order
does not matter.

- Exact-span precision is TP / (TP + FP). Duplicate alerts are not counted.
- Exact-span recall is TP / (TP + FN). An alert with the wrong range does not
  match a label.
- Case-distinct-value recall counts the distinct secret values found anywhere
  in each case, even when no exact range is available. A value repeated in one
  case counts once. Totals add up the per-case counts. This measures value
  recognition, not coverage of each occurrence.
- An alert in an unknown region is an unknown alert. An alert without a range
  is an unlocated alert. Neither counts as a false positive. An expected
  occurrence without an exact match is still an exact-span false negative,
  even when its value was found. For decoded findings, read both recall
  metrics together.
- A located alert that matches no label is a false positive. An alert that
  overlaps a positive with the wrong range or value also counts as a location
  mismatch. Reviewed-negative alert density counts only alerts outside
  positive and unknown regions, per MiB of reviewed negative bytes.
- A rate with a zero total is written as `null`, never as a perfect score.
  Per-family TP and FN counts and per-case results show the counts behind
  each rate.

## Limits and exit status

Each scan has limits on work, decoded bytes and finding records. An
incomplete scan keeps the indices of positives it did not find, the reason it
stopped and an `incomplete` status. It is never reported as a complete clean
scan. `measured` means only that the scans completed. It is not an accuracy
threshold. A passing `check-baseline` means the results are reproducible, not
that every label passed.

The tool exits 0 when it writes a report or verifies a file, also when the
report status is `incomplete`. It exits 1 for invalid input or an operational
failure. Automation must read the scan status and counts before it accepts a
detection result.

## Report contents

Reports leave out source text, paths and secret bytes. They keep case IDs,
rule selections and counts; the case IDs are synthetic names. JSON parse
errors do not repeat the input. This does not make user-supplied metadata
safe to publish.

Reports record the SHA-256 of `gitleaks.toml` (`DEFAULT_CONFIG_SHA256`), the
fingerprint of each built-in rule file, the rule profile (`default-rules`),
the generator and evaluator source fingerprints and the corpus fingerprint. These fingerprints use FNV-1a, which detects accidental changes
but does not prove authenticity. Saved run evidence must also record the
source revision and build identity. The report fingerprints do not identify a
release binary.

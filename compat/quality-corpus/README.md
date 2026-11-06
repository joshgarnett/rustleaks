# Synthetic detection quality corpus

This corpus measures detection and exact-location behavior on a small set of
first-party synthetic examples. Its labels are independent of detector output.
It is separate from the pinned Go oracle corpora and does not estimate deployment
precision, provider-format validity, or credential activity.

The maintained generator is
`crates/rustleaks-compat/src/evaluation/generator.rs` with the independent
`pilot.rs` catalog. It produces
`cases-v1.json`; the evaluator produces `baseline-v1.json`. Both files are
generated and must not be hand-edited. All material in this corpus is covered by
the repository's MIT license. No live credentials or external datasets are used.

## Generate and replay

Run from the repository root after formatting the generator and evaluator:

```sh
bazelisk run //crates/rustleaks-compat:rustleaks_quality -- generate
bazelisk run //crates/rustleaks-compat:rustleaks_quality -- baseline
bazelisk run //crates/rustleaks-compat:rustleaks_quality -- check
bazelisk run //crates/rustleaks-compat:rustleaks_quality -- check-baseline
```

`just quality-eval` checks the maintained corpus and prints its current report.
The compat unit tests verify exact corpus regeneration, baseline replay, and
hand-calculated metric controls. Regeneration can update source fingerprints
without changing counts. Review counts and labels independently: never change a
label merely to improve a detector's result.

## Labels and scope

Every input byte belongs to one non-overlapping positive occurrence, reviewed
negative region, or unknown region. Positive labels carry the intended decoded
secret bytes, its exact source extent, family, and expected provider rule IDs.
Those bytes are test inputs, never evidence of an active credential. Encoded
source extents identify known fixture bytes; they do not grant the engine an
exact source mapping it cannot provide.

The catalog contains 72 cases: 19 original controls and 53 native-pilot
controls. The original cases cover provider patterns, generic assignments,
provider/generic overlap, repeated occurrences, paired fields, invalid UTF-8,
percent decoding, multiline private-key-shaped material, documentation/vendor
paths, benign identifiers, near misses, placeholders, and unknown labels. A
misleading `api_key` field containing a benign generated identifier deliberately
challenges false-alert handling. The key-shaped block is not a usable key.

Related variants share a leakage group and stay in one tune or holdout split.
Validation rejects groups, identical inputs, and intended secret values shared
across splits. These mechanical checks supplement the explicit group labels;
they cannot discover all semantic near-duplicates. This catalog is deliberately
small and does not provide an independent real-world holdout population.

The pilot adds three provider families, Azure field-order permutations,
MongoDB raw and percent-encoded userinfo, encoded envelopes, repeated
occurrences, invalid bytes, templates, malformed near misses and explicit
sovereign-endpoint/IPv6 coverage gaps. The bounded pack's format references and
dispositions are in
[`rustleaks-extra-v1.md`](../../crates/rustleaks-core/default/rustleaks-extra-v1.md).
All variants from one pilot family share a split. These are specification-based
structural controls; their `holdout` label does not imply unseen real-world data.

The full-default and full-native assessments score every positive on identical
inputs. The native assessment explicitly selects `rustleaks-extra-v1`; it does
not change default evaluation or either copied Gitleaks configuration.
Individual-rule assessments score only positives attributed to that rule; other positive regions become
unknown for that assessment. `scored_positive_indices` refers to the original
case labels. A provider-specific rule is therefore not penalized for unrelated
provider families.

## Metrics

One exact source range and secret value form an observed occurrence. Repeated
alerts for that occurrence count separately as duplicate alerts. Attribution is
correct if any alert for the matched occurrence names an expected rule; order
does not affect this decision.

- Exact-span precision is TP / (TP + FP), with duplicate alerts excluded.
- Exact-span recall is TP / (TP + FN). A wrong span does not match a label.
- Case-distinct-value recall counts intended distinct secret values recognized
  anywhere in each case, even when an exact source mapping is unavailable.
  Repeated identical values within one case count once; totals sum these
  per-case counts. This is value recognition, not occurrence coverage.
- Unknown regions produce unknown alerts, and missing mappings produce unlocated
  alerts. Neither is counted as a false positive. An expected occurrence lacking
  an exact match remains an exact-span false negative, even when its value was
  recognized. Read both recall metrics together for decoded findings.
- A located unmatched alert is a false positive. Alerts overlapping a positive
  with the wrong range/value also increment location mismatches. Only alerts
  outside positive and unknown regions contribute to reviewed-negative alert
  density, reported per MiB of explicitly labeled negative bytes.
- Undefined rates serialize as `null`, never as perfect scores. Per-family
  exact-span TP/FN and per-case results retain small-denominator context.

Scans have explicit work, decoded-byte and finding-record limits. An incomplete
scan retains missing-positive indices, termination and an `incomplete` assessment
status. It cannot be reported as a complete clean scan. `measured` means only
that scans completed; it is not an accuracy acceptance threshold. Successful
`check-baseline` means reproducibility, not that every detector label passed.
The CLI exits zero when it successfully emits a report or verifies an artifact,
including a report whose status is `incomplete`; invalid inputs or operational
failures exit one. Automation must inspect scan status and counts before making
a detector-quality acceptance decision.

Reports omit source text, paths, and secret bytes. Case IDs, rule selections and
counts remain metadata; the maintained identifiers are chosen synthetic labels.
JSON parse failures do not echo arbitrary input. This is not a general promise
that user-supplied metadata is safe to publish.

The loaded default bytes must equal the checked-in compatibility mirror. The
repository's existing pin/hash gate verifies that mirror's SHA-256. Reports also
record the loaded-byte fingerprint, declared pin, native pack identity and bytes,
generator/evaluator source
fingerprints and corpus fingerprint. FNV-1a is used for accidental-drift checks,
not authenticity or collision resistance. Retained execution evidence must also
record source revision and build identity; these report fingerprints do not
attest a release binary.

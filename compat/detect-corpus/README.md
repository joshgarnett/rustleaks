# Go direct-detector corpus

This directory freezes raw direct-fragment behavior from Gitleaks
commit `b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b` and Go 1.25.0. Generate it with:

```sh
cargo xtask generate detect
cargo xtask generate detect --check
```

`--check` verifies the sibling revision, exact default-config SHA-256, and
expected read-only sibling status; runs the Go oracle tests; executes every
request through the explicit `--detect` mode; and byte-compares all generated
artifacts. The manifest is the source of truth for counts and hashes.

The gate is intentionally limited to the raw pass (`max_decode_depth = 0`) and
zero redaction. It covers effective-map/duplicate execution, the global keyword
prefilter, path-only and path-plus-regex rules (including retained Windows
paths), `skipReport`, full/implicit/explicit capture selection, strict entropy
thresholds, byte-based locations and source lines, newline trimming, the
case-sensitive `gitleaks:allow` toggle, and the decimal-megabyte target limit.
Eight records reproduce upstream
`detect/detect_test.go` cases with their `TM-*` identities; the focused records
freeze additional byte and boundary behavior. `AS-LOCATION-*` links identify
the two upstream private-location assertions; because the helper is private,
the JSONL invokes location through the public detector path and does not claim
a standalone call to the private function.

`matrix-coverage-v1.json` reconciles all 42 deterministic rows in
the deterministic detector matrix to committed requests. `M4-ENT-008` is
kept out of deterministic JSONL: Go map iteration produces both zero- and
one-finding outcomes at the exact threshold. The real-detector Go test
`TestDirectDetectorEntropyThresholdOutcomeSet` performs 100,000 bounded scans,
requires both outcomes, and requires every accepted finding to have entropy
bits `0x4046a218`. D-0012 resolves the outcome set: the Rust parity gate also
proves its selected admissible scalar-order f64 result and threshold predicate.

All request content, config, paths, commit metadata, and every text-bearing
finding field use standard base64. Consequently invalid UTF-8 survives both
directions without JSON replacement. Entropy is stored as exact
`math.Float32bits`. Findings preserve duplicates and are sorted only by their
complete canonical JSON representation to remove upstream rule-map order.
Every public `report.Finding` field is represented: `Fragment` is explicitly
nullable and `required_findings` is explicitly an empty array in this
pre-composite gate. Direct `Detect` does not assign fingerprints, so that field
is present and empty.

The metadata case supplies `remote_platform: "none"` with an empty remote URL.
That is the upstream `NoPlatform` sentinel required when a `CommitInfo` is
present; a nil `CommitInfo.Remote` is dereferenced by the pinned detector.
Nonempty SCM link generation is a later source/SCM concern. The generator
rejects any nonempty URL, any platform other than empty/`none`, or any nonempty
finding link.

Out of this gate: allowlists, decoding, composite/required rules, generic-rule
suppression, redaction, baselines, ignore/session filtering, and source/SCM
orchestration.

Files:

- `requests-v1.jsonl`: exact protocol inputs, behavior IDs, and upstream trace
  links;
- `outcomes-v1.jsonl`: canonical pinned-Go observations;
- `request-metadata-v1.jsonl`: per-record byte counts, hashes, and finding
  counts;
- `matrix-coverage-v1.json`: every semantic-audit row and its request/evidence
  disposition;
- `manifest-v1.json`: corpus version, scope, exclusions, totals, and whole-file
  hashes.

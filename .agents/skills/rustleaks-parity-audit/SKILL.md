---
name: rustleaks-parity-audit
description: Audit Rustleaks functional compatibility against frozen historical Gitleaks evidence and Rust contracts by reconciling traceability, replaying Rust regressions and classifying each difference as functional or presentation. Use for parity reviews and unexplained baseline-versus-Rust outcomes, not general test failures.
---

# Rustleaks parity audit

Audit evidence, not similarity. Read the [compatibility
policy](../../../docs/user/gitleaks-differences.md#compatibility-policy),
`docs/dev/testing-and-parity.md`,
`compat/upstream-revision.txt`, `compat/test-manifest.toml`,
`compat/behavior-matrix.toml`, `compat/presentation-dispositions.toml`,
`compat/api-inventory-v1.json`, and `compat/api-dispositions-v1.jsonl` before
selecting a scope.

## Select and reconcile the boundary

Map the reported behavior to one or more maintained scopes: bootstrap,
configuration, regular expressions, detection, allowlists, decoding,
composite rules, sessions, sources, Git, reports, or CLI. Inspect that scope's
README, manifest, requests, outcomes, coverage, negative controls, and Rust
tests. Confirm that every claimed upstream identity has a direct Rust test or
a precise disposition and that revision/config identities agree.

Use only synthetic inputs or reviewed upstream fixtures. Preserve raw bytes,
spans, locations, finding fields, fingerprints, report fields, error classes,
ordering, and exit behavior in the comparison. Redact secret values in review
notes.

## Run the evidence

For a narrow committed replay, use the relevant Bazel target, for example:

```sh
bazelisk test //crates/rustleaks-core:detect_corpus_test
```

Run the complete committed replay with:

```sh
just parity
```

Verify offline integrity, local traceability and Rust replay with:

```sh
cargo xtask regression-check
```

Use `cargo xtask qualify` for complete local release hardening against a clean,
committed candidate. The live Go oracle and upstream rediscovery are retired.
Historical generator commands are provenance, not current instructions.

Do not edit accepted outcomes to make a replay pass. Reproduce an unexplained
difference in a temporary corpus or focused test first.

## Classify differences

Assign each difference exactly one disposition:

- exact supported behavior after correcting the harness or Rust code;
- a named safe Rust disposition with an executable negative control;
- an explicit profile exclusion requiring maintainer approval;
- a presentation disposition for a reviewed change to help, usage, error
  wording, log, banner or summary text; or
- a Rustleaks defect.

A presentation disposition needs a reviewed expectation that matches the
stated intent of the change, but not maintainer approval. For frozen CLI
evidence, record it in `compat/presentation-dispositions.toml`. Never use a
presentation disposition for exit status, findings, reports, error class,
severity, child process cleanup, or disclosure. JSON key order and CSV column
order are presentation under the policy, but report and findings comparisons
still pin them. Changing that order first needs a reviewed change to those
comparisons so that they compare parsed fields; a disposition alone cannot
cover it.

Record permitted nondeterministic ordering separately as a documented
normalization. It is not a difference disposition.

Never normalize findings, spans, fingerprints, report fields, error classes,
suppression, or exit status. A missing mapping, stale artifact, unclassified
outcome, unused presentation disposition, or unapproved exclusion is a failed
audit.

Report the pinned identities, scope and cases, commands and results, each
difference and its field, classification, tests or artifacts changed, remaining
native gaps, and PASS or FAIL. Compatibility-sensitive fixes must finish with
`just ci`; add `just security` when hostile-input or dependency boundaries
changed.

---
name: rustleaks-parity-audit
description: Audit Rustleaks compatibility against the pinned Gitleaks oracle by reconciling traceability, replaying committed and fresh corpora, and classifying exact semantic differences. Use for parity reviews and unexplained Go-versus-Rust outcomes, not general test failures.
---

# Rustleaks parity audit

Audit evidence, not similarity. Read `docs/COMPATIBILITY.md`,
`compat/upstream-revision.txt`, `compat/test-manifest.toml`,
`compat/behavior-matrix.toml`, `compat/api-inventory-v1.json`, and
`compat/api-dispositions-v1.jsonl` before selecting a scope.

## Select and reconcile the boundary

Map the reported behavior to one or more maintained scopes: bootstrap,
configuration, regular expressions, detection, allowlists, decoding,
composite rules, sessions, sources, Git, reports, or CLI. Inspect that scope's
README, manifest, requests, outcomes, coverage, negative controls, and Rust
tests. Confirm that every claimed upstream identity has a direct Rust test or
a precise disposition and that revision/config identities agree.

Use only synthetic inputs or reviewed upstream fixtures. Preserve raw bytes,
spans, locations, finding fields, errors, ordering, and exit behavior in the
comparison. Redact secret values in review notes.

## Run the evidence

For a narrow committed replay, use the relevant Bazel target, for example:

```sh
bazelisk test //crates/rustleaks-core:detect_corpus_test
```

Run the complete committed replay with:

```sh
just parity
```

When the exact pinned Gitleaks checkout is present at `../gitleaks`, verify
fresh Go outcomes and the complete local release-hardening boundary with:

```sh
cargo xtask oracle generate --check
cargo xtask parity --all
```

The full differential command requires a clean, committed candidate tree;
normally run it in the shared validation clone after the focused fix is
committed.

Do not edit accepted outcomes to make a replay pass. Reproduce an unexplained
difference in a temporary corpus or focused test first.

## Classify differences

Assign each difference exactly one disposition:

- exact supported behavior after correcting the harness or Rust code;
- a named safe Rust disposition with an executable negative control;
- an explicit profile exclusion requiring maintainer approval; or
- a Rustleaks defect.

Record permitted nondeterministic presentation ordering separately as a
documented normalization. It is not a semantic-difference disposition.

Never normalize semantic fields, missing findings, spans, errors, suppression,
or exit status. A missing mapping, stale artifact, unclassified outcome, or
unapproved exclusion is a failed audit.

Report the pinned identities, scope and cases, commands and results, field-level
differences, classification, tests or artifacts changed, remaining native
gaps, and PASS or FAIL. Compatibility-sensitive fixes must finish with
`just ci`; add `just security` when hostile-input or dependency boundaries
changed.

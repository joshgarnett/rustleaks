---
name: rustleaks-rule-maintenance
description: Maintain Rustleaks default-rule or custom-rule behavior with grounded positive and negative cases, exact source spans, keyword and entropy behavior, and allowlist coverage. Use for rule semantics and rule tests; use rustleaks-upstream-sync for a new Gitleaks pin.
---

# Rustleaks rule maintenance

Read `docs/COMPATIBILITY.md`, the applicable config and detection
corpus READMEs, and the rule-related entries in `compat/test-manifest.toml`.
Determine whether the request changes copied upstream defaults, supported TOML
semantics, or Rustleaks test coverage.

Do not independently edit the copied default configuration. A change derived
from a new Gitleaks revision must use `rustleaks-upstream-sync` and update the
pin, both config copies, hashes, generated evidence, and provenance together.
An intentional Rustleaks-only default divergence requires explicit maintainer
approval and a named compatibility disposition.

## Build evidence

For each rule behavior, add or identify:

- a grounded positive case that should produce the exact rule, match, secret,
  byte span, line, and column;
- a near-miss negative case that would fail if the regex, keyword filter,
  entropy threshold, secret group, or path condition were broadened;
- invalid UTF-8, overlapping, boundary, or multiline coverage when relevant;
- global and rule allowlist coverage for the affected condition, including
  stop-word, regex, path, commit, and target-rule behavior where applicable;
- extension and composite behavior when the rule participates in either; and
- a synthetic value or reviewed upstream fixture, never a live credential.

Keep Go regex translation and dependency types private. Do not alter matching
bytes or offsets in a corpus normalizer.

## Validate

Run the narrowest applicable targets, then the local gate:

```sh
bazelisk test //crates/rustleaks-core:default_rule_corpus_test
bazelisk test //crates/rustleaks-core:detect_corpus_test
bazelisk test //crates/rustleaks-core:allowlist_test
just ci
```

Add `bazelisk test //crates/rustleaks-core:config_test` for TOML, extension,
or config-loading changes. Use `cargo xtask parity --all` with the pinned
sibling checkout when supported behavior, generated corpora, or the upstream
comparison changes, but only against a clean, committed candidate tree. This
full differential gate replaces separate parity, package, and fuzz runs. When
the full differential gate is not required, run `just fuzz-smoke` for a parser,
regex, decoder, or hostile-input boundary change.

Report the rule identifiers, intended supported behavior, positive and
negative cases, exact span evidence, allowlist effect, compatibility
classification, commands and results, and any approval required.

---
name: rustleaks-upstream-sync
description: Assess an approved candidate Gitleaks baseline and its import plan, preserving frozen historical evidence, copied configuration, provenance and Rust regression contracts. Use only for upstream revision updates, not ordinary Rustleaks rule edits.
---

# Rustleaks upstream sync

Read `docs/dev/updating-upstream.md`, `docs/dev/testing-and-parity.md`, the
[compatibility
policy](../../../docs/user/gitleaks-differences.md#compatibility-policy),
`compat/upstream-revision.txt`, and `compat/test-manifest.toml`.
The live Go oracle and automatic upstream rediscovery are retired. Historical
generator commands are not current maintenance commands.

## Establish the candidate

Require maintainer approval for the exact candidate commit and import scope.
Honor approval already present in the session. Record its immutable revision,
relationship to the accepted pin, and default-config SHA-256. Inspect upstream
source and the actual commit range without changing the accepted baseline.

Inventory rules, configuration, regular expressions, detection, sources,
reports, CLI behavior, tests, fixtures and licenses. Establish independently
reviewable expected results and an explicit provenance plan before replacing
accepted inputs. If the approved task requires external executable tooling or
dependencies outside the agreed scope, identify that boundary before using it.
Do not restore the retired oracle merely to satisfy an old command reference.

## Preserve evidence and behavior

Keep historical observations immutable. Version candidate evidence separately
and retain its source/generator identities. Generated expected outcomes must
not be derived solely from current Rust output. Use reviewed deterministic
tooling for generated inventories and snapshots; do not hand-edit them.

Update the approved pin, the upstream default-config copy, evidence
bindings, fixture inventory, hashes and attribution together. The pin and its
SHA-256 describe the upstream copy. Apply the new upstream rules to the shipped
default rules and keep or rework each listed Rustleaks change, so that
`crates/rustleaks-core/tests/default_rules.rs` still names every difference. Preserve copied bytes,
modes, symlinks and licenses. Keep old generator hashes as historical facts,
not requirements that deleted generator code still exists.

Classify every difference as exact behavior, a named safe Rust disposition,
an explicitly approved profile exclusion, a presentation change, or a defect.
Rustleaks does not need to adopt upstream presentation changes. No
normalization may conceal functional differences. Add direct Rust tests and
material negative controls for the adopted behavior and its exact findings,
spans, and error classes.

## Validate

Run the affected focused Bazel checks after related edits are integrated, then:

```sh
cargo xtask regression-check
just ci
just security
cargo xtask qualify
```

Full qualification requires a clean, committed candidate and includes package,
external-consumer, Miri, fuzz and performance checks. Do not rerun contained
gates without a changed input or unresolved concern. Refresh the matching
native target evidence; cross-compilation does not prove runtime support.

Obtain independent compatibility and Rust/API review. Report old/new source
identities and hashes, adopted behavior, exact evidence and results, copied
material and licenses, host limitations and any remaining approval. Do not
publish or change repository settings without authorization for those actions.

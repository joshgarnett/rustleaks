---
name: rustleaks-upstream-sync
description: Assess an approved candidate Gitleaks baseline and its import plan, preserving frozen historical evidence, copied configuration, provenance and Rust regression contracts. Use only for upstream revision updates, not ordinary Rustleaks rule edits.
---

# Rustleaks upstream sync

Read `docs/UPDATING_UPSTREAM.md`, `docs/COMPATIBILITY.md`,
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

Update the approved pin, both default-config copies, evidence bindings,
fixture inventory, hashes and attribution together. Preserve copied bytes,
modes, symlinks and licenses. Keep old generator hashes as historical facts,
not requirements that deleted generator code still exists.

Classify every difference as exact behavior, a named safe Rust disposition,
an explicitly approved profile exclusion, or a defect. No normalization may
conceal semantic differences. Add direct Rust tests and material negative
controls for the adopted behavior and its exact bytes, spans and errors.

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

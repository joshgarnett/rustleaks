---
name: rustleaks-upstream-sync
description: Assess and integrate a candidate Gitleaks revision into Rustleaks, including the pin, copied configuration, provenance, generated compatibility evidence, and complete differential validation. Use only for upstream revision updates, not ordinary Rustleaks rule edits.
---

# Rustleaks upstream sync

Treat an upstream update as one reviewed compatibility transaction. Do not
replace the accepted baseline or sibling checkout before the candidate passes.

## Establish the candidate

1. Read `docs/UPDATING_UPSTREAM.md`,
   `docs/COMPATIBILITY.md`, `compat/upstream-revision.txt`, and
   `compat/test-manifest.toml`.
2. Require maintainer approval for the exact candidate Gitleaks commit. Record
   the immutable commit, its relationship to the current pin, and the SHA-256
   of `config/gitleaks.toml`.
3. Work in an isolated temporary parent containing a clean Rustleaks clone and
   a read-only candidate Gitleaks checkout at the clone's `../gitleaks` path.
   Keep the accepted repository and accepted sibling checkout unchanged.
4. Review upstream release notes and the actual commit range. Inventory rule,
   config schema, regex, detector, source, report, CLI, test, fixture, license,
   Go toolchain, and dependency changes before editing Rustleaks.

## Update one identity

Update these identity-bearing files together:

- `compat/upstream-revision.txt`;
- `crates/rustleaks-core/default/gitleaks.toml`;
- `compat/config-corpus/default-gitleaks.toml`;
- revision and config-hash fields in `compat/test-manifest.toml` and generated
  corpus manifests;
- copied fixtures and their provenance inventory;
- API, assertion, constructor, benchmark, and corpus evidence affected by the
  candidate; and
- adjacent license files, `NOTICE`, and attribution when upstream material or
  terms changed.

Use the maintained Rust `xtask` generators. Inspect the `generate` dispatch in
`crates/xtask/src/main.rs` to select the applicable scope and its
`cargo xtask generate <scope>` and `--check` forms. Do not hand-edit generated
JSON, JSONL, snapshots, or corpus outcomes. Generate into a temporary path when
a command supports one, review the complete delta, then replace accepted bytes
only after classification.

Classify every difference as exact supported behavior, a named safe Rust
disposition, an explicit profile exclusion, or a Rustleaks defect. Do not add
normalization to conceal a semantic difference. Any profile exclusion or
compatibility exception requires maintainer approval.

## Validate

From the isolated Rustleaks clone with the candidate at `../gitleaks`, run the
affected generator checks first, then the complete gates:

```sh
cargo xtask oracle generate --check
cargo xtask parity --all
just ci
just security
```

`cargo xtask parity --all` requires a clean worktree, so validate generated
changes before committing and run it against the committed candidate tree.
It includes package, external-consumer, and fuzz checks; do not rerun those
contained gates.

The review record must identify the old and new commits and config hashes,
commands and exact results, generated counts, classified differences, copied
material and licenses, native target evidence not run, and every approval
still required. Do not publish, change GitHub settings, or replace the
maintainer's accepted sibling checkout.

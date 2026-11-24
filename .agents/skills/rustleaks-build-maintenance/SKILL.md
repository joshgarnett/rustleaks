---
name: rustleaks-build-maintenance
description: Maintain Rustleaks Bazel, rules_rust, Rust toolchain, crate-universe, target matrix, manifests, lockfiles, and Just command interface while preserving Cargo packages and external consumers. Use for build and dependency-graph maintenance, not ordinary Rust source changes.
---

# Rustleaks build maintenance

Read `docs/dev/architecture.md`, `docs/dev/dependencies.md`,
`MODULE.bazel`, `.bazelrc`, `justfile`, and
`crates/xtask/src/build_system.rs`. Bazel is the build authority. Cargo remains
the metadata, package, and named-tooling interface.

## Preserve the graph

- Keep first-party Cargo members, Bazel packages, feature profiles, tests,
  assets, and dependencies represented in both graphs.
- Keep `rustleaks-core` free of source, report, CLI, archive, Git, async,
  parallel, native-library, and C or C++ build requirements in its default
  graph.
- Keep all eight declared Rust targets explicit. Cross-build success is not
  native runtime support.
- Treat `Cargo.lock`, `cargo-bazel-lock.json`, and `MODULE.bazel.lock` as one
  reviewed lock boundary. Never hand-edit generated lock entries.
- Keep Just recipes small and cross-platform. Put nontrivial logic in tested
  Rust `xtask` code rather than Just or Bazel command strings.

Dependency, toolchain and `rules_rust` changes are listed under [Approval
boundaries](../../../AGENTS.md#approval-boundaries) and need maintainer
approval before the edit. The crate-universe dependency input counts as a
dependency change. Ordinary first-party Bazel target and feature
maintenance needs no approval, but it must keep and check the graph
contract.
Use only this public regeneration command after approval:

```sh
just deps-repin
```

Review all three lockfile diffs, dependency source and license changes, build
scripts, native links, unsafe inventory, MSRV, and target-specific selection.
Do not use an unlocked Cargo command to mask a Bazel or lock error.

## Validate

Start with the affected Bazel package and contract checks. Inspect the public
interface and resolved metadata with:

```sh
just doctor
cargo metadata --locked --format-version 1
bazelisk test //crates/xtask:xtask_unit_test
```

Finish graph, manifest, lockfile, toolchain, feature, target, or packaged-asset
changes with:

```sh
just ci
just security
```

Add the commands that the [local
workflow](../../../CONTRIBUTING.md#local-workflow) table names for the change,
such as `just package-check` or `cargo xtask qualify`. Run the [clean-clone
checks](../../../CONTRIBUTING.md#clean-clone-checks) when self-contained
builds, lockfiles, build rules, assets, features, toolchains, repository
configuration or clean-test tools can change.

Report versions before and after, approval, changed graph edges and files,
lock regeneration, package contents and consumers, eight-target compile
results, native tests actually run, commands and results, and remaining risks.

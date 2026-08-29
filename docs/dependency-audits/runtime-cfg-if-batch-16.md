# Runtime dependency audit: cfg-if batch 16

Review date: 2026-08-29.

Locked graph baseline: Rustleaks commit
`39554d21f8e354c53126bf7bb63dbac29006fbd6`, with `Cargo.lock` SHA-256
`e3c24453ec42115d43dd5b2b679e43cdb6e1b0802393932d3ae199db2e502d82`.
The lockfile is unchanged by this audit batch.

`cfg-if 1.0.4` is a normal dependency of `sha2`, `filetime`, and
`crc32fast`. The locked graph reaches it through archive decoding in
`rustleaks-sources` and `rustleaks-sevenz`, the CLI and compatibility runner,
and maintenance code in `xtask`. The generated inventory records the CLI and
`xtask` roots, no selected feature, every declared target, no build script,
and no `links` value. The unselected `rustc-dep-of-std` feature adds the
optional `rustc-std-workspace-core` package; the active Rustleaks resolution
has no dependency below `cfg-if`.

The review covered all 14 packaged files and 716 packaged text lines,
including all 212 lines of Rust source, the test target, manifests, package
lockfile, licenses, README, changelog, and repository automation. A RustSec
check at advisory database commit
`b331df68b3ed0e99594d259040bdcb9de3c7c8a4` found no vulnerability,
unmaintained, unsound, or yanked warning in the exact Rustleaks lockfile. An
exact-package GitHub Advisory Database query and the upstream repository's
public advisory page returned no record. MIT OR Apache-2.0 matches
`deny.toml`; both license texts are packaged and there is no `NOTICE` file.
No peer audits, wildcard trust, criteria changes, or exceptions were used.

## `cfg-if 1.0.4`

- Archive: `cfg-if-1.0.4.crate`; SHA-256
  `9330f8b2ff13f34540b44e946ef35111825727b38d33286ef986142615121801`.
  The packaged VCS identity is verified upstream commit
  `3510ca6abea34cbbc702509a4e50ea9709925eda` at the repository root and tag
  `v1.0.4`. All 14 archive members are regular files with mode `0644`. A
  fresh extraction matched cargo-vet's source byte for byte apart from
  Cargo's `.cargo-ok` marker. Every file shared with the exact upstream
  commit matches byte for byte, and packaged `Cargo.toml.orig` matches the
  upstream manifest. The normalized manifest, VCS record, and package
  lockfile are Cargo packaging metadata. `LICENSE-APACHE` and `LICENSE-MIT`
  have respective SHA-256 values
  `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2`
  and `378f5840b258e2779c39418f3f2d7b2ba96f1c7917dd6be0713f88305dbda397`.
- Rustleaks use: the exported `cfg_if!` declarative macro lets `sha2`,
  `filetime`, and `crc32fast` select target or capability-specific items at
  compile time. Rustleaks does not expose a `cfg-if` type or invoke package
  logic against runtime configuration, findings, files, or archives.
- Selection behavior: the public rule requires an initial `if`, accepts zero
  or more `else if` branches and an optional final `else`, then processes one
  branch per internal recursion. Each emitted branch requires its own cfg
  expression and negates every prior expression, so at most the first
  matching branch survives. The final else has no positive condition and
  negates all earlier expressions. A private grouping rule keeps one cfg
  attribute over every token in a selected branch. `$crate` references keep
  recursive expansion hygienic across downstream crates. Invalid invocation
  grammar produces an ordinary compiler error.
- Unsafe and dependency inventory: the package contains no unsafe block,
  unsafe function, external function, native interface, mutable static, or
  interior-mutability implementation. Its selected feature set has no
  dependency, so no dependency unsafe code is active below it. The optional
  compiler-workspace `core` alias is not selected in the locked graph and does
  not change the macro implementation when compiled in the all-feature check.
- Native and authority boundary: the archive has no build script, native
  source, generated-at-build source, or `links` declaration. Production code
  opens no file or socket, reads no environment variable, starts no process
  or thread, writes no log, and maintains no process-global state. Packaged
  GitHub Actions files are repository automation and do not execute when the
  dependency is built or deployed.
- Panic and resource behavior: the macro implementation contains no panic,
  indexing, allocation, arithmetic, or runtime loop. Expansion recurses once
  per source branch and repeats prior cfg expressions in later branches, so a
  deliberately large developer-authored chain can consume compiler recursion
  and approximately quadratic expanded token space. Rust compiler macro and
  resource limits bound the eventual failure. This is a compile-time
  availability property of developer-controlled Rust source and is not
  reachable from hostile Rustleaks runtime input.
- Published-source evidence: on Rust 1.88.0, the default and all-production-
  feature configurations each passed two unit tests, one cross-crate test,
  and one documentation test. On the Rustleaks MSRV toolchain, Rust 1.85.0,
  both the selected featureless library and the all-feature library compiled
  without test-only flags. With the upstream `msrv_test` cfg used to omit the
  newer `cfg(true)` and `cfg(false)` test, both configurations also passed the
  same three executable tests and documentation test.
- Test limitation: the unmodified test module does not compile on Rust 1.85.0
  because its test-only `cfg(true)` and `cfg(false)` syntax was still
  experimental on that compiler. Those tokens are inside `#[cfg(test)]` and
  are absent from dependency library builds. Rustleaks does not use those cfg
  predicates. No passing unmodified Rust 1.85.0 test result is claimed.
- Conclusion: complete source review, exact archive and VCS provenance,
  first-match macro analysis, active and all-feature compilation, tests,
  license evidence, and advisory results support `safe-to-deploy` for the
  locked Rustleaks graph. The documented compile-time expansion limit and
  test-suite compatibility gap do not require an exception.

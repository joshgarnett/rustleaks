# Runtime dependency audit: equivalent batch 22

Review date: 2026-08-29.

Locked graph baseline: Rustleaks commit
`7e9a695c989b67923948a022c95bd68f5a88a667`, with `Cargo.lock` SHA-256
`e3c24453ec42115d43dd5b2b679e43cdb6e1b0802393932d3ae199db2e502d82`.
The lockfile is unchanged by this audit batch.

`equivalent 1.0.2` is recorded as a normal dependency of `indexmap 2.14.0`
in the locked metadata closure. Neither package is reachable from a workspace
root in the exact all-feature Cargo tree, and the generated inventory records
no workspace consumer. The inventory records no selected feature, every
declared target, no build script, no `links` value, and no production
dependency below the package. At the baseline, Cargo-vet still tracks the
locked package and its bootstrap exemption.

The review covered all 10 packaged files and 471 packaged text lines,
including all 113 lines of Rust source, manifests, package lockfile, workflow,
licenses, README, and VCS record. A RustSec check at advisory database commit
`b331df68b3ed0e99594d259040bdcb9de3c7c8a4` found no vulnerability,
unmaintained, unsound, or yanked warning for the package. An exact-version
GitHub Advisory Database query returned no advisory affecting
`equivalent 1.0.2`. Apache-2.0 OR MIT matches `deny.toml`; both license texts
are packaged and there is no `NOTICE` file. No peer audits, wildcard trust,
criteria changes, or exceptions were used.

## `equivalent 1.0.2`

- Archive: `equivalent-1.0.2.crate`; SHA-256
  `877a4ace8713b0bcf2a4e7eec82529c029f1d0619886d18145fea96c3ffe5c0f`.
  The packaged VCS record identifies upstream commit
  `44cdd44f8b8ebb5f9ae096c7550a5e74ffb7d6ae` at the repository root; tag
  `v1.0.2` resolves to that commit. All 10 archive members are regular files
  with mode `0644`. A fresh extraction matched cargo-vet's source byte for
  byte apart from Cargo's `.cargo-ok` marker. Source, workflow, README,
  licenses, and development configuration match the exact upstream tree, and
  `Cargo.toml.orig` matches the upstream manifest. The normalized manifest,
  package lockfile, and VCS record are Cargo packaging metadata.
  `LICENSE-APACHE` and `LICENSE-MIT` have respective SHA-256 values
  `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2`
  and
  `7365cc8878a1d7ce155a58c4ca09c3d7a6be413efa5334a80ea842912b669349`.
- Rustleaks use: there is no reachable workspace path to the package in the
  locked graph. If a future path selects it through `indexmap`, the package
  supplies traits that let a borrowed query key compare for equality or
  ordering against a stored key of another type.
- Type and comparison behavior: the `Equivalent` blanket implementation
  accepts an equality-comparable query and a stored key that borrows that
  query type, then compares the query with the borrowed key. The `Comparable`
  blanket implementation adds total ordering and compares the same values.
  User implementations may support representations without a `Borrow`
  relationship. The documented requirement that equivalent keys hash alike,
  and the expected consistency between equality and ordering, are semantic
  contracts for implementors and map consumers. Violations can produce
  incorrect lookup behavior but do not create memory unsafety in this crate.
- Unsafe and dependency inventory: the package contains no unsafe block,
  unsafe function, external declaration, native binding, or production
  dependency. Both blanket implementations use only safe `core` traits and
  references. It does not retain, reinterpret, allocate, or mutate caller
  data.
- Native and authority boundary: the archive has no build script, native
  source, generated-at-build source, or `links` declaration. It is `no_std`
  and opens no file or socket, reads no environment variable, starts no
  process or thread, allocates no memory, writes no log, and maintains no
  package or process-global state. The packaged workflow does not execute when
  the dependency is built or deployed.
- Panic and resource behavior: each blanket method performs one caller-owned
  borrow and one equality or ordering comparison. It contains no package loop,
  recursion, allocation, indexing, arithmetic, or explicit panic. Time,
  recursion, and panic behavior of `Borrow`, `Eq`, `Ord`, or a user
  implementation remain properties of the caller-selected types.
- Published-source evidence: on Rust 1.88.0 and the Rustleaks MSRV toolchain,
  Rust 1.85.0, the all-feature package configuration passed with zero defined
  unit tests and one documentation test. The same counts passed on the
  repository's pinned nightly toolchain. A temporary harness exercised the
  blanket borrowed-string equality and ordering implementations and a custom
  cross-representation `Equivalent` implementation on Rust 1.88.0 and Rust
  1.85.0. No unsafe code or target-specific branch warranted Miri or
  cross-target execution.
- Conclusion: complete source review, exact archive and VCS provenance,
  trait-contract analysis, current and MSRV tests, license evidence, and
  advisory results support `safe-to-deploy`. The presently unreachable graph
  position and caller-owned comparison semantics do not require an exception.

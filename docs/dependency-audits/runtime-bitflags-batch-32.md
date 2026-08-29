# Runtime dependency audit: bitflags batch 32

Review date: 2026-08-29.

Locked graph baseline: Rustleaks commit
`3b19a40271ed047d63c6efb89bd9ae73d9ec1d60`, with `Cargo.lock` SHA-256
`e3c24453ec42115d43dd5b2b679e43cdb6e1b0802393932d3ae199db2e502d82`.
The lockfile is unchanged by this audit batch.

`bitflags 2.13.1` is a normal dependency of `rustleaks-sources` and `xtask`.
It remains outside the publishable core's normal and build graphs. The selected
feature is `std`; the selected package graph has no normal dependency, build
script, `links` value, native code, generated production source, proc macro,
or target-specific dependency.

A fresh refresh and minimization of the Bytecode Alliance, Google, ISRG,
Mozilla, and Zcash cargo-vet imports supplied no version-specific coverage for
the exact locked package. The local review therefore covered all 64 packaged
files and 8,507 packaged lines, including 6,351 lines of Rust source. A RustSec
check at advisory database commit
`b331df68b3ed0e99594d259040bdcb9de3c7c8a4` found no vulnerability, yanked,
unmaintained, or unsound warning for the exact package. An exact-package GitHub
Advisory Database query returned no advisory for `bitflags 2.13.1`. MIT OR
Apache-2.0 is allowed by `deny.toml`, both license texts are packaged, and
there is no `NOTICE` file. No publisher trust, wildcard audit, criteria change,
or exception was used.

## `bitflags 2.13.1`

- Archive: `bitflags-2.13.1.crate`; 51,395 bytes; SHA-256
  `b588b76d00fde79687d7646a9b5bdf3cc0f655e0bbd080335a95d7e96f3587da`.
  The checksum matches `Cargo.lock`, `cargo-bazel-lock.json`, and the generated
  inventory. All 64 archive members are regular files with mode `0644`. A
  fresh archive extraction matches cargo-vet's review source byte for byte
  apart from Cargo's `.cargo-ok` marker.
- Provenance: the packaged VCS record identifies upstream commit
  `f92a2921b41644b02ca5d50a6ace542e309e6a6f`, and lightweight release tag
  `2.13.1` points to that commit. Packaged production source,
  `Cargo.toml.orig`, readme, changelog, specification, security policy, and
  licenses match the exact VCS tree byte for byte. The release commit and tag
  are unsigned. The registry checksum and exact VCS comparison provide the
  retained source identity without claiming signed provenance.
- Release scope: relative to 2.13.0, the production change caches the result
  of the statically generated `all()` expression in a constant. The value is
  computed from the same generated flags and removes repeated runtime
  evaluation without changing accepted bit patterns. The two subsequent
  upstream commits change documentation only.
- Unsafe boundary: production source forbids unsafe code outside tests. The
  only macro-emitted unsafe implementations are optional Bytemuck `Pod` and
  `Zeroable` implementations for the transparent internal wrapper. Macro use
  restricts its storage type to primitive integers, which have no padding and
  admit every bit pattern; each implementation additionally requires the
  matching trait on that storage type. Bytemuck is not selected by Rustleaks.
- Authority boundary: production code performs no filesystem or socket access,
  environment read, process or thread creation, logging, build-time execution,
  or mutable global operation. The selected library is synchronous and
  operates on caller-owned values and borrowed strings.
- Hostile-input and resource behavior: the selected parser splits a borrowed
  string into tokens, validates named or hexadecimal forms, and uses checked
  slice access and integer radix parsing. Work is proportional to the input
  length times the statically declared flag count. With `std`, parse errors
  allocate only a copy of the rejected token. Iteration and set operations are
  bounded by the input bits and static flag declaration, with no production
  panic, recursion, or unchecked indexing path.
- Optional features: Serde preserves the underlying bits and parses the same
  bounded textual representation; Arbitrary generates only known bits; and
  Bytemuck uses the reviewed transparent-wrapper boundary. None grants file,
  network, process, thread, logging, or global-state authority.
- Licenses: the packaged MIT and Apache-2.0 texts have SHA-256 values
  `6485b8ed310d3f0340bf1ad1f47645069ce4069dcc6bb46c7d5c6faf41de1fdb`
  and
  `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2`.
  There is no `NOTICE` file or additional packaged license obligation.
- Selected-feature evidence: the exact published source passed 54 unit tests
  and 20 documentation tests on Rustleaks' Rust 1.88 MSRV and current stable
  Rust 1.98. One compile-fail documentation example is intentionally ignored.
- Full-package evidence: current stable passed 57 all-feature unit tests and
  the same documentation suite. Pinned-nightly Miri passed 53 all-feature unit
  tests, including the Bytemuck, Serde, and Arbitrary paths, plus 20
  documentation tests. Four upstream round-trip tests are disabled under Miri.
  At the exact tagged VCS commit, current stable also passed 57 unit tests, the
  complete compile-pass and compile-fail integration suite, and 20
  documentation tests.
- Rustleaks evidence: the authoritative
  `//crates/rustleaks-sources:archive_sources_test`,
  `//crates/rustleaks-sources:rustleaks_sources_archives_unit_test`, and
  `//crates/xtask:xtask_unit_test` targets pass for the locked selected graph.
  The repository's normal CI target matrix provides compilation evidence for
  the eight required targets.
- Conclusion: complete source review, exact archive and VCS provenance,
  selected and optional-feature boundary review, multi-toolchain tests, Miri,
  upstream compile tests, Rustleaks integration tests, license evidence, and
  exact-version advisory results support `safe-to-deploy` for
  `bitflags 2.13.1`.

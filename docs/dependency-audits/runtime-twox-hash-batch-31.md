# Runtime dependency audit: twox-hash batch 31

Review date: 2026-08-29.

Locked graph baseline: Rustleaks commit
`779274d0050a51a71c0b1e8206d03f59dfeb4cd4`, with `Cargo.lock` SHA-256
`e3c24453ec42115d43dd5b2b679e43cdb6e1b0802393932d3ae199db2e502d82`.
The lockfile is unchanged by this audit batch.

`twox-hash 2.1.4` is a normal dependency of `lz4_flex 0.14.0` through the
`xxhash32` feature. It reaches `rustleaks-cli` and `rustleaks-sevenz` through
the archive source graph and remains outside the publishable core's normal and
build graphs. The selected package graph has no normal dependency, build
script, `links` value, native code, generated production source, proc macro,
or target-specific dependency.

A fresh refresh and minimization of the Bytecode Alliance, Google, ISRG,
Mozilla, and Zcash cargo-vet imports supplied no version-specific coverage for
the exact locked package. The local review therefore covered all 25 packaged
files and 5,478 packaged lines, including 4,778 lines of Rust source. A RustSec
check at advisory database commit
`b331df68b3ed0e99594d259040bdcb9de3c7c8a4` found no vulnerability, yanked,
unmaintained, or unsound warning for the exact package. An exact-package GitHub
Advisory Database query returned no advisory for `twox-hash 2.1.4`. MIT is
allowed by `deny.toml`, the license text is packaged, and there is no `NOTICE`
file. No publisher trust, wildcard audit, criteria change, or exception was
used.

## `twox-hash 2.1.4`

- Archive: `twox-hash-2.1.4.crate`; 37,026 bytes; SHA-256
  `5283634e518fe9e82c7b20520bb4bc209009fd16c82077c802f8111ecbb0117a`.
  The checksum matches `Cargo.lock`, `cargo-bazel-lock.json`, and the generated
  inventory. All 25 archive members are regular files with mode `0644`. A
  fresh archive extraction matches cargo-vet's review source byte for byte
  apart from Cargo's `.cargo-ok` marker.
- Provenance: the packaged VCS record identifies upstream commit
  `6f866bffe73900c63df2650be4eed41e3ed9b500`, and lightweight release tag
  `v2.1.4` points to that commit. Packaged production source,
  `Cargo.toml.orig`, readme, changelog, and license match the exact VCS tree
  byte for byte. The release commit and tag are unsigned. The registry
  checksum and exact VCS comparison provide the retained source identity
  without claiming signed provenance.
- Release scope: 2.1.4 changes documentation stability only. The preceding
  2.1.3 release removed debug-build arithmetic panics from the 32-bit and
  64-bit streaming hashers. There are no post-release commits on the upstream
  default branch.
- Selected unsafe boundary: `xxhash32` stores 16 buffered bytes in four
  initialized `u32` lanes. Its byte-slice views preserve size and lower the
  required alignment, mutable access remains exclusive, and the lane load is
  an unaligned read from an exact 16-byte chunk. Buffer offsets are maintained
  within the fixed array and all slice operations remain checked.
- Unselected unsafe inventory: the 64-bit streaming implementation uses the
  analogous 32-byte buffer and unaligned lane load. XXH3 validates custom
  secret lengths before constructing its transparent secret view, establishes
  fixed-buffer lengths before unchecked assumptions, bounds every stripe and
  tail operation to validated slices, and dispatches target-feature functions
  only after runtime detection. AVX2, SSE2, NEON, and scalar implementations
  read and write exact fixed-size arrays through bounded loops. The built-in
  implementations of the documented unsafe fixed-buffer traits preserve the
  required length and aliasing contracts.
- Authority boundary: production code performs no filesystem or socket access,
  environment read, process or thread creation, logging, build-time execution,
  or mutable global operation. Runtime CPU feature detection in unselected
  XXH3 implementations selects an implementation without granting external
  authority.
- Hostile-input and resource behavior: the selected hasher reads borrowed byte
  slices, stores at most 16 pending bytes, performs no allocation, and uses
  work proportional to input length. Length and algorithm arithmetic use the
  specified wrapping behavior. Internal chunk and buffer invariants are
  maintained by safe entry points, and malformed bytes cannot select an
  out-of-bounds read or write.
- License: the packaged MIT text has SHA-256
  `f59bcb1c02654665f78a5f290bae76b6358137675f6459f51e6d474a4623d8ea`.
  There is no `NOTICE` file or additional packaged license obligation.
- Selected-feature evidence: with Rustleaks' Rust 1.88 MSRV and current stable
  Rust 1.98, the exact published source passed 10 selected-feature library
  tests with one intentionally ignored 4 GiB length test. The crate-level
  readme examples require the disabled `xxhash64` feature, so a selected-only
  documentation-test invocation does not compile those examples. The exact
  selected library passed the same tests under pinned-nightly Miri.
- Full-package evidence: current stable passed 62 all-feature unit tests with
  the same large test ignored and five documentation tests. Pinned-nightly
  Miri passed those 62 tests with scalar XXH3 dispatch on native AArch64 macOS,
  32-bit little-endian `i686-unknown-linux-gnu`, and 64-bit big-endian
  `s390x-unknown-linux-gnu`. The native vector path was exercised by the stable
  tests; Miri does not implement the selected NEON inline assembly.
- Reference evidence: at the exact tagged VCS commit, the upstream comparison
  workspace passed 34 property tests against the repository's pinned xxHash C
  submodule commit `7546e25c96c736896f6ff25e30042de523926182`. The tests cover all
  implemented algorithms, seeds and secrets, input offsets, and single- and
  multi-chunk streaming paths.
- Rustleaks evidence: the authoritative
  `//crates/rustleaks-sources:archive_sources_test` and
  `//crates/rustleaks-sources:rustleaks_sources_archives_unit_test` targets pass
  for the locked selected graph. The repository's normal CI target matrix
  provides compilation evidence for the eight required targets.
- Conclusion: complete source review, exact archive and VCS provenance,
  selected and unselected unsafe-boundary review, native and cross-model Miri
  evidence, reference-C property tests, Rustleaks archive tests, license
  evidence, and exact-version advisory results support `safe-to-deploy` for
  `twox-hash 2.1.4`.

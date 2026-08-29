# Runtime dependency audit: crc32fast batch 25

Review date: 2026-08-29.

Locked graph baseline: Rustleaks commit
`a649010cc76b26b0b319cec869c6fbae25d12e21`, with `Cargo.lock` SHA-256
`e3c24453ec42115d43dd5b2b679e43cdb6e1b0802393932d3ae199db2e502d82`.
The lockfile is unchanged by this audit batch.

`crc32fast 1.5.1` is a normal dependency of `flate2 1.1.9`. The locked graph
reaches it only through `xtask` package and release-artifact maintenance. The
generated inventory records the selected `default` and `std` features, every
declared target, a build script, no `links` value, and no core normal or build
path. The exact all-target Cargo tree is `crc32fast -> flate2 -> xtask`. Its
only normal dependency is separately covered `cfg-if 1.0.4`.

The review covered all 19 packaged files and 2,852 packaged text lines,
including all 2,108 lines of Rust production, test, benchmark, and build-script
source, manifests, package lockfile, workflow, licenses, README, and VCS
record. A RustSec check at advisory database commit
`b331df68b3ed0e99594d259040bdcb9de3c7c8a4` found no vulnerability,
unmaintained, unsound, or yanked warning in the exact Rustleaks lockfile. An
exact-version GitHub Advisory Database query returned no advisory affecting
`crc32fast 1.5.1`. MIT OR Apache-2.0 matches `deny.toml`; both license texts
are packaged and there is no `NOTICE` file. The local conclusion does not rely
on peer audits, wildcard trust, criteria changes, or exceptions.

## `crc32fast 1.5.1`

- Archive: `crc32fast-1.5.1.crate`; SHA-256
  `8498c871161e1742aaa9d52551b2d6ebdd4c3d45a3be423e3728f33b955be550`.
  The packaged VCS record identifies upstream commit
  `a150f65ce810793293d5c9dd815f4510eb6d8e4c` at the repository root;
  lightweight tag `v1.5.1` points directly at that commit. All 19 archive
  members are regular files with mode `0644`. Cargo-vet's source matches a
  fresh archive extraction byte for byte apart from Cargo's `.cargo-ok`
  marker. Every packaged source, test, benchmark, workflow, README, license,
  and ignore file matches the exact upstream tree, and `Cargo.toml.orig`
  matches the upstream manifest. The normalized manifest, package lockfile,
  and VCS record are Cargo packaging metadata; the upstream fuzz workspace is
  not included in the published package. `LICENSE-APACHE` and `LICENSE-MIT`
  have respective SHA-256 values
  `c6596eb7be8581c18be736c846fb9173b69eccf6ef94c5135893ec56bd92ba08`
  and
  `61d383b05b87d78f94d2937e2580cce47226d17823c0430fbcad09596537efcf`.
- Rustleaks use: `xtask` reaches `flate2` while unpacking locally produced
  crates.io packages and release artifacts. `flate2` uses `crc32fast` for
  DEFLATE-related checksums. The package does not enter a published Rustleaks
  crate or decide Rustleaks source-adapter error classifications.
- Algorithm behavior: the baseline implementation uses bounded slice
  processing and fixed lookup tables. The AArch64 specialization uses the CRC
  instruction only after compile-time or runtime feature selection. The x86
  specialization requires SSE2, SSE4.1, SSSE3, and PCLMULQDQ before selecting
  its base fold and separately requires AVX2 or AVX-512F with VPCLMULQDQ for
  the wide folds. Every specialized path handles short and tail input before
  issuing its fixed-width loads and returns a checksum equivalent to the
  bytewise reference implementation.
- Unsafe inventory: the AArch64 state uses target CRC intrinsics only when the
  feature has been established, and `align_to::<u64>()` is valid because every
  bit pattern is valid for `u64`. The x86 state uses unaligned SIMD loads with
  16-, 32-, or 64-byte widths only after its caller has established the
  corresponding slice length. The 1,536-byte triple-stream path partitions
  input into disjoint in-bounds ranges before loading. Its local 16-byte load
  reads a fully initialized array. No pointer escapes, no Rust reference is
  created from foreign storage, and no safe caller must uphold a hidden
  alignment, lifetime, initialization, or CPU-feature obligation.
- Native and authority boundary: the package contains no native source,
  generated source, or `links` declaration. Its build script reads Cargo's
  `RUSTC` environment value, executes that compiler with `--version`, parses
  the minor version, and emits only compiler configuration for intrinsics
  stabilized in Rust 1.80 and 1.89. The library opens no file or socket,
  reads no environment variable, starts no process or thread, writes no log,
  and maintains no mutable process-global state. Standard-library CPU feature
  detection is the only runtime platform query.
- Panic and resource behavior: hashing is iterative, bounded by the input
  slice, and uses constant auxiliary memory. CRC combination is bounded by the
  64-bit length width. `new_with_initial_len` permits an arbitrary initial
  length, so a subsequent `update` or `combine` can overflow `amount` and
  panic in overflow-checked builds or wrap otherwise. The published benchmark
  can trigger this with random 64-bit lengths because its harness repeatedly
  combines the same state. Rustleaks constructs ordinary zero-length hashers
  through `flate2`, so neither the synthetic initial-length overflow nor the
  benchmark-harness defect is reachable in its locked use.
- Published-source evidence: on Rust 1.88.0 and Rust 1.85.0, ordinary locked
  default-feature tests passed seven unit tests, five exhaustive integration
  tests, and two documentation tests. Library-only no-default-feature checks
  passed on both toolchains. No-default all-target test compilation lacks the
  test-only `Vec` and `vec!` imports, and the default all-target benchmark can
  hit the documented synthetic length overflow; neither failure occurs in
  the library test or selected Rustleaks build. Pinned-nightly `build-std`
  checks compiled the selected library for all seven non-native required
  targets; the native AArch64 macOS target was exercised by the tests.
- Additional unsafe evidence: the complete default-feature unit, exhaustive,
  and documentation tests passed natively on AArch64 macOS under
  AddressSanitizer. A strict-provenance Miri harness compared each specialized
  implementation with the bytewise reference across misalignment and boundary
  lengths through 8,192 bytes. It passed for forced AArch64 CRC, x86
  SSE/PCLMULQDQ, x86 AVX2/VPCLMULQDQ, and x86
  AVX-512F/VPCLMULQDQ configurations. This directly exercised the unsafe
  fixed-width loads and the 16-, 128-, 256-, and 1,536-byte transition paths.
- Security-history review: an upstream report questioned the x86 unaligned
  load. The load intrinsic explicitly permits unaligned addresses, every
  caller performs the required length check, the reporter agreed with that
  analysis, and the report was closed. Complete source review and the focused
  provenance checks found no remaining unsound path.
- Conclusion: complete source and unsafe review, exact archive, tag, and VCS
  provenance, all-required-target compilation, native multi-toolchain tests,
  native AddressSanitizer and strict-provenance Miri execution, license
  evidence, and advisory results support `safe-to-deploy`. The unreachable
  synthetic length overflow and published test-harness defects are documented
  limitations and do not require an exception.

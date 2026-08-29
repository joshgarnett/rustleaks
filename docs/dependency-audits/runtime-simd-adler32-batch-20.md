# Runtime dependency audit: simd-adler32 batch 20

Review date: 2026-08-29.

Locked graph baseline: Rustleaks commit
`e3e529ea925d805c69bdfa190a0ca54e84aff6e9`, with `Cargo.lock` SHA-256
`e3c24453ec42115d43dd5b2b679e43cdb6e1b0802393932d3ae199db2e502d82`.
The lockfile is unchanged by this audit batch.

`simd-adler32 0.3.10` is a normal dependency of `miniz_oxide 0.8.9`,
which is used by `flate2 1.1.9`. The locked graph reaches it only through
gzip compression and decompression in `xtask`. The generated inventory
records the `xtask` root, no selected feature, every declared target, no build
script, and no `links` value. The package has no production dependency below
it and is outside the core normal or build graph.

The review covered all 22 packaged files and 3,224 packaged text lines,
including all 1,958 lines of Rust production and test source, manifests,
package lockfile, workflows, licenses, README, changelog, and VCS record. A
RustSec check at advisory database commit
`b331df68b3ed0e99594d259040bdcb9de3c7c8a4` found no vulnerability,
unmaintained, unsound, or yanked warning in the exact Rustleaks lockfile. An
exact-version GitHub Advisory Database query returned no advisory affecting
`simd-adler32 0.3.10`. MIT matches `deny.toml`; its license text is packaged
and there is no `NOTICE` file. No peer audits, wildcard trust, criteria
changes, or exceptions were used.

## `simd-adler32 0.3.10`

- Archive: `simd-adler32-0.3.10.crate`; SHA-256
  `3a219298ac11a56ea9a6d2120044824d6f01aeb034955e7af7bc16858527deea`.
  The packaged VCS record identifies upstream commit
  `d93164f98d7fe2daf883f2e1bec82778dd26199a` at the repository root; annotated
  tag `v0.3.10` resolves to that commit. All 22 archive members are regular
  files with mode `0644`. A fresh extraction matched cargo-vet's source byte
  for byte apart from Cargo's `.cargo-ok` marker. Source, workflows, package
  lockfile, changelog, README, license, and development configuration match
  the exact upstream tree, and `Cargo.toml.orig` matches the upstream
  manifest. The normalized manifest and VCS record are Cargo packaging
  metadata. `LICENSE.md` has SHA-256
  `42a35170233e83e18856792e748de4c1ce4a63b2afce9a370c89ef3fe23f9f2d`.
- Rustleaks use: `miniz_oxide 0.8.9` uses the package for Adler-32 checksum
  updates in the `flate2` backend reached by `xtask` gzip artifact handling.
  No package feature is selected. Adler-32 provides format-integrity error
  detection and is not an authentication or collision-resistance boundary.
- Dispatch and algorithm behavior: `Adler32` retains the two reduced 16-bit
  sums and a safe function pointer selected at construction. With `std`, x86
  variants use runtime CPU feature detection; without `std`, x86, ARM, and
  WebAssembly variants are exposed only when their target feature is enabled
  at compile time. Selection prefers AVX-512, NEON, AVX2, SSSE3, SSE2, and
  WebAssembly SIMD before the scalar fallback. Every implementation processes
  at most one Adler reduction interval at a time, uses exact SIMD blocks, and
  handles the zero-to-block-size remainder with scalar slice iteration.
- Arithmetic bounds: scalar work reduces after 5,552 bytes. The 32-byte SIMD
  variants use a 5,536-byte interval, and AVX-512 uses 5,504 bytes. These are
  below the standard Adler-32 32-bit accumulation bound. SSE2, SSSE3, and AVX2
  signed pair products reach at most 16,065; AVX-512 reaches at most 32,385,
  below the signed 16-bit maximum. A NEON 16-bit column accumulates at most
  44,115. Weighted and prior-sum terms stay within the 32-bit interval bound,
  and each implementation reduces before the next interval.
- Unsafe inventory: x86 and NEON variants load only from exact 32-byte or
  64-byte slice chunks; the second 16-byte pointer in SSE2, SSSE3, NEON, and
  WebAssembly remains inside the same 32-byte chunk. Unaligned x86 and
  WebAssembly loads use the corresponding unaligned operation. Target-feature
  functions are reached only through checked runtime detection or matching
  compile-time target configuration. Vector transmutation is between equal-
  size integer-vector representations, and every intrinsic argument has the
  required lane width. There is no external allocation, ownership transfer,
  foreign interface, mutable static, or process-global cache behind the
  unsafe code.
- Native and authority boundary: the archive has no build script, native
  source, generated-at-build source, or `links` declaration. Selected code is
  `no_std`, allocates no memory, and opens no file or socket, reads no
  environment variable, starts no process or thread, writes no log, and
  maintains no process-global state. The optional `std` feature adds runtime
  x86 feature detection and helpers over caller-provided `Read` and `BufRead`
  values; it does not acquire a file or other authority itself. Packaged
  upstream workflow files do not execute when the dependency is built or
  deployed.
- Panic and resource behavior: checksum updates are O(n), use constant state,
  and do not recurse. Production indexing is through exact chunks and their
  remainders. Debug assertions restate lengths established by those safe slice
  iterators. The optional reader helpers propagate I/O errors; a caller-
  supplied reader can prevent progress by violating the ordinary trait
  contract. Those helpers are not selected in the locked graph. Rustleaks
  reaches the package only in maintenance gzip work, where `xtask` owns the
  input and output authority.
- Published-source evidence: on Rust 1.88.0, the selected no-default-feature
  configuration passed 32 unit tests and four documentation tests; the
  default configuration passed 32 unit tests and eight documentation tests.
  The same configurations and counts passed on the Rustleaks MSRV toolchain,
  Rust 1.85.0. The all-feature configuration passed 32 unit tests and eight
  documentation tests on the repository's pinned nightly toolchain. Native
  execution exercised the selected AArch64 NEON path.
- Additional unsafe evidence: a temporary harness compared the published
  package with a simple per-byte Adler-32 reference across empty and short
  inputs, 31-, 32-, and 33-byte SIMD boundaries, lengths around the 5,536-byte
  reduction boundary, multiple reduction intervals, varied incremental write
  sizes, and resumed checksums. It passed under the repository's pinned Miri
  toolchain with strict provenance for AArch64 NEON, baseline x86-64 SSE2,
  x86-64-v2 SSSE3, x86-64-v3 AVX2, and the optional nightly x86-64-v4 AVX-512
  implementations. The WebAssembly SIMD loads and vector conversions were
  covered by complete source and bounds review but not native execution.
- Conclusion: complete source and unsafe review, exact archive and VCS
  provenance, arithmetic and slice-bound analysis, selected and optional
  feature tests, multi-architecture strict-provenance Miri, license evidence,
  and advisory results support `safe-to-deploy`. Linear checksum work,
  noncryptographic checksum semantics, and the unselected reader progress
  assumption do not require an exception.

# Runtime dependency audit: adler2 batch 17

Review date: 2026-08-29.

Locked graph baseline: Rustleaks commit
`7f063ef40ef25c1428d080c5b5429a8ad28fbb13`, with `Cargo.lock` SHA-256
`e3c24453ec42115d43dd5b2b679e43cdb6e1b0802393932d3ae199db2e502d82`.
The lockfile is unchanged by this audit batch.

`adler2 2.0.1` is a normal dependency of `miniz_oxide 0.9.1` and
`miniz_oxide 0.8.9`. The locked graph reaches it through archive decoding in
`rustleaks-sources` and `rustleaks-sevenz`, the CLI and compatibility runner,
and maintenance code in `xtask`. The generated inventory records the CLI,
`rustleaks-sevenz`, and `xtask` roots, no selected feature, every declared
target, no build script, and no `links` value. The active package has no
dependency below it. Its optional `std` and `rustc-dep-of-std` features are
not selected in the Rustleaks resolution.

The review covered all 13 packaged files and 1,113 packaged text lines,
including all 442 lines of library Rust source, the 109-line benchmark,
inline tests, manifests, package lockfile, licenses, README, changelog, and
release process. A RustSec check at advisory database commit
`b331df68b3ed0e99594d259040bdcb9de3c7c8a4` found no vulnerability,
unmaintained, unsound, or yanked warning in the exact Rustleaks lockfile. An
exact-package GitHub Advisory Database query and the upstream repository's
public advisory page returned no record. 0BSD OR MIT OR Apache-2.0 matches
`deny.toml`; all three license texts are packaged and there is no `NOTICE`
file. No peer audits, wildcard trust, criteria changes, or exceptions were
used.

## `adler2 2.0.1`

- Archive: `adler2-2.0.1.crate`; SHA-256
  `320119579fcad9c21884f5c4861d16174d0e06250625266f50fe6898340abefa`.
  The packaged VCS identity is verified upstream commit
  `89a031a0f42eeff31c70dc598b398cbf31f1680f` at the repository root. No tag
  points at that commit. All 13 archive members are regular files with mode
  `0644`. A fresh extraction matched cargo-vet's source byte for byte apart
  from Cargo's `.cargo-ok` marker. Every packaged file shared with the exact
  upstream commit matches byte for byte, and packaged `Cargo.toml.orig`
  matches the upstream manifest. The normalized manifest, VCS record, and
  package lockfile are Cargo packaging metadata. `LICENSE-0BSD`,
  `LICENSE-APACHE`, and `LICENSE-MIT` have respective SHA-256 values
  `861399f8c21c042b110517e76dc6b63a2b334276c8cf17412fc3c8908ca8dc17`,
  `8ada45cd9f843acf64e4722ae262c622a2b3b3007c7310ef36ac1061a30f6adb`,
  and `23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3`.
- Rustleaks use: `miniz_oxide 0.9.1` uses `adler2` to update and verify the
  zlib stream checksum over decompressed output reached through archive
  adapters. `miniz_oxide 0.8.9` also resolves the package, but its selected
  `simd` feature uses `simd-adler32` for checksum updates. Adler-32 is a weak
  format-integrity checksum and is not an authentication or collision-
  resistance boundary.
- Algorithm behavior: `Adler32` keeps the two standard reduced sums, supports
  construction from a prior checksum, hashes byte slices, and implements
  `core::hash::Hasher`. The optimized routine splits the input into a maximal
  four-byte-multiple prefix and a zero-to-three-byte remainder, accumulates
  exact four-byte chunks in four lanes, folds the lanes in Adler order, and
  processes the remainder byte by byte. It reduces after at most 5,552
  four-byte groups, or 22,208 bytes. The maximum
  lane-weighted increment is 4,294,624,680, below the implementation's
  32-bit reduction bound by 277,095, leaving room for the prior reduced sum.
  Slice access is through `chunks_exact(4)` and its remainder, so the four
  lane indices are in bounds. Combining partial checksums uses widened
  arithmetic and reduces before returning the two 16-bit components.
- Unsafe and dependency inventory: the package forbids unsafe Rust and
  contains no unsafe block, unsafe function, external function, native
  interface, mutable static, or interior-mutability implementation. Its
  selected feature set has no dependency, so no dependency unsafe code is
  active below it. The unselected compiler-workspace feature adds the
  optional `rustc-std-workspace-core` package without changing the reviewed
  checksum algorithm.
- Native and authority boundary: the archive has no build script, native
  source, generated-at-build source, or `links` declaration. Selected
  production code opens no file or socket, reads no environment variable,
  starts no process or thread, writes no log, and maintains no process-global
  state. The unselected `std` feature adds a helper over a caller-provided
  `BufRead`; it does not acquire a file or other authority itself. The upstream
  repository's `.github` automation is excluded from the archive and does not
  execute when the dependency is built or deployed.
- Panic and resource behavior: selected checksum updates are O(n), use
  constant state, allocate no memory, and do not recurse. The indexed lane
  operations are bounded by exact four-byte chunks. A large decompressed
  output consumes linear checksum CPU, while the archive adapters own input,
  output, and decompression limits. The optional `BufRead` loop depends on the
  ordinary trait contract that a nonempty successful read makes progress; a
  malicious implementation can otherwise prevent termination. That helper is
  not selected in the locked graph and does not widen Rustleaks authority.
- Published-source evidence: on Rust 1.88.0, the selected no-default-feature
  configuration passed five unit tests and three documentation tests. The
  default and all-feature configurations each passed six unit tests and four
  documentation tests. The same three configurations passed with the same
  counts on the Rustleaks MSRV toolchain, Rust 1.85.0. All-feature tests used
  the optional `rustc-std-workspace-core 1.0.0` package only in this isolated
  published-source check.
- Additional algorithm evidence: a temporary test harness compared the
  optimized routine with a simple per-byte Adler-32 reference for empty and
  short inputs, lengths around the 22,208-byte reduction boundary, varied
  chunk sizes, resume points, arbitrary initial checksums, and a one-million-
  byte input. Both selected-feature tests passed. The harness changed only a
  fresh temporary extraction after archive and VCS provenance comparisons; it
  is not represented as published package content or committed Rustleaks
  source.
- Conclusion: complete source review, exact archive and VCS provenance,
  arithmetic and bounds analysis, active and all-feature compilation, tests,
  license evidence, and advisory results support `safe-to-deploy` for the
  locked Rustleaks graph. Linear caller-controlled work, noncryptographic
  checksum semantics, and the unselected `BufRead` progress assumption are
  documented properties and do not require an exception.

# Runtime dependency audit: compression batch 42

Review date: 2026-08-31.

Locked graph baseline: Rustleaks commit
`e350eb1ae0416d638e2f06d573e529fa9a32797d`, with `Cargo.lock` SHA-256
`8f3893f06c74b312afd2ef9b6a240eaab6d5e3b5a4abe0eff1302a912d468eb4`.
The lockfile is unchanged by this audit batch.

`flate2 1.1.9` is used only by unpublished `xtask` release maintenance.
`brotli-decompressor 5.0.3` is a normal dependency of the unpublished archive
graph through `rustleaks-sources` and the retained `rustleaks-sevenz` fork.
Both packages apply on every maintained target and remain outside the default
`rustleaks-core` graph. Neither package has a build script, `links` value,
native compilation, generated build output, or proc macro.

The configured Bytecode Alliance, Google, ISRG, Mozilla, and Zcash cargo-vet
imports supplied no version-specific `safe-to-deploy` path for either exact
release. The residual local review therefore covered both exact full packages.
The maintained locked RustSec and cargo-deny gates cover advisory, license,
and source policy without an exception. No publisher trust, wildcard audit,
criteria change, or policy exception was used.

## `flate2 1.1.9`

- Archive: `flate2-1.1.9.crate`; 82,745 bytes; SHA-256
  `843fba2746e448b37e26a819579957415c8cef339bf08564fe8b7ddbd959573c`.
  The checksum matches `Cargo.lock` and the generated inventory. Cargo-vet's
  extracted source contains 65 files and 10,146 lines; its audit estimate is
  9,731 lines.
- Provenance: the packaged VCS record identifies official upstream commit
  `19ddb18bf11199858fbc6504d079448fafd1606e` in
  `https://github.com/rust-lang/flate2-rs`. Tag `1.1.9` points to that commit.
  Packaged production source, tests, examples, `Cargo.toml.orig`, README,
  maintenance policy, and both license files match the exact VCS tree byte for
  byte. This establishes exact archive-to-VCS identity without claiming signed
  provenance.
- Feature and dependency boundary: Rustleaks selects
  `any_impl`, `default`, `miniz_oxide`, and `rust_backend`. The selected backend
  is pure Rust. The optional C zlib and zlib-rs backends are not selected.
  `xtask` uses gzip construction and decoding only for local release artifact
  preparation and verification.
- Selected unsafe boundary: the selected package contains two small unsafe
  operations. One initializes a `MaybeUninit` output buffer before exposing it
  as bytes. The other extends a `Vec` only by the backend-reported initialized
  output count, clamped to its spare capacity. The safe stream wrappers retain
  buffer ownership and validate backend progress and status. The unselected C
  backend contains allocator and zlib FFI code; the unselected zlib-rs adapter
  retains that backend's API boundary.
- Authority and hostile-input boundary: the library reads and writes through
  caller-provided buffers or I/O traits. It does not access the network,
  processes, threads, paths, the environment, logging, or mutable global state.
  Gzip parsing bounds optional names and comments at 65,535 bytes and validates
  header CRC, payload CRC, and decoded size. Truncation and corrupt streams
  return I/O or format errors. Panics cover documented caller misuse and
  internal invariants rather than ordinary malformed stream handling.
- Resource behavior: decoder output storage and input ownership are caller
  controlled. The Rustleaks call graph uses this package only in local release
  maintenance, not when scanning untrusted archives. Ordinary allocation
  failure remains possible.
- Licenses and project files: packaged `LICENSE-APACHE`, `LICENSE-MIT`,
  `README.md`, and `MAINTENANCE.md` have respective SHA-256 values
  `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2`,
  `025436edff4cfcdde17a5811fdea78892d8482efd1abdec5a17872d07a4f2112`,
  `7958879222474ae6e290335294d3e752bb9142d611bcf800bb1c8ba0a9620871`,
  and
  `2904034aa8766570e5ba28b787084ea123b7c137bd688c0900d3bb6cf69a17eb`.
  Apache-2.0 and MIT are allowed by `deny.toml`.
- Package evidence: the exact selected package passed all targets on Rust
  1.88.0: 67 unit and integration tests passed and all examples compiled.
  Tests cover buffer boundaries, early flushes, empty and truncated reads,
  gzip parsing, checksums, multi-member streams, and zero-writing readers.
- Conclusion: exact archive and VCS provenance, complete selected-feature and
  package source review, unsafe analysis, package tests, license evidence,
  limited maintenance reachability, and maintained policy gates support
  `safe-to-deploy` for `flate2 1.1.9` in the locked graph.

## `brotli-decompressor 5.0.3`

- Archive: `brotli-decompressor-5.0.3.crate`; 197,262 bytes; SHA-256
  `3a32acac15fe1967bc3986b2a6347dffc965602354ea6f450ad07e8bfd253583`.
  The checksum matches `Cargo.lock` and the generated inventory. Cargo-vet's
  extracted source contains 38 files and 33,180 lines; its audit estimate is
  33,151 lines. Most of that volume is fixed prefix, context, transform,
  dictionary, and Huffman test-vector data.
- Provenance: the packaged VCS record identifies official upstream commit
  `b56177b8eb3d2440536281397e5ffe06eedf1a5c` in
  `https://github.com/dropbox/rust-brotli-decompressor`. No tag points directly
  to that commit. Packaged production source, `Cargo.toml.orig`, README, and
  license match the exact VCS tree byte for byte. Cargo's normalized manifest
  and VCS metadata are expected packaging additions. Upstream test data is an
  expected registry-package omission. This establishes exact archive-to-VCS
  identity without claiming a release tag or signed provenance.
- Feature and dependency boundary: Rustleaks selects only `std`, which uses
  `alloc-no-stdlib` and `alloc-stdlib`. The optional `unsafe`, `ffi-api`,
  `seccomp`, and benchmark surfaces are not selected. The crate root forbids
  unsafe code unless `unsafe` or `ffi-api` is selected, so Rustleaks' compiled
  dependency contains no unsafe Rust, FFI, native code, or build-time code.
- Decoder review: bit intake, window and meta-block headers, Huffman tables,
  context maps, literal and distance decoding, dictionary transforms, ring
  buffer copies, truncation, padding, and error-state transitions use checked
  slices or structured decoder errors in the selected safe implementation.
  Fixed lookup tables and the embedded Brotli dictionary were reconciled with
  the exact upstream tree. Invalid distances, transforms, padding, Huffman
  spaces, arguments, and allocation results return explicit failures.
- Unselected surfaces: the optional unsafe implementation replaces selected
  checked slice copies with raw non-overlapping copies under decoder
  invariants. The optional C API accepts caller-owned raw pointers and custom
  allocator functions, contains the corresponding unsafe pointer and
  allocation conversions, and catches panics when built with its default
  standard-library FFI policy. Those features are absent from Rustleaks.
- Authority boundary: the selected library operates through caller-provided
  `Read` and `Write` implementations. It does not access paths, files, the
  environment, the network, processes, threads, runtime logging, or mutable
  process-global state. Its command-line binary and optional FFI surface are
  not built into the Rustleaks dependency graph.
- Resource boundary: the upstream standard reader accepts Brotli's optional
  large-window format, which can request a ring buffer larger than Rustleaks'
  64 MiB default member ceiling before output accounting observes a byte.
  This audit added an early `0x11` large-window header rejection to both
  Rustleaks Brotli entry points, including each skippable 7z Brotli frame.
  Ordinary Brotli remains subject to member, cumulative, spool, entry, depth,
  cancellation, and checked output limits. Allocation failure within those
  limits can still abort.
- Panic and I/O behavior: malformed and truncated selected streams return
  `InvalidData`. Repeated reads after clean completion return zero, and extra
  trailing bytes are reported on a later read. Assertions cover internal
  state-machine invariants. Rustleaks bounds decoded output, checks
  cancellation between reads, and applies its maintained 7z panic policy.
  The public writer can spin if a caller supplies a nonconforming writer that
  repeatedly returns `Ok(0)`; Rustleaks does not use that writer surface.
- License and project files: the package declares `BSD-3-Clause/MIT`.
  Packaged `LICENSE` and `README.md` have respective SHA-256 values
  `c0c56f26d9c051cac4d200c34c84e7ae9aaa853e01a982a1df08b09931e518ae`
  and
  `5d1fe1083d9940c165dda0ea76c18c54b8f6476d21040a2af9cb8784086d0c70`.
  The declared licenses are allowed by `deny.toml`.
- Package evidence: the exact selected registry source passed 31 library
  tests on Rust 1.88.0. The registry archive omits files referenced by its
  binary test target, so a literal packaged `--all-targets` run cannot compile
  those tests. Restoring the 87 byte-identical excluded fixtures from the
  exact recorded VCS commit produced 31 library and 76 binary test passes and
  compiled the example. The focused Rustleaks source and 7z unit suites also
  passed with the new pre-allocation guard.
- Conclusion: exact archive and VCS provenance, complete selected-feature and
  package source review, inactive-feature unsafe analysis, upstream package
  tests, Rustleaks integration tests, license evidence, maintained policy
  gates, and the new large-window guard support `safe-to-deploy` for
  `brotli-decompressor 5.0.3` in the locked graph. This does not claim that
  callers without Rustleaks' outer limits inherit its resource policy.

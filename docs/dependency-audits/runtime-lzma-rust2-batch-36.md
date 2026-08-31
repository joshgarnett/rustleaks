# Runtime dependency audit: lzma-rust2 batch 36

Review date: 2026-08-30.

Locked graph baseline: Rustleaks commit
`58344d61da79f1c04af7212554993aadd4b9f81e`, with `Cargo.lock` SHA-256
`e3c24453ec42115d43dd5b2b679e43cdb6e1b0802393932d3ae199db2e502d82`.
The lockfile is unchanged by this audit batch.

`lzma-rust2 0.20.0` is a normal runtime dependency of the unpublished archive
graph and remains outside the default `rustleaks-core` graph. The locked
workspace selects `std`, `xz`, and `lzip`; `xz` also selects the optional
`sha2` dependency. The package applies on every maintained target. It has no
build script, `links` value, native compilation, generated production source,
or proc macro. Rustleaks does not select the `encoder` or `optimization`
features.

A fresh refresh and minimization of the Bytecode Alliance, Google, ISRG,
Mozilla, and Zcash cargo-vet imports supplied no version-specific coverage for
the exact locked package. The residual local review therefore covered all 90
packaged files and 24,755 cargo-vet audit lines. The maintained locked RustSec
and cargo-deny gates cover advisory and source policy without accepting an
exception. The Apache-2.0 license is allowed by `deny.toml`, and its text is
packaged. No publisher trust, wildcard audit, criteria change, or exception
was used.

## `lzma-rust2 0.20.0`

- Archive: `lzma-rust2-0.20.0.crate`; 309,107 bytes; SHA-256
  `e6effa5c575f68109664a511f378c0e170888e33a426694ee0910a673762bd47`.
  The checksum matches `Cargo.lock` and the generated inventory. All 90
  archive members are regular files with mode `0644`. A fresh extraction
  matches cargo-vet's review source byte for byte apart from Cargo's
  `.cargo-ok` marker.
- Provenance: the packaged VCS record identifies upstream commit
  `e7b2aa18ca9fd5670ca5f1b1859f749a8161b628` in
  `https://github.com/hasenbanck/lzma-rust2`. Annotated unsigned tag `v0.20.0`
  points to that commit, which remains the upstream default-branch head at the
  review date. Packaged production source, project files, license, and README
  match the exact VCS tree. Cargo's normalized manifest, `Cargo.toml.orig`,
  lockfile, and VCS metadata are expected packaging additions or rewrites;
  the upstream fuzz workspace and excluded test data are expected omissions.
  This establishes exact archive-to-VCS identity without claiming signed
  provenance.
- Feature and dependency boundary: Rustleaks selects decoding, streaming,
  multithreaded reader, LZIP, and XZ APIs through `std`, `lzip`, and `xz`.
  The optional `sha2 0.11.0` dependency supplies XZ SHA-256 checksums and
  remains a separately tracked cargo-vet unit. Encoder APIs and the
  `optimization` feature are not selected. Development-only Criterion and
  static liblzma dependencies are not in the published normal graph.
- Selected unsafe boundary: the crate root applies `forbid(unsafe_code)` when
  `optimization` is disabled, so Rustleaks' selected package code contains no
  unsafe Rust, native code, or FFI. The complete package review also covered
  the unselected `optimization` implementation: bounded unchecked match
  slices, bounded unaligned native-word comparisons, range-decoder assembly
  with clamped buffer reads on AArch64 and x86-64, runtime-dispatched SIMD
  normalization over aligned slice partitions, and bounded unaligned encoder
  fast-reject reads. The exact default-feature test and fuzz builds exercise
  that optional unsafe implementation even though Rustleaks does not compile
  it.
- Authority boundary: the package reads compressed bytes and writes decoded
  bytes through caller-provided `Read` and `Write` implementations. It does
  not access paths, files, the environment, the network, processes, logging,
  or mutable process-global state. Its `std` multithreaded reader variants may
  create and join worker threads; Rustleaks uses single-threaded readers and
  streaming decoders.
- Hostile-input behavior: LZMA, LZMA2, LZIP, and XZ headers, properties,
  filters, indexes, sizes, checksums, state transitions, truncation, and
  corruption paths were reviewed. Decoder construction exposes dictionary
  memory limits, uses fallible large-buffer allocation, and rejects malformed
  properties and unsupported structures. Internal state assertions and
  mutex-poison handling can panic only when package invariants or a prior
  worker panic have already failed; malformed-input tests and fuzz targets
  exercise the public parser boundary without an observed panic.
- Rustleaks controls: `rustleaks-sources` additionally bounds archive depth,
  entry count, member size, total expanded bytes, and spooled input; checks
  cancellation; limits decoder output; and verifies archive-level integrity
  before emitting content. `rustleaks-sevenz` applies codec memory limits and
  the maintained archive panic policy. These outer controls bound the package
  in Rustleaks and are not generalized to other consumers.
- License: packaged `LICENSE` has SHA-256
  `43070e2d4e532684de521b885f385d0841030efa2b1a20bafb76133a5e1379c1`.
  Packaged `README.md` has SHA-256
  `477ecbe9893cb92e17bfadabb8b12189b2ad4fbfb14f9c4ee23b7d8e4d841a9a`.
  There is no packaged `NOTICE` or additional license file.
- Published evidence: the exact upstream default-feature source passed its 31
  library tests, all maintained LZIP, LZMA, LZMA2, XZ, stream,
  multithreading, reference-compatibility, regression, unwind-safety, and
  documentation suites on current stable Rust. Three upstream tests marked
  ignored by default are multi-gigabyte or exhaustive stress cases. The
  selected `std,xz,lzip` feature subset passed 21 library tests on current
  stable and exact Rust 1.85.0, which is older than Rustleaks' Rust 1.88 MSRV.
- Fuzz evidence: all eight upstream default-feature targets (`lzip`,
  `lzip_stream`, `lzma`, `lzma_stream`, `lzma2`, `lzma2_stream`, `xz`, and
  `xz_stream`) completed 1,000 libFuzzer runs each with 4,096-byte inputs,
  10-second per-input timeouts, and a 1,024 MiB RSS cap on the exact release
  checkout without a crash or sanitizer failure. The default feature set
  includes the optional optimization and encoder implementation. Miri was not
  run because `cargo-miri` is not installed for the available nightly; adding
  or changing a toolchain is outside this audit's authority. Rustleaks'
  selected graph forbids unsafe code, and the optional unsafe boundary was
  reviewed and exercised separately.
- Conclusion: complete source review, exact archive and VCS provenance,
  selected-feature and full-package unsafe analysis, multi-toolchain tests,
  bounded fuzzing, Rustleaks resource controls, license evidence, and the
  maintained advisory gates support `safe-to-deploy` for `lzma-rust2 0.20.0`.
  The audit does not certify the separately tracked `sha2 0.11.0` dependency
  or claim that callers without Rustleaks' outer resource policy inherit its
  archive limits.

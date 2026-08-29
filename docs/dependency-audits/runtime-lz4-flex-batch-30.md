# Runtime dependency audit: lz4_flex batch 30

Review date: 2026-08-29.

Locked graph baseline: Rustleaks commit
`fbf37a7800fcc29a36777a7b8aa0747d25c3db37`, with `Cargo.lock` SHA-256
`e3c24453ec42115d43dd5b2b679e43cdb6e1b0802393932d3ae199db2e502d82`.
The lockfile is unchanged by this audit batch.

`lz4_flex 0.14.0` is a normal dependency of `rustleaks-sources` and
`rustleaks-sevenz`. It reaches `rustleaks-cli` and `rustleaks-compat` through
those packages and remains outside the publishable core's normal and build
graphs. The selected features are `alloc`, `checked-decode`, `frame`,
`safe-decode`, `safe-encode`, and `std`. The only selected normal dependency is
`twox-hash 2.1.4` with its `xxhash32` feature; its review remains a separate
cargo-vet backlog item. The package has no build script, `links` value, native
code, generated production source, proc macro, or target-specific dependency.

A fresh refresh and minimization of the Bytecode Alliance, Google, ISRG,
Mozilla, and Zcash cargo-vet imports supplied no version-specific coverage for
the exact locked package. The local review therefore covered all 19 packaged
files and 6,068 packaged lines, including 4,821 lines of Rust source. A RustSec
check at advisory database commit
`b331df68b3ed0e99594d259040bdcb9de3c7c8a4` found no vulnerability, yanked,
unmaintained, or unsound warning for the exact package. An exact-package GitHub
Advisory Database query returned no advisory for `lz4_flex 0.14.0`. MIT is
allowed by `deny.toml`, the license text is packaged, and there is no `NOTICE`
file. No publisher trust, wildcard audit, criteria change, or exception was
used.

## `lz4_flex 0.14.0`

- Archive: `lz4_flex-0.14.0.crate`; 45,637 bytes; SHA-256
  `ecbdfe44b1bd960b68170b417450a628c43f7cf56bb3c5317e61cb230ee7f226`.
  The checksum matches `Cargo.lock`, `cargo-bazel-lock.json`, and the generated
  inventory. All 19 archive members are regular files with mode `0644`. A
  fresh archive extraction matches cargo-vet's review source byte for byte
  apart from Cargo's `.cargo-ok` marker.
- Provenance: the packaged VCS record identifies upstream commit
  `1bffdcbbf906a234b913937cb2f57c0245915038`, and release tag `0.14.0` points
  to that commit. Packaged production source, `Cargo.toml.orig`, readme, and
  license match the exact VCS tree byte for byte. The commit is an unsigned
  GitHub merge commit. The registry checksum and exact VCS comparison provide
  the retained source identity without claiming signed provenance.
- Release scope: 0.14.0 adds an allocation feature so block APIs can compile
  without a heap while preserving the prior safe and unsafe implementations.
  It contains the preceding releases' zero-offset decompression, short external
  dictionary, and 32-bit maximum-output-size fixes. Post-release upstream
  production changes add stricter lints and prevent constructing the legacy
  8 MiB block size for a current-format encoder; they do not correct a selected
  Rustleaks decoder security boundary.
- Selected unsafe boundary: enabling both `safe-encode` and `safe-decode`
  excludes `fastcpy_unsafe`, the pointer-backed sink, and the pointer block
  decoder. The selected compression, decompression, frame, and sink modules use
  `forbid(unsafe_code)`. `twox-hash` remains the selected dependency unsafe
  boundary and is tracked separately by the dependency policy.
- Unselected unsafe inventory: the complete pointer encoder and decoder were
  reviewed even though Rustleaks does not compile them. Pointer reads remain
  within the input slice, dictionary references are limited to the 64 KiB LZ4
  window, zero and out-of-range offsets are rejected, output writes are bounded
  by the caller-provided capacity, overlapping match copies use overlap-aware
  operations, and vector lengths are installed only after initialized output
  bytes have been produced. Compression wild copies rely on the format's final
  literal reserve and the checked maximum-output allocation. The upstream
  checked unsafe profile passed its unit and documentation tests on both tested
  toolchains. The pinned Miri harness completed 1,000 malformed block and
  dictionary iterations without an invalid-access report.
- Authority boundary: production code performs no filesystem or socket access,
  environment read, process or thread creation, logging, build-time execution,
  or mutable global operation. Frame APIs operate only through caller-supplied
  `Read` and `Write` values. Documentation examples mention files, and upstream
  tests compile native comparison libraries, but neither capability is present
  in the published production graph.
- Hostile-input behavior: the selected safe decoder validates frame magic,
  version and reserved bits, header, block, and content checksums when present,
  block sizes, content size, literal ranges, output capacity, match offsets,
  dictionary ranges, and block-field input ranges. The current frame format
  accepts blocks up to 4 MiB, and the legacy format uses an 8 MiB block maximum.
  The decoder allocates bounded per-block source and destination buffers based
  on that validated maximum rather than a caller-controlled content-size field.
  Block helpers that allocate from a prepended size are outside the Rustleaks
  path; both Rustleaks consumers use `FrameDecoder`.
- Resource behavior: generic `Read::read_to_end` remains caller-bounded, as for
  any streaming reader. Rustleaks reads through a fixed buffer, checks
  cancellation between reads, rejects output beyond the 64 MiB member limit,
  and charges decoded bytes to the 256 MiB archive total. Frame work is
  proportional to compressed input plus produced output under those bounds.
  Ordinary Rust allocation failure can still abort.
- Panic and integer review: malformed selected-path block fields return
  structured errors before slice copies. Length accumulation is bounded by the
  validated frame block size in Rustleaks. Internal header conversions operate
  on the exact prebuffered header length, and caller misuse of `BufRead::consume`
  retains the standard trait's panic contract. Checked additions and bounded
  buffers prevent an attacker-controlled wrap from reaching a selected copy.
- License: the packaged MIT text has SHA-256
  `0982c33390159842ecce8e9d6ce2e5e39961fe0e0ffbb2eec39c9ba46db6db10`.
  There is no `NOTICE` file or additional packaged license obligation.
- Published-source evidence: with Rustleaks' Rust 1.88 MSRV and current stable
  Rust 1.98, the exact published source passed 19 unit tests and 10
  documentation tests in the selected default profile. On both toolchains the
  checked unsafe profile `alloc,frame,checked-decode` passed 22 unit tests and
  10 documentation tests. The `nightly` feature is an internal compiler-mode
  switch and is not part of either stable profile.
- Exact-commit evidence: at the tagged VCS commit, current stable passed 19 unit
  tests, 44 integration tests with one intentionally ignored large-input test,
  and 10 documentation tests. Together with the checked unsafe-profile tests
  above, the evidence covers safe and unsafe regressions, malformed blocks,
  short dictionaries, zero offsets, independent and linked frames, block and
  content checksums, content length, all current frame block sizes, legacy
  frames, concatenated frames, reference-library interoperability,
  property-generated round trips, and inputs through 10 MiB.
- Rustleaks evidence: the authoritative
  `//crates/rustleaks-sources:archive_sources_test` and
  `//crates/rustleaks-sources:rustleaks_sources_archives_unit_test` targets pass
  for the locked selected graph. The repository's normal CI target matrix
  provides compilation evidence for the eight required targets; native AArch64
  macOS behavior is exercised by the package, Miri, and Rustleaks test runs.
- Conclusion: complete source review, exact archive and VCS provenance, a
  safe-only selected graph, review and Miri evidence for the disabled pointer
  implementation, hostile-input and interoperability tests, Rustleaks archive
  limits, license evidence, and exact-version advisory results support
  `safe-to-deploy` for `lz4_flex 0.14.0`.

# Runtime dependency audit: compcol batch 39

Review date: 2026-08-30.

Locked graph baseline: Rustleaks commit
`b2dd8469fa998134b2f74454db6cd570de216216`, with `Cargo.lock` SHA-256
`e3c24453ec42115d43dd5b2b679e43cdb6e1b0802393932d3ae199db2e502d82`.
The lockfile is unchanged by this audit batch.

`compcol 0.6.10` is a normal runtime dependency of the unpublished archive
graph and remains outside the default `rustleaks-core` graph. Rustleaks
selects only `alloc` and `rar2`. The package applies on every maintained
target. It has no build script, `links` value, native compilation, generated
production source, proc macro, or target-specific dependency. The selected
normal graph has no dependency package.

An exemption-free refresh and minimization of the Bytecode Alliance, Google,
ISRG, Mozilla, and Zcash cargo-vet imports supplied no version-specific
coverage for this release. The residual local review covered the complete
package inventory and 119,706 cargo-vet audit lines, with direct review of the
selected library compilation and its RAR2 parser. The maintained RustSec and
cargo-deny gates cover advisory, license, and source policy for the locked
graph without accepting an exception. No publisher trust, wildcard audit,
criteria change, or exception was used.

## `compcol 0.6.10`

- Archive: `compcol-0.6.10.crate`; 1,293,697 bytes; SHA-256
  `c11ff3545f0554bd738d69ab7d4556713f7b986706563b0554a89339cee83396`.
  The checksum matches `Cargo.lock`, `cargo-bazel-lock.json`, and the generated
  inventory. All 304 archive members are regular files with mode `0644`.
  Cargo-vet's extracted review source is backed by that exact archive.
- Provenance: the packaged VCS record identifies official upstream commit
  `811bdd7cddd301ee406207d9eaa369f85af569a1` in
  `https://github.com/KarpelesLab/compcol`. Annotated unsigned tag `v0.6.10`
  points to that commit. Packaged project files match the exact VCS tree.
  Cargo's normalized manifest, original manifest copy, generated lockfile,
  VCS record, and `.cargo-ok` marker are expected package additions or
  rewrites; the upstream fuzz workspace is intentionally excluded. This
  establishes archive-to-VCS identity without claiming signed provenance.
- Feature and dependency boundary: `alloc` provides boxed decoder state and
  owned buffers. `rar2` selects the RAR2 decoder, its fixed tables, bit reader,
  canonical Huffman decoder, and audio predictor. It selects no dependency,
  standard-library, thread, async, native, or build-time implementation. The
  package's many other codecs, factory, standard I/O adapters, Tokio adapter,
  and command-line binary are not compiled in the Rustleaks graph. A future
  feature change must reopen this review.
- Unsafe boundary: the crate root and manifest forbid unsafe Rust, and the
  complete production source contains no unsafe block or declaration. The
  selected graph has no dependency unsafe boundary. All-feature compilation
  preserves the same crate-level prohibition.
- Authority boundary: the selected `no_std` library operates only on caller
  byte slices and owned buffers. It performs no file or path access,
  environment read, network access, process or thread creation, logging, or
  mutable process-global operation. The unselected command-line binary and
  tests use standard I/O, files, environment arguments, and reference tools;
  none of those capabilities enters Rustleaks.
- Hostile-input behavior: RAR2 input is buffered until `finish` because the
  format's unpacked length is supplied by the archive header. The decoder
  validates truncated bit input, code lengths, Kraft oversubscription, absent
  trees, symbol ranges, match lengths and distances, block restarts, and final
  output length. Slice accesses are checked. Match emission is capped at the
  caller-supplied unpacked length, and invalid state returns a typed error.
  The fixed decoder window is 1 MiB.
- Rustleaks controls: the RAR adapter validates the unpacked length against the
  configured member limit before constructing the decoder, caps the root or
  nested archive spool, checks cancellation between codec calls, validates
  decoder progress and exact output length, and verifies the RAR member CRC
  before emitting bytes. With default limits, compressed input and decoded
  output are each at most 64 MiB. The dependency additionally buffers its
  input and materializes its output, so transient memory includes those copies
  plus the fixed window. Ordinary Rust allocation failure can still abort as
  documented by the repository resource contract.
- Panic and integer review: input-derived bit widths and table indices are
  bounded before shifts or indexing. Length-table repeat runs clamp at the
  fixed table boundary. Offset arithmetic uses fixed-width values and checked
  range tests before conversion to an index. The only production assertion in
  the selected parser guards a private const-generic call where every caller
  passes a slice no larger than its matching array. Debug assertions guard
  private bit-reader invariants. No malformed-input panic was observed in the
  selected tests, the all-feature suite, or the bounded fuzz campaign.
- License: the package declares MIT, which is allowed by `deny.toml`. Packaged
  `LICENSE` has SHA-256
  `a7009ce74b33a2afcf9ab38007bf3c8f5020d9b816dc5fc7296bf17e6d7dc796`.
  Packaged `README.md` and `SECURITY.md` have SHA-256 values
  `ce9ff6f8ff9be7107822df02d3d9dfef07ba758f8aa558f394523bc622b65856`
  and
  `b67191a4aa4e7a5195dc5d39418b0e87e0ab931c9f7a2e93ad8e513c0a197f52`.
  There is no packaged `NOTICE` or additional license file.
- Package evidence: on Rustleaks' Rust 1.88 MSRV, the exact published source
  passed 14 selected-feature unit tests, 19 selected RAR2 integration tests,
  and the applicable documentation tests with `alloc,rar2`. Its all-target,
  all-feature suite enumerated 1,763 tests and passed all 1,762 executed
  tests; one timing stress test remained intentionally ignored. That broader
  run exercises every packaged codec, the optional Tokio dependency, I/O
  adapters, command-line binary, cross-tool fixtures, malformed inputs,
  streaming partitions, and reset behavior, but does not make those
  unselected surfaces reachable from Rustleaks.
- Fuzz and repository evidence: the exact upstream `decoder_rar2` harness
  completed 1,000 libFuzzer runs with 4,096-byte inputs, a five-second
  per-input timeout, and a 2,048 MiB RSS cap without a crash or sanitizer
  failure. The fresh uncached
  `//crates/rustleaks-sources:archive_sources_test` target passed and includes
  the committed compressed RAR2 corpus. The repository's authoritative CI
  target matrix retains compilation evidence for all eight required targets.
- Conclusion: exact archive and VCS provenance, complete package inventory,
  direct selected-source review, safe-only dependency-free selected code,
  hostile-input and allocation analysis, upstream tests and fuzzing,
  Rustleaks archive controls, license evidence, and maintained advisory gates
  support `safe-to-deploy` for `compcol 0.6.10` in the locked Rustleaks graph.
  The audit does not claim that unbounded callers inherit Rustleaks' archive
  limits or that unselected package features enter the Rustleaks boundary.

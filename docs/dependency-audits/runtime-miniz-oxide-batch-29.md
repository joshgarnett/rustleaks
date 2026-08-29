# Runtime dependency audit: miniz_oxide batch 29

Review date: 2026-08-29.

Locked graph baseline: Rustleaks commit
`e5e02826762076d227a0c29d3d45856b639fea40`, with `Cargo.lock` SHA-256
`e3c24453ec42115d43dd5b2b679e43cdb6e1b0802393932d3ae199db2e502d82`.
The lockfile is unchanged by this audit batch.

`miniz_oxide 0.9.1` is a normal dependency of `rustleaks-sources` and
`rustleaks-sevenz`, and reaches `rustleaks-cli` and `rustleaks-compat` through
those packages. It is outside the publishable core's normal and build graph.
The selected package feature is `with-alloc`; the only normal dependency is
the separately audited `adler2 2.0.1`. The package has no build script,
`links` value, native code, or generated production source. Its only
target-specific production branch moves a large compression buffer to the
heap on `wasm32`.

The approved Bytecode Alliance import supplies a `safe-to-deploy` audit chain
from `miniz_oxide 0.7.1` through `0.8.9`. A fresh refresh and minimization of
all five approved peer imports supplied no audit for the `0.8.9 -> 0.9.1`
delta. This local review is limited to that remaining delta. Cargo-vet reports
540 insertions and 185 deletions in the review diff.

## `miniz_oxide 0.8.9 -> 0.9.1`

- Archives: `miniz_oxide-0.8.9.crate` has SHA-256
  `1fa76a2c86f704bdb222d66965fb3d63269ce38518b83cb0575fca855ebb6316`;
  `miniz_oxide-0.9.1.crate` has SHA-256
  `b63fbc4a50860e98e7b2aa7804ded1db5cbc3aff9193adaff57a6931bf7c4b4c`.
  Both values match `Cargo.lock`; the latter also matches
  `cargo-bazel-lock.json` and the generated inventory. The 0.9.1 archive has
  19 regular files, all with mode `0644`, and contains 7,850 lines, including
  7,299 lines of Rust. A fresh extraction matches cargo-vet's review source
  byte for byte apart from Cargo's `.cargo-ok` marker.
- Provenance: the packaged VCS record identifies upstream commit
  `4e582392df3a739d2b0dfd2c537dc33e8942be38` under `miniz_oxide/` in the
  official repository. Packaged production source, `Cargo.toml.orig`, readme,
  and license files match that exact commit. There is no matching release tag,
  and GitHub reports the commit as unsigned; the registry checksum and exact
  VCS comparison provide the retained source identity without claiming signed
  provenance.
- Delta scope: decompression changes harden oversubscribed and incomplete
  Huffman-table validation and add a caller-selected output limit to the
  low-level decoder. Compression changes add bounded window-size parameters,
  explicit partial and no-sync flush modes, cloning for compressor state, a
  smaller distance lookup, stored-block cleanup, and a heap-backed large
  buffer on `wasm32`. Manifest changes make Serde's allocation and standard
  library features explicit and update the optional SIMD dependency. The
  selected Rustleaks graph enables none of Serde, SIMD, standard-library, or
  internal `rustc-dep-of-std` integration.
- Unsafe and dependency boundary: the crate retains
  `#![forbid(unsafe_code)]`, and the complete production source contains no
  unsafe block or implementation. The selected `adler2` dependency is also
  covered by a local full audit. Optional `simd-adler32` is not selected in
  the 0.9.1 Rustleaks graph and is not part of this delta certification.
- Authority boundary: production code performs no file or socket access,
  environment read, process or thread creation, logging, or mutable global
  operation. Upstream integration tests use files and an optional environment
  variable, but Cargo excludes `tests/` and `benches/` from the published
  package and those capabilities are not compiled into the library.
- Hostile-input and resource behavior: the inflate state machine validates
  Huffman symbols, distances, wrapper checksums, output capacity, and forward
  progress using safe slice operations and error statuses. Whole-buffer helper
  APIs can allocate according to decompressed output and are documented as
  unsuitable for unbounded real-world input. Rustleaks instead uses streaming
  inflate. `rustleaks-sources` checks cancellation and forward progress and
  bounds every output extension; `rustleaks-sevenz` streams into caller-owned
  buffers and the archive orchestration applies its resource limits. Work is
  proportional to consumed compressed data and emitted output under those
  downstream bounds.
- Panic and correctness review: new arithmetic that bounds output uses
  saturating addition and clamps to the caller's slice. Invalid table and
  distance states return decoder failures. The changed fast-path capacity
  check is conservative and falls back to the checked byte-copy state. A
  post-release correction changes an internal compression flag expression;
  upstream records that expression as unreachable in its call paths.
  Rustleaks invokes only decompression in production, so the compression-only
  expression is outside the selected runtime path and cannot introduce memory
  unsafety in this safe-only crate.
- Licenses and advisories: `MIT OR Zlib OR Apache-2.0` is allowed by
  `deny.toml`. All three license alternatives are packaged, with SHA-256
  values `799e9ca9d179295ef372f25d3769cdda7d25bb2668add6a6a1e22d1e4c678b8d`,
  `0a54e647fe54104658b5e563c04c6f9edf251710e47bce692e0bd990a4ddaa39`,
  and `0d542e0c8804e39aa7f37eb00da5a762149dc682d7829451287e11b938e94594`;
  the additional packaged `LICENSE` has SHA-256
  `4108245a1f2df9d4e94df8abed5b4ba0759bb2f9b40a6b939f1be141077ae50b`.
  There is no `NOTICE` file. RustSec database commit
  `b331df68b3ed0e99594d259040bdcb9de3c7c8a4` reports no vulnerability,
  yanked, unmaintained, or unsound warning for 0.9.1. The GitHub Advisory
  Database returns no Rust advisory for the package.
- Test evidence: the exact published source passed 29 unit tests and 2
  documentation tests with the selected feature on Rust 1.85.0. The public
  feature union `with-alloc,std,simd,serde,block-boundary` passed the same 29
  unit and 2 documentation tests on Rust 1.85.0 and current stable. Literal
  `--all-features` is not a supported profile because it combines the internal
  `rustc-dep-of-std` mode with the public API. At the exact VCS commit, the
  public feature union additionally passed 23 integration tests covering
  flush alignment, output limits, round trips, malformed Huffman tables,
  truncated input, prior panic and loop regressions, and block boundaries.
- Target evidence: pinned-nightly `build-std` checks compiled the selected
  `with-alloc` library for all seven non-native required targets and for
  `wasm32-unknown-unknown`, which exercises the changed target-specific
  allocation branch. Native AArch64 macOS behavior was exercised by the
  multi-toolchain and exact-commit test runs.
- Conclusion: the trusted audit chain through 0.8.9, complete 0.9.1 delta
  review, exact archive and VCS provenance, safe-only source, hostile-input
  tests, selected target builds, license evidence, and advisory results
  support a `safe-to-deploy` delta certification for 0.8.9 to 0.9.1.

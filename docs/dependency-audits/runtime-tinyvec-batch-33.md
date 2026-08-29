# Runtime dependency audit: tinyvec batch 33

Review date: 2026-08-29.

Locked graph baseline: Rustleaks commit
`86565e7c26489a4517efaf4576b1c3829e93f0d7`, with `Cargo.lock` SHA-256
`e3c24453ec42115d43dd5b2b679e43cdb6e1b0802393932d3ae199db2e502d82`.
The lockfile is unchanged by this audit batch.

`tinyvec 1.12.0` is a normal dependency of `rustleaks-bzip2`,
`rustleaks-cli`, and `rustleaks-sevenz`. It remains outside the publishable
core's normal and build graphs. Rustleaks selects no tinyvec features. The
selected package graph has no normal dependency, build script, `links` value,
native code, generated production source, proc macro, or target-specific
dependency. Rustleaks directly uses only fixed-capacity `ArrayVec` values in
`rustleaks-bzip2`, with standard-array capacities from 6 through 18,001.

A fresh refresh and minimization of the Bytecode Alliance, Google, ISRG,
Mozilla, and Zcash cargo-vet imports supplied no version-specific coverage for
the exact locked package. The residual local review therefore covered all 26
packaged files and 9,171 packaged lines, including 7,456 lines of Rust source.
A RustSec check at advisory database commit
`b331df68b3ed0e99594d259040bdcb9de3c7c8a4` found no vulnerability, yanked,
unmaintained, or unsound warning for the exact package. An exact-package GitHub
Advisory Database query returned no advisory for `tinyvec 1.12.0`. Zlib OR
Apache-2.0 OR MIT is allowed by `deny.toml`, all three license texts are
packaged, and there is no `NOTICE` file. No publisher trust, wildcard audit,
criteria change, or exception was used.

## `tinyvec 1.12.0`

- Archive: `tinyvec-1.12.0.crate`; 56,568 bytes; SHA-256
  `bb4ebadaa0af04fab11ae01eb5f9fdb5f9c5b875506e210e71c07873528baa7f`.
  The checksum matches `Cargo.lock` and the generated inventory. All 26
  archive members are regular files with mode `0644`. A fresh archive
  extraction matches cargo-vet's review source byte for byte apart from
  Cargo's `.cargo-ok` marker.
- Provenance: the packaged VCS record identifies upstream commit
  `347ddc6463159eec38d3758a8881a22f44d50373`, and annotated release tag
  `v1.12.0` points to that commit. Packaged production source,
  `Cargo.toml.orig`, readme, changelog, rustfmt configuration, debug metadata,
  and licenses match the exact VCS tree byte for byte. The release commit and
  tag are unsigned. The registry checksum and exact VCS comparison provide
  the retained source identity without claiming signed provenance.
- Release scope: relative to 1.11.0, the production changes add optional
  `bin-proto` and `schemars` integrations, cap eager capacity selected from
  untrusted deserialization lengths, and update documentation and type
  annotations. Decoding still consumes only elements actually present in the
  input. One subsequent upstream commit adds a new constructor and tests and
  does not alter the reviewed release.
- Unsafe boundary: the crate forbids unsafe code, including production paths
  behind optional features. Array storage is exposed only through safe slices.
  The safe, user-implementable `Array` trait can cause a panic or incorrect
  capacity report if implemented inconsistently, but cannot create unchecked
  memory access. Rustleaks uses standard arrays, whose implementations are
  fixed by the crate.
- Selected boundary: Rustleaks uses only `ArrayVec` with fixed standard-array
  capacities. Length is stored as `u16`; slice access, shifting, insertion,
  removal, and draining use checked safe operations. Capacity exhaustion is a
  documented panic, and Rustleaks' capacities are within the representable
  range. The selected path does not allocate.
- Authority boundary: production code performs no filesystem or socket access,
  environment read, process or thread creation, logging, build-time execution,
  or mutable global operation. The selected library is synchronous and
  operates on caller-owned values and borrowed slices.
- Hostile-input and resource behavior: selected work is bounded by fixed
  capacities and caller iteration. Optional `TinyVec` heap paths allocate in
  proportion to elements actually accepted. Optional deserializers cap eager
  preallocation from an untrusted length prefix to approximately 4 KiB and
  reject fixed-array item counts over capacity. There is no recursion or
  unchecked indexing path.
- Optional features: the reviewed stable feature union includes allocation,
  Serde, Arbitrary, Borsh, generic-array, bin-proto, defmt, schemars, spare
  slice access, and the experimental formatting implementation. The optional
  formatting implementation and array capacities above `u16::MAX` are
  unselected, use safe operations, and create no memory unsafety or ambient
  authority. Nightly-only slice partitioning and debugger metadata add no
  production authority and are not selected.
- Licenses: the packaged Apache-2.0, MIT, and Zlib texts have SHA-256 values
  `cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30`,
  `fd80a26fbb3f644af1fa994134446702932968519797227e07a1368dea80f0bc`,
  and
  `84b34dd7608f7fb9b17bd588a6bf392bf7de504e2716f024a77d89f1b145a151`.
  There is no `NOTICE` file or additional packaged license obligation.
- Selected-feature evidence: the exact published source passed 5 unit tests,
  14 integration tests, and 38 documentation tests on Rustleaks' Rust 1.88
  MSRV and current stable Rust 1.98.
- Full-package evidence: current stable passed the stable feature union's 7
  unit tests, 51 integration tests, and 73 documentation tests, including the
  hostile Borsh length regression. Pinned-nightly Miri passed the selected
  graph's 5 unit tests, 14 integration tests, and 38 documentation tests, then
  the stable feature union's 7 unit tests, 51 integration tests, and 73
  documentation tests.
- Rustleaks evidence: the authoritative
  `//crates/rustleaks-bzip2:rustleaks_bzip2_unit_test`,
  `//crates/rustleaks-bzip2:rustleaks_bzip2_doc_test`,
  `//crates/rustleaks-sevenz:oracle_codecs_test`, and
  `//crates/rustleaks-sources:archive_sources_test` targets pass for the locked
  selected graph. The repository's normal CI target matrix provides
  compilation evidence for the eight required targets.
- Conclusion: complete source review, exact archive and VCS provenance,
  selected and optional-feature boundary review, multi-toolchain tests, Miri,
  Rustleaks integration tests, license evidence, and exact-version advisory
  results support `safe-to-deploy` for `tinyvec 1.12.0`.

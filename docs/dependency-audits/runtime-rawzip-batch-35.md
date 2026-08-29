# Runtime dependency audit: rawzip batch 35

Review date: 2026-08-29.

Locked graph baseline: Rustleaks commit
`68ecdb2c07906ec908de34668008b6620edc0539`, with `Cargo.lock` SHA-256
`e3c24453ec42115d43dd5b2b679e43cdb6e1b0802393932d3ae199db2e502d82`.
The lockfile is unchanged by this audit batch.

`rawzip 0.5.1` is a normal dependency of `rustleaks-sources` and remains
outside the default `rustleaks-core` graph. Rustleaks selects the `alloc` and
`std` features on every maintained target. The package has no normal
dependencies, build script, `links` value, native compilation, generated
production source, proc macro, or target restriction.

A fresh refresh and minimization of the Bytecode Alliance, Google, ISRG,
Mozilla, and Zcash cargo-vet imports supplied no version-specific coverage for
the exact locked package. The residual local review therefore covered all 64
packaged files and 18,949 cargo-vet audit lines, including all 9,998 source
lines counted with tests. An exact-package GitHub Advisory Database query
returned no advisory affecting `rawzip 0.5.1`. The MIT license is allowed by
`deny.toml`, and its text is packaged. No publisher trust, wildcard audit,
criteria change, or exception was used.

## `rawzip 0.5.1`

- Archive: `rawzip-0.5.1.crate`; 256,630 bytes; SHA-256
  `75a2b2577f5fd7e26caabd4aa7bba1ef18653ff32204eea251c1136db1a549f3`.
  The checksum matches `Cargo.lock` and the generated inventory. All 64
  archive members are regular files with mode `0644`. A fresh extraction
  matches cargo-vet's review source byte for byte apart from Cargo's
  `.cargo-ok` marker.
- Provenance: the packaged VCS record identifies upstream commit
  `571e479673646848ec16b12213b7600d639971d8` in
  `https://github.com/m-ou-se/rawzip`. Annotated unsigned tag `v0.5.1` points
  to that commit, which also remains the upstream default-branch head at the
  review date. Packaged production source, `Cargo.toml.orig`, `LICENSE.txt`,
  `README.md`, and common project files match the exact VCS tree. Cargo's
  normalized manifest and VCS metadata are expected packaging differences.
  The published archive also contains two `.git` path files with public ref
  and log residue. They contain no credentials or sensitive content and do
  not affect compilation or runtime behavior. The registry checksum and
  exact VCS comparison establish retained source identity without claiming
  signed provenance.
- Rust boundary: the package is dependency-free production Rust and declares
  `#![forbid(unsafe_code)]`. Its parser operates on caller-supplied byte
  slices or readers and does not use native code, FFI, raw pointers, or unsafe
  blocks. The reviewed production `expect` calls follow explicit parsed-length
  checks. A poisoned reader mutex can panic only after the wrapped reader has
  already panicked; Rustleaks uses the slice-backed path.
- Authority boundary: the package parses ZIP metadata and exposes logical
  entry names and compressed data to its caller. It performs no filesystem
  extraction, network access, environment read, process or thread creation,
  logging, or mutable global operation. Raw entry paths remain logical source
  names in Rustleaks and are never converted into filesystem writes.
- Hostile-input behavior: end records, central-directory entries, local
  headers, extra fields, offsets, lengths, and data-descriptor variants are
  parsed with explicit bounds and checked arithmetic. Truncated, inconsistent,
  unsupported, or overflowing structures return errors. The package leaves
  decompression, CRC verification, duplicate-name policy, recursive archive
  handling, and aggregate resource policy to its caller, as documented by its
  API.
- Rustleaks controls: `rustleaks-sources` independently bounds archive depth,
  entry count, member size, total expanded bytes, and spooled input; checks
  cancellation; performs bounded decompression; and verifies declared size and
  CRC before emitting content. These controls supply the resource and
  integrity policy that rawzip intentionally leaves to callers. The audit does
  not generalize those Rustleaks-specific controls to other rawzip consumers.
- License: packaged `LICENSE.txt` has SHA-256
  `2af4d13698993a15849a869b4c2ed4954cf251768ad145f371774adb96697e0c`.
  There is no packaged `NOTICE` or additional license obligation.
- Published evidence: the exact published source passed 185 unit tests, 156
  integration tests, its examples, and 47 documentation tests on current
  stable Rust. The same unit, integration, and example suites passed on Rust
  1.88. Miri was not run because `cargo-miri` is not installed; the package's
  prohibition of unsafe production code leaves no unsafe implementation
  boundary for Miri to validate.
- Fuzz and integration evidence: the upstream `fuzz_zip` target completed
  10,000 bounded libFuzzer runs on the exact package without a crash. The
  authoritative `//crates/rustleaks-sources:archive_sources_test` target
  passes for Rustleaks' selected graph and exercises archive parsing under the
  maintained outer limits.
- Conclusion: complete source review, exact archive and VCS provenance,
  selected-feature and dependency-boundary analysis, multi-toolchain tests,
  bounded fuzzing, Rustleaks integration evidence, license evidence, and the
  exact-version advisory result support `safe-to-deploy` for `rawzip 0.5.1`.
  The audit preserves the package's documented caller responsibility for
  decompression, integrity, recursion, names, and resource limits; Rustleaks
  supplies those controls outside the package.

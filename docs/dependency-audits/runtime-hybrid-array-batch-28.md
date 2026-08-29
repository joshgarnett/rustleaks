# Runtime dependency audit: hybrid-array batch 28

Review date: 2026-08-29.

Locked graph baseline: Rustleaks commit
`518eca0839277f458575a9446c0b018befa37c2f`, with `Cargo.lock` SHA-256
`e3c24453ec42115d43dd5b2b679e43cdb6e1b0802393932d3ae199db2e502d82`.
The lockfile is unchanged by this audit batch.

`hybrid-array 0.4.14` is a normal dependency of `block-buffer 0.12.1`
and `crypto-common 0.2.2`. The locked graph reaches both through
`digest 0.11.3` and `sha2 0.11.0`, including the `lzma-rust2`,
`rustleaks-sources`, `rustleaks-sevenz`, and `xtask` paths. The generated
inventory records `rustleaks-cli` and `xtask` as workspace consumers. No
package feature is selected. The direct `typenum 1.20.1` dependency selects
its `const-generics` feature. The package has no build script, `links` value,
native code, target-specific production branch, or core normal or build graph
path.

A fresh temporary refresh and minimization of the Bytecode Alliance, Google,
ISRG, Mozilla, and Zcash cargo-vet imports produced no change and provided no
version-specific coverage for the exact locked package. The local review
covered all 24 packaged files and 4,993 packaged lines, including 3,882 lines
of Rust source and tests. A RustSec check at advisory database commit
`b331df68b3ed0e99594d259040bdcb9de3c7c8a4` found no vulnerability or yanked
warning for the exact package. An exact-package GitHub Advisory Database query
returned no advisory for `hybrid-array 0.4.14`. Apache-2.0 OR MIT matches
`deny.toml`, both license texts are packaged, and there is no `NOTICE` file.
No publisher trust, wildcard audit, criteria change, or exception was used.

## `hybrid-array 0.4.14`

- Archive: `hybrid-array-0.4.14.crate`; SHA-256
  `707114b52a152fa7bdb290cd7cd5912d9467273b6d74e21b8d81aca1f8533f6b`.
  All 24 archive members are regular files with mode `0644`. Cargo's registry
  source matches a fresh archive extraction byte for byte apart from Cargo's
  `.cargo-ok` marker. The packaged VCS record identifies upstream commit
  `1b65ce708c931d27b2a17400d0dad92500f23f30`, and release tag `v0.4.14`
  points at that commit. Production source, tests, documentation, changelog,
  licenses, workflows, and `Cargo.toml.orig` match the exact VCS tree. The
  normalized manifest, package lockfile, and VCS record are Cargo packaging
  metadata. `LICENSE-APACHE` and `LICENSE-MIT` have respective SHA-256 values
  `a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5`
  and
  `70c9d40f1f9545c3f133b8a67206e89da850f6468eed072281bb3701514114a9`.
- Rustleaks use: `block-buffer` and `crypto-common` use fixed-size `Array`
  values inside the digest implementation selected by `sha2`. Rustleaks does
  not construct a caller-selected `ArraySize`, enable an optional package
  feature, or expose `hybrid-array` in a public API. The direct `typenum`
  dependency forbids unsafe code. Its complete source audit remains a separate
  cargo-vet backlog item.
- Unsafe size invariant: the package defines one public unsafe `ArraySize`
  trait. Its associated array type must contain exactly `Unsigned::USIZE`
  elements. The package's macro supplies implementations for literal array
  lengths and generates tests that compare every literal with the matching
  typenum value, including the optional extra-size table. A downstream crate
  can write an incorrect unsafe implementation, but the locked graph uses only
  package-provided implementations.
- Unsafe memory operations: the 29 source unsafe blocks fall into four
  reviewed groups. Transparent array and slice casts preserve element type,
  alignment, lifetime, and checked length. Split, concatenate, flatten, and
  unflatten operations constrain sizes with typenum sum, difference, product,
  quotient, and remainder relationships; they transfer each owned element
  exactly once through `ManuallyDrop`, and runtime offset or flattened-length
  multiplication is checked where needed. `MaybeUninit` construction uses a
  guard that drops exactly the initialized prefix on an error or panic and
  calls `assume_init` only after every slot is written. The explicit `Send`,
  `Sync`, and optional `Pod` and `Zeroable` implementations retain the
  corresponding element-type bounds. Pinned strict-provenance Miri exercised
  the all-feature tests for array construction, casts, splitting, flattening,
  iteration, optional integrations, and size mappings without an
  invalid-access report.
- Authority and resource boundary: the crate is `no_std` and performs no file
  or socket access, environment read, process or thread creation, logging,
  global mutation, recursion, or build-time generation. Selected operations
  are linear in a compile-time array size or a caller-owned slice length and
  do not allocate. Optional `alloc` conversions allocate only their fixed
  array length, and ordinary allocation failure can abort.
- Panic and hostile-input behavior: the crate parses no untrusted byte format.
  Fallible slice and iterator conversions return errors on a length mismatch.
  The standard `FromIterator` implementation deliberately panics on a length
  mismatch, zero-sized chunk requests panic, and flattening a sufficiently
  long slice of zero-sized arrays can panic when its logical length exceeds
  `usize`; these conditions are documented. Rustleaks reaches fixed digest
  buffer sizes and none of those caller-selected interfaces.
- Published-source evidence: the default-feature suite passed on the declared
  Rust 1.85.0 MSRV with 63 unit and integration tests plus 6 documentation
  tests. The all-feature suite passed on Rust 1.85.0 and current stable with 91
  unit and integration tests plus 6 documentation tests on each toolchain.
  Pinned nightly Miri with symbolic alignment checks and strict provenance
  passed the complete all-feature suite of 91 tests plus 6 documentation
  tests on AArch64 macOS.
- Target evidence: pinned-nightly `build-std` checks compiled the selected
  no-feature library for the seven non-native required targets. Native AArch64
  macOS behavior was exercised by the multi-toolchain and Miri test runs. The
  package has no target-specific production branch.
- Conclusion: complete source review, exact archive and VCS provenance, unsafe
  size and memory proofs, selected and all-feature tests, all-required-target
  compilation, Miri execution, license evidence, and advisory results support
  `safe-to-deploy` for the locked Rustleaks graph.

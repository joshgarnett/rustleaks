# Runtime dependency audit: crypto-common batch 18

Review date: 2026-08-29.

Locked graph baseline: Rustleaks commit
`fb8746fc4f787fdf98205402372c306304617f7e`, with `Cargo.lock` SHA-256
`e3c24453ec42115d43dd5b2b679e43cdb6e1b0802393932d3ae199db2e502d82`.
The lockfile is unchanged by this audit batch.

`crypto-common 0.2.2` is a normal dependency of `digest 0.11.3`, which is
used by `sha2 0.11.0`. The locked graph reaches it through XZ SHA-256 checksum
handling in `lzma-rust2`, the archive-enabled sources graph, and SHA-256
maintenance operations in `xtask`. The generated inventory records the CLI
and `xtask` roots, no selected optional feature, every declared target, no
build script, and no `links` value. Its selected dependency is
`hybrid-array 0.4.14` with that package's default feature, which selects
`typenum 1.20.1` with `const-generics` and `default`.

The review covered all 11 packaged files and 1,784 packaged text lines,
including all 853 lines of Rust source, manifests, the package lockfile,
licenses, README, changelog, and VCS record. A RustSec check at advisory
database commit `b331df68b3ed0e99594d259040bdcb9de3c7c8a4` found no vulnerability,
unmaintained, unsound, or yanked warning in the exact Rustleaks lockfile. An
exact-package GitHub Advisory Database query returned no record, and the
upstream repository reports no published security advisory. MIT OR
Apache-2.0 matches `deny.toml`; both license texts are packaged and there is
no `NOTICE` file. No peer audits, wildcard trust, criteria changes, or
exceptions were used.

## `crypto-common 0.2.2`

- Archive: `crypto-common-0.2.2.crate`; SHA-256
  `ce6e4c961d6cd6c9a86db418387425e8bdeaf05b3c8bc1411e6dca4c252f1453`.
  The packaged VCS record identifies upstream commit
  `93dee26c6bde3741a197f1c5f6b7baac277705f3` under `crypto-common`; tag
  `crypto-common-v0.2.2` points at that commit. All 11 archive members are
  regular files with mode `0644`. A fresh extraction matched cargo-vet's
  source byte for byte apart from Cargo's `.cargo-ok` marker. Source,
  changelog, README, licenses, and `Cargo.toml.orig` match the exact upstream
  tree. The normalized manifest, package lockfile, and VCS record are Cargo
  packaging metadata. `LICENSE-APACHE` and `LICENSE-MIT` have respective
  SHA-256 values
  `a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5`
  and
  `d2e7ec5355c96eeade56b09187ceb48a6a30299da3ce7531a66d3d11405ab963`.
- Rustleaks use: the package supplies fixed-size array aliases, size traits,
  initialization traits, error types, and serializable-state support used
  through `digest` and `sha2`. `lzma-rust2` uses SHA-256 as an XZ stream
  integrity check, while `xtask` hashes fixtures, evidence, and candidate
  release artifacts. SHA-256 integrity checks are not an authentication
  boundary. Rustleaks source does not directly name the package's hazardous
  state module.
- Type and algorithm behavior: key, IV, block, and output sizes are type-level
  `hybrid-array` lengths. Slice initialization first converts the input to an
  exact-size array reference and returns `InvalidLength` or `InvalidKey` when
  conversion fails. Integer and array state serialization uses fixed-size
  little-endian chunks. Work is linear in a compile-time array length, does
  not recurse, and performs no package-owned heap allocation. The package
  warns that serialized algorithm state may contain sensitive data. Rustleaks
  does not persist that state through this API.
- Unsafe and dependency inventory: the crate root forbids unsafe Rust, and
  the package contains no unsafe block, unsafe function, external function,
  native interface, mutable static, or interior-mutability implementation.
  The active `hybrid-array` dependency uses unsafe traits and pointer and
  initialization operations to implement its array representation. That
  package remains covered by its separate exemption and is not represented
  as audited by this worksheet. `typenum`, below it, forbids unsafe Rust.
- Native and authority boundary: the archive has no build script, native
  source, generated-at-build source, or `links` declaration. Selected code is
  `no_std` and opens no file or socket, reads no environment variable, starts
  no process or thread, writes no log, and maintains no process-global state.
  The unselected `rand_core` feature accepts a caller-provided random number
  generator. The unselected `getrandom` feature adds ambient system random
  number generation; its fallible method returns the provider error and its
  documented infallible convenience method panics on provider failure. The
  unselected `zeroize` feature enables the dependency's zeroization support.
- Panic and resource behavior: selected slice conversion reports invalid
  lengths. Fixed-width state conversions use exact chunks, with one disclosed
  exception below. `SetIvState::peek` restores the saved IV after its
  caller-provided closure returns normally; unwinding through that closure
  bypasses the restore. The caller controls both the implementation and
  closure, and Rustleaks does not use this trait. Type-level arrays can place
  correspondingly large values on the stack when downstream code selects
  large sizes, but hostile archive bytes do not select Rust types or array
  lengths.
- Disclosed correctness limitation: the published implementations for
  `[u128; N]` state use an eight-byte element size instead of sixteen bytes.
  Their serialize and deserialize operations therefore panic rather than
  produce or accept truncated state. A focused harness reproduced both
  deterministic panics. Upstream commit
  `14d3d2ce9fd48bd96395044f55ca72540a2b8d6a` changes the element size to
  sixteen bytes for an unreleased `0.2.3`. This is a developer-selected API in
  the explicitly hazardous state module, not a memory-safety issue or a path
  selected by hostile input. The locked SHA-2 implementation serializes its
  `u32` and `u64` state arrays with its own fixed-size loops and its block
  length with the correct scalar `u128` implementation, so the limitation is
  not reachable in Rustleaks.
- Published-source evidence: on Rust 1.88.0, selected no-default-feature and
  default test runs passed with no package unit or documentation tests. The
  all-feature run passed with no unit tests and four ignored documentation
  examples. The same configurations and counts passed on the Rustleaks MSRV
  toolchain, Rust 1.85.0. The all-feature checks compiled the optional
  `getrandom`, `rand_core`, and `zeroize` paths against the package lockfile.
- Additional focused evidence: a temporary external harness checked exact
  slice-length rejection and acceptance, scalar and array state round trips,
  normal-return IV restoration, and the disclosed `u128` array panic. All
  four tests passed on Rust 1.88.0 and 1.85.0 against the actual Rustleaks
  dependency versions. The harness is not represented as published package
  content or committed Rustleaks source.
- Conclusion: complete package source review, exact archive and VCS
  provenance, selected and optional feature analysis, focused behavior tests,
  license evidence, and advisory results support `safe-to-deploy`. The
  dependency unsafe boundary remains separately exempt. The disclosed
  hazardous-module correctness limitation and caller-controlled unwind and
  type-size behaviors are not reachable from hostile Rustleaks input and do
  not require an exception.

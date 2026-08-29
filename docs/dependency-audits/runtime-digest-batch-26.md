# Runtime dependency audit: digest batch 26

Review date: 2026-08-29.

Locked graph baseline: Rustleaks commit
`05ae9a6f185e79efe83296f92b2518fc58b7c695`, with `Cargo.lock` SHA-256
`e3c24453ec42115d43dd5b2b679e43cdb6e1b0802393932d3ae199db2e502d82`.
The lockfile is unchanged by this audit batch.

`digest 0.11.3` is a normal dependency of `sha2 0.11.0`. The locked graph
reaches it through `lzma-rust2`, `rustleaks-sources`, and `xtask`; the generated
inventory records the `rustleaks-cli` and `xtask` workspace consumers. The
inventory selects `alloc`, `block-api`, `default`, and `oid` on every declared
target, with no build script or `links` value. The package is outside the core
normal or build graph. The exact all-target paths begin
`digest -> sha2 -> lzma-rust2 -> rustleaks-sources -> rustleaks-cli` and
`digest -> sha2 -> xtask`.

The review covered all 26 packaged files and 4,244 packaged lines, including
all 2,984 lines of Rust production, macro, development-support, and test
source, manifests, package lockfile, licenses, README, changelog, binary test
fixture, and VCS record. A RustSec check at advisory database commit
`b331df68b3ed0e99594d259040bdcb9de3c7c8a4` found no vulnerability,
unmaintained, unsound, or yanked warning in the exact Rustleaks lockfile. An
exact-version GitHub Advisory Database query returned no advisory affecting
`digest 0.11.3`. MIT OR Apache-2.0 matches `deny.toml`; both license texts are
packaged and there is no `NOTICE` file. No peer audits, wildcard trust,
criteria changes, or exceptions were used.

## `digest 0.11.3`

- Archive: `digest-0.11.3.crate`; SHA-256
  `f1dd6dbb5841937940781866fa1281a1ff7bd3bf827091440879f9994983d5c2`.
  The packaged VCS record identifies upstream commit
  `2fb9ed8922e244117040bb037a7d141a6a2b8228` and path `digest`; tag
  `digest-v0.11.3` points directly at that commit. All 26 archive members are
  regular files with mode `0644`. Cargo-vet's source matches a fresh archive
  extraction byte for byte apart from Cargo's `.cargo-ok` marker. Production,
  test, documentation, changelog, licenses, fixture, and `Cargo.toml.orig`
  match the `digest` directory at the exact upstream commit. The normalized
  manifest, package lockfile, and VCS record are Cargo packaging metadata.
  `LICENSE-APACHE` and `LICENSE-MIT` have respective SHA-256 values
  `a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5`
  and
  `af59cea35d7f5e2777a713b8d155d65efa2c339eb43f3c14e868c6ac8506edad`.
- Rustleaks use: `sha2` supplies SHA-256 to `lzma-rust2` for archive integrity
  behavior and is also a direct dependency of `rustleaks-sources` and `xtask`.
  `digest` supplies the shared fixed-output hashing traits, buffered wrapper
  macros, allocation-backed dynamic-digest support, and OID trait integration.
  It supplies no hash algorithm or secret-dependent implementation itself.
- Trait and wrapper behavior: selected APIs delegate byte slices to
  caller-selected hash implementations, enforce output buffer lengths before
  conversion to fixed arrays, and use type-level output and block sizes for
  buffering and truncation. The generated fixed, compile-time variable,
  runtime variable, and XOF wrappers retain the algorithm state and bounded
  block buffer, then delegate finalization to the implementation. A
  compile-time variable wrapper unwraps construction after its type-level
  size is proven no greater than the implementation maximum; an implementation
  that rejects another size in that range can cause construction to panic.
  This is an implementor-contract and availability limitation, not a memory
  safety boundary in `digest`.
- Unsafe and dependency inventory: the crate root forbids unsafe code. The
  package contains no unsafe block, unsafe function, external declaration,
  native binding, or generated-at-build source. Selected production
  dependencies are `crypto-common`, `block-buffer`, and `const-oid`; all are
  already locked in the reviewed graph. The optional MAC, random, test-helper,
  and zeroization features are not selected, but their complete source and
  macro output paths were also reviewed.
- Native and authority boundary: the archive has no build script, native
  source, `links` declaration, file or socket operation, environment read,
  process or thread creation, log output, or package-global mutable state. It
  is `no_std`; allocations occur only when a caller selects the `alloc`
  convenience methods and requests boxed dynamic or XOF output. The requested
  output length controls the allocation and can exhaust memory if an
  application passes an untrusted unbounded length. Rustleaks reaches fixed
  SHA-256 output sizes and does not expose such an allocation choice.
- Panic and resource behavior: update and finalize work is delegated to the
  caller-selected algorithm and is linear in caller-provided input or output.
  Dynamic finalization allocates the algorithm's fixed output size and unwraps
  only after allocating that exact length. Slice-based finalization returns
  `InvalidBufferSize` before conversion when the caller length differs.
  Development helpers use fixed stack buffers and unchecked test assertions;
  they are excluded from the selected production feature set. Hash provider
  implementations remain responsible for their advertised size contracts,
  buffering semantics, and algorithm resource behavior.
- Published-source evidence: on Rust 1.88.0, the Rustleaks MSRV toolchain Rust
  1.85.0, and the repository's pinned nightly toolchain, package unit and
  integration targets compiled and passed with the selected feature profile.
  Three of four documentation tests passed on each toolchain. The remaining
  example fails because the published package lockfile pins the example's
  `sha2` dependency to `digest 0.11.2` while the package under test is
  `digest 0.11.3`, producing two intentionally incompatible trait versions.
  This packaging-only test dependency defect is not in a selected production
  path. A temporary harness patched `sha2` to the exact reviewed source and
  passed on all three toolchains, exercising streaming and one-shot SHA-256,
  dynamic cloning and finalization, exact output, reset, and wrong-buffer
  rejection. The selected library also passed a no-default-feature MSRV check.
- Target and interpreter evidence: pinned-nightly `build-std` checks compiled
  the selected `alloc`, `block-api`, `default`, and `oid` behavior for all
  seven non-native required targets; the native AArch64 macOS target was
  exercised by the multi-toolchain tests. The exact-source harness also passed
  under pinned Miri on AArch64 macOS. No unsafe or target-specific package
  branch required native execution on another architecture.
- Conclusion: complete source and macro review, exact archive and VCS
  provenance, selected-feature tests across current, MSRV, and nightly
  toolchains, all-required-target compilation, Miri execution, license
  evidence, and advisory results support `safe-to-deploy`. The published
  documentation-test lockfile mismatch, caller-selected boxed-output size, and
  provider trait contracts are documented limitations and do not require an
  exception for the locked Rustleaks graph.

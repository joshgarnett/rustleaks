# Runtime dependency audit: block-buffer batch 19

Review date: 2026-08-29.

Locked graph baseline: Rustleaks commit
`11b2d7f6e607d31444b39b16a59e7ea41ef57f75`, with `Cargo.lock` SHA-256
`e3c24453ec42115d43dd5b2b679e43cdb6e1b0802393932d3ae199db2e502d82`.
The lockfile is unchanged by this audit batch.

`block-buffer 0.12.1` is a normal dependency of `digest 0.11.3`, which is
used by `sha2 0.11.0`. The locked graph reaches it through XZ SHA-256 checksum
handling in `lzma-rust2`, the archive-enabled sources graph, and SHA-256
maintenance operations in `xtask`. The generated inventory records the CLI
and `xtask` roots, no selected optional feature, every declared target, no
build script, and no `links` value. Its selected dependency is
`hybrid-array 0.4.14` with no selected feature, which reaches
`typenum 1.20.1`.

The review covered all 12 packaged files and 1,706 packaged text lines,
including all 1,191 lines of Rust production and test source, manifests, the
package lockfile, licenses, README, changelog, and VCS record. A
RustSec check at advisory database commit
`b331df68b3ed0e99594d259040bdcb9de3c7c8a4` found no vulnerability,
unmaintained, unsound, or yanked warning in the exact Rustleaks lockfile. An
exact-version GitHub Advisory Database query returned no advisory affecting
`block_buffer 0.12.1`. The upstream repository has one applicable published
advisory, described below, for versions before 0.12.1. MIT OR Apache-2.0
matches `deny.toml`; both license texts are packaged and there is no `NOTICE`
file. No peer audits, wildcard trust, criteria changes, or exceptions were
used.

## `block-buffer 0.12.1`

- Archive: `block-buffer-0.12.1.crate`; SHA-256
  `d2f6c7dbe95a6ed67ad9f18e57daf93a2f034c524b99fd2b76d18fdfeb6660aa`.
  The packaged VCS record identifies upstream commit
  `cbd0963c685df025c42bed31f78c50d1bada3805` under `block-buffer`; tag
  `block-buffer-v0.12.1` points at that commit. All 12 archive members are
  regular files with mode `0644`. A fresh extraction matched cargo-vet's
  source byte for byte apart from Cargo's `.cargo-ok` marker. Source,
  changelog, README, licenses, and `Cargo.toml.orig` match the exact upstream
  tree. The normalized manifest, package lockfile, and VCS record are Cargo
  packaging metadata. `LICENSE-APACHE` and `LICENSE-MIT` have respective
  SHA-256 values
  `a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5`
  and
  `98181e7249d0c01737645ec982499ce99a0f07eb8f7d625b8840d799d10dbc01`.
- Rustleaks use: the package supplies fixed-size eager and lazy block buffers
  used through `digest` and `sha2`. It divides caller-provided bytes into
  fixed-size blocks, retains an incomplete block, and supports hash padding.
  `lzma-rust2` uses SHA-256 for XZ stream integrity, while `xtask` hashes
  fixtures, evidence, and candidate release artifacts. SHA-256 integrity
  checks are not an authentication boundary.
- Type and algorithm behavior: the sealed block-size implementation admits
  only type-level sizes from one through 255 bytes. Eager buffers store their
  position in the final byte of `MaybeUninit` inline storage and require a
  position strictly below the block size. Lazy buffers use a separate `u8`
  position and allow a full block. Input processing uses exact block chunks,
  checked slice splits, and a zero-to-block-size remainder. Serialization
  records a one-byte position and deserialization rejects an invalid position
  or nonzero unused tail. Work is linear in the caller-provided slice, does
  not recurse, and performs no package-owned heap allocation.
- Unsafe and dependency inventory: package unsafe code initializes and reads
  the inline cursor, copies bounded slice data into `MaybeUninit` storage,
  exposes only the initialized prefix, converts fully initialized blocks to
  references, and dispatches through the sealed eager or lazy invariants.
  Exact chunking and the one-through-255 block-size seal keep pointer offsets,
  byte positions, and casts in range. `ResetGuard` restores a valid empty or
  exhausted state when a caller-provided compression, block-generation, or
  read closure unwinds. The raw `ptr::read` clone copies only sealed inline
  array and unit or byte position state; each copy owns no external resource,
  and the optional drop action zeroizes its own copy. Its nearby comment that
  the type does not implement `Drop` is stale, but the concrete sealed field
  and drop behavior keep the operation sound. The active `hybrid-array`
  dependency uses unsafe array representation operations. That package
  remains covered by its separate exemption and is not represented as audited
  by this worksheet. `typenum`, below it, forbids unsafe Rust.
- Native and authority boundary: the archive has no build script, native
  source, generated-at-build source, or `links` declaration. Selected code is
  `no_std` and opens no file or socket, reads no environment variable, starts
  no process or thread, writes no log, and maintains no process-global state.
  The unselected `zeroize` feature adds only zeroization of inline buffer and
  position storage through `zeroize 1.8.2`.
- Panic and resource behavior: fallible constructors and deserializers reject
  invalid lengths or state. Infallible construction, explicit position
  setting, padding with an oversized suffix, and `ReadBuffer::write_block`
  with a length at least the block size panic on caller contract violations.
  The `write_block` prose says bigger than the block size although equality
  also panics; Rustleaks does not call this API directly, and hostile bytes do
  not select its type-level size or callback lengths. Caller-provided closures
  may panic, but the published 0.12.1 guards restore the position invariant.
  Linear block processing is bounded by the archive adapter's member,
  cumulative, spool, and cancellation controls when reached from hostile
  archive input.
- Published advisory: GitHub advisory `GHSA-qwgh-2vcv-g2f7` reports that in
  versions before 0.12.1, a caught callback panic could leave the inline
  cursor invalid and lead to out-of-bounds access. The advisory identifies
  0.12.1 as the first patched version. Upstream fix commit
  `9aa541d55770f47bb1c50c1d476d167977e3de2a` adds `ResetGuard` around every
  temporarily broken invariant and adds panic regressions. The packaged
  release commit is its direct child and contains that source and those tests.
- Published-source evidence: on Rust 1.88.0, default and all-feature test
  runs each passed 11 integration tests and three documentation tests against
  the package lockfile. The same configurations and counts passed on the
  dependency's Rust 1.85.0 MSRV. The all-feature checks exercised optional
  zeroization. The package lock selects `hybrid-array 0.4.12`; a separate
  temporary resolution pinned the exact Rustleaks-selected
  `hybrid-array 0.4.14`, and the selected no-default-feature configuration
  passed the same tests on Rust 1.88.0 and Rust 1.85.0.
- Additional unsafe evidence: the complete all-feature package test suite
  passed under the repository's pinned Miri toolchain with strict provenance.
  The exact Rustleaks-selected `hybrid-array 0.4.14` profile also passed all
  11 integration tests under pinned Miri with strict provenance. Both runs
  included the eager and read-buffer caught-panic regressions from the
  advisory fix.
- Conclusion: complete source and unsafe review, exact archive and VCS
  provenance, selected and optional feature analysis, package tests,
  strict-provenance Miri, license evidence, and exact advisory classification
  support `safe-to-deploy`. The dependency unsafe boundary remains separately
  exempt. Documented caller-contract panics and linear block-buffer work do not
  require an exception.

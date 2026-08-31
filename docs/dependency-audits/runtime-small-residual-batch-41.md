# Runtime dependency audit: small residual batch 41

Review date: 2026-08-31.

Locked graph baseline: Rustleaks commit
`32304418e9b903223d62aafeb4acf3b7f05879f3`, with `Cargo.lock` SHA-256
`8f3893f06c74b312afd2ef9b6a240eaab6d5e3b5a4abe0eff1302a912d468eb4`.
The lockfile is unchanged by this audit batch.

This review covers `alloc-no-stdlib 2.0.4`, `alloc-stdlib 0.2.4`,
`cpufeatures 0.3.0`, and `zstd-zero 0.1.0`. All four are normal
dependencies of the unpublished archive graph and remain outside the normal
and build graphs of `rustleaks-core`. The two allocator packages are reached
through `brotli-decompressor 5.0.3`. `cpufeatures` is reached through
`sha2 0.11.0`. `zstd-zero` is used directly by `rustleaks-sources` and the
private 7z decoder.

An exemption-free refresh of the configured Bytecode Alliance, Google, ISRG,
Mozilla, and Zcash cargo-vet imports supplied no version-specific
`safe-to-deploy` path for any package in this batch. The local reviews used
the complete exact package sources. No publisher trust, wildcard audit,
criteria change, dependency change, or exception was used.

## `alloc-no-stdlib 2.0.4`

- Archive: `alloc-no-stdlib-2.0.4.crate`; 10,105 bytes; SHA-256
  `cc7bb162ec39d46ab1ca8c77bf72e890535becd1751bb45f64c597edb4c8c6b3`.
  The checksum matches `Cargo.lock` and the generated dependency inventory.
  The archive has 20 regular members, 16 with mode `0644` and four with mode
  `0755`.
- Provenance: the packaged VCS record identifies official upstream commit
  `6032b6a9b20e03737135c55a0270ccffcc1438ef` in
  `https://github.com/dropbox/rust-alloc-no-stdlib`. Every packaged project
  file matches that commit byte for byte. Cargo's normalized manifest, VCS
  record, marker, and generated package lockfile are the only packaging
  additions or rewrites. The commit is not tagged, so this establishes exact
  archive-to-VCS identity without claiming signed provenance.
- Selected boundary: the package has no dependency, build script, `links`
  value, proc macro, target dependency, standard-library dependency, or
  selected feature. Its 951 production Rust lines define allocator traits,
  checked slice wrappers, a freelist allocator, macros for caller-owned
  storage, and an optional C allocation backing store.
- Reachability: Rustleaks reaches the allocator traits and safe slice wrappers
  through Brotli's `StandardAlloc` and `HeapAlloc` implementations. It does
  not call `CallocBackingStore::new`, instantiate a global-storage macro, or
  enable the package's `unsafe` feature.
- Unsafe boundary: complete production source contains ten `unsafe` tokens,
  one unsafe constructor, three unsafe blocks, and three `static mut` tokens
  in macro definitions. The unsafe constructor accepts caller-provided C
  allocation and release functions, constructs a slice from their returned
  pointer, and requires the caller to uphold allocation, initialization,
  alignment, and lifetime preconditions. Its `Drop` implementation calls the
  retained release function only for an owned non-null pointer. The global
  storage macros require the caller to enter unsafe code before binding their
  mutable statics. None of these paths is selected by Rustleaks.
- Resource and panic behavior: the selected freelist allocator panics on
  exhaustion and uses checked Rust slice indexing. Rustleaks does not use that
  allocator. The reached standard allocator implementations live in
  `alloc-stdlib` and use ordinary `Vec` and `Box` allocation. Allocation
  failure remains subject to the repository resource contract.
- License: the package declares BSD-3-Clause. Packaged `LICENSE` has SHA-256
  `c0c56f26d9c051cac4d200c34c84e7ae9aaa853e01a982a1df08b09931e518ae`.
  There is no packaged `NOTICE` or additional license file.
- Evidence: the exact package passed nine tests on Rust 1.88 with no selected
  feature. Compiler warnings concern historical edition, conditional test
  names, implicit C ABI spelling, unused imports, and forgetting a reference.
  They do not identify a reached unsafe precondition or failed test.

## `alloc-stdlib 0.2.4`

- Archive: `alloc-stdlib-0.2.4.crate`; 6,730 bytes; SHA-256
  `0e76a019e91224d279006ff972f1e984179a6e9feb050adba6ce8274aef23195`.
  The checksum matches `Cargo.lock` and the generated dependency inventory.
  The archive has 12 regular members, eight with mode `0644` and four with
  mode `0755`.
- Provenance: the packaged VCS record identifies official upstream commit
  `ae42d22078b98549e987d2f03d12df7b984fde47` and path `alloc-stdlib` in
  `https://github.com/dropbox/rust-alloc-no-stdlib`. Tag `0.2.4` points to
  that commit. Every packaged project file matches the exact VCS tree.
  Cargo's normalized metadata and generated package lockfile account for the
  packaging-only files.
- Selected boundary: the only normal dependency is
  `alloc-no-stdlib 2.0.4`. The package has no build script, `links` value,
  native compilation, proc macro, target dependency, or selected feature.
  Its 470 production Rust lines provide `Vec` and `Box` backed implementations
  of the allocator traits.
- Reachability and unsafe boundary: Brotli uses `StandardAlloc` and
  `HeapAlloc`, which initialize every element before exposing a boxed slice.
  With the `unsafe` feature disabled, the crate root forbids unsafe code and
  removes `new_uninitialized_memory_pool` from compilation. The remaining
  unsafe tokens occur in the disabled item and test or example conditions.
  Rustleaks does not enable the unsafe feature.
- Authority and resource behavior: the selected library allocates and frees
  caller-sized standard-library buffers. It performs no file, environment,
  network, process, thread, logging, or mutable process-global operation.
  Rustleaks bounds compressed input and decoded output around the Brotli
  decoder. Ordinary allocation failure remains possible.
- License: the package declares BSD-3-Clause. The package archive does not
  include a license or notice file. The exact upstream repository root
  `LICENSE` has SHA-256
  `c0c56f26d9c051cac4d200c34c84e7ae9aaa853e01a982a1df08b09931e518ae`
  and supplies the declared BSD-3-Clause text. Cargo-deny accepts the declared
  license for the locked graph.
- Evidence: the exact package passed eleven tests on Rust 1.88 with no
  selected feature. Compiler warnings concern historical conditional test
  names and implicit C ABI spelling in tests.

## `cpufeatures 0.3.0`

- Archive: `cpufeatures-0.3.0.crate`; 14,156 bytes; SHA-256
  `8b2a41393f66f16b0823bb79094d54ac5fbd34ab292ddafb9a0456ac9f87d201`.
  The checksum matches `Cargo.lock` and the generated dependency inventory.
  All 16 archive members are regular files with mode `0644`.
- Provenance: the packaged VCS record identifies official RustCrypto `utils`
  commit `31e6ec3727f11f9f5e0c106e282014653a4d7bb7` and path `cpufeatures`.
  Tag `cpufeatures-v0.3.0` points to that commit. Every packaged project file
  matches the exact VCS tree; Cargo's normalized metadata and generated
  package lockfile are the only packaging changes.
- Selected boundary: the package has no features, build script, `links`
  value, native compilation, proc macro, allocation, file access, network
  access, or background work. `libc` is selected only for AArch64 Linux,
  Android, and Apple targets and LoongArch64 Linux. The crate requires Rust
  1.85, below the repository's Rust 1.88 baseline.
- Unsafe inventory: the 589 production Rust lines contain eleven `unsafe`
  tokens, eight unsafe blocks, and three unsafe helper functions. X86 and
  x86-64 execute the architecture CPUID and XGETBV intrinsics after the
  corresponding capability bits are checked. AArch64 Linux and Android read
  kernel hardware capabilities through `getauxval`. Apple AArch64 passes
  fixed NUL-terminated names and live typed output storage to `sysctlbyname`.
  LoongArch64 Linux uses a register-only `cpucfg` assembly block and
  `getauxval`. No safe API accepts a caller-controlled pointer or instruction.
- State and failure behavior: each generated detector caches one Boolean in
  an `AtomicU8`. Concurrent initialization can repeat detection and store the
  same derived result; it does not expose non-atomic shared state. Relaxed
  ordering is sufficient because no other data is published. Apple helper
  assertions can panic if the fixed name is not NUL-terminated or the
  operating system violates the expected `u32` result contract. Neither
  condition is derived from archive input.
- Reachability: Rustleaks reaches `cpufeatures` only through SHA-2 hardware
  dispatch. It cannot request arbitrary feature strings at runtime. The
  maintained native matrix executes the selected AArch64 and x86-64 branches
  across Linux, macOS, and Windows.
- Licenses: the package declares MIT or Apache-2.0. Packaged
  `LICENSE-APACHE` and `LICENSE-MIT` have SHA-256 values
  `a9040321c3712d8fd0b09cf52b17445de04a23a10165049ae187cd39e5c86be5`
  and
  `ae9baa7beea910273c2f384c2a6b721fb7bd02bda3436074a1072e4ee689f985`.
- Evidence: the exact package passed its two applicable AArch64 tests on
  Rust 1.88 on Apple Silicon. The x86 and LoongArch64 test binaries compiled
  with no applicable runtime cases on that host. Repository target and native
  lanes provide the cross-target compilation and runtime evidence described
  above.

## `zstd-zero 0.1.0`

- Archive: `zstd-zero-0.1.0.crate`; 27,031 bytes; SHA-256
  `ff386b8e5bbe3cf2b73dfb0601c19715885473825a2bb9cf3a2b9d401c2dd0cf`.
  The checksum matches `Cargo.lock` and the generated dependency inventory.
  All 15 archive members are regular files with mode `0644`.
- Provenance: the packaged VCS record identifies official `oci-zero` commit
  `7083ae46382148a36259df74adb12828e0784828` and path `zstd-zero` in
  `https://github.com/pawelchcki/oci-zero`. Every packaged project file
  matches that commit byte for byte. Cargo's normalized metadata and generated
  package lockfile account for the packaging-only files. No release tag points
  to the commit.
- Selected boundary: the package has no normal dependency, feature, build
  script, `links` value, native compilation, proc macro, allocation, standard
  library dependency, filesystem access, network access, thread, log, or
  mutable process-global state. Its 2,053 production Rust lines forbid unsafe
  code.
- Decoder structure: the caller supplies history, compressed-block, and
  literal buffers. Frame windows must fit the history buffer, blocks and
  regenerated literals must fit their exact buffers, dictionary frames are
  rejected, and compressed block size is capped at 128 KiB. Bit widths,
  entropy table states, symbol ranges, lengths, offsets, frame output,
  checksums, and content sizes are checked before indexing or conversion.
  Decoder errors poison the current state until reset.
- Rustleaks controls: `rustleaks-sources` supplies at most the configured
  member limit for history, two fixed 128 KiB scratch buffers, checked
  cancellation between output callbacks, and a bounded output vector. The 7z
  adapter additionally bounds compressed input, history, and exact declared
  output. Both adapters use fallible allocation and reject decoder stalls.
  Default source member and spool limits are 64 MiB.
- License: the package declares MIT or Apache-2.0 but does not package a
  license or notice file. The exact upstream repository root contains
  `LICENSE-APACHE` and `LICENSE-MIT` with SHA-256 values
  `c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4`
  and
  `bd518d3c5beae04045f02a6ed307c45cadfa4d0fc2939ccaf45a1eb905354afe`.
  Cargo-deny accepts the declared license for the locked graph.
- Package evidence: on Rust 1.88, five library tests, five ordinary
  conformance tests, two deterministic differential tests, and six robustness
  tests passed. The separate official decode-corpus case remained ignored
  because its external generator was not supplied. Fresh uncached Rustleaks
  7z unit, codec oracle, archive source, and archive unit tests also passed.
- Conclusion: complete source review, exact archive and VCS identity, safe
  dependency-free implementation, bounded caller-controlled storage, checked
  hostile-input state transitions, checksum and size validation, package
  cross-checks, and fresh Rustleaks consumer tests support `safe-to-deploy`
  for `zstd-zero 0.1.0` in the locked Rustleaks graph.

## Batch conclusion

The exact sources, selected feature and target paths, unsafe boundaries,
capabilities, allocation and panic behavior, licenses, package tests, and
Rustleaks consumer tests support `safe-to-deploy` for all four versions in
the locked graph. This conclusion does not enable the allocator crates'
unsafe feature, extend Rustleaks resource limits to arbitrary callers, or
substitute for the separate audits of Brotli, SHA-2, or libc.

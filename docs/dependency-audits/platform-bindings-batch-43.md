# Platform dependency audit: bindings batch 43

Review date: 2026-08-31.

Locked graph baseline: Rustleaks commit
`feccd941bc2cd4d60426542fed87d01a8e9c86c5`, with `Cargo.lock` SHA-256
`8f3893f06c74b312afd2ef9b6a240eaab6d5e3b5a4abe0eff1302a912d468eb4`.
The lockfile and dependency graph are unchanged by this audit batch.

`libc 0.2.189`, `linux-raw-sys 0.12.1`, and `windows-sys 0.61.2`
are target-specific dependencies outside the publishable core's normal and
build graphs. A fresh import of the configured Bytecode Alliance, Google,
ISRG, Mozilla, and Zcash cargo-vet sources supplied no exact-version
`safe-to-deploy` path for these releases. The residual review therefore used
full local audits. No publisher trust, wildcard audit, criteria change, or
exception was used.

## `libc 0.2.189`

- Archive: `libc-0.2.189.crate`; 851,502 bytes and 404 members; SHA-256
  `3eaf3ede3fee6db1a4c2ee091bf8a8b4dccdc6d17f656fb07896ee72867612f2`.
  The checksum matches `Cargo.lock` and the generated inventory.
- Provenance: the packaged VCS record identifies official upstream commit
  `ef0906e20828777175f65caa7e681a0ce33c559a` in
  `https://github.com/rust-lang/libc`. Tag `0.2.189` points to that commit.
  Packaged Rust sources and project metadata match that tree, and
  `Cargo.toml.orig` matches the upstream manifest. Cargo's generated manifest,
  extraction marker, and lockfile normalization are the only package-local
  differences.
- Selected boundary: Rustleaks enables `default` and `std`. The package is
  reached through unpublished source and maintenance crates on maintained
  Unix targets. It exports raw platform types, constants, helper macros, and
  FFI declarations. It does not initiate an operating-system operation,
  network request, thread, or log on its own.
- Build boundary: `build.rs` reads Cargo target, feature, and compiler
  variables, invokes the configured Rust compiler for its version, and emits
  an allowlisted set of `cfg` values. FreeBSD CI and Emscripten probes invoke
  fixed version commands and are not selected by the maintained Rustleaks
  targets. It does not download content or generate production source.
- Unsafe boundary: raw FFI functions and pointer-based helpers remain unsafe
  to the caller. The implemented Rust helpers fall into repeated families for
  control-message traversal, file-descriptor and CPU bit sets, signal unions,
  device-number packing, and platform forwarding functions. Bounds and null
  checks occur where the corresponding C macro defines them; operations that
  require a valid caller-provided pointer retain an unsafe signature. `DIR`
  send and synchronization implementations apply only to opaque platform
  handles, and no safe method dereferences their storage.
- Licenses: the package declares `MIT OR Apache-2.0`. Packaged `LICENSE-MIT`
  and `LICENSE-APACHE` have SHA-256 values
  `123a331b5dbf04c30097fa43b8f858bc85df671fe776de498d01f3d6b7c1f69e`
  and
  `62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a`.
- Evidence: the exact registry package passed six library tests and compiled
  its constant-function test on Rust 1.88. The exact VCS workspace passed the
  same tests, five control-message tests, 7,162 native C ABI checks, one SemVer
  check, one style check, 15 style-rule tests, and its applicable documentation
  checks on Apple Silicon.
- Conclusion: exact provenance, selected-feature and build-script review,
  unsafe-helper classification, native ABI validation, licenses, and the
  maintained-target Rustleaks gates support `safe-to-deploy` for the locked
  graph.

## `linux-raw-sys 0.12.1`

- Archive: `linux-raw-sys-0.12.1.crate`; 3,006,116 bytes and 473 members;
  SHA-256
  `32a66949e030da00e8c7d4434b251670a91556f4144941d37452769c25d58a53`.
  The checksum matches `Cargo.lock` and the generated inventory.
- Provenance: the packaged VCS record identifies official upstream commit
  `0e2918cf3e366d9c923d4ca05f169b49d826db56` in
  `https://github.com/sunfishcode/linux-raw-sys`. Tag `v0.12.1` points to that
  commit. Packaged project files match that tree, and `Cargo.toml.orig`
  matches the upstream manifest. The excluded generator, Cargo metadata, and
  extraction files account for the package-tree differences.
- Selected boundary: Rustleaks enables `auxvec`, `elf`, `errno`, `general`,
  `ioctl`, `no_std`, and `prctl`. The crate has no build script, native build,
  runtime initialization, filesystem access, network access, thread, or log.
  Its selected modules are generated Linux UAPI constants and C-layout types.
- Unsafe boundary: the selected generated modules repeat one bindgen helper
  implementation. Raw bitfield access requires valid caller pointers and
  retains unsafe signatures. Safe bitfield methods use checked slice indexing.
  Flexible-array conversion remains unsafe because the caller supplies the
  backing length. Integer transmutations are between equal-width integer
  aliases. The remaining callback types are declarations and do not call a
  function.
- Licenses: the package declares
  `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT`. The three packaged
  license files have SHA-256 values
  `268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5`,
  `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2`,
  and
  `23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3`.
- Evidence: on Rust 1.88, the exact package compiled and ran its empty library
  test harness under both the selected Rustleaks features and the default
  feature set. The repository's maintained Linux target gates compile the
  selected architecture modules through Rustix.
- Conclusion: exact provenance, generated-source and unsafe-template review,
  licenses, exact-package checks, and maintained Linux integration support
  `safe-to-deploy` for the locked graph.

## `windows-sys 0.61.2`

- Archive: `windows-sys-0.61.2.crate`; 2,517,186 bytes and 257 members;
  SHA-256
  `ae137229bcbd6cdf0f7b80a31df61766145077ddf49416a728b02cb3921ff3fc`.
  The checksum matches `Cargo.lock` and the generated inventory.
- Provenance: the packaged VCS record identifies path `crates/libs/sys` at
  official upstream commit `32c3144490c016fe496a0aed769bce60987a2e9d` in
  `https://github.com/microsoft/windows-rs`. No tag points directly to that
  commit. Packaged project files match that exact subtree, and
  `Cargo.toml.orig` matches its manifest. Cargo metadata and extraction files
  account for the package-tree differences.
- Selected boundary: Rustleaks reaches `Win32_Foundation`,
  `Win32_Networking_WinSock`, and `Win32_System_Diagnostics_Debug`, with their
  parent feature modules. The crate has no build script or runtime
  initialization. `windows-link` expands static raw DLL declarations; it does
  not perform dynamic loading or an operation during compilation.
- Unsafe boundary: selected APIs are raw Windows declarations with caller
  pointer, handle, buffer, and lifetime requirements. Function pointer fields
  and callbacks remain unsafe. The only selected unsafe expression pattern is
  `core::mem::zeroed()` in generated `Default` implementations for C-layout
  structures and unions whose fields are zero-valid scalar, pointer, array, or
  nested POD representations. COM vtables with required function pointers do
  not receive those defaults. No safe wrapper dereferences a pointer or calls
  an API.
- Licenses: the package declares `MIT OR Apache-2.0`. Packaged `license-mit`
  and `license-apache-2.0` match the exact VCS subtree and have SHA-256 values
  `c2cfccb812fe482101a8f04597dfc5a9991a6b2748266c47ac91b6a5aae15383`
  and
  `c16f8dcf1a368b83be78d826ea23de4079fe1b4469a0ab9ee20563f37ff3d44b`.
- Evidence: on Rust 1.88, the exact package compiled once with the selected
  Rustleaks feature set and once with every feature. The maintained Windows
  target gates compile both x86-64 and AArch64 consumers.
- Conclusion: exact subtree provenance, selected raw-FFI and generated-default
  review, licenses, selected and all-feature compilation, and maintained
  Windows integration support `safe-to-deploy` for the locked graph.

This batch reduces the repository from four cargo-vet exemption records to the
single separately tracked `sha2 0.11.0` exemption. It does not change a
dependency version, feature, lockfile, target policy, or public API.

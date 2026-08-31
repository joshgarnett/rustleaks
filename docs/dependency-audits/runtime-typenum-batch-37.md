# Runtime dependency audit: typenum batch 37

Review date: 2026-08-30.

Locked graph baseline: Rustleaks commit
`d4dfa60856ce55dbf48463abbc7b9e6b597add4f`, with `Cargo.lock` SHA-256
`e3c24453ec42115d43dd5b2b679e43cdb6e1b0802393932d3ae199db2e502d82`.
The lockfile is unchanged by this audit batch.

`typenum 1.20.1` is a normal transitive dependency of the unpublished archive
graph through `hybrid-array`, `digest`, and `sha2`. It remains outside the
default `rustleaks-core` graph. The locked workspace selects
`const-generics`; the implicit default feature is empty. The package applies
on every maintained target. It has no build script, `links` value, native
compilation, generated-at-build-time production source, or proc macro.

An exemption-free refresh of the Bytecode Alliance, Google, ISRG, Mozilla,
and Zcash cargo-vet imports supplied no version-specific coverage for any of
the 14 exact remaining exemptions, including this release. The residual
local review covered all 26 packaged files and 41,159 cargo-vet audit lines.
The maintained RustSec and cargo-deny gates cover advisory, license, and
source policy for the locked graph without accepting an exception. No
publisher trust, wildcard audit, criteria change, or exception was used.

## `typenum 1.20.1`

- Archive: `typenum-1.20.1.crate`; 105,479 bytes; SHA-256
  `b6f5e870be6c3b371b77fe0ee0bafb859fa4964b4404c27de1d380043c4dda20`.
  The checksum matches `Cargo.lock` and the generated inventory. All 26
  archive members are regular files with mode `0644`. A fresh extraction
  matches cargo-vet's review source byte for byte apart from Cargo's
  `.cargo-ok` marker.
- Provenance: the packaged VCS record identifies upstream commit
  `0db9a0f731981f29266b63586c29fa07e4477b1a` in
  `https://github.com/paholg/typenum`. Lightweight unsigned tag `v1.20.1`
  and the upstream default-branch head both point to that commit at the
  review date. Packaged production source, tests, licenses, README, and
  non-Cargo project files match the exact VCS tree. `Cargo.toml.orig` matches
  the VCS manifest; Cargo's normalized manifest, VCS record, and lockfile
  removal of the excluded generator workspace member are expected packaging
  changes. The excluded generator, workflows, local tooling, and development
  files are expected omissions. This establishes exact archive-to-VCS
  identity without claiming signed provenance.
- Generated content: the VCS generator has no dependencies and writes only
  the four declared generated files beneath the checkout. Running it at the
  exact release commit and applying the project's normal Rust formatting
  reproduced `src/gen/consts.rs`, `src/gen/generic_const_mappings.rs`,
  `src/gen/op.rs`, and `tests/generated.rs` byte for byte. Their respective
  SHA-256 values are
  `9aa17739639f2e3f516cd9136e05beb19492491431df71a1e2aa4e3ec78e176c`,
  `891e3a1917e39eebd1306765158c26c4ff2d9a85b197844100638591ec6658fb`,
  `b91eadcee885bc0ab929b64492f7b04641cde71ddf8e9aa455d324f1723c61de`,
  and
  `3034ec2bce8abe6c70d1d0aa87bec56f6c5f95db16dde365377973f7d8f3911d`.
- Feature and dependency boundary: Rustleaks selects the safe-only
  `const-generics` mapping used by `hybrid-array`. The optional `i128` and
  `strict` features add primitive conversions and compile-time lint policy.
  The optional `scale_info` feature adds only `TypeInfo` derives and a
  separately governed optional dependency; Rustleaks does not select it.
  The exact all-feature package was compiled and tested, but this audit does
  not certify optional dependency packages outside the locked graph.
- Safety and authority boundary: the crate root applies
  `forbid(unsafe_code)` for every feature. The complete package contains no
  unsafe Rust, FFI, assembly, intrinsics, allocator use, file or path access,
  environment access, network access, process execution, threads, logging,
  or mutable process-global state. Production code is `no_std` and operates
  on zero-sized type-level values, primitive conversions, trait resolution,
  and declarative macro expansion.
- Untrusted-input boundary: the package does not parse runtime input. Its
  public macros consume caller-authored Rust tokens at compile time and
  expand to type aliases and trait operations. Deep caller-authored type
  expressions can consume compiler recursion and memory, but that is a build
  resource property rather than a runtime input capability. Rustleaks uses
  only the bounded generated const mapping selected by `hybrid-array`.
- Test evidence: on Rust 1.98.0, the exact all-feature package passed 19 unit
  tests, 1,743 generated arithmetic tests, and 60 documentation tests. The
  selected `const-generics` profile passed the same 1,822 tests on Rustleaks'
  Rust 1.88 MSRV and on installed Rust 1.85.0. The upstream Rust 1.41 MSRV was
  not installed and was not added for this review; no compatibility claim is
  made below the tested Rust 1.85 toolchain.
- License: the package declares `MIT OR Apache-2.0`, both allowed by
  `deny.toml`. Packaged `LICENSE`, `LICENSE-MIT`, and `LICENSE-APACHE` have
  SHA-256 values
  `db11fec9946737df39ca3898d9cd8c10ec6f6c3a884a6802b0ad0b81b4e8f23a`,
  `a825bd853ab71619a4923d7b4311221427848070ff44d990da39b0b274c1683f`,
  and
  `516b24e051bf5630880ebbd55c40a25ce9552ebaf8970a53e8976eb70e522406`.
  Packaged `README.md` has SHA-256
  `a0226a558788e7552b098e9781cce07e0fc87055d04a16c6c68866ad2e2c9c19`.
  There is no packaged `NOTICE` or additional license file.
- Conclusion: exact archive and VCS provenance, complete safe-code and
  capability review, reproducible generated content, all-feature and selected
  feature tests, multi-toolchain evidence, license evidence, and the
  maintained advisory gates support `safe-to-deploy` for `typenum 1.20.1`.
  The audit does not claim runtime-input limits for arbitrary consumer-authored
  compile-time type expressions or certify the unselected optional dependency.

# Runtime dependency exception: sha2 0.11.0

Review date: 2026-08-31. Maintainer approval date: 2026-09-02.

Locked graph baseline: Rustleaks commit
`3003cc33b0d76a5576046be1f4fd2f50cfe30dd7`, with `Cargo.lock` SHA-256
`8f3893f06c74b312afd2ef9b6a240eaab6d5e3b5a4abe0eff1302a912d468eb4`.
The lockfile is unchanged by this exception record.

## Source and graph

- Package: `sha2 0.11.0` from crates.io, checksum
  `446ba717509524cb3f22f17ecc096f10f4822d76ab5c0b9822c5f9c284e825f4`.
- Provenance: the registry source matches RustCrypto `hashes` commit
  `ffe093984c004769747e998f77da8ff7c0e7a765` and tag `sha2-v0.11.0`.
- Roles: `rustleaks-sources` uses SHA-256 for XZ integrity checks through its
  unpublished `archives` feature, `lzma-rust2` uses it through its `xz`
  feature, and unpublished `xtask` uses it for maintenance hashes.
- Selected targets: the maintained graph compiles only x86-64 and ARM64
  targets. It does not set `sha2_backend`, `sha2_256_backend`, or
  `sha2_512_backend` to the opt-in RISC-V backend.
- Capabilities: the package has no build script, native library, `links`
  declaration, file, network, process, thread, logging, or mutable global
  authority. Its normal dependencies are `cfg-if`, `cpufeatures`, and
  `digest`.
- Licenses: the package declares MIT or Apache-2.0 and includes both license
  texts. Cargo-deny accepts them in the locked graph.

## Decision

The complete source review did not support a package-wide `safe-to-deploy`
certification. The unresolved concern is confined to the explicitly selected
RISC-V `riscv-zknh` backend. That backend is outside Rustleaks' maintained
target matrix and is not selected by the locked build configuration, so the
review found no affected Rustleaks runtime path.

Upstream commit `a71566a89f78720dbdaf4aed9883760870e8ef90` removes the
relevant RISC-V workaround. As of 2026-09-02, crates.io still lists 0.11.0 as
the latest release and no `sha2` release tag contains that commit. A Git source
is not permitted by the Rustleaks build contract, and creating a local fork
would add maintenance risk for code outside the supported target boundary.

The maintainer therefore approved retaining one time-bounded cargo-vet
exemption through 2026-11-23. The exemption is temporary policy coverage, not
an audit or a claim that every `sha2 0.11.0` backend is safe to deploy. Its
scope note records the Rustleaks decision boundary but does not narrow the
package-level exemption interpreted by cargo-vet.

## Resolution and reopen triggers

Replace the exemption with a qualifying version-specific peer audit, a
truthful local audit of a fixed registry release, or another separately
approved dependency resolution. Reopen this decision immediately if Rustleaks
adds RISC-V support, selects a RISC-V SHA-2 backend, changes the package source
or version, broadens publication of a consumer, or receives new advisory or
audit evidence. Otherwise review it no later than 2026-11-23.

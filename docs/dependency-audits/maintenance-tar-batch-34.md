# Maintenance dependency audit: tar batch 34

Review date: 2026-08-29.

Locked graph baseline: Rustleaks commit
`a65a5eabf81a5812df2f76876629398c47da1cfd`, with `Cargo.lock` SHA-256
`e3c24453ec42115d43dd5b2b679e43cdb6e1b0802393932d3ae199db2e502d82`.
The lockfile is unchanged by this audit batch.

`tar 0.4.46` is a normal dependency of unpublished `xtask` and remains
outside the publishable core's normal and build graphs. Rustleaks selects the
`default` and `xattr` features. The package has no build script, `links`
value, native compilation, generated production source, proc macro, or
target restriction. Its selected normal dependencies are `filetime`, `libc`,
and Unix-only `xattr`. Their locked coverage is respectively a local full
audit, a remaining exemption, and a peer-imported audit. This record covers
the `tar` package itself and does not substitute for the residual `libc`
review.

A fresh refresh and minimization of the Bytecode Alliance, Google, ISRG,
Mozilla, and Zcash cargo-vet imports supplied no version-specific coverage for
the exact locked package. The residual local review therefore covered all 27
packaged files and 9,569 packaged lines, including all 8,319 lines of Rust and
all 5,317 lines of production Rust. A RustSec check at advisory database
commit `b331df68b3ed0e99594d259040bdcb9de3c7c8a4` found no vulnerability for
the exact package. An exact-package GitHub Advisory Database query returned
no advisory affecting `tar 0.4.46`. MIT OR Apache-2.0 is allowed by
`deny.toml`, both license texts are packaged, and there is no `NOTICE` file.
No publisher trust, wildcard audit, criteria change, or exception was used.

## `tar 0.4.46`

- Archive: `tar-0.4.46.crate`; 70,809 bytes; SHA-256
  `3f6221d9a6003c78398e3b239969f352578258df48c8eb051caadae0015bc840`.
  The checksum matches `Cargo.lock` and the generated inventory. All 27
  archive members are regular files with mode `0644`. A fresh extraction
  matches cargo-vet's review source byte for byte apart from Cargo's
  `.cargo-ok` marker.
- Provenance: the packaged VCS record identifies upstream commit
  `fc459c149f83bf4daceaa52e17d351989002e1a9` in
  `https://github.com/composefs/tar-rs`. Lightweight unsigned tag `0.4.46`
  points to that commit. Packaged production source and common project files
  match the exact VCS tree. `Cargo.toml.orig` matches the upstream manifest;
  `.cargo_vcs_info.json`, the packaged lockfile, and normalized `Cargo.toml`
  are expected packaging metadata. The registry checksum and exact VCS
  comparison establish retained source identity without claiming signed
  provenance.
- Release scope: relative to 0.4.45, the release fixes PAX size handling for
  intermediary extension headers, adds exact regression and cross-parser
  cases for `GHSA-3cv2-h65g-fgmm`, documents the extraction TOCTOU boundary
  and builder symlink behavior, adds opt-in absolute archive paths, and
  updates release infrastructure. The two later upstream commits add Renovate
  configuration and synchronized infrastructure files without changing
  production source.
- Rustleaks use: package checking extracts Cargo's freshly produced
  `rustleaks-core` archive into a new staging directory. Release tooling builds
  deterministic archives from controlled fixed paths with `append_data`, then
  validates entries without unpacking them and rejects non-file or duplicate
  entries. Rustleaks does not call `append_dir_all`, enable ownership or
  permission restoration, or expose `tar` to runtime source scanning.
- Header unsafe boundary: `Header`, `OldHeader`, `UstarHeader`, and
  `GnuHeader` are 512-byte, alignment-one `repr(C)` layouts composed only of
  byte arrays. Their reference casts assert equal size and alignment.
  `Header::from_byte_slice` asserts the documented 512-byte precondition;
  byte-slice alignment is sufficient for the alignment-one header.
  `GnuExtSparseHeader` is also an all-byte, 512-byte, alignment-one
  `repr(C)` layout, so zero initialization and byte-array transmutation create
  no invalid value or misalignment.
- Filesystem unsafe boundary: sparse-file discovery calls `lseek` and, where
  supported, `fpathconf` with a live borrowed file descriptor and checks
  sentinel results before using offsets. Optional ownership restoration checks
  integer conversions, passes either a live file descriptor to `fchown` or a
  checked `CString` to `lchown`, and propagates operating-system errors. These
  ownership calls are disabled by default and unselected by Rustleaks.
- Authority boundary: the package intentionally reads filesystem metadata and
  content while building archives and can create files, directories, links,
  permissions, timestamps, ownerships, and xattrs while unpacking. It performs
  no network access, environment read, process or thread creation, logging, or
  mutable global operation. `Archive::unpack` rejects parent traversal, strips
  root and prefix components, validates hard-link destinations, and
  canonicalizes destination parents. It documents that concurrent mutation of
  the destination remains outside its threat model. Builder filesystem walks
  also document their historical follow-symlinks default and recommend
  disabling it. Neither discretionary behavior is reached by Rustleaks'
  controlled xtask paths.
- Hostile-input behavior: header checksums, entry rounding, stream positions,
  sparse offsets and lengths, and sparse real sizes use checked validation.
  PAX size overrides apply only to the described file entry, not GNU or PAX
  extension headers, closing the reviewed parser differential. Malformed
  headers, duplicate extension records, truncated data, overlapping sparse
  regions, and arithmetic overflow return errors. The public
  `Header::from_byte_slice` length panic and builder accessors' internal
  option invariants are documented or construction-controlled and are not
  attacker-driven parser paths.
- Resource behavior: normal entry reads and writes stream through caller-owned
  readers and writers. Long-name and PAX extension payloads allocate in
  proportion to data present in the archive, with initial allocation capped at
  128 KiB. Sparse metadata can request a large logical output from a small
  physical archive, and the crate provides no global entry, byte, or disk
  budget. Callers processing untrusted archives therefore need outer resource
  limits. Rustleaks uses the package only for bounded, controlled package and
  release artifacts; hostile runtime archives use the separately bounded
  source adapters and owned codecs.
- Licenses: packaged `LICENSE-MIT` and `LICENSE-APACHE` have respective
  SHA-256 values
  `8ca6b96cea9e67c6c5c63f452c31bd396db8bd2406231fdea5d48ef462b48077`
  and
  `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2`.
  There is no packaged `NOTICE` or additional license obligation.
- Published and upstream evidence: the exact published source passed its one
  library unit test and 14 documentation tests on Rust 1.88 and current stable
  Rust. The exact VCS release, which retains the upstream test fixtures,
  passed one library unit test and all 84 integration tests on both toolchains.
  The two macOS xattr cases were rerun outside the filesystem sandbox after
  their sandbox-only permission failures and passed. Rust 1.88 also passed all
  14 documentation tests.
- Interpreter and integration evidence: pinned-nightly Miri with strict
  provenance and symbolic alignment checks passed the sparse-file FFI unit
  test and all 12 header tests. The authoritative
  `//crates/xtask:xtask_unit_test` target passes for Rustleaks' selected graph,
  including package extraction and release-artifact behavior. The normal
  hosted matrix supplies compilation and xtask evidence for the maintained
  target set.
- Conclusion: complete source review, exact archive and VCS provenance,
  selected-feature and dependency-boundary analysis, multi-toolchain tests,
  Miri, Rustleaks integration tests, license evidence, and exact-version
  advisory results support `safe-to-deploy` for `tar 0.4.46`. The audit notes
  preserve the documented extraction TOCTOU and builder symlink discretion;
  Rustleaks' use does not rely on either behavior.

# Runtime dependency audit: windows-link batch 21

Review date: 2026-08-29.

Locked graph baseline: Rustleaks commit
`fb2ac33a7dff7efc48741dddbec6b728db232fb7`, with `Cargo.lock` SHA-256
`e3c24453ec42115d43dd5b2b679e43cdb6e1b0802393932d3ae199db2e502d82`.
The lockfile is unchanged by this audit batch.

`windows-link 0.2.1` is a normal target-specific dependency of
`windows-sys 0.61.2`. Cargo's unified all-target metadata closure reaches it
through `errno` and `rustix`, including the `xattr` and `tar` maintenance
path. The generated inventory records the `rustleaks-sources` and `xtask`
roots, no selected feature, every declared target, no build script, and no
`links` value. Exact Cargo trees for all eight required targets found no
realizable Rustleaks path: the roots select `rustix` or `xattr` only on Unix,
while `windows-link` is selected below them only on Windows. Cargo-vet still
requires coverage for the package in its unified graph.

The review covered all eight packaged files and 352 packaged text lines,
including all 39 lines of Rust source, manifests, package lockfile, licenses,
README, and VCS record. A RustSec check at advisory database commit
`b331df68b3ed0e99594d259040bdcb9de3c7c8a4` found no vulnerability,
unmaintained, unsound, or yanked warning in the exact Rustleaks lockfile. An
exact-version GitHub Advisory Database query returned no advisory affecting
`windows-link 0.2.1`. MIT OR Apache-2.0 matches `deny.toml`; both license texts
are packaged and there is no `NOTICE` file. No peer audits, wildcard trust,
criteria changes, or exceptions were used.

## `windows-link 0.2.1`

- Archive: `windows-link-0.2.1.crate`; SHA-256
  `f0805222e57f7521d6a62e36fa9163bc891acd422f971defe97d64e70d0a4fe5`.
  The packaged VCS record identifies verified upstream commit
  `d468916ac27a36fb8a12bafc1bf5c0ec2fe92238` under `crates/libs/link`; no
  upstream tag points at that commit. All eight archive members are regular
  files with mode `0644`. A fresh extraction matched cargo-vet's source byte
  for byte apart from Cargo's `.cargo-ok` marker. Source, README, licenses,
  and `Cargo.toml.orig` match the exact upstream subtree. The normalized
  manifest, package lockfile, and VCS record are Cargo packaging metadata.
  `license-mit` and `license-apache-2.0` have respective SHA-256 values
  `c2cfccb812fe482101a8f04597dfc5a9991a6b2748266c47ac91b6a5aae15383`
  and
  `c16f8dcf1a368b83be78d826ea23de4079fe1b4469a0ab9ee20563f37ff3d44b`.
- Rustleaks use: no required target realizes the unified metadata path to the
  package. If a future Windows graph selects it, `windows-sys` uses the macro
  to declare fixed Windows system imports. The package contributes linker
  declarations only; downstream Windows API signatures and call safety remain
  covered by the separate `windows-sys` exemption.
- Macro and target behavior: on Windows x86, `link!` emits an external block
  with a `raw-dylib`, verbatim library name, and undecorated import-name type.
  Other Windows architectures omit only the x86 decoration control. On
  non-Windows targets, the macro emits the external declarations without a
  link attribute, which supports compile-time generation but cannot resolve
  Windows symbols at link time. Library names, ABI names, optional symbol
  names, and function tokens are caller-supplied compile-time tokens; the
  package performs no runtime parsing or library selection.
- Unsafe and dependency inventory: the package contains no unsafe block or
  unsafe function and has no production dependency. Macro expansion creates
  external function declarations, whose calls remain unsafe under the macro's
  Rust 2021 definition context. The package does not assert the validity of a
  caller-supplied ABI or signature; that FFI contract belongs to the macro
  consumer. It neither calls a foreign function nor exposes a safe wrapper
  around one.
- Native and authority boundary: the archive has no build script, generated-
  at-build source, native source, or `links` declaration. It is `no_std` and
  emits no executable runtime code of its own. It opens no file or socket,
  reads no environment variable, starts no process or thread, allocates no
  memory, writes no log, and maintains no state. On Windows, the generated
  static import names a caller-selected literal DLL for normal loader
  resolution; the package does not perform dynamic path lookup or loading.
- Panic and resource behavior: macro expansion is compile-time token
  substitution with no recursion over input data. The emitted declarations
  contain no loop, allocation, panic, or runtime resource work. Link failures
  are build outcomes, not deployed runtime behavior.
- Published-source evidence: on Rust 1.88.0 and Rust 1.85.0, the library test
  target compiled and passed with zero defined unit tests. A temporary
  `no_std` harness instantiated both the ordinary and explicit-link-name macro
  forms and compile-checked on both toolchains. Using the repository's already
  installed pinned nightly source, the same harness compile-checked for
  x86_64-pc-windows-msvc, aarch64-pc-windows-msvc, and
  i686-pc-windows-msvc; the last target exercised the x86-only undecorated
  import branch.
- Documentation-test limitation: the single README example calls
  `kernel32.dll` imports without a Windows target guard. Its documentation
  test therefore fails to link on macOS with undefined `GetLastError` and
  `SetLastError` symbols on both Rust 1.88.0 and Rust 1.85.0. The package
  library and compile-only macro harness pass, and no required Rustleaks
  target selects the package. This documentation portability defect does not
  create a runtime safety or authority exception.
- Conclusion: complete source and macro-expansion review, exact archive and
  VCS provenance, target-resolution analysis, Windows cross-target checks,
  license evidence, and advisory results support `safe-to-deploy`. The
  unrealized locked path, caller-owned FFI contracts, and non-Windows README
  link failure are documented properties and do not require an exception.

# Maintenance dependency audit: rustix batch 40

Review date: 2026-08-30.

Locked graph baseline: Rustleaks commit
`a0cab21f3e45f3b03c2d920a3399769d9c023215`, with `Cargo.lock` SHA-256
`e3c24453ec42115d43dd5b2b679e43cdb6e1b0802393932d3ae199db2e502d82`.
The lockfile is unchanged by this audit batch.

`rustix 1.1.4` is outside the publishable core's normal and build graphs. It
is a Unix-targeted normal dependency of `xattr` in unpublished `xtask` and a
development dependency used by `rustleaks-sources` and `xtask` process-cleanup
tests. Rustleaks selects `alloc`, `default`, `fs`, `process`, and `std`. The
package has a build script but no `links` value, native compilation, generated
production source, or proc macro.

An exemption-free review of the Bytecode Alliance, Google, ISRG, Mozilla, and
Zcash cargo-vet sources supplied no `safe-to-deploy` path to this exact
release. The available Rustix records stop on older `0.x` releases, and the
source reorganization through `1.1.4` makes a local delta larger than the
complete current source. The residual local review therefore used the exact
full package. No publisher trust, wildcard audit, criteria change, or
exception was used.

## `rustix 1.1.4`

- Archive: `rustix-1.1.4.crate`; 425,241 bytes; SHA-256
  `b6fe4565b9518b83ef4f91bb47ce29620ca828bd32cb7e408f0062e9930ba190`.
  The checksum matches `Cargo.lock` and the generated inventory. All 332
  archive members are regular files with mode `0644`. Cargo-vet's extracted
  source contains 333 files and 75,459 lines including Cargo metadata; its
  audit estimate is 74,249 lines.
- Provenance: the packaged VCS record identifies official upstream commit
  `c4caf5caaa7e93828a2e4a4cdba1dd0171e45717` in
  `https://github.com/bytecodealliance/rustix`. Unsigned annotated tag
  `v1.1.4` points to that commit. All 328 packaged project files outside
  Cargo's generated metadata match the exact VCS tree byte for byte, and
  `Cargo.toml.orig` matches the upstream manifest. This establishes exact
  archive-to-VCS identity without claiming signed provenance.
- Feature and dependency boundary: the selected surface is the standard
  library, allocation support, filesystem operations, and process operations.
  It uses `bitflags` plus target-selected `linux-raw-sys`, `libc`, `errno`, or
  `windows-sys`. The current consumers select Rustix only on Unix. Linux uses
  the direct syscall backend on the maintained x86-64 and AArch64 targets;
  Apple targets use the libc backend. This audit covers Rustix itself and does
  not substitute for the remaining audits of those target dependencies.
- Build boundary: `build.rs` reads Cargo's target, feature, and compiler
  variables, checks for packaged architecture source, and invokes the selected
  Rust compiler on fixed feature-detection snippets. It writes compiler
  metadata only under Cargo's `OUT_DIR`, emits configuration flags, and does
  not read unrelated files, contact a network, invoke a shell, compile native
  code, or generate production source. A configured `RUSTC_WRAPPER` remains a
  caller-owned build input.
- Rustleaks reachability: `xattr` calls Rustix's checked path, descriptor,
  buffer, and extended-attribute APIs for controlled maintenance archives.
  Rustleaks process tests convert a nonzero child identifier to `Pid` and call
  `waitpid` with `NOHANG` to verify cleanup. Rustix is not linked into
  `rustleaks-core` and is not a normal runtime dependency of a published
  package.
- Unsafe inventory: the package contains unsafe Rust by design. The complete
  source has 154 Rust files containing the word `unsafe`, including 511 unsafe
  functions, 1,049 unsafe blocks, and 22 unsafe trait implementations. The
  libc and direct-syscall backends account for 36 and 47 of those files.
  Cargo-geiger on the selected Apple feature graph reported 50 used unsafe
  functions, 1,946 used unsafe expressions, ten used unsafe implementations,
  and one used unsafe trait. These counts are a review map, not the safety
  conclusion.
- Unsafe structure: safe public functions convert paths to checked C strings,
  retain descriptor lifetimes with I/O-safety types, pass slices as pointer
  and length pairs, and construct initialized buffers or owned descriptors
  only after an operating-system success result. Direct syscalls use typed
  argument and return registers, preserve pointer provenance, and select only
  the matching architecture implementation. The libc backend checks sentinel
  returns before converting results. Raw memory, ioctl, runtime, and advanced
  networking operations retain explicit unsafe preconditions where the
  operating system cannot provide a safe contract.
- Trait and global-state boundary: unsafe `Send` and `Sync` implementations
  cover directory state guarded by mutable access, byte-only socket storage,
  and returned `siginfo_t` values whose raw pointers are not dereferenced by
  safe methods. Unsafe ioctl and socket-address traits bind an opcode or a
  live temporary layout to the call. There is no `static mut`. Atomic globals
  cache weak dynamic symbols and kernel-provided auxv or vDSO addresses;
  release/acquire synchronization or immutable kernel-lifetime data supports
  later reads. Experimental explicit-auxv initialization is not selected.
- Authority and hostile-input boundary: the crate exposes caller-requested
  filesystem, process, network, thread, memory, and system interfaces but does
  not initiate them in the background. It creates no worker thread, performs
  no implicit network access, and emits no runtime log. Interior-NUL paths
  return errors. Kernel return values and output lengths are checked before
  safe conversion. This is an operating-system binding rather than a parser;
  input size, file descriptors, paths, processes, and resource lifetime remain
  caller-owned.
- Panic and resource behavior: selected Rustleaks calls allocate only for
  caller-provided path or output storage and propagate operating-system
  failures. Assertions protect ABI, layout, documented constructor, or
  successful-kernel-result invariants. Some unselected platform and
  experimental paths intentionally assert kernel ABI assumptions, and the
  optional auxv fallback can panic after an unexpected read failure. Those
  paths are outside the selected feature and call graph. Ordinary allocation
  failure and operating-system resource exhaustion remain possible.
- Licenses and notices: the package declares
  `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT`. Apache-2.0 and MIT are
  allowed by `deny.toml`. Packaged `LICENSE-MIT`, `LICENSE-APACHE`,
  `LICENSE-Apache-2.0_WITH_LLVM-exception`, `COPYRIGHT`, and `SECURITY.md` have
  respective SHA-256 values
  `23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3`,
  `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2`,
  `268872b9816f90fd8e85db5a28d33f8150ebb8dd016653fb39ef1f94f2686bc5`,
  `377c2e7c53250cc5905c0b0532d35973392af16ffb9596a41d99d202cf3617c9`,
  and
  `4d75afb09dd28eb5982e3a1f768ee398d90204669ceef3240a16b31dcf04148a`.
  There is no packaged `NOTICE` file. The maintained RustSec and cargo-deny
  checks pass this exact locked graph without an exception.
- Package evidence: on Rust 1.88, the exact selected package passed 22 library
  tests. Its documentation examples expose two `event` examples even when
  that feature is absent; adding only `event` produced 23 library and 13
  documentation passes. The broad non-internal feature profile passed 31
  library and 23 documentation tests. Literal `--all-features` additionally
  selects the nightly-only `rustc-dep-of-std` mode and therefore is not a
  stable-toolchain profile.
- Upstream and interpreter evidence: the exact VCS release retains tests
  excluded from the registry package. With the selected feature surface on
  Rust 1.88, it passed 121 unit, integration, and documentation tests with
  three intentional ignores. The exact release commit has 51 successful
  upstream checks covering its Rust 1.63 MSRV, stable Rust, Linux architectures,
  musl, both Linux backends, macOS, Windows, FreeBSD, formatting, and
  no-default-feature profiles. Pinned-nightly Miri passed 15 pure layout,
  constructor, C-string, time, signal, and identifier tests; filesystem-backed
  cases are unsupported by Miri's macOS foreign-function model rather than
  failing an interpreter check.
- Rustleaks evidence: fresh uncached
  `//crates/rustleaks-sources:git_sources_test` and
  `//crates/rustleaks-sources:native_sources_test` targets passed on Apple
  Silicon. The unchanged locked graph passed the repository's full local and
  hosted security, Bazel, package, parity, fuzz, and eight-target native gates
  immediately before this audit batch.
- Conclusion: exact archive and VCS provenance, complete package inventory,
  selected-feature and both-backend source review, unsafe and global-state
  analysis, build-script review, exact upstream multi-platform CI, package and
  upstream tests, focused Miri, Rustleaks integration evidence, license
  evidence, and maintained advisory gates support `safe-to-deploy` for
  `rustix 1.1.4`. This conclusion does not extend Rustleaks' resource limits to
  arbitrary Rustix callers or certify the remaining target dependency
  exemptions.

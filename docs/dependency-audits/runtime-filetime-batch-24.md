# Runtime dependency audit: filetime batch 24

Review date: 2026-08-29.

Locked graph baseline: Rustleaks commit `d38ed90b36e5d9b26637734f8789b89c351ba618`, with `Cargo.lock`
SHA-256
`e3c24453ec42115d43dd5b2b679e43cdb6e1b0802393932d3ae199db2e502d82`.
The lockfile is unchanged by this audit batch.

`filetime 0.2.29` is a normal dependency of `tar 0.4.46`. The locked graph
reaches it only through `xtask` package and release-artifact maintenance. The
generated inventory records the `xtask` root, no selected feature, every
declared target, no build script, and no `links` value. The package is outside
the core normal or build graph. The exact all-target Cargo tree is
`filetime -> tar -> xtask`.

The review covered all 19 packaged files and 2,079 packaged text lines,
including all 1,182 lines of Rust production and test source, manifests,
package lockfile, workflow, licenses, README, and VCS record. A RustSec check
at advisory database commit `b331df68b3ed0e99594d259040bdcb9de3c7c8a4`
found no vulnerability, unmaintained, unsound, or yanked warning in the exact
Rustleaks lockfile. An exact-version GitHub Advisory Database query returned
no advisory affecting `filetime 0.2.29`. MIT OR Apache-2.0 matches
`deny.toml`; both license texts are packaged and there is no `NOTICE` file.
No peer audits, wildcard trust, criteria changes, or exceptions were used.

## `filetime 0.2.29`

- Archive: `filetime-0.2.29.crate`; SHA-256
  `5c287a33c7f0a620c38e641e7f60827713987b3c0f26e8ddc9462cc69cf75759`.
  The packaged VCS record identifies upstream commit
  `ab5ee65b5e4fe2de19dbe7d4fe08bc31e945949c` at the repository root;
  lightweight tag `0.2.29` points directly at that commit. All 19 archive
  members are regular files with mode `0644`. Cargo-vet's source matches a
  fresh archive extraction byte for byte apart from Cargo's `.cargo-ok`
  marker. Source, workflow, README, licenses, `.gitignore`, and
  `Cargo.toml.orig` match the exact upstream tree. The normalized manifest,
  package lockfile, and VCS record are Cargo packaging metadata.
  `LICENSE-APACHE` and `LICENSE-MIT` have respective SHA-256 values
  `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2`
  and
  `378f5840b258e2779c39418f3f2d7b2ba96f1c7917dd6be0713f88305dbda397`.
- Rustleaks use: `xtask` uses `tar` to unpack a locally produced crates.io
  package during package checks and to read or unpack release artifacts.
  `tar` converts archive modification times with zero nanoseconds and uses
  `filetime` to set regular-file or symlink timestamps when unpacking. The
  dependency does not enter a published Rustleaks crate.
- Timestamp behavior: `FileTime` stores signed seconds and unsigned
  nanoseconds, converts between Unix and Windows epochs, reads platform
  metadata, and delegates regular-file updates to `std::fs::File::set_times`.
  Unix symlink updates use `utimensat` where available and fall back to
  `utimes` or `lutimes`; Linux remembers only an `ENOSYS` result before using
  the fallback. Windows uses safe standard-library file-handle APIs, Redox
  uses safe `O_NOFOLLOW` file opening, and the non-Emscripten WebAssembly
  implementation reports symlink updates as unsupported.
- Unsafe inventory: every Unix syscall receives a live NUL-terminated
  `CString` pointer and a live two-element timestamp array for the duration of
  the call. Zero initialization is valid for `libc::timespec`; the code then
  initializes both fields, using `UTIME_OMIT` for an absent timestamp. macOS
  checks the result of `dlsym` before converting the non-null address to the
  exact `utimensat` C signature and caches only the address or an unavailable
  sentinel in an atomic integer. The selected function is invoked with the
  same argument and return types. No unsafe code creates a Rust reference,
  transfers ownership, indexes memory, or exposes a safe wrapper with a
  caller-owned validity obligation.
- Native and authority boundary: the archive has no build script, native
  source, generated-at-build source, or `links` declaration. It opens or
  updates only caller-supplied paths and handles; the caller owns that
  filesystem authority. It opens no socket, reads no environment variable,
  starts no process or thread, writes no log, and performs no dynamic library
  path selection. The macOS lookup asks the already loaded process image for
  the fixed `utimensat` symbol.
- Panic and resource behavior: timestamp setting is constant-memory and uses
  a bounded number of system calls. `from_unix_time` accepts an arbitrary
  `u32` nanosecond value even though `nanoseconds` documents a value below one
  billion; converting such a caller-constructed invalid value to `SystemTime`
  can panic. Extreme values outside a platform's representable timestamp
  range can also fail or panic during standard-library conversion. The locked
  `tar` path always supplies zero nanoseconds and a header-derived `i64`
  second value. Non-Emscripten WebAssembly metadata accessors are
  `unimplemented!`; WebAssembly is outside the required Rustleaks target set.
  These value-range and unsupported-target limitations do not permit memory
  unsafety or ambient authority.
- Published-source evidence: on Rust 1.88.0, Rust 1.85.0, and the repository's
  pinned nightly toolchain, all eight native unit tests passed. The pinned
  nightly run also passed both documentation tests. Pinned-nightly
  `build-std` checks compiled the library for all seven non-native required
  targets; the native AArch64 macOS target was exercised by the tests. The
  musl checks emitted only libc's documented deprecation warning for aliases
  that will follow a future musl time-width change.
- Additional unsafe evidence: the complete published test suite, including
  regular-file, directory, symlink, pre-epoch, and single-timestamp updates,
  passed natively on AArch64 macOS under AddressSanitizer. This exercises the
  selected macOS `dlsym`, function-pointer conversion, `utimensat` call, and
  timestamp-buffer paths with runtime memory instrumentation. Other Unix
  target branches received complete source review and pinned-nightly
  cross-target compilation but were not natively executed in this audit.
- Conclusion: complete source and unsafe review, exact archive and VCS
  provenance, all-required-target compilation, native multi-toolchain tests,
  native AddressSanitizer execution, license evidence, and advisory results
  support `safe-to-deploy`. The caller-constructed invalid-nanosecond panic,
  platform timestamp ranges, and unsupported WebAssembly metadata accessors
  are documented limitations and do not require an exception.

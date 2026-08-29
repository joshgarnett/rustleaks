# Runtime dependency audit: errno batch 23

Review date: 2026-08-29.

Locked graph baseline: Rustleaks commit
`853e96226d8c1853c8ce9ba405f9a6e9e9c608ca`, with `Cargo.lock` SHA-256
`e3c24453ec42115d43dd5b2b679e43cdb6e1b0802393932d3ae199db2e502d82`.
The lockfile is unchanged by this audit batch.

`errno 0.3.14` is a normal target-specific dependency of `rustix 1.1.4`.
Cargo's unified all-target metadata closure records the `rustleaks-sources`
and `xtask` roots. Exact Cargo trees for the eight required targets reach the
package only on the two Apple targets, through `xattr 1.6.1` and `tar 0.4.46`
in `xtask`. The generated inventory records the selected `std` feature, no
build script, no `links` value, and no core normal or build path. The selected
Apple implementation depends on `libc 0.2.189`. The unified package metadata
also declares the target-specific `windows-sys 0.61.2` dependency; both
dependencies remain covered separately and are not represented as audited by
this worksheet.

The review covered all 18 packaged files and 1,142 packaged text lines,
including all 472 lines of Rust source, manifests, package lockfile,
workflows, licenses, README, changelog, and VCS record. A RustSec check at
advisory database commit
`b331df68b3ed0e99594d259040bdcb9de3c7c8a4` found no vulnerability,
unmaintained, unsound, or yanked warning for the package. An exact-version
GitHub Advisory Database query returned no advisory affecting `errno 0.3.14`.
MIT OR Apache-2.0 matches `deny.toml`; both license texts are packaged and
there is no `NOTICE` file. No peer audits, wildcard trust, criteria changes,
or exceptions were used.

## `errno 0.3.14`

- Archive: `errno-0.3.14.crate`; SHA-256
  `39cab71617ae0d63f51a36d69f866391735b51691dbda63cf6f96d042b63efeb`.
  The packaged VCS record identifies upstream release commit
  `ffc03bfb9eb491013567115e6eea560948cd9e52` at the repository root; no
  upstream tag points at that commit. All 18 archive members are regular
  files with mode `0644`. A fresh extraction matched cargo-vet's source byte
  for byte apart from Cargo's `.cargo-ok` marker. Source, workflows,
  changelog, README, licenses, and development configuration match the exact
  upstream tree, and `Cargo.toml.orig` matches the upstream manifest. The
  normalized manifest, package lockfile, and VCS record are Cargo packaging
  metadata. `LICENSE-APACHE` and `LICENSE-MIT` have respective SHA-256 values
  `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2`
  and
  `8764a597675778ddfd4e25f81b08a05dbcf089ac05662df7613fe67f150e3aa2`.
- Rustleaks use: on Apple hosts, the maintenance-only tar path reaches the
  package through `xattr` and `rustix` for operating-system error access and
  formatting. No required Linux or Windows target realizes a locked workspace
  path to the package. It does not parse archive bytes or decide Rustleaks
  error classifications.
- Platform behavior: Unix and WASI implementations read and write the
  target's thread-local error slot and use `strerror_r` for a fixed-size error
  description. Windows reads and writes the calling thread's last-error value
  and uses `FormatMessageW` with a caller-owned fixed buffer. Hermit exposes
  its documented zero-valued placeholder. Unrecognized targets fail at
  compile time. The public integer wrapper can convert to `i32`, to a standard
  I/O error with `std`, and to formatted debug or display output.
- Unsafe inventory: Unix and WASI pass a 1,024-byte zeroed stack buffer to the
  bounded `strerror_r` interface, then measure the returned NUL-terminated
  message. Darwin documents NUL termination even on `ERANGE`; the XSI return
  handling accepts both current positive errors and the historical negative
  form. The UTF-8 conversion uses only the valid prefix reported by
  `core::str`. Error-location pointers and their thread-local lifetime come
  from each target ABI. Windows passes a 2,048-element UTF-16 stack buffer to
  `FormatMessageW`, whose successful return is the bounded character count;
  its UTF-16 decoder writes only complete encoded scalar values into a
  separate 2,048-byte buffer before creating the string view. Windows error
  integer casts preserve the underlying 32-bit value. No raw pointer escapes,
  and the package creates no safe alias to mutable foreign storage.
- Native and authority boundary: the archive has no build script, native
  source, generated-at-build source, or `links` declaration. It allocates no
  package-owned heap memory and opens no file or socket, reads no environment
  variable, starts no process or thread, writes no log, and maintains no
  package-global state. Its explicit purpose is to read or replace the
  calling thread's operating-system error value. Description formatting asks
  the operating system for its fixed error text; it does not select or open a
  caller-controlled resource.
- Panic and resource behavior: error access is constant work. Unix formatting
  uses one 1,024-byte buffer; Windows formatting uses fixed UTF-16 and UTF-8
  buffers and bounded linear conversion. A foreign function failure becomes
  a formatted fallback rather than a package panic. Formatter and callback
  failures propagate through their ordinary Rust contracts. The package does
  not recurse or perform input-sized allocation.
- Published-source evidence: against the exact Rustleaks-selected
  `libc 0.2.189`, default-feature runs passed four unit tests and one
  documentation test on Rust 1.88.0, Rust 1.85.0, and the repository's pinned
  nightly toolchain. No-default-feature runs passed one unit test and one
  documentation test on the same three toolchains. Nightly compile checks
  with the selected target dependencies passed for all seven non-native
  required targets; the native AArch64 Apple tests exercised the selected
  implementation.
- Additional unsafe evidence: a temporary harness formatted known, unknown,
  negative, and extreme 32-bit error codes, round-tripped thread-local error
  values, and checked standard I/O error conversion on Rust 1.88.0 and Rust
  1.85.0. The same harness passed under AddressSanitizer on native AArch64
  macOS. Miri cannot execute the required operating-system FFI, so the review
  used native sanitizer execution, cross-target compilation, and the complete
  platform-contract analysis above.
- Conclusion: complete source and unsafe review, exact archive and VCS
  provenance, selected dependency and target analysis, native and cross-target
  evidence, AddressSanitizer execution, license evidence, and advisory results
  support `safe-to-deploy`. The separate dependency unsafe boundaries,
  explicit thread-local error mutation, and unrealized non-Apple graph paths
  do not require an exception.

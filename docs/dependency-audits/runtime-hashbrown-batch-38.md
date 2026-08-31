# Runtime dependency audit: hashbrown batch 38

Review date: 2026-08-31.

Locked graph baseline: Rustleaks commit
`30d35a9342a5f665eb839d0e6709e4ad3a31a190`, with `Cargo.lock` SHA-256
`e3c24453ec42115d43dd5b2b679e43cdb6e1b0802393932d3ae199db2e502d82`.
The lockfile is unchanged by this audit batch.

`hashbrown 0.17.1` is retained in the lock boundary as a normal dependency of
`indexmap`, which is itself an optional dependency of `toml`. The generated
inventory reports no current workspace consumer and no enabled feature. No
workspace-selected feature activates that retained chain. It remains outside
the default `rustleaks-core` graph. The package has no build script, `links`
value, native compilation, generated production source, proc macro, or target
restriction.

An exemption-free refresh of the Bytecode Alliance, Google, ISRG, Mozilla,
and Zcash cargo-vet imports supplied no version-specific coverage for this
release. The residual local review covered all 50 packaged files and 26,562
cargo-vet audit lines. The maintained RustSec and cargo-deny gates cover
advisory, license, and source policy for the locked graph without accepting an
exception. No publisher trust, wildcard audit, criteria change, or exception
was used.

## `hashbrown 0.17.1`

- Archive: `hashbrown-0.17.1.crate`; 155,512 bytes; SHA-256
  `ed5909b6e89a2db4456e54cd5f673791d7eca6732202bbf2a9cc504fe2f9b84a`.
  The checksum matches `Cargo.lock`, `cargo-bazel-lock.json`, and the generated
  inventory. All 50 archive members are regular files with mode `0644`.
  Cargo-vet's extracted review source is backed by that exact archive.
- Provenance: the packaged VCS record identifies upstream commit
  `c62a63a61b7caf2de8f9ecb7b06a66b0ab6bdf3d` in
  `https://github.com/rust-lang/hashbrown`. Annotated unsigned tag `v0.17.1`
  resolves to that commit. Packaged project files match the exact VCS tree.
  Cargo's normalized manifest, generated package lockfile, original manifest
  copy, VCS record, and `.cargo-ok` marker are expected package additions.
  This establishes archive-to-VCS identity without claiming signed
  provenance.
- Feature and dependency boundary: the locked Rustleaks graph selects no
  feature and has no active consumer. The complete review also covered the
  default hasher, allocator, equivalent-key, raw-entry, serde, Rayon, and
  rustc-internal source paths. Optional dependency packages outside the locked
  graph are not certified by this record. Future activation of this lockfile
  edge would change the generated consumer and feature inventory and require
  review of that reachable configuration.
- Unsafe boundary: the implementation uses unsafe Rust for allocation layout,
  raw bucket and control-byte pointers, SIMD group loads, iterator construction,
  in-place rehashing, custom allocators, and low-level entry APIs. The review
  traced allocation and deallocation layouts, `isize` capacity caps, zero-sized
  bucket handling, alignment, initialized control groups, pointer provenance,
  iterator variance, mutable alias exclusion, and public caller obligations.
  The generic, SSE2, NEON, and LoongArch control-group implementations retain
  equivalent load widths and bounds. Public unsafe insertion and replacement
  methods document the uniqueness or validity invariant delegated to callers.
- Panic and destruction boundary: hashing, equality, cloning, allocation,
  predicates, and user destructors can panic. Scope guards and partial-clone
  guards restore control bytes, lengths, ownership, and deallocation state so
  unwinding does not create double drops or invalid live entries. Some
  user-panic paths may leak or discard an entry as documented, but the reviewed
  guards preserve memory safety. Upstream tests exercise clone, clone-from,
  extraction, custom allocator, iterator, duplicate-key, and panic cases.
- Authority boundary: production code is `no_std` collection machinery. It
  performs no file or path access, environment read, network access, process
  execution, logging, or mutable process-global operation. The optional Rayon
  implementations delegate parallel work to Rayon when selected; Rustleaks
  does not select that feature. Filesystem, threads, printing, and mutable
  globals found in the package are confined to tests, benchmarks, and examples.
- Untrusted-input and resource behavior: table capacity and work follow caller
  insertions, hash quality, and requested reservation. Checked layout arithmetic
  rejects capacity overflow, `try_reserve` reports allocation failure, and
  ordinary allocating APIs retain Rust's normal panic or abort behavior on
  allocation failure. The default `foldhash` builder is explicitly documented
  as lacking the standard library hasher's HashDoS resistance. Neither that
  builder nor any map operation is reachable in the current Rustleaks graph.
  Consumers that activate it must not treat it as collision-attack resistant.
- Optional serde and parallel behavior: deserialization caps an untrusted size
  hint at 4,096 before allocation and then inserts through the checked table
  path. Rayon producers split disjoint iterator ranges, and parallel drain and
  ownership guards preserve single ownership during cancellation or unwind.
  These features were reviewed and tested but remain inactive in Rustleaks.
- Test evidence: the exact published source passed 172 tests and all target
  harnesses with `rayon,serde,raw-entry,rustc-internal-api` on Rust 1.98.0 and
  Rustleaks' Rust 1.88 MSRV. The default profile passed 113 tests and all target
  harnesses on the package's Rust 1.85 MSRV. A focused default-profile Miri run
  passed the raw-table uninitialized-drop regression. The package's
  no-default-feature test module assumes APIs supplied by default features, so
  no Miri result is claimed for that unsupported test configuration.
- Target evidence: exact no-default-feature library checks passed for
  `aarch64-apple-darwin`, `x86_64-unknown-linux-gnu`, and
  `x86_64-pc-windows-msvc` on installed Rust 1.98 target libraries. Native
  tests ran on AArch64 macOS. Target libraries for the other maintained triples
  were not installed for this package review, so this record makes no
  all-target package claim. The inactive package remains covered by the
  repository's authoritative eight-target graph checks.
- License: the package declares `MIT OR Apache-2.0`, both allowed by
  `deny.toml`. Packaged `LICENSE-MIT` and `LICENSE-APACHE` have SHA-256 values
  `ff8f68cb076caf8cefe7a6430d4ac086ce6af2ca8ce2c4e5a2004d4552ef52a2`
  and
  `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2`.
  There is no packaged `NOTICE` or additional license file.
- Conclusion: exact archive and VCS provenance, complete production and test
  source review, unsafe and panic-boundary analysis, multi-toolchain tests,
  focused Miri evidence, selected target builds, license evidence, and the
  maintained advisory gates support `safe-to-deploy` for `hashbrown 0.17.1`.
  The audit does not claim collision-attack resistance for the optional default
  hasher or runtime reachability in the current Rustleaks graph.

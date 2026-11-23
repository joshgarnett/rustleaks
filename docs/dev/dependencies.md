# Dependencies

This page is for maintainers. It states the dependency policy, the unsafe
code boundary of the dependency graph, and the decisions about archive
codecs. Adding or updating a dependency needs maintainer approval. The checks
that enforce this policy are in [Security checks](security-checks.md).

## Policy

- Prefer small, maintained crates with compatible permissive licenses and a
  good security record. Record lasting choices on this page. Commit
  `Cargo.lock`.
- `just deps-repin` is the only command that regenerates the Cargo,
  crate-universe and Bazel module lockfiles. It keeps existing resolutions
  unless changed requirements need updates. Review every lockfile diff,
  including the separate fuzz workspaces.
- `rustleaks-core` must not depend on the CLI, sources, reports, archives,
  Git, async runtimes or parallel runtimes. Its public API must not expose a
  regex type.
- `rustleaks-sources` and `rustleaks-report` depend only on the core. The CLI
  may use all three. `rustleaks-compat` and `xtask` are unpublished leaves.
- Owned crates forbid unsafe code. A dependency with necessary unsafe code
  needs isolation, a written reason, license review and adversarial tests.
- License and advisory checks must pass before a release. An advisory may be
  waived only with a time-limited entry, backed by evidence, in
  `supply-chain-exceptions.toml`. Never remove the check to hide it.
- Published crates use semver ranges that work with the MSRV, Rust 1.95
  (`rust-version` in the root `Cargo.toml`). Development uses the pinned toolchain in `rust-toolchain.toml`. CI also
  builds with the MSRV and runs the native platform lanes.
- Any change to a dependency version, feature, target or publication boundary
  reopens the review on this page.

There is no Go module or other executable oracle in the dependency graph.

## Core dependencies

### Regex

`rustleaks-core` requires `regex-syntax ^0.8.5` and
`regex-automata ^0.4.12`, so that applications can share these maintained
release lines. These versions use Unicode 16 tables. So Unicode properties and
case folding can differ from the pinned Go behavior for code points assigned
or changed after Unicode 15. The private frontend still accepts only Go
property names. The generated Go lowercase tables used outside regular
expressions stay on Unicode 15. A regex dependency update needs the full
regex regression corpus and a security review.

The core and core fuzz manifests turn on the `regex-automata` features
`meta`, `hybrid`, `dfa-onepass`, `nfa-backtrack` and `perf`, with the syntax,
Unicode and PikeVM features. The private meta engine uses pooled search
caches, literal acceleration, the lazy DFA and bounded capture engines. It
keeps leftmost-first matching and the Go frontend. There is no `regex`,
`grep-regex` or `grep-searcher` dependency.

`dfa-build` stays off, and the meta configuration turns off full DFA
construction so that feature unification downstream cannot turn it on. The
lazy DFA cache is 2 MiB per direction and the one-pass DFA limit is 1 MiB.
These are not a heap limit for the whole engine. The
[backend review](../dependency-audits/regex-meta-backend.md) records the
source paths, the minimum-version API check and the fallback policy.

### JSON

`serde_json` is a runtime dependency of the core because the Gitleaks
baseline file is a JSON report. The session parser wraps its tokenizer with
a private visitor that matches Go field handling, null and duplicate fields,
invalid UTF-8 and lone surrogate replacement. No JSON type appears in the
public session API.

## Unsafe code in dependencies

All owned crate roots use `#![forbid(unsafe_code)]`, and the release check
rejects owned unsafe code. Some registry dependencies contain unsafe code
inside.

Dependency review uses the locked Cargo and Bazel resolutions, cargo-deny,
cargo-vet, RustSec and the unsafe inventory. Written audits of exact package
versions are in [`docs/dependency-audits/`](../dependency-audits/README.md),
and the cargo-vet records in `supply-chain/audits.toml` point to them. It does not hash complete
dependency trees, because those hashes change on every routine update without
showing whether a security boundary changed.

The dependency check looks at the all-target normal graph of
`rustleaks-core` and the all-feature graph of `rustleaks-sources`. It rejects
higher-layer or codec dependencies in the core, common native build helpers,
native `-sys` crates, and any package that declares Cargo's `links` key.
This check reads the dependency graph. It is not compile evidence; the
target compile checks are separate.

The cargo-geiger check requires used unsafe code in exactly these 23 packages
on every checked host:

```text
aho-corasick@1.1.5
alloc-no-stdlib@3.0.0
alloc-stdlib@0.3.0
block-buffer@0.12.1
brotli-decompressor@6.3.2
const-oid@0.10.2
hybrid-array@0.4.15
itoa@1.0.18
lz4_flex@0.14.2
lzma-rust2@0.25.0
memchr@2.8.3
proc-macro2@1.0.107
regex-automata@0.4.19
semver@1.0.28
serde_core@1.0.229
serde_json@1.0.154
sha2@0.11.1
syn@3.0.9
toml_parser@1.1.5+spec-1.1.0
twox-hash@2.1.5
unicode-ident@1.0.27
winnow@1.0.5
zmij@1.0.23
```

Some targets also show used unsafe code in `cpufeatures@0.3.1` and
`libc@0.2.191`. These are the only two reviewed additions. The check fails
when a common package disappears, an unreviewed package appears, or a
first-party crate reports unsafe code. This inventory detects change. It is
not an audit or a reachability claim.

### Core

The unsafe boundary of the published core is narrow:

- `aho-corasick`, `regex-automata` and `memchr` provide checked search APIs
  over borrowed byte slices, and keep architecture-specific acceleration
  inside;
- `serde`, `serde_json`, `toml`, `winnow` and their helpers provide safe
  parsing and serialization APIs; and
- proc-macro crates run at build time and are not linked into the library.

The regex features above reach the lazy DFA transition indexing and the
thread-aware cache pool of `regex-automata 0.4.19`. The
[backend review](../dependency-audits/regex-meta-backend.md) covers them for
0.4.18, and the
[2026-11-23 delta review](../dependency-audits/maintenance-2026-11-23.md)
covers the changes in 0.4.19, including the pool's fixed default of 8
shards.
Owned code uses pooled safe search APIs and never mixes caches between
expressions. The pool keeps scratch space across scans; concurrent searches
and cloned engines can keep more caches.

### Archives

The `archives` feature of `rustleaks-sources` is the only production
boundary for archive codecs. No codec type crosses the source API, no codec
enters `rustleaks-core`, and the default features resolve no codec. The codec
graph is pinned exactly.

- `lzma-rust2 0.25.0` has optimization turned off. `lz4_flex` uses its
  checked, safe encode and decode features.
- The bzip2, RAR and 7z forks in this repository forbid unsafe code.
- RAR2 uses `compcol 0.8.0` with only `alloc` and `rar2`. That graph has no
  normal dependencies, build script, native code or unsafe Rust. Version
  0.8.0 streams decoded output from the fixed 1 MiB window instead of
  building the whole member in memory. A synthetic archive regression keeps
  expected bytes that were checked against the pinned Go decoder. The
  [compcol 0.7.8 review](../dependency-audits/compcol-0.7.8.md) records the
  repeated-match correction and a notice issue in unselected bzip2 code,
  which Rustleaks neither compiles nor redistributes. The
  [0.8.0 delta review](../dependency-audits/maintenance-2026-11-20.md#compcol)
  records the streaming change and why the exemption remains. Turning on
  other codecs or distributing their sources reopens the review.
- XZ checksums use pinned `sha2`. Its portable and hardware dispatch is the
  main intended unsafe boundary for archives.
- The Bazel workspace feature union turns on the SIMD checksum path in
  `miniz_oxide` through `flate2`, using the audited `simd-adler32 0.3.10`.
  The Cargo graph for sources alone keeps a narrower feature set.
- The owned 7z parser checks unique stream bindings, packed input references
  and acyclic coder graphs before it builds any decoder. This is safe Rust
  with linear work bounded by the header.

Archive input is also limited by depth, entry, member, total and spool
limits, and is covered by hostile-input tests and fuzzing.

### Platform crates

`rustix`, `libc`, `linux-raw-sys` and `windows-sys` appear only through
target-specific development checks that watch process cleanup. They are not
normal dependencies of the published core. Audit the platform graph again if
one becomes a normal dependency.

### Tokenizer data

The Vercel predicate uses immutable cl100k data under the OpenAI and
tiktoken-rs MIT notices next to it. This adds no Cargo dependency and no
runtime loader. The generator checks the original asset hash and size, both
licenses, the full source vocabulary and every derived table byte. See the
[tokenizer data README](../../crates/rustleaks-core/data/README.md).

### Limits of this review

A plain text search also finds the word `unsafe` in several selected crates.
This counts comments, tests, build code, unused features and other target
branches, so it overstates active code. The safety argument is the exact
feature graph, the safe API boundary, the resource limits, the focused tests
and fuzzing, and the version and source policy together. It is not a claim
that all dependencies are safe Rust.

`cargo deny check` must pass advisories, bans, licenses and sources. CI runs
the platform tests natively on all eight targets (see
[Testing](testing.md#platforms)). The tests reach
dependency code only with the inputs they pass to it. Compiling for a target
does not test its architecture-specific unsafe paths.

## Archive codec decision

### Decision

Keep three private decoder forks, `rustleaks-bzip2`, `rustleaks-rar-codec`
and `rustleaks-sevenz`, and work on narrow upstream changes. No evaluated
released crate meets the full archive boundary. The forks stay outside
`rustleaks-core`, and no codec type enters a public API.

| Fork | Upstream | Why it stays |
| --- | --- | --- |
| `rustleaks-bzip2` | `bzip2-rs 0.1.2` | Replaces input-dependent `unwrap`, `unreachable!` and assertions with structured errors, replaces `crc32fast` with an owned safe CRC, and checks the combined stream CRC. `bzip2 0.6.1` uses `libbz2-rs-sys`, a large unsafe boundary without cargo-vet coverage. |
| `rustleaks-rar-codec` | `rars 0.9.3` | Keeps only the RAR3 and RAR5 decoders, with checked arithmetic, fallible growth, Huffman checks, bounded VM programs and filters, and output limits. `rars` has no decoder-only feature; it brings writing, encryption, recovery, parallelism and file system code. |
| `rustleaks-sevenz` | `sevenz-rust2 0.20.2` | Removes encoder, writer, file system and AES code, and adds checked offsets, fallible allocation, bounded metadata and coder graph checks. `sevenz-rust2 0.22.2` with the needed codecs adds `zstd-sys`, a native linked library. These changes cannot be made with an extension trait around the upstream API. |

Fork provenance:

| Fork | Upstream archive SHA-256 | Upstream commit |
| --- | --- | --- |
| `rustleaks-bzip2 0.1.2-rustleaks.1` | `beeb59e7e4c811ab37cc73680c798c7a5da77fc9989c62b09138e31ee740f735` | `359904e0132d10acfe0896b878efbf4b137a3e0a` |
| `rustleaks-rar-codec 0.9.3-rustleaks.1` | `68ff174e95890b9e1c01601a93f35f60c017162fb1bd723dfef9f684ae2ffdb6` | `54e744d0e70998d1aea9b1ae8a9bc7eaecd127f3`, extracted at `1f4f885577485d954c5e9a470a728d0111dc6f11` with the same codec tree |
| `rustleaks-sevenz 0.20.2-rustleaks.1` | `29225600349ef74beda5a9fffb36ac660a24613c0bde9315d0c49be1d51e9c24` | `424ebdb8fa98b78b8e1c18f73c9add6972fe5496` |

Each fork keeps the upstream license next to its code:

- `rustleaks-bzip2` keeps MIT or Apache-2.0 (`LICENSE-MIT` and
  `LICENSE-APACHE`).
- `rustleaks-rar-codec` keeps the upstream `COPYING` grant, a short custom
  license. `Cargo.toml` names it with `license-file`, and `deny.toml`
  accepts it as `LicenseRef-Rustleaks-Rar-Codec` only while the hash of
  `COPYING` is unchanged.
- `rustleaks-sevenz` keeps Apache-2.0 (`LICENSE`).

The configured cargo-vet peers have no exact `safe-to-deploy` audit for the
evaluated replacement graphs. Publisher-wide trust and wildcard audits are
not an alternative.

### Fork changes

`rustleaks-bzip2`:

- Returns structured errors where the upstream decoder used `unwrap`,
  `unreachable!` or input assertions.
- Uses an owned, safe, non-reflected CRC-32 in `src/crc.rs`.
- Checks each block CRC and the combined stream CRC in `src/block/mod.rs`.
  The combined CRC is updated only after a block CRC passes, with a
  rotate-left followed by XOR.
- `src/block/tests.rs` covers empty, single-block and multi-block streams,
  output chunk sizes, changed block and combined CRCs, and a truncated final
  CRC.

`rustleaks-rar-codec`:

- Keeps only the RAR3 and RAR5 decoder state machines (`src/codec/rar29.rs`
  and `src/codec/rar50.rs`). RAR1.3 and RAR2.0 are removed; RAR2 comes from
  `compcol`.
- Removes the container, writer, encryption, recovery, parallel and file
  system code, and every dependency.
- Adds checked arithmetic, fallible growth, Huffman checks, bounded RAR VM
  programs and filters, and output limits set by the caller.
- The RAR3 and RAR5 encoders are compiled only for tests, which encode data
  and decode it back. They stay in place so the code is easy to compare with
  upstream. `rustleaks-sources` calls only the RAR3 and RAR5 decoders and the
  `crc32` module.
- Container parsing, CRC checks, panic containment and archive limits stay in
  `rustleaks-sources`.

`rustleaks-sevenz`:

- Keeps only the reader and the selected decoders. Encoder, writer, file
  system and AES code is removed.
- `src/reader.rs` adds checked offsets and sizes, fallible allocation,
  bounded metadata and a memory limit set by the caller.
- `src/decoder.rs` keeps the coder graph private and checks it before any
  decoder is built.
- `tests/oracle_codecs.rs` holds direct codec fixtures.
- `rustleaks-sources` checks next-header ranges and declared sizes before
  parsing, applies archive limits during iteration and contains panics. The
  compressed 7z path is rejected under `panic=abort`.

The archive boundary is implemented in
`crates/rustleaks-sources/src/archive.rs` and tested in
`crates/rustleaks-sources/tests/archive_sources.rs` and the `archive` fuzz
target.

### Replacement criteria

Reevaluate only a released registry version. A new evaluation resolves the
dependency graph again; do not reuse an old resolution. Each rule below must
hold:

- It supports the workspace MSRV and all eight declared targets.
- It is a released registry crate, not a Git dependency.
- It stays outside `rustleaks-core` and keeps its types private.
- It keeps the required formats and error classes. An intended behavior
  change needs separate approval.
- It keeps every archive resource, cancellation, path, link and panic-policy
  control.
- It adds no encoder, file system, async runtime or unrelated API.
- Every unsafe block, build script, native library, C or C++ build, `links`
  key, proc macro and target-specific dependency is listed.
- It passes native tests for every claimed format.
- It passes the archive unit and corpus tests, the CLI corpus replay,
  panic-abort checks, fuzzing and resource-limit tests.
- It meets the license, notice and source policy.
- It passes cargo-deny, RustSec and cargo-vet. Run `just security` on its
  exact locked graph.
- It clearly reduces the owned fork code or maintenance work.

One clear failure is enough to reject a candidate. An early rejection does
not waive the rest of the review if the candidate is considered again.

### Replacing a fork

A replacement is a separate dependency change that needs approval. Name the
exact crate, version, source, checksum, features, graph, licenses, unsafe and
native inventory, MSRV and compatibility result. After approval:

1. Follow the build maintenance procedure and run `just deps-repin`.
2. Review all Cargo and Bazel lockfile changes.
3. Remove the old crate and its targets. Keep licenses and notices.
4. Run the dependency, archive, corpus, fuzz, panic-abort, native,
   clean-clone, package and release checks.

Archive support must not shrink without notice.

Draft upstream changes must not be submitted without separate approval.

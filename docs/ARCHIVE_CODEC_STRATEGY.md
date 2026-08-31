# Archive codec strategy

Status: observed 2026-08-31. This document records the current replacement
decision for the unpublished archive codec forks. It does not authorize a
dependency change, a reduction in archive behavior, or publication of a codec,
source, report, or CLI crate.

## Decision

No evaluated released package satisfies the complete Rustleaks archive
boundary. Retain the three private forks temporarily and pursue narrow upstream
changes. Reevaluate only a released registry version with an exact approved
dependency graph. The forks remain outside `rustleaks-core` and no codec type
enters a public API.

The current archive boundary is implemented by
[`rustleaks-sources`](../crates/rustleaks-sources/src/archive.rs). It enforces
depth, entry, member, cumulative expansion, spool, cancellation, path,
traversal, link, and panic-policy controls. The corresponding integration and
limit evidence is in
[`archive_sources.rs`](../crates/rustleaks-sources/tests/archive_sources.rs),
the [`archive` fuzz target](../crates/rustleaks-sources/fuzz/fuzz_targets/archive.rs),
and [`RESOURCE_LIMITS.md`](RESOURCE_LIMITS.md).

## Replacement criteria

A replacement must satisfy all of these conditions:

- support Rust 1.88 and all eight declared compile targets;
- be a released registry package, not a Git dependency;
- remain outside `rustleaks-core` and keep implementation types private;
- preserve the required formats and source-adapter error classifications, or
  identify an intentional behavior change for separate approval;
- preserve all archive resource, cancellation, path, link, and panic-policy
  controls;
- avoid adding encoder, filesystem, async-runtime, or unrelated product
  surfaces to the Rustleaks API;
- identify every unsafe block, build script, native library, C or C++ build,
  `links` declaration, proc macro, and target-specific dependency;
- pass Rust 1.88, native tests for every claimed family, archive unit and
  corpus tests, parity, panic-abort checks, fuzzing, and resource-limit tests;
- satisfy license, notice, source, cargo-deny, RustSec, and peer-first
  cargo-vet policy; and
- measurably reduce owned fork code or maintenance burden.

An early objective failure is enough to reject a candidate. It does not waive
the remaining review if that candidate is reconsidered later.

## Reproduction method

The retained source archives were read from Cargo's registry cache. Archive
SHA-256 values were checked directly. Each local tree digest was produced from
the sorted relative file names and individual SHA-256 values for every file in
the named crate directory. Mechanical source deltas use `git diff --no-index
--numstat` between the extracted registry `src` tree and the retained `src`
tree. RAR compares the two `src/codec` trees because the local crate is an
extraction, not a copy of the upstream container API.

Candidate graphs were resolved in isolated scratch packages with exact
versions and `cargo metadata --locked`. The dependency count excludes the
scratch root. The recorded lock digest is the SHA-256 of that generated
`Cargo.lock`. These lockfiles are evidence for this observation, not proposed
workspace lockfiles.

Configured peer evidence was checked in the Bytecode Alliance, Google, ISRG,
Mozilla, and Zcash cargo-vet audit files. Candidate evaluation did not query a
vulnerability advisory API. A future transaction must run the maintained
`just security` gate against its exact locked graph.

## Retained provenance and deltas

| Fork | Exact upstream source | Commit provenance | License and retained notice | Local tree SHA-256 | Mechanical source delta |
| --- | --- | --- | --- | --- | --- |
| `rustleaks-bzip2 0.1.2-rustleaks.1` | `bzip2-rs 0.1.2`, archive `beeb59e7e4c811ab37cc73680c798c7a5da77fc9989c62b09138e31ee740f735` | Cargo VCS record `359904e0132d10acfe0896b878efbf4b137a3e0a` | MIT or Apache-2.0; retained license hashes `a45da9aad6e4c77faac5b8be230daf2e2cab653b66e95b0f21e353116fed2da9` and `c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4` | `36016964862e6d5e294b55bec20028cebc099c65a298927e8988b741bde6263a` | 10 files, 250 additions, 173 deletions |
| `rustleaks-rar-codec 0.9.3-rustleaks.1` | `rars 0.9.3`, archive `68ff174e95890b9e1c01601a93f35f60c017162fb1bd723dfef9f684ae2ffdb6` | Registry archive commit `54e744d0e70998d1aea9b1ae8a9bc7eaecd127f3`; extraction commit `1f4f885577485d954c5e9a470a728d0111dc6f11`, whose codec tree is unchanged from the archive commit | MIT or Apache-2.0; retained upstream `COPYING` hash `e0db3404ecb210e185232f58c0f528bd403fe0e439ce869ffda80351cc561122` | `7bd1e53828c23527148f3bac546c48df926e6aa493bb6739ee3b33f5fa6a1e55` | 8 codec files, 481 additions, 6,164 deletions |
| `rustleaks-sevenz 0.20.2-rustleaks.1` | `sevenz-rust2 0.20.2`, archive `29225600349ef74beda5a9fffb36ac660a24613c0bde9315d0c49be1d51e9c24` | Cargo VCS record `424ebdb8fa98b78b8e1c18f73c9add6972fe5496` | Apache-2.0; retained license hash `c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4` | `3a060de28a59308491f5303476bf77c682fdef49f89c23aa5a07c75f1bf42796` | 28 files, 955 additions, 3,877 deletions |

The VCS record resolves the previously missing exact commit for
`sevenz-rust2 0.20.2`.

### BZip2

The local fork replaces decoder `unwrap`, `unreachable!`, and consumption
assertions on hostile input with structured errors. It replaces `crc32fast`
with the safe table-free non-reflected CRC in
[`crc.rs`](../crates/rustleaks-bzip2/src/crc.rs). It validates block CRCs and
the combined stream CRC in
[`block/mod.rs`](../crates/rustleaks-bzip2/src/block/mod.rs). The combined CRC
updates only after a block CRC succeeds and uses a rotate-left followed by XOR.

[`block/tests.rs`](../crates/rustleaks-bzip2/src/block/tests.rs) covers an
empty stream, single-block and multi-block streams, multiple output chunk
sizes, a changed final combined CRC, a changed block CRC, a truncated final
CRC, and the combination operation. Decoder error and streaming behavior are
covered beside the implementation and through the source archive tests.

The nonsemantic changes are crate naming, dependency removal, documentation,
formatting, and the Rust 1.88 workspace policy. The semantic changes are the
structured hostile-input failures, owned CRC implementation, and combined CRC
validation.

### RAR3 and RAR5

The local crate extracts the RAR3 and RAR5 codec state machines and removes
RAR1.3 and RAR2.0 support from this fork. RAR2 remains supplied separately by
the selected `compcol` decoder. It removes the upstream container, writer,
encryption, recovery, parallel, and filesystem dependency graph. The local
adapter is in [`lib.rs`](../crates/rustleaks-rar-codec/src/lib.rs), with the
retained state machines in
[`rar29.rs`](../crates/rustleaks-rar-codec/src/codec/rar29.rs) and
[`rar50.rs`](../crates/rustleaks-rar-codec/src/codec/rar50.rs).

The retained codec code adds checked arithmetic, fallible capacity growth,
Huffman validation, bounded RAR VM programs and filters, and caller-provided
output ceilings. No dependency or unsafe Rust remains in the local crate.
Container parsing, CRC validation, unwind containment, and archive-wide limits
remain owned by `rustleaks-sources`. Direct codec tests remain beside the state
machines, and archive behavior is exercised by the source integration and fuzz
targets.

Mechanical deletions account for most of the delta. The semantic delta is the
checked and bounded decoder behavior required by the source-layer contract.
Some upstream-derived encoder helpers remain only to keep the codec tests and
mechanical comparison tractable; they are not called by `rustleaks-sources`.

### 7z

The local fork removes encoder, writer, filesystem utility, and AES
implementation modules. It retains only the reader and selected decoder
surface. [`reader.rs`](../crates/rustleaks-sevenz/src/reader.rs) adds checked
offset and size composition, fallible allocation, bounded metadata retention,
and a caller-selected memory ceiling. [`decoder.rs`](../crates/rustleaks-sevenz/src/decoder.rs)
keeps the coder graph private. The selected pure Rust codec adapters are under
[`codec`](../crates/rustleaks-sevenz/src/codec.rs), with direct oracle fixtures
in [`oracle_codecs.rs`](../crates/rustleaks-sevenz/tests/oracle_codecs.rs).

The source layer preflights next-header ranges and declared sizes before
backend parsing, applies archive-wide limits during iteration, and contains
unwinds. The compressed 7z path is rejected under `panic=abort` because unwind
containment is then unavailable.

The nonsemantic changes are crate naming, visibility, documentation, and the
workspace policy. The semantic changes are surface removal, checked parser and
allocation behavior, coder-graph validation, controlled codec selection, and
resource integration.

## Current released candidates

| Need | Candidate and observation | Exact graph | Material boundary | Result |
| --- | --- | --- | --- | --- |
| BZip2 | `bzip2 0.6.1`, released 2025-10-16, Rust 1.82, archive `f3a53fac24f34a81bc9954b5d6cfce0c21e18ec6959f44f56e8e90e4bb7c346c`, commit `eebf6e470f6c4a14295fcaf43c619ae4a0e5690a` | Default features; 2 dependencies; lock `a687ecd3b0bf0c340d4196e5f7722f9b286396c1a4891bef7619c8ef26e1bd69` | Adds `libbz2-rs-sys 0.2.5`. Its chosen Rust allocator graph has no build script or `links`. A conservative source scan finds 134 `unsafe` tokens across four Rust files in its C ABI, raw-pointer, and allocation layer. Licenses are MIT or Apache-2.0 plus bzip2-1.0.6. | Reject. It replaces a safe bounded decoder with a larger unsafe boundary and lacks exact peer `safe-to-deploy` coverage. |
| RAR3/RAR5 | `rars 0.9.3`, released 2026-08-22, declared Rust 1.87, archive `68ff174e95890b9e1c01601a93f35f60c017162fb1bd723dfef9f684ae2ffdb6`, commit `54e744d0e70998d1aea9b1ae8a9bc7eaecd127f3` | No feature selection; 43 dependencies; lock `5f6445a4608eb9b30d5ccc0887862f49f5f9adba55ce90ea1ae6f105698ad28e` | Includes read, write, recovery, crypto, parallel, and filesystem surfaces. The resolved `aes 0.9.3` requires Rust 1.89. The graph includes build scripts, proc macros, and `links = "rayon-core"`. Top-level `rars` has no unsafe Rust, but its full dependency boundary is not the dependency-free decoder boundary. Licenses resolve to the MIT, Apache-2.0, Unicode-3.0, LGPL-2.1-or-later, and Unlicense expressions recorded by Cargo metadata. | Reject. The fresh graph fails Rust 1.88 and cannot select a decoder-only surface. |
| 7z | `sevenz-rust2 0.22.2`, released 2026-08-25, Rust 1.93, archive `cb967eb8b29410e61e8c9005058fcfd5889d0b827856beb25529c73dfc86a98a`, commit `b7e265168b67342194df332e1456c667476a6574` | No defaults plus `brotli,bzip2,deflate,lz4,zstd`; 45 dependencies; lock `bcb87858a6648735f9615375de9c9262ef9d851487ceb53ad8d370f102d35dce` | Top-level source has no unsafe Rust, but the selected graph includes build scripts, proc macros, and `zstd-sys 2.0.16+zstd.1.5.7` with `links = "zstd"` and bundled native code. Cargo metadata records Apache-2.0, MIT, BSD, Zlib, Unicode, LGPL, and bzip2 license expressions. | Reject. It fails Rust 1.88 and the selected codec set adds a native linked boundary. |
| 7z alternative | `sevenz-rust 0.6.1`, released 2024-07-17, Rust 1.70, archive `26482cf1ecce4540dc782fc70019eba89ffc4d87b3717eb5ec524b5db6fdefef`, commit `95c3b26f5b702c147a8d3fd33a34be0c85063693` | No defaults plus `bzip2,zstd`; 71 dependencies; lock `31bf31f20b6d367c169593c7058361e6d55f515eeeab3c5632a99be6bf238fcd` | The upstream repository is unavailable. The top-level reader uses unsafe raw-pointer calls. The graph includes `bzip2-sys` and `zstd-sys` build scripts, native code, and `links` declarations, and it cannot select the full required Brotli and LZ4 format set. | Reject. It lacks current source maintenance, required codecs, and the required safe and native-free boundary. |

### Exact candidate package sets

These are the complete package identities in each generated lock, excluding
only its scratch root. Target-specific packages remain listed because the
replacement criteria cover the complete declared target matrix.

`bzip2 0.6.1` default graph:

```text
bzip2@0.6.1, libbz2-rs-sys@0.2.5
```

`rars 0.9.3` graph:

```text
aes@0.9.3, aho-corasick@1.1.5, block-buffer@0.12.1, bumpalo@3.20.3,
cfg-if@1.0.4, cipher@0.5.2, cmov@0.5.4, const-oid@0.10.2,
cpubits@0.1.1, cpufeatures@0.3.1, crossbeam-deque@0.8.7,
crossbeam-epoch@0.9.20, crossbeam-utils@0.8.22, crypto-common@0.2.2,
ctutils@0.4.2, digest@0.11.3, either@1.18.0, getrandom@0.4.3,
hmac@0.13.0, hybrid-array@0.4.14, inout@0.2.2, js-sys@0.3.104,
libc@0.2.189, memchr@2.8.3, once_cell@1.21.4, proc-macro2@1.0.107,
quote@1.0.47, r-efi@6.0.0, rars@0.9.3, rayon-core@1.13.0,
rayon@1.12.0, rustversion@1.0.23, sha1@0.11.0, sha2@0.11.0,
syn@2.0.119, typenum@1.20.1, unicode-ident@1.0.24,
wasm-bindgen-macro-support@0.2.127, wasm-bindgen-macro@0.2.127,
wasm-bindgen-shared@0.2.127, wasm-bindgen@0.2.127, zeroize@1.9.0,
zeroize_derive@1.5.0
```

`sevenz-rust2 0.22.2` selected graph:

```text
adler2@2.0.1, alloc-no-stdlib@2.0.4, alloc-stdlib@0.2.4,
brotli-decompressor@5.0.3, brotli@8.0.4, bumpalo@3.20.3,
bzip2@0.6.1, cc@1.4.4, cfg-if@1.0.4, crc32fast@1.5.1,
find-msvc-tools@0.1.11, flate2@1.1.10, futures-core@0.3.34,
futures-task@0.3.34, futures-util@0.3.34, getrandom@0.4.3,
jobserver@0.1.35, js-sys@0.3.104, libbz2-rs-sys@0.2.5,
libc@0.2.189, lz4_flex@0.14.0, lzma-rust2@0.20.1,
miniz_oxide@0.9.1, once_cell@1.21.4, pin-project-lite@0.2.17,
pkg-config@0.3.34, proc-macro2@1.0.107, quote@1.0.47, r-efi@6.0.0,
rustversion@1.0.23, sevenz-rust2@0.22.2, shlex@2.0.1,
simd-adler32@0.3.10, slab@0.4.12, syn@2.0.119, twox-hash@2.1.4,
unicode-ident@1.0.24, wasm-bindgen-macro-support@0.2.127,
wasm-bindgen-macro@0.2.127, wasm-bindgen-shared@0.2.127,
wasm-bindgen@0.2.127, zlib-rs@0.6.7, zstd-safe@7.2.4,
zstd-sys@2.0.16+zstd.1.5.7, zstd@0.13.3
```

`sevenz-rust 0.6.1` selected graph:

```text
autocfg@1.5.1, bit-set@0.6.0, bit-vec@0.7.0,
block-buffer@0.10.4, bumpalo@3.20.3, byteorder@1.5.0,
bzip2-sys@0.1.13+1.0.8, bzip2@0.4.4, cc@1.4.4, cfg-if@1.0.4,
chrono@0.4.45, cpufeatures@0.2.17, crc-catalog@2.5.0, crc@3.4.0,
crypto-common@0.1.7, deranged@0.5.8, digest@0.10.7,
filetime@0.2.29, filetime_creation@0.2.0, find-msvc-tools@0.1.11,
futures-core@0.3.34, futures-task@0.3.34, futures-util@0.3.34,
generic-array@0.14.7, getrandom@0.4.3, jobserver@0.1.35,
js-sys@0.3.104, libc@0.2.189, lzma-rust@0.1.7, nt-time@0.8.1,
num-conv@0.2.2, num-traits@0.2.19, once_cell@1.21.4,
pin-project-lite@0.2.17, pkg-config@0.3.34, powerfmt@0.2.0,
proc-macro2@1.0.107, quote@1.0.47, r-efi@6.0.0,
rustversion@1.0.23, serde_core@1.0.229, serde_derive@1.0.229,
sevenz-rust@0.6.1, sha2@0.10.9, shlex@2.0.1, slab@0.4.12,
syn@2.0.119, syn@3.0.4, time-core@0.1.9, time-macros@0.2.32,
time@0.3.55, typenum@1.20.1, unicode-ident@1.0.24,
version_check@0.9.5, wasm-bindgen-macro-support@0.2.127,
wasm-bindgen-macro@0.2.127, wasm-bindgen-shared@0.2.127,
wasm-bindgen@0.2.127, windows-sys@0.52.0, windows-targets@0.52.6,
windows_aarch64_gnullvm@0.52.6, windows_aarch64_msvc@0.52.6,
windows_i686_gnu@0.52.6, windows_i686_gnullvm@0.52.6,
windows_i686_msvc@0.52.6, windows_x86_64_gnu@0.52.6,
windows_x86_64_gnullvm@0.52.6, windows_x86_64_msvc@0.52.6,
zstd-safe@7.2.4, zstd-sys@2.0.16+zstd.1.5.7, zstd@0.13.3
```

The named versions were the newest crates.io releases on 2026-08-31. The
original `bzip2-rs 0.1.2` was still its newest release. The `rars` repository
had no open issues, but the package still offered no decoder-only feature.
`sevenz-rust2` issue
[#65](https://github.com/hasenbanck/sevenz-rust2/issues/65) tracked a Rust
native Zstandard alternative. The `bzip2` repository issue
[#40](https://github.com/trifectatechfoundation/bzip2-rs/issues/40) tracked a
pure Rust implementation. Neither had produced a qualifying release.

### Peer-first cargo-vet disposition

The configured peers provide no exact `safe-to-deploy` path for these
candidate graphs. Google records `bzip2 0.6.1` under its `ub-risk-2` criterion,
which is not mapped to Rustleaks `safe-to-deploy`. ISRG records
`libbz2-rs-sys 0.1.1`, not candidate version 0.2.5. Google records an older
`zstd-sys 2.0.9+zstd.1.5.5` under different criteria. No configured peer record
was found for the exact `rars`, `sevenz-rust2`, or `sevenz-rust` candidates.
Publisher-wide trust and wildcard audits are not alternatives.

## Upstream-ready work

These are draft scopes. They must not be submitted without separate approval.

### BZip2 patch draft

Title: `return structured decoder errors and validate the combined stream CRC`

Problem statement:

- hostile input can reach internal panic assertions in `bzip2-rs 0.1.2`;
- the decoder validates block CRCs but not the stored combined stream CRC; and
- the relevant state and transitions are private, so downstream wrapping
  cannot implement the missing validation.

Proposed patch:

1. replace reachable input-dependent assertions, `unwrap`, and
   `unreachable!` paths with the existing decoder error flow;
2. retain a stream `combined_crc`, initialized to zero;
3. after each validated block, update it with
   `combined_crc.rotate_left(1) ^ block_crc`;
4. compare the stored final CRC before completing the stream; and
5. add the empty, single-block, multi-block, chunking, corrupt-block,
   corrupt-final-CRC, truncated-final-CRC, and combine-operation tests listed
   in the BZip2 section.

The smallest reference implementation and tests are the linked local block,
CRC, decoder, and test files. Preserve upstream authorship and dual licensing
when preparing the actual patch.

### RAR issue and patch draft

Title: `provide a decoder-only feature or package for RAR3 and RAR5 codecs`

Problem statement:

The released package has no feature boundary between decoding and writer,
recovery, encryption, parallel, and filesystem functions. A consumer that
accepts hostile archive bytes cannot select the decoder state machines without
the unrelated graph. Fresh resolution also exceeds the consumer's Rust 1.88
policy through a transitive dependency.

Proposed upstream shape:

1. move RAR3 and RAR5 codec state machines and shared filters into a
   dependency-free decoder package or feature;
2. keep container I/O, filesystem extraction, writer, recovery, encryption,
   and parallel features outside that package;
3. make output and VM/filter ceilings caller-selectable and use fallible
   allocation and checked arithmetic;
4. preserve the current decoder tests and add hostile Huffman, VM/filter,
   truncation, and output-limit cases; and
5. publish a release whose exact feature graph supports Rust 1.88.

The local adapter and codec files provide the mechanical extraction and test
material. An upstream patch should minimize or eliminate the retained encoder
helpers rather than copying the local crate wholesale.

### 7z issue and patch draft

Title: `offer a Rust 1.88 decoder-only profile with checked parser limits`

Problem statement:

The current release requires Rust 1.93. The feature set needed for Rustleaks'
formats selects a native linked Zstandard implementation, while the retained
fork uses a private decoder-only surface with checked parser and allocation
behavior.

Proposed upstream shape:

1. provide a decoder-only profile without writer, filesystem utility, async,
   or encoder APIs;
2. preserve a Rust 1.88-compatible release line while it remains supported;
3. allow pure Rust Brotli, BZip2, Deflate, LZ4, LZMA/LZMA2, XZ, and Zstandard
   decoder selection without a `links` dependency;
4. make next-header, block, metadata, allocation, and coder-graph ceilings
   explicit and fallible; and
5. add the existing oracle codec cases plus preflight, malformed graph,
   allocation, panic-abort, and archive-wide resource tests.

The local reader, decoder, codec adapters, oracle tests, and source archive
tests are the patch reference. The current upstream issue for a native Rust
Zstandard alternative should be resolved in a released version before this
profile can qualify.

## Future replacement transaction

Any replacement is a separate approval-bound dependency transaction. It must
name the exact crate, version, source, checksum, features, graph, licenses,
unsafe and native inventory, MSRV, and compatibility result. After approval,
use the build-maintenance procedure and `just deps-repin`, inspect all Cargo
and Bazel lockfile changes, remove the obsolete owned crate and targets, retain
licenses and notices, and run the complete dependency, archive, parity, fuzz,
panic-abort, native, clean-clone, package, and release gates. Archive scope may
not be reduced silently.

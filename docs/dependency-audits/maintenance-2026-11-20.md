# Dependency maintenance review, 2026-11-20

Review date: 2026-11-20. Reviewer: Claude Code.

## Evidence and scope

The registry archives for the old and new locked versions were downloaded
from crates.io and matched against their Cargo checksums before review. Every
member of each new archive is a regular file. The review covered changed
production Rust, manifests, build scripts, licenses, features, unsafe code,
target gates, and the Rustleaks call sites. Packaged test and tooling changes
were inspected for their role; this record does not claim execution of
upstream test suites. The local delta records extend the existing full and
delta audits. They do not repeat a full review of unchanged source.

The cached cargo-vet peer imports cover none of these versions. A fresh peer
query was not made.

No new native dependency, `links` declaration, build script, or proc macro is
introduced. No selected code adds unsafe Rust. Every license file is
byte-identical to the previous version, and the declared licenses are
unchanged. Declared Rust versions are unchanged: `compcol` 1.95, `toml`,
`toml_datetime` and `serde_spanned` 1.85, `lz4_flex` 1.81, and `flate2`
1.67. Brotli still declares no MSRV; its normalized manifest now states the
implied 2015 edition. All versions compile with the pinned Rust 1.95.0
toolchain under Bazel.

## Reviewed deltas

| Package | Versions | Security-relevant review |
| --- | --- | --- |
| `brotli-decompressor` | 6.2.0 to 6.3.2 | Bit reader rewritten to the C layout with masked shifts and checked loads; padded lookup tables, fixed Huffman table windows, and metablock buffer reuse replace panicking indexes. Selected `std` code still forbids unsafe. |
| `flate2` | 1.1.10 to 1.1.11 | Write-side decoders reject truncated streams at `finish`; `reset` drains instead of finishing; partial writes no longer shift buffered output; gzip encoder reports header progress before input errors. The miniz_oxide reset clears the dictionary. |
| `lz4_flex` | 0.14.0 to 0.14.2 | One loop bound in the unsafe decoder uses `offset_from` instead of forming a pointer past the end. That module is not compiled with `safe-decode`. |
| `serde_spanned` | 1.1.2 to 1.1.3 | Adds an exact `size_hint` to the span map access; no other production change. |
| `toml` | 1.2.0+spec-1.1.0 to 1.2.1+spec-1.1.0 | Array and table deserializers report the remaining parsed item count as `size_hint`; dependency floors move to the reviewed `serde_spanned` and `toml_datetime`. |
| `toml_datetime` | 1.1.2+spec-1.1.0 to 1.1.3+spec-1.1.0 | Adds an exact `size_hint` to the datetime map access; no other production change. |
| `compcol` | 0.7.8 to 0.8.0 | Selected RAR2 decoder now streams output from a fixed window and buffered input. Covered by the standing exemption, not an audit. See below. |

## Brotli

Rustleaks selects only `std` and uses the streaming `Decompressor` reader in
`rustleaks-sevenz` and the archive adapter. The `unsafe`, `ffi-api` and
`seccomp` features stay unselected, so the crate root keeps
`forbid(unsafe_code)`.

The bit reader now keeps unread bits right-aligned with a count of valid
bits, as the C decoder does. Every variable shift is masked to the register
width or bounded by the refill condition. 16-bit loads and single-byte pulls
use checked slice access with a zero or `false` fallback. A new slice-based
reader for the command loop matches fixed-size slice prefixes before each
refill, and its 32-bit split reads stay within 16 bits per refill. The block
length and command tables are padded to 32 and 1024 entries so masked
indexes cannot leave the table; padding entries are entry 0 and valid
Huffman tables never produce them.

Huffman lookups in the command loop go through fixed-size windows. Tree
group decoding reserves the alphabet's maximum table size past each tree,
and a missing or out-of-range tree resolves to a static all-zero table. The
codes buffer grows through the allocator and copies the trees already built.
Context maps, context modes and tree groups are now kept across metablocks
of one stream and reused when large enough; tree offsets past the current
count are set to `u32::MAX`, and single-tree context maps zero exactly the
used prefix. Stale entries can only come from an earlier metablock of the
same stream. Ring buffer copies keep their length checks against the
allocation slack. Compound and shared dictionary copies use checked
subslices.

The one-shot `brotli_decode` now limits its first ring buffer from the
output size hint to four times the decoded size. Rustleaks does not use the
one-shot API. FFI changes (fallible state allocation, `drop_in_place`, a
version constant checked at compile time, and `ManuallyDrop` memory blocks)
are behind the unselected `ffi-api` feature. Rustleaks keeps its large-window
rejection and output budgets.

## flate2

Only `xtask` depends on `flate2`, with default features disabled and
`miniz_oxide` selected. It builds and reads release gzip archives. The
selected backend change replaces the miniz_oxide decompressor reset with a
full reset, so a reused decoder cannot match against the previous stream's
dictionary. The write-side `zio::Writer` gains a finished flag and a buffer
cursor. Encoder `finish` stops at stream end, and decoder `finish` returns
`UnexpectedEof` when no more output appears before stream end. The write
retry loop no longer spins when the codec consumes no input and produces no
output.

The C and zlib-rs backends now keep window bits and gzip mode across reset.
The zlib-rs backend adds uninitialized output paths and raises its optional
floor to zlib-rs 0.6.7. Neither backend is selected, and no C compiler or
native library enters the graph.

## lz4_flex

Rustleaks selects `checked-decode`, `frame`, `safe-decode`, `std` and, in
`rustleaks-sources`, `safe-encode`. With `safe-decode` the crate compiles
`decompress_safe` under `forbid(unsafe_code)` and does not compile the
changed `block/decompress.rs`. The change there replaces a comparison that
formed `output_ptr.add(1)` with `offset_from`. The `nightly` feature no
longer enables `optimize_attribute`; it is unselected.

## TOML family

`rustleaks-core` parses configuration through `toml` with default features.
The new `size_hint` values equal the count of items already parsed into
memory, so a visitor that preallocates from them cannot allocate more than
the parsed document holds. Serde also caps its own preallocation. Each
iterator is a `vec::IntoIter` or the crate's map iterator, both with an
exact length.
The three crates still forbid unsafe Rust.

## compcol

`compcol 0.8.0` is a semver-breaking release. Rustleaks uses only
`rar2::Decoder::with_unpack_size`, the `Decoder` trait's `decode` and
`finish`, and `Status`, through a generic adapter. Those items keep their
signatures. The trait gains `set_output_limit` with a default body, and a
new `ContiguousDecoder` trait is implemented only by LZMA, XZ, LZMA2 and
Zstandard. `bazelisk build //crates/rustleaks-sources/...` succeeds, and the
archive unit, semantics, sources, streaming and stress test targets pass,
including `extracts_rar2_repeat_match_followed_by_old_offset`.

The registry archive is 2,417,598 bytes with SHA-256
`f4be160df80e77bdf4902bb026c6a0f6c700ec7793379c26305d45e293e17b8c`. Its 397
members are regular files; only `tools/embed-crosscheck.sh` is executable.
The VCS record names upstream commit `e26808238313877b7e628a9b6459c542c5c25f3d`.
Source identity against that upstream tree was not checked in this review.

The selected `alloc` and `rar2` build compiles `error`, `traits`, `limit`,
`vec` and `rar2`. `rar2/audio.rs`, `huffman.rs` and `tables.rs` are
unchanged. Shared changes add the advisory output limit, forward it from
`LimitedDecoder`, and make the vector helper fail on a stalled encoder
instead of looping. The selected graph still has no normal dependency,
build script, native code, `links`, or target-specific edge. A new optional
`memmap2` dependency serves only the CLI binary behind the unselected `mmap`
feature, and it is not in the lockfile. The package lint changes from
`forbid` to `deny` for that binary; the library root keeps
`#![forbid(unsafe_code)]`, and no library source contains unsafe code.

The RAR2 decoder no longer decodes the whole member into an internal vector
at `finish`. It now:

- accepts all input in `decode`, decodes while fewer than 64 KiB are
  waiting, and hands bytes out from both `decode` and `finish`;
- keeps waiting bytes in the fixed 1 MiB window; a compile-time assertion
  keeps the 64 KiB limit plus the longest 260-byte match below the window
  size;
- caps every match at the declared size, so output stops exactly at
  `unpack_size`;
- rewinds the bit reader when a step runs out of input, and reads each
  block header into a copy of the length table that is committed only after
  its trees build;
- drops consumed input once at least 4 KiB and half the buffer are behind
  the reader, rebasing the reader by exactly that count;
- reports an error after the bytes decoded before it are handed out, and
  poisons the decoder; and
- rejects input when no unpack size was set.

Memory held for output no longer grows with the declared size. Buffered
input still grows with the compressed member; the adapter bounds that by its
spool and member limits. The adapter already handled output from `decode`,
`StreamEnd` from `decode`, and an exact final length, so it needs no change.

The upstream changelog lists a 0.7.9 security pass covering hangs, CPU use,
limit bypasses and integrity gaps, and the 0.8.0 diff corrects many 32-bit
`usize` overflows in unselected codecs, among them Brotli, BWT, bzip2,
Huffman, LZFSE, LZMA, Quantum, the range coder, RAR5, SIT13, Snappy and ZIP
reduce. The 0.7.8 record does not name the codec that held the earlier
32-bit availability concern. This review covered the selected code and
shared API, not every unselected codec in a diff of about 44,000 lines.
It cannot confirm that the concern is gone. The bzip2 notice discrepancy in
the [0.7.8 review](compcol-0.7.8.md#license-scope) is unchanged: the archive
still has only the MIT `LICENSE`, with SHA-256
`a7009ce74b33a2afcf9ab38007bf3c8f5020d9b816dc5fc7296bf17e6d7dc796`.

A full audit is therefore not recorded. The standing exemption moves to
0.8.0 with the same scope: exactly `alloc` and `rar2`, the eight maintained
64-bit targets, outside the core graph, and no redistribution of unselected
codec sources. The vet check constants in `crates/xtask/src/security.rs` now
name 0.8.0 and its archive checksum. Reopen this decision under the existing
conditions.

## Validation boundary

`cargo vet --locked` passes with these records and the moved exemption.
The cargo-geiger package list now names `brotli-decompressor@6.3.2` and
`lz4_flex@0.14.2`; a new cargo-geiger run was not made for this review.
Source review does not replace the format, build, lint, test, package,
advisory, parity, or target checks for the integrated change.

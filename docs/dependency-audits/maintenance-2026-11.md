# Dependency maintenance review, November 2026

Review date: 2026-11-04. Reviewer: OpenAI Codex.

## Evidence and scope

The registry archives for the old and new locked versions were compared
against their Cargo checksums before review. The review covered changed
production Rust, manifests, build scripts, licenses, features, target gates,
and the adapter call sites. Packaged test and tooling changes were inspected
for their role; this record does not claim execution of upstream test suites.
The local delta records extend the existing full audits. They do not repeat a
full review of unchanged source.

The configured cargo-vet peers were queried first. Their evidence covers
`tinyvec 1.13.3` and `cpufeatures 0.3.1`; the `libc` delta starts at the
peer-covered `0.2.190`. The other new records cover the remaining deltas.
Owned `rustleaks-core` is explicitly marked `audit-as-crates-io = false`:
its workspace source is not the registry package with the same name.

No new native dependency, `links` declaration, build-script authority, or
dependency type in the public core API is introduced. Core semver ranges and
Rust 1.88 remain unchanged. `thiserror` now declares Rust 1.77 and `sha2`
Rust 1.88. Brotli does not declare an MSRV, so its compatibility requires the
maintained compile checks rather than a metadata claim.

## Reviewed deltas

| Package | Versions | Security-relevant review |
| --- | --- | --- |
| `alloc-no-stdlib` | 2.0.4 to 3.0.0 | C allocator API moves behind the explicit unsafe feature; default code forbids unsafe. |
| `alloc-stdlib` | 0.2.4 to 0.3.0 | Allocator dependency generation changes; production allocator implementation is unchanged. |
| `bitflags` | 2.13.1 to 2.13.2 | Generated constant placement fixes a compiler error; no new unsafe implementation. |
| `brotli-decompressor` | 5.0.3 to 6.2.0 | Checked stream spans, ring offsets, block types, allocation results, and malformed lengths; shared-dictionary and FFI changes reviewed separately below. |
| `cfg-if` | 1.0.4 to 1.0.5 | Documentation and metadata changes; macro implementation is unchanged. |
| `crc32fast` | 1.5.1 to 1.5.4 | Vector loads now bounds-check slices; ARM input conversion no longer uses `align_to`; CPU-feature dispatch remains guarded. Scalar and ARM parallel checksum algebra and partial-word packing were inspected. |
| `equivalent` | 1.0.2 to 1.0.3 | Trait-contract documentation; implementation is unchanged. |
| `flate2` | 1.1.9 to 1.1.10 | Zero-progress gzip writes now fail; oversized extra fields are rejected; incomplete deflate input returns an error. Reset and optional backend changes preserve ownership. |
| `hybrid-array` | 0.4.14 to 0.4.15 | Adds the U513 length implementation; existing unsafe implementation is unchanged. |
| `indexmap` | 2.14.0 to 2.14.2 | Disjoint mutable references are created only after full bounds and uniqueness checks; index assertions and initialization macros preserve those invariants. |
| `libc` | 0.2.190 to 0.2.191 | ABI additions and corrected platform layouts; Emscripten build detection changes; no new safe wrapper authority. |
| `lzma-rust2` | 0.20.0 to 0.25.0 | Fallible incremental dictionary growth, stricter stream completion, streamed XZ indexes, checked BCJ2 spans, and bounded worker-pool changes; decoder, encoder, and optional paths were reviewed. |
| `rawzip` | 0.5.1 to 0.5.2 | Checked archive-offset addition, bounds before narrowing, terminal iterator errors, and saturating timestamp conversion. |
| `rustix` | 1.1.4 to 1.1.6 | Corrected zero-length xattr queries, checked ancillary-message lengths and whole descriptors, padding representation, 32-bit UID syscalls, terminal ioctl arguments, and checked timespec carry. |
| `serde_json` | 1.0.151 to 1.0.154 | Invalid UTF-8 errors use the first invalid byte, negative zero and finite f32 handling are corrected. New optional no-std preserve-order hashing is outside the selected graph. |
| `serde_spanned` | 1.1.1 to 1.1.2 | Production Rust is unchanged; packaging and lint changes. |
| `syn` | 3.0.4 to 3.0.9 | Lifetime/operator parsing and `Punctuated::retain` changes use checked safe operations; unsafe implementation is unchanged. |
| `thiserror`, `thiserror-impl` | 2.0.20 to 2.0.21 | Turbofish formatting/parser correction; no new build-script behavior or authority. |
| `toml` | 1.1.4 to 1.2.0 | Numeric ownership, duplicate-key rejection, and serializer insertion changes; insertion offsets are derived from UTF-8 string lengths and applied in reverse order. |
| `toml_datetime` | 1.1.1 to 1.1.2 | Production Rust is unchanged; packaging and lint changes. |
| `toml_parser` | 1.1.3 to 1.1.5 | Lexer capacity is capped to representable token storage; unchecked whitespace/comment/newline access is removed. |
| `toml_writer` | 1.1.2 to 1.2.0 | New fast path accepts only ASCII characters that do not require escaping; quotes, backslashes, and control bytes retain escaping. |
| `twox-hash` | 2.1.4 to 2.1.5 | XXH3 assertions follow checked private dispatch and secret-length bounds; selected XXH32 source is unchanged. |
| `unicode-ident` | 1.0.24 to 1.0.27 | Unicode 18 generated identifier tables and dual lookup bases; an independent bounds check verified both tables and zero fallback chunks. These are macro identifiers, not the regex Unicode tables. |
| `winnow` | 1.0.4 to 1.0.5 | Lint/lifetime refactors and bounded usize hex parsing; unsafe implementation is unchanged. |
| `xattr` | 1.6.1 to 1.7.0 | Sizing uses explicit rustix query APIs instead of zero-length output buffers. |
| `zstd-zero` | 0.1.0 to 0.2.1 | Entropy storage moves to checked caller-owned buffers; counters are bounded by validated table sizes and reset before reuse. Strict Huffman literal completion is enabled by default. |

TOML-family versions retain their `+spec-1.1.0` metadata in the lock and audit
records. The affected Apache license files replace an example copyright
placeholder with contributor attribution; license terms are unchanged.
Other reviewed license texts are unchanged.

## Compression feature boundaries

Brotli's selected `std` implementation still forbids unsafe Rust. Its new
serialized-dictionary parser bounds list counts and byte spans. Safe borrowed
dictionary APIs require static storage; the opt-in FFI retains an explicit
caller lifetime contract and uses checked spans and fallible allocation.
The FFI, unsafe, seccomp, and standalone dictionary-file CLI paths are not
selected. Rustleaks retains its large-window header rejection and output
budgets; the upstream constructor alone is not a bounded-resource guarantee.

`flate2` selects `miniz_oxide` explicitly with default features disabled.
This preserves the pure-Rust compression backend. Upstream now requires
`miniz_oxide 0.9.1` with SIMD checksum support, so the separate 0.8.9 instance
disappears. The miniz default feature enables only allocation. Its SIMD
feature selects the already audited `simd-adler32 0.3.10`, whose source is
unchanged. The safe slice adapter, compile-time CPU dispatch, and scalar
fallback were checked against that existing audit. Cargo's sources-only
graph does not select SIMD; Bazel's workspace feature union does. The latter
therefore includes the reviewed SIMD checksum boundary in archive builds.
Neither path introduces a C compiler or native library. Flate2's optional
runtime-detection feature is not enabled by this declaration.

LZMA keeps optimization disabled and forbids unsafe in the selected feature
graph. The new buffered reader can discard unread input through `into_inner`;
Rustleaks does not use that recovery API. LZIP retains concatenated-member
handling through the new explicit constructor argument. The source adapter
sets sevenz's thread count to one. The upstream raw LZMA2 and XZ multithreaded
readers retain their separate older schedulers, out-of-order buffers, and
detached shutdown behavior; worker-pool improvements do not cover those APIs.
Some metadata, output, and preset allocations remain infallible. Existing
adapter limits remain necessary, and the review does not claim universal
allocation-failure recovery or bounded resources for every upstream API.

Zstandard adapter allocations remain fallible and keep the existing history,
block, literal, and output limits. The additional entropy storage has fixed
sizes supplied by the decoder constants. Both adapters use the strict default
constructor; malformed truncated literal streams are not silently padded.

`compcol 0.6.10` is retained. Its selected RAR2 implementation is byte-identical
to 0.7.3, while that release adds unrelated embedded codecs. The retained
version avoids expanding the audit scope without a selected-code security
benefit. Later releases require a newer Rust toolchain. This is not a claim
that every dependency is at its newest published version.

## SHA-2 exception resolution

`sha2 0.11.1` resolves the RISC-V concern in the prior
[complete-source review](runtime-sha2-exception.md). The complete production
delta, including all architecture backends, was reviewed against that
baseline. The workaround that formed an out-of-bounds aligned pointer is
removed from both RISC-V hash implementations. ARM64 vector loads now derive
their pointers from the complete block slice. The remaining x86 loads retain
their slice-length and detected CPU-feature preconditions. No new dependency,
build script, native link, or external authority is added.

The fixed release receives a version-specific local audit and replaces the
temporary 0.11.0 exemption. This does not claim native RISC-V execution or
re-execution of the prior review's test suite.

## Validation boundary

The dependency locks are regenerated through `just deps-repin`. A focused
cargo-geiger 0.13.0 run on the all-feature source package returned complete
metrics and the same 23 common plus two host-specific unsafe-bearing package
names, with the reviewed version changes. All five owned crate roots in that
graph reported zero used unsafe and `forbids_unsafe = true`.

Source review and inventory do not replace final format, build, lint, test,
package, advisory, cargo-vet, parity, or target validation. Those gate outcomes
must be recorded separately for the integrated candidate.

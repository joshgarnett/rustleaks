# compcol 0.7.8 dependency review

Review date: 2026-11-05. Baseline: the
[0.6.10 audit](runtime-compcol-batch-39.md).

## Source and graph

The registry archive is 2,020,899 bytes with SHA-256
`7a9657f9d47c2bc36be681f158d208f40bafdd1c8c32003dac8e7dfe0cb68a97`.
Its 386 members are regular files: 385 have mode `0644` and the optional
`tools/embed-crosscheck.sh` has mode `0755`. The package VCS record identifies
[upstream commit d01ed4e1](https://github.com/KarpelesLab/compcol/tree/d01ed4e1e5e7764fc602a2a20266aa214fe89d02).
All 382 project members match that tree byte for byte. The four expected
packaging additions or replacements are normalized `Cargo.toml`, `Cargo.lock`,
`.cargo_vcs_info.json`, and `Cargo.toml.orig`; the original manifest matches
the upstream manifest. This establishes source identity, not signed provenance.

Registry metadata declares Rust 1.95 and MIT and reports the version as not
yanked. Fresh Bytecode Alliance, Google, ISRG, Mozilla, and Zcash audit files
contain no compcol coverage. The dependency remains exact-pinned with default
features disabled and only `rar2`, which enables `alloc`. It remains outside
the publishable core graph on all eight maintained targets.

The selected graph has no normal transitive dependency, build script, native
code, `links`, proc macro, or target-specific edge. Optional Tokio remains
unselected; the new `lzfse_rust` dependency is development-only. The crate root
and manifest still forbid unsafe Rust, and the production source introduces
no unsafe block or declaration. No new file, network, process, thread,
environment, or global-state authority enters the selected library.

## Selected behavior and controls

The RAR2 production delta changes only `rar2/decoder.rs`:

- Repeat-last-match symbol 256 now commits its offset to the recent-offset
  ring before emitting the match. A later old-offset symbol therefore sees
  the correct history.
- Initial output reservation is capped at 64 MiB. Actual decoded output may
  grow beyond that cap, and allocation remains infallible. This is an initial
  reservation limit, not a memory budget or an OOM-recovery guarantee.

Shared changes add `Error::NeedDictionary`, stop `discard_output` at stream
end, and make the allocating one-shot helper drain buffered output after
input exhaustion. Rustleaks uses the RAR2 decoder's `decode` and `finish`
methods, not the discard or one-shot helpers. Its public API exposes no
compcol implementation types.

The adapter still checks member size before constructing the decoder, bounds
archive spooling, checks cancellation between calls, validates progress and
exact output length, and verifies member CRC before emitting bytes. Default
compressed-input and output limits are each 64 MiB. Dependency input/output
copies and the fixed 1 MiB window remain additional memory costs; callers
that raise archive limits can increase those costs. Cancellation does not
interrupt one synchronous codec call.

## Broader production delta

Review includes changed production bodies and their surrounding invariants,
including code excluded by the Rustleaks feature selection:

- Bzip2 block sorting, incremental symbol decoding, randomized-block table,
  concatenated streams, permissive Huffman tables, and encoder flushing.
  Block sizes remain bounded by the format; Huffman lookup still rejects
  invalid decoded indices after removing the earlier complete-tree rule.
- Brotli resumable meta-block state, LHA adaptive and static Huffman changes,
  the new LZF codec, BCJ transforms, legacy ZIP raw constructors, RAR3/5,
  LZX, and finish/drain corrections. Checks cover resumable cursors, bounded
  tables, match distances, output lengths, resets, and error propagation.
- LZMA ZIP framing, LZMA2 dictionary resets and window arithmetic, XZ filter
  chains and checksums, and Zstd history/window limits. XZ verifies CRC32,
  CRC64, and SHA-256 checks but still accepts unsupported check identifiers
  without verification; this is not a general integrity guarantee.
- HPACK/QPACK decoded-header limits, allocating helpers, factory dispatch,
  synchronous I/O retry state, and Tokio progress/flush handling. Header caps
  do not imply a bound on every temporary literal allocation. Optional I/O
  and command-line authority remains confined to explicitly selected APIs.
- Deflate/Deflate64 tables, encoder strategy and dictionary handling, moved
  gzip/zlib implementations, shared checksums and bit helpers, embedded
  codecs, LZFSE, and PPMd8/ZIP. PPMd's header bounds its model arena, uses
  fallible arena reservation, and guards arena accesses and allocator walks;
  other small allocations retain ordinary allocator behavior.

Embedded gzip intentionally skips header CRC verification, and its history
can span concatenated members. Payload CRC and size checks remain, and
references stay within previously produced output. These are format and
integrity limitations; they do not establish a memory or data-isolation
failure. Embedded codecs are not selected by Rustleaks.

Source review does not establish complete format parity or universal bounded
allocation for every optional codec. Enabling another codec or redistributing
additional dependency source requires review of that actual boundary.

## License scope

The MIT `LICENSE` is unchanged, with SHA-256
`a7009ce74b33a2afcf9ab38007bf3c8f5020d9b816dc5fc7296bf17e6d7dc796`.
There is an upstream notice discrepancy outside the selected code:
`bzip2/bwt.rs` identifies a faithful port of bzip2 1.0.8 `blocksort.c`, and
`bzip2/decoder.rs` attributes its randomization table to `randtable.c`.
The [official bzip2 1.0.8 source archive](https://sourceware.org/pub/bzip2/bzip2-1.0.8.tar.gz)
requires source redistributions to retain its copyright notice, conditions,
and disclaimer. The compcol archive contains the copyright attribution but
does not include those full license terms. Its MIT metadata alone does not
resolve this discrepancy.

That bzip2 module is excluded by the maintained `alloc,rar2` selection.
Rustleaks uses its own bzip2 dependency, and its release archive constructor
includes only the CLI binary, root `LICENSE`, `NOTICE`, and `README.md`.
The core package excludes compcol entirely. Neither output redistributes
the affected compcol source or compiled module. Before distributing that
source or enabling that feature, obtain corrected upstream notices or retain
the required bzip2 terms and modified-source attribution after license review.
This review neither relabels the port MIT nor waives a license requirement.
Cargo-vet's security criterion is separate from this distribution analysis.

## Focused evidence

The synthetic adapter regression
`extracts_rar2_repeat_match_followed_by_old_offset` exercises a short match,
another offset, repeat-last-match, then an older-offset reference. Under
Rust 1.95.0, the isolated exact adapter test fails with 0.6.10 at its CRC
check and passes with 0.7.8. The pinned Go `rardecode/v2 2.2.0` decoder returns
the same member name and 12 output bytes. The generated 175-byte archive has
SHA-256 `d2bb2276c1f8c6a96b34f3660ad82f01ea865264e211c33229c66ac421a550db`.
It contains only synthetic data and is generated by the test, not copied
from an upstream fixture.

The previous version's full suite and fuzz results are baseline evidence
only; they are not reported as executions of 0.7.8. Repository validation is
reported separately for the integrated toolchain and dependency change.

## Disposition

The selected RAR2 source review and focused regression support the intended
behavior change. Package-wide `safe-to-deploy` certification is withheld:
review identified an unresolved availability concern outside the maintained
feature and target selection. The approved standing exemption in
`supply-chain/config.toml` records this gap without a calendar expiry. No local
full or delta audit certifies the package.

The exemption is specific to registry version 0.7.8 and its reviewed archive.
The vet gate requires exactly `alloc` and `rar2` in the resolved workspace and
Bazel graphs, the eight maintained 64-bit targets, and absence from the core
graph with every core feature enabled. Existing package and release-archive
contracts keep unselected codec sources outside distributed artifacts. This
decision does not authorize redistributing those sources.

Reopen review before changing the version, source, features, targets,
consumers, or source-distribution boundary, and on new audit or advisory
evidence. Replace the exemption when an upstream fix and qualifying audit
provide the required coverage. Feature exclusion establishes current
reachability; it does not narrow cargo-vet's package-level exemption semantics.

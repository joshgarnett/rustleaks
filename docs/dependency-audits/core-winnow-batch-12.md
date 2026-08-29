# Core dependency audit: Winnow batch 12

Review date: 2026-08-29.

Locked graph baseline: Rustleaks commit
`056bbc5ae35118040b56426cd18ab1a873f94fe0`, with `Cargo.lock` SHA-256
`e3c24453ec42115d43dd5b2b679e43cdb6e1b0802393932d3ae199db2e502d82`.
The lockfile is unchanged by this audit batch.

The package is a normal dependency reachable from the publishable core and
all five other workspace consumers. Its exact consumers, selected features,
target expressions, build-script status, `links` value, checksum, and
cargo-vet disposition are in `supply-chain/inventory-v1.json`. It applies to
every declared target, has no build script or `links` value, and selects no
features or dependencies. The source archive came from the crates.io registry
source recorded in `Cargo.lock`.

The review covered all 40,330 lines of packaged Rust source under `src`, 5,948
lines of packaged Rust examples, manifests, package lockfile, README, VCS
metadata, license, tests, documentation, and every selected and unselected
feature branch. Cargo-vet estimated 47,156 lines for the complete audit. A
fresh RustSec check at advisory database commit
`6420e39260b3d771b049954cf5d52b57e2118da4` found no vulnerability or warning
in the exact 71-package Rustleaks lockfile. Exact-version GitHub Advisory
Database and upstream repository advisory queries returned no published
record. MIT matches `deny.toml`; its license text is packaged and there is no
`NOTICE` file. No peer audits, wildcard trust, criteria changes, or exceptions
were used.

## `winnow 1.0.4`

- Archive: `winnow-1.0.4.crate`; SHA-256
  `23b97319f7b8343df12cc98938e5c3eb436064524c8d2b4e30a1d3a36eecdf81`.
  The packaged VCS identity is commit
  `7539ec0fc27144bfdcf9a68b0dbbec48bd0d5bae`, at the repository root. All 107
  archive members are regular files with mode `0644`. A fresh extraction
  matched Cargo's registry extraction byte for byte apart from Cargo's
  `.cargo-ok` marker. `LICENSE-MIT` has SHA-256
  `cb5aedb296c5246d1f22e9099f925a65146f9f0d6b4eebba97fd27a6cdbbab2d`.
- Rustleaks use: `toml_parser` uses `AsBStr`, `ContainsToken`, `FindSlice`,
  `Location`, `Offset`, `Stream`, `LocatingSlice`, and `TokenSlice` while the
  `toml` facade also uses `Stream` and `TokenSlice`. The exact core paths are
  `winnow -> toml -> rustleaks-core` and
  `winnow -> toml_parser -> toml -> rustleaks-core`. With no selected Winnow
  feature, only the stream layer and supporting macros compile. The parser,
  ASCII, binary, allocation, SIMD, recovery, documentation, and debug
  features are not selected.
- Safe stream behavior: byte, UTF-8 string, byte-display, locating, partial,
  stateful, and token streams advance through checked slices and retain typed
  checkpoints. String token offsets are found through `char_indices`, so safe
  slicing remains on UTF-8 boundaries. Search returns checked ranges into the
  borrowed input. `Stateful` intentionally does not roll caller state back
  when the input checkpoint resets. Rustleaks' TOML stack uses borrowed UTF-8
  and token slices created by its lexer.
- Unsafe boundary: the `Stream` trait exposes two public unsafe methods whose
  documented preconditions require an in-bounds offset and preservation of
  stream invariants such as UTF-8 boundaries. The concrete slice, string,
  `Bytes`, and `BStr` implementations use `get_unchecked` only under that
  contract; debug builds first execute the checked operation. `LocatingSlice`,
  `Partial`, `Stateful`, `TokenSlice`, and the unselected `Recoverable` wrapper
  forward the same unsafe contract without weakening it. No safe or private
  production caller invokes either unchecked method. The remaining two unsafe
  operations convert `&[u8]` to `&Bytes` or `&BStr`; both destination types are
  `repr(transparent)` unsized wrappers over `[u8]`, preserving layout,
  lifetime, and mutability. No violated unsafe invariant was found.
- Unselected parser behavior: parser and combinator loops reject successful
  child parsers that consume no input. Range conversions saturate exclusive
  zero endpoints. Parser assertions panic in debug builds and become parse
  errors in release builds. The public `todo` parser is an explicitly
  documented panic. Complete-parser panic sites require a partial stream to
  violate the top-level API contract. Unordered-sequence `Option` unwraps
  occur only after the loop has either filled every field or returned the
  accumulated error. Expression parsing recurses according to a
  caller-provided grammar and has no independent stack-depth limit.
- Unselected ASCII and binary behavior: decimal conversion delegates to
  checked standard parsing, hexadecimal conversion bounds the digit count to
  the output width, and escaped parsers enforce forward progress. Integer
  readers consume fixed byte widths. Bit parsers use safe Rust arithmetic and
  safe slicing, but caller-supplied counts and arbitrary `Bits` tuples can
  overflow or underflow their `usize` calculations in debug builds, or later
  reach a checked slicing panic after release wrapping. Rustleaks selects
  neither feature and constructs no bit stream.
- Native and build boundary: the archive has no build script, external
  function, native library, C or C++ source, generated production source, or
  `links` declaration. The selected Winnow node has no dependency edges. The
  optional `simd` feature delegates search to `memchr`; Rustleaks does not
  select it.
- Ambient authority: selected production code opens no file or socket, reads
  no environment variable, starts no process or thread, writes no log, and
  retains no mutable process-global state. The explicit unselected `debug`
  feature reads `COLUMNS`, queries stderr terminal state and size, writes trace
  output to stderr, and uses a process-global atomic trace depth. The packaged
  NDJSON example opens a user-named file and examples write diagnostic output;
  examples are not library behavior.
- Allocation and availability: the selected graph is `no_std` and performs no
  allocation. Featureless substring search scans candidate positions with
  `starts_with`, so a caller-selected long needle can take product time in the
  haystack and needle lengths. Rustleaks' TOML grammar searches fixed short
  delimiters within its caller-owned configuration input. Allocation-enabled
  accumulators cap only their initial reservation at 64 KiB and can still grow
  with parsed output. Recovery retains errors in a vector. Ordinary allocation
  failure can abort. Parser-enabled expression grammars can recurse according
  to input and grammar structure. These unselected or caller-owned resource
  boundaries are not independent Rustleaks limits.
- Panic and protocol behavior: safe stream slicing and indexing intentionally
  panic for an out-of-bounds offset or invalid UTF-8 boundary. `Offset` expects
  the current slice to derive from the starting slice; unrelated slices can
  violate its debug assertion or wrap the integer subtraction in release.
  `Offset` over a zero-sized element slice divides by zero. Bit-slice length
  calculations assume valid bit endpoints. Winnow's own parsers maintain
  these contracts, and Rustleaks uses related byte, string, and lexer-token
  slices rather than zero-sized elements or arbitrary bit tuples. No ordinary
  hostile TOML input reaches an unexplained panic or memory-safety path.
- Upstream evidence: warning-denied default library tests passed 270 tests.
  The non-debug optional-feature set `unstable-doc simd unstable-recover`
  passed the same 270 tests with warnings denied. Featureless library tests
  passed 16 tests without warning denial; warning denial rejects an
  unconditional `BuildHasher` import and a test-only unused macro. Default
  doctests passed 282 tests with 2 ignored, and all-feature doctests passed 348
  tests with 5 ignored, both with warnings denied. Featureless doctests passed
  12 tests with 2 ignored and the same import warning. Eleven separately
  selected packaged examples built with warnings denied and passed all 45 of
  their tests.
- Upstream evidence limits: the packaged all-target suite cannot compile the
  JSON benchmark because its referenced `third_party/nativejson-benchmark`
  data is omitted, and the C-expression test accesses a private sibling
  method. The all-feature library suite compiled all feature code and passed
  270 tests, but its debug transcript test could not create the omitted
  `assets/trace.new.svg` path. These are published-archive test-harness limits,
  not runtime failures, and no passing result is claimed for those commands.
  Rustleaks' uncached core unit, configuration, and session-corpus Bazel
  targets all passed, covering the selected TOML parsing path.
- Conclusion: the complete reviewed source, selected stream-only reachability,
  unsafe and authority review, upstream and Rustleaks tests, advisory results,
  and license evidence support `safe-to-deploy` for the locked Rustleaks
  graph. The documented caller-protocol and resource limitations do not
  require an exception and remain part of the dependency boundary.

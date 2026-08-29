# Core dependency audit: Search foundation batch 7

Review date: 2026-08-28.

Locked graph baseline: Rustleaks commit
`5a467a951574e780b88fc3089313735335f15249`, with `Cargo.lock` SHA-256
`e3c24453ec42115d43dd5b2b679e43cdb6e1b0802393932d3ae199db2e502d82`.
The lockfile is unchanged by this audit batch.

The package is a direct normal dependency of `rustleaks-core` and is also
reachable through `regex-automata`. Its exact workspace consumers, selected
features, target expressions, build-script status, `links` value, checksum,
and cargo-vet disposition are in `supply-chain/inventory-v1.json`. It applies
to every declared target, has no build script or `links` value, and has one
selected normal dependency, `memchr 2.8.3`, which has a local
`safe-to-deploy` audit. The source archive came from the crates.io registry
source recorded in `Cargo.lock`.

The review covered every packaged production and test source file, manifest,
license, README, design note, workflow, and selected feature. The selected
features are `default`, `perf-literal`, and `std`; optional `logging` is not
selected. `cargo audit --deny warnings --color never` refreshed the RustSec
database and found no warning in the exact locked graph. An exact-package
GitHub Advisory Database query returned no record. Unlicense OR MIT matched
`deny.toml`; the archive contains `UNLICENSE`, `LICENSE-MIT`, and `COPYING`.
No peer audits, wildcard trust, criteria changes, or exceptions were used.

## `aho-corasick 1.1.5`

- Archive: `aho-corasick-1.1.5.crate`; SHA-256
  `c982642fa9e8606056828ee9a8505737230110bb1099153c79efe865c59d12ba`.
  The packaged VCS identity is commit
  `5178060ce73d91938f8582d0360e3be031380440`.
- Rustleaks use: core configuration compilation builds standard-semantics
  automatons from normalized rule keywords and allowlist stop words. Scan
  setup reports construction failure as a structured `ScanError::Prefilter`,
  and configuration compilation reports invalid stop-word construction as a
  structured `ConfigError::InvalidPattern`. Searches operate on borrowed,
  in-memory byte slices. Rustleaks does not use the crate's stream,
  replacement, raw-pointer, or low-level automaton APIs.
- Automaton boundary: the public unsafe `Automaton` trait is sealed, so
  downstream code cannot introduce an implementation. The reviewed DFA,
  contiguous NFA, noncontiguous NFA, reference, and internal `Arc` adapters
  preserve valid start and transition state identifiers. State, pattern, and
  compact-index construction checks representation limits and returns
  `BuildError` before an identifier can exceed its representation.
- Construction and search: trie construction, failure transitions, state
  shuffling, contiguous encoding, DFA premultiplication, and byte-class
  remapping retain checked IDs and slice bounds. The failure graph moves
  toward a start state and terminates. Empty-pattern, anchored, overlapping,
  leftmost-first, and leftmost-longest cases have distinct tested handling.
  Prefilters can skip candidates but either confirm the complete pattern or
  return an exact packed-search match, so they do not introduce false
  negatives.
- Unsafe and architecture boundary: packed search is limited to 128 non-empty
  patterns. Raw pointers are derived from one borrowed haystack, and minimum
  vector-read lengths are asserted by the safe facade before SSSE3, AVX2, or
  NEON code runs. Pointer-distance calls require same-allocation ordered
  pointers; pointer-to-integer conversions compute result offsets and are not
  converted back into pointers. Pattern verification checks remaining length
  before short unaligned reads. x86 constructors use runtime feature detection
  before constructing target-feature-specific implementations. AArch64 NEON
  selection is compile-time gated on architecture, feature, and little-endian
  layout. SIMD masks have fixed sizes, bucket and pattern identifiers are
  construction-checked, and every candidate is confirmed against the original
  pattern.
- Resource behavior: automaton construction is proportional to combined
  pattern length, but representations have different constants and a forced
  DFA can use substantially more memory. Automatic selection attempts a DFA
  only for at most 100 patterns, otherwise preferring the contiguous NFA and
  falling back to the noncontiguous NFA if compact encoding reaches its limit.
  Packed prefilters have a hard 128-pattern cap and normally apply stricter
  heuristics. In-memory search is bounded by the input and automaton. Stream
  search, which Rustleaks does not call, allocates at least 64 KiB and enough
  rolling-buffer space for the longest pattern. Allocation exhaustion remains
  Rustleaks' documented process-level boundary; representational overflow and
  unsupported search configurations return errors.
- Ambient authority and failure behavior: the selected implementation does
  not read files, environment variables, network resources, or process state;
  spawn threads or processes; maintain mutable globals; or emit logs. Stream
  APIs operate only on caller-provided `Read` and `Write` values. Documented
  infallible convenience APIs can panic for invalid spans, replacement counts,
  or unsupported search configurations. Rustleaks uses fallible construction
  and valid in-memory search configurations.
- Package evidence: all 150 selected-feature unit tests passed, covering
  scalar, NFA, DFA, stream, Rabin-Karp, packed, SSSE3, AVX2, and AArch64 NEON
  behavior as applicable on the host. All 102 runnable documentation tests
  passed and five examples were intentionally ignored. A blanket
  `-Dwarnings` first exposed one test-build `dead_code` warning and three
  lifetime-syntax warnings from the current compiler. The successful runs
  allowed only `dead_code` and `mismatched_lifetime_syntaxes` while continuing
  to deny every other warning.
- Provenance evidence: strict-provenance Miri passed the complete packed-search
  test modules, the architecture-vector tests applicable to the host,
  pointer-sensitive regressions, and the exhaustive 625-case case-insensitive
  prefilter regression without an undefined-behavior report. The supplemental
  full-suite run was intentionally interrupted during the repetitive
  leftmost-search matrix because its interpreter cost was disproportionate;
  the ordinary selected-feature suite covers that complete matrix. The Miri
  command therefore exited with status 130 from the interrupt and is not
  recorded as a complete-suite pass.
- Conclusion: the reviewed source and completed evidence support
  `safe-to-deploy` for the locked Rustleaks graph.

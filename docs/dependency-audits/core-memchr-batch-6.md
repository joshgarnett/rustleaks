# Core dependency audit: Search foundation batch 6

Review date: 2026-08-28.

Locked graph baseline: Rustleaks commit
`82757272ddeeddc2b17335b931bcdfa9e0eb40d9`, with `Cargo.lock` SHA-256
`e3c24453ec42115d43dd5b2b679e43cdb6e1b0802393932d3ae199db2e502d82`.
The lockfile is unchanged by this audit batch.

The package is a normal dependency reachable from `rustleaks-core` and five
workspace-only packages. Its exact workspace consumers, selected features,
target expressions, build-script status, `links` value, checksum, and
cargo-vet disposition are in `supply-chain/inventory-v1.json`. It applies to
every declared target, has no build script or `links` value, and has no normal
dependencies. The source archive came from the crates.io registry source
recorded in `Cargo.lock`.

The review covered every packaged production source file, target-specific
implementation, manifest, license, notice, README, included test, example, and
benchmark. `cargo audit --deny warnings --color never` updated the RustSec
database and found no warning in the exact locked graph. An exact-package
GitHub Advisory Database query returned no record. Unlicense OR MIT matched
`deny.toml`; the archive contains `UNLICENSE`, `LICENSE-MIT`, and `COPYING`.
No peer audits, wildcard trust, criteria changes, or exceptions were used.

## `memchr 2.8.3`

- Archive: `memchr-2.8.3.crate`; SHA-256
  `cf8baf1c55e62ffcace7a9f06f4bd9cd3f0c4beb022d3b367256b91b87513d98`.
  The packaged VCS identity is commit
  `5fdb40c054e1fff359a2f7bdf7f87a13b34b465d`.
- Graph: selected features `alloc` and `std`. Optional `logging` and
  `rustc-dep-of-std` features are not selected. The package is reachable from
  `rustleaks-core` through `aho-corasick`, `regex-automata`, and `serde_json`.
  Those packages use checked slice-based byte-search and substring-search
  APIs. Rustleaks owned source does not call a raw `memchr` architecture API.
- Safe API boundary: public slice searches derive pointers from the borrowed
  slice and keep returned offsets inside that allocation. Raw-pointer entry
  points state their caller contracts. Internal pointer-distance and
  unreachable optimizations are guarded by same-allocation, ordering, and
  return-range invariants established by the checked entry points.
- Unsafe and architecture boundary: the scalar implementation uses checked
  prefix and suffix handling around aligned or unaligned word reads. Generic
  vector code and the SSE2, AVX2, AArch64 NEON, and WebAssembly facades retain
  the same slice-derived bounds. x86 runtime dispatch checks the CPU feature
  before selecting and caching an exactly typed function pointer. The cached
  `AtomicPtr` is the only mutable process-global state. NEON and WebAssembly
  selection is compile-time gated. There is no native compilation or foreign
  library.
- Substring algorithms: the packed-pair finder checks the remaining haystack
  length before comparing a candidate with the complete needle. This includes
  the current guard for the regression documented by upstream issue 225,
  where a finder can be reused with a longer needle. Two-Way search retains
  worst-case linear scanning. Rabin-Karp is selected only for a constant small
  haystack and confirms candidates after its wrapping hash. Shift-Or limits
  needles to 15 bytes and uses a fixed 256-entry mask.
- Hostile input and limits: byte and substring searches are bounded by the
  haystack and needle. The selected code has no recursion or input-controlled
  stack growth. Searchers use fixed stack state; an owned substring finder may
  allocate a copy of its needle, and Shift-Or uses one fixed-size boxed table.
  The package performs no implicit file, environment, network, process,
  thread, or logging operation in the selected graph.
- Failure behavior: two low-level generic packed-pair functions assert their
  documented minimum haystack length. Checked public search construction and
  meta-dispatch establish that precondition before reaching them. Other
  reviewed panic and unchecked paths depend on internal bounds, candidate, or
  pointer invariants described above.
- Package evidence: on AArch64 macOS, 112 selected-feature package tests and
  24 documentation tests passed with default features disabled and
  `alloc,std` selected. A blanket `-Dwarnings` first exposed two upstream
  `dead_code` warnings from host-unselected internal mask types. The successful
  runs allowed only `dead_code` and continued to deny every other warning.
  Tests exercised scalar, NEON, iterator, packed-pair, Rabin-Karp, Shift-Or,
  Two-Way, forward, and reverse search behavior, including exhaustive and
  property cases.
- Provenance evidence: strict-provenance Miri completed 54 unit tests and 24
  documentation tests for the selected feature graph without undefined
  behavior. The host run cannot execute x86 SSE2 and AVX2 instructions; their
  complete source and packaged regression were reviewed, while Rustleaks'
  eight-target compilation and hosted native x86 jobs remain separate project
  evidence.
- Conclusion: the reviewed version satisfies `safe-to-deploy` for the locked
  Rustleaks graph.

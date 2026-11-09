# Regex meta backend dependency review

Review date: 2026-11-09.

This review covers the selected execution paths added by `regex-automata`
features `meta`, `hybrid`, `dfa-onepass`, `nfa-backtrack`, and `perf` in the
core and standalone core fuzz manifests. The locked package remains
`regex-automata 0.4.18`; its version, registry source, checksum, and licenses
are unchanged. The feature expansion selects literal-search edges to the
existing `aho-corasick` and `memchr` packages. It introduces no native code,
build script, logging feature, or additional dependency package.

The [complete source audit](core-regex-automata-batch-14.md) records package
provenance, licenses, and analysis of selected and previously unselected
source. Its direct-PikeVM execution boundary is historical. This review
updates the reachable paths and resource argument without replacing that
evidence or treating prior test results as validation of the new backend.

## Compilation and API boundary

`GoRegex` keeps the backend private and exposes no dependency implementation
types. The translator, Go property namespace, malformed-UTF-8 normalization,
and original-byte span mapping remain the compatibility boundary. The reviewed
meta configuration uses leftmost-first matching, UTF-8 empty-match boundaries,
all captures, and these explicit limits:

| Control | Setting and scope |
| --- | --- |
| NFA size | 256 MiB for each NFA, including the reverse NFA |
| PikeVM working set | Existing conservative 256 MiB estimate per expression |
| Lazy DFA cache | 2 MiB per direction per cache, allocated on demand |
| One-pass DFA | 1 MiB per expression; failure to build selects another engine |
| Fully compiled DFA | `dfa(false)` and no selected `dfa-build` feature |

The lazy and one-pass settings retain the dependency's defaults explicitly.
They bound individual components, not total configuration or process memory.
Disabling full DFA construction in configuration also preserves that choice
when an external consumer unifies additional dependency features.

The source-pattern, nesting, and repetition limits remain 1 MiB, 4,096, and
1,000 respectively. Patterns above the existing deep-compilation threshold
retain the named thread with a 32 MiB stack and structured thread-error
handling. Parsing produces one HIR. A temporary forward Thompson NFA supplies
the unchanged PikeVM working-set estimate before search-cache allocation; it
is dropped before meta compilation from the same HIR. Meta does not expose
its internal NFA or accept a prebuilt one, so this preserves the existing
rejection boundary at the cost of another forward-NFA construction. Existing
parser and forward-NFA error text remain unchanged. The reverse NFA is
an additional compilation component subject to its own 256 MiB limit. If
that limit prevents meta construction after the identical forward NFA passed,
compilation retries with both DFA engines disabled. The forward-only engines
preserve pattern acceptance without relaxing the limit. Other meta errors are
not retried. A small Unicode-letter regression exercises this path.

Effective-rule validation reads capture counts from the already-compiled
selected matcher. Rule construction and extension merging keep the source and
matcher paired, so this removes redundant compilation without moving syntax
validation or changing secret-group errors.

The official `regex-automata 0.4.12` source was checked for `parse_with`,
`build_from_hir`, pooled `search`, `search_captures`, and the configuration
methods above. These APIs do not require a higher dependency minimum. The
newer `pool_capacity` method is absent from that minimum and is not used.

## Search, caching, and unsafe code

The reviewed sources are `src/meta/{regex,strategy,wrappers}.rs`,
`src/hybrid/{dfa,search}.rs`, `src/dfa/onepass.rs`,
`src/nfa/thompson/{compiler,pikevm,backtrack}.rs`, and `src/util/pool.rs` in
`regex-automata 0.4.18`.

Pooled `search`, `search_captures`, and `is_match` keep mutable scratch space
associated with the compiled expression. Owned code passes checked spans and
does not construct caches for each call or mix caches between expressions.
The meta engine can use literal acceleration, lazy DFA search, one-pass
captures, or bounded backtracking, with PikeVM as its general fallback.
Whole-match enumeration remains eager and preserves Go's empty-match
suppression and decoded-rune advancement. Capture extraction from a trimmed
secret candidate remains a separate haystack search.

Newly reachable dependency unsafe code includes hybrid transition indexing
and the pool's owner slot. Hybrid search checks haystack bounds and tagged
state identifiers before unchecked transitions. State identifiers come from
the same current DFA cache; unknown transitions return through checked cache
construction. The pool assigns unique thread identities, grants exclusive
owner access, and protects other cache stacks with mutexes. Guard ownership
and dropped-state tracking prevent duplicate returns. The earlier audit
records these invariants in detail. One-pass and bounded-backtracker search
use safe Rust. Owned code continues to forbid unsafe Rust.

Caches persist across scans of one Engine. Concurrent searches can allocate
additional caches, and a cloned regex shares compiled automata but owns a new
pool. Pool sharding and retained concurrency high-water marks are not a heap
quota. A meta cache may retain forward and reverse lazy-DFA storage,
additional reverse-strategy storage, and fallback-engine scratch space.
The dependency uses internal thread-local and atomic pool bookkeeping; its
0.4.18 default shard selection can query available parallelism. Search does
not start workers or introduce an owned global cache.

`Regex::memory_usage()` excludes pooled caches, and a fresh cache does not
measure later fallback allocations. Retained-memory evidence must therefore
identify the measurement method, compiled pattern count, scan history,
concurrency, and live Engine state. Idle process RSS includes allocator and
runtime residency and must not be described as exact live cache bytes.

## Hostile input and validation

Lazy DFA cache churn or an unusable cache capacity can remove the speedup.
Large Unicode classes increase compilation and cache pressure. The meta
engine retries with bounded engines and ultimately PikeVM; a PikeVM search
remains linear in haystack length for a fixed expression, with a potentially
large NFA-dependent factor. This is not a portable latency guarantee or a
linear bound for an entire eager match-enumeration operation. Cancellation
remains cooperative, and regex evaluation remains indivisible. Ordinary
allocation failure and allocator overhead remain outside the numeric limits.

Candidate validation is pending: differential capture and span comparisons,
frozen compatibility replay, all first-party tests, format/build/lint and
target checks, package consumers, fuzz build and smoke campaigns including
`go_regex`, and `just security`. Performance evidence must include the existing
compile, hostile-miss, and peak-RSS budgets plus warmed Engine retention.
No new advisory, vetting, unsafe, or compatibility exception is accepted by
this review. A final passing conclusion requires those results and resolution
of any unexplained divergence.

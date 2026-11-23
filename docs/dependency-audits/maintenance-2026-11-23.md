# Dependency maintenance review, 2026-11-23

Review date: 2026-11-23. Reviewer: Claude Code.

## Evidence and scope

The registry archives for `regex-syntax` 0.8.11 and 0.8.12 and
`regex-automata` 0.4.18 and 0.4.19 were downloaded from crates.io and matched
against their Cargo checksums before review:

| Archive | SHA-256 |
| --- | --- |
| `regex-syntax-0.8.12.crate` | `d902046e6a28a1e4c3cab97258a0ce11e994903f01c2d97a9447a0b3df85f4f6` |
| `regex-automata-0.4.19.crate` | `41d60ef07df457506a0a1a2073112eb4aae5733dbd2813c3da77d1b0fd441158` |

Both new archives name upstream commit
`4226f214c56e584304520adb9080bcc4c792390e`. Every member is a regular file.
The review covered every changed file in both archives: production Rust,
manifests, packaged tests, and the Rustleaks call sites. This record extends
the full audits in [core-regex-syntax-batch-13.md](core-regex-syntax-batch-13.md)
and [core-regex-automata-batch-14.md](core-regex-automata-batch-14.md) and the
[backend review](regex-meta-backend.md). It does not repeat a full review of
unchanged source, and it does not claim execution of upstream test suites.

The cached cargo-vet peer imports cover neither version. A fresh peer query
was not made.

No new dependency, native dependency, `links` declaration, build script or
proc macro is introduced. No added or removed line contains `unsafe`. The
license files are byte-identical to the previous versions, and the declared
licenses are unchanged. Both crates still declare Rust 1.65.
`regex-automata` 0.4.19 raises its `regex-syntax` floor from 0.8.5 to 0.8.12.
The Rustleaks ranges, `regex-syntax ^0.8.5` and `regex-automata ^0.4.12`,
still allow both versions, and the core does not need a manifest change.

## Reviewed deltas

| Package | Versions | Security-relevant review |
| --- | --- | --- |
| `regex-syntax` | 0.8.11 to 0.8.12 | Alternation no longer lifts a common prefix that can match more than one way; interval canonicalization runs in place; the AST parser can be reused; derived `Ord` and `Default` replace manual impls. |
| `regex-automata` | 0.4.18 to 0.4.19 | Meta pool capacity default is 8 instead of the available parallelism; the backtracker guard excludes the engine when its haystack limit is 0; PikeVM ignores excess caller slots; one-pass slot handling; `Span::offset` checks overflow; DFA serialization reads the high byte-set bucket at the right offset; full DFA acceleration in `stopat` advances one byte; new `Regex::is_match_with`. |

## `regex-syntax`

Rustleaks reaches this crate through `regex_automata::util::syntax::parse_with`
and `regex_syntax::escape_into`. The required literal and literal anchor
analyses in `regex/required_literals.rs` and `regex/literal_anchor.rs` walk
the parsed HIR in production code. Both handle any HIR shape, so a changed
shape can change only how well they skip searches, not which matches are
found.

- `hir::Hir::alternation` lifts a common prefix out of `Concat` branches. It
  now stops at the first shared element that is not a literal, a class or a
  look-around assertion. Before, `ab*b|ab*c` became `ab*(?:b|c)`, which
  matches `abbc` in `abbc` instead of `abb` under leftmost-first semantics.
  The new form matches Go. A rule whose alternation branches share a
  repetition prefix could report a different match end under 0.8.11. Of
  the 693 distinct `regex`, `path`, `regexes` and `paths` patterns in the
  built-in rule files, 685 parse with plain `regex-syntax`, and only one
  gets a different HIR: the `hasLowConfidenceHost` allowlist regex of two
  connection rules. Allowlist regexes are evaluated with `is_match`, and
  both forms accept the same strings, so allowlist decisions do not
  change. The 8 patterns that need the Go translation first have no
  alternation with a shared repetition prefix. The regex corpus passes with
  0.8.12.
- `IntervalSet::canonicalize` now merges sorted ranges in place and
  truncates, instead of appending the merged ranges and draining the
  original half. The loop keeps one write index at or below the read index,
  merges each range into the last written one when `union` succeeds, and
  otherwise copies it to the next slot. The result is the same set; peak
  memory for a class is lower.
- `ast::parse::ParserI::reset` now also resets the capture index, capture
  names and scratch buffer, and the "parser can only be used once" assertion
  is removed. Rustleaks builds a new parser for every pattern.
- `Position` derives `Ord`. The derived order compares `offset` first, then
  line and column, so it is consistent with `Eq`. `ExtractKind` derives
  `Default` with the same `Prefix` default. Doc comment whitespace changes in
  `hir/mod.rs` have no effect.

## `regex-automata`

Rustleaks selects `meta`, `hybrid`, `dfa-onepass`, `nfa-backtrack`, `perf`,
the syntax and Unicode features and the PikeVM, and turns full DFA
construction off.

- `meta::Config::get_pool_capacity` returns 8 when no capacity is set,
  instead of `std::thread::available_parallelism()` read once through a
  process-wide lazy value. The capacity is the number of cache stacks that
  threads other than the pool owner use, chosen by thread ID. Each stack
  still holds any number of caches. A thread that finds its stack locked
  builds a new cache and drops it after the search. Rustleaks does not set a
  capacity, so a scan with more than 8 workers shares stacks between
  workers. The dependency no longer reads the CPU count, which removes the
  process-global query noted in the backend review. Folder scans of 8
  public repositories with 12 workers on an Apple M5 Ultra (36 logical
  CPUs), comparing optimized builds of the previous `main` and this change
  over three runs each, reported identical findings, the same wall time
  within 1 percent, CPU time up to 1 percent higher and peak memory 4 to 8
  percent lower.
- `meta::wrappers::BoundedBacktrackerEngine::get` now skips the backtracker
  when the span length is greater than or equal to its maximum haystack
  length. The maximum is 0 when the NFA has more states than the visited
  set has bits (2,097,152 with the default 256 KiB capacity). In that case
  an empty span used to reach the backtracker, fail with `HaystackTooLong`,
  and panic on the meta layer's `unwrap`. Rustleaks enables the
  backtracker. Its 256 MiB PikeVM working-set limit leaves a narrow range
  of NFA sizes where this could happen. Spans
  of exactly the maximum length now go to the PikeVM, with the same
  result.
- `PikeVM::search_slots_imp` truncates the caller's slot slice to the NFA's
  slot count before it sets up the cache, so a longer slice cannot index
  past a slot table row.
- `onepass::DFA::try_search_slots` uses the fast path only when at least two
  implicit slots exist, and handles a zero-pattern NFA in the copy path.
  Rustleaks compiles with `WhichCaptures::All`, which always has two
  implicit slots.
- `Span::offset` uses `checked_add` and panics on overflow instead of
  wrapping in release builds.
- `ByteSet::from_bytes` reads the high 128-bit bucket after the low bucket.
  This affects deserialized full DFAs only. Rustleaks does not deserialize
  automata and does not build full DFAs.
- The full DFA search in `meta::stopat` starts acceleration one byte past the
  current position. Rustleaks turns the full DFA off, so this path is not
  reached.
- New `meta::Regex::is_match_with` takes an explicit cache. Rustleaks does
  not call it yet. Removed `clone()` calls on `Copy` values, `core::` paths
  for integer constants, the derived `WhichCaptures` default (still `All`),
  and `clear()` in place of `truncate(0)` on the backtracker's visited set
  have no effect.

Both manifests change the packaged `include` glob from `testdata/**.toml` to
`testdata/**/*.toml`; neither archive gains a file from it. The packaged
tests add regression cases for the alternation change, parser reuse,
`Position` ordering, quit-set serialization, excess PikeVM slots, searches
without capture groups and `Span::offset`. The upstream test named for the
backtracker guard checks only the comparison, not the meta layer.

## Validation boundary

`cargo vet --locked` passes with the delta records for both crates. The
cargo-geiger package list now names `regex-automata@0.4.19`; a new
cargo-geiger run was not made for this review. Source review does not
replace the format, build, lint, test, package, advisory or target checks
for the integrated change.

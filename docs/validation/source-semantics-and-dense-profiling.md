# Source semantics and dense profiling validation

Validation date: 2026-11-05. Base source commit:
`48042081719bac70800d8416595941336b2314b8`.

This bounded S3/P3 increment corrects three production defects, extends Git and
7z semantic tests, adds two compressed archive seed families, and profiles scans
with many findings. No production optimization is accepted. Broader work remains
open in the [roadmap](../ROADMAP.md).

The baseline inventory contained 789 source entries. The clean validation
snapshot identifies the integrated candidate at commit
`6bb133095b9e4cc3d02ed24d81e8004905d247a0`, tree
`b443d38427cefda757822d400cb7f3c6cacc2b49`. Its 791 source entries were verified
by bytes, modes and symlink targets. This local validation identity excludes
the subsequent validation documentation.

## Production corrections

| Boundary | Defect and correction | Evidence |
| --- | --- | --- |
| Git and SCM metadata | Nontext diff headers lost quoted paths or truncated names containing an apparent destination separator. Decode equal default paths exactly and use authoritative rename/copy destinations. | A before-fix parser regression lost path bytes; a real synthetic Git repository then failed archive blob lookup. The fixed source expands both tested archive paths with exact content and commit metadata. |
| Git and SCM metadata | The old hunk start position was never validated. Validate it as signed 64-bit text, matching the pinned parser. | Four malformed positions failed the before-fix regression. Four signed boundary/control values remain accepted, including negative positions accepted by the pinned Go parser. |
| Archives | Cancellation observed while reading a 7z member became a recoverable decode issue. Preserve a distinct cancellation value through the decoder boundary. | The before-fix traversal returned the wrong classification. The corrected source returns `SourceError::Cancelled` whenever the finite test's cancellation state is observed. |

The Git probes used Go 1.26.10 and pinned `go-gitdiff v0.9.1`: 23 path cases
and eight old-position cases. The hunk property covers 48 valid constructions
and 48 truncated variants, checking compacted added bytes, no-newline markers,
new positions, subsequent hunks and file boundaries. Omitting no-newline handling
deliberately fails that property. Exact path and file ceilings are checked too.
The native archive-path regression is Unix-gated and ran on macOS ARM64.
Invalid-byte filenames have byte-parser coverage; this filesystem rejected
their creation, so no native invalid-filename result is claimed.

Seven archive tests execute 249 finite traversals across COPY, Deflate and LZ4:
complete payloads and order, observed cancellation, CRC/packed-data corruption,
container truncation, inclusive member/entry/total limits, nesting charges and
callback outcomes. Eight deliberate production mutations each fail the intended
test. They target payload truncation, suppressed CRC errors, exclusive resource
ceilings, omitted nested charges, ignored callback stop and lost cancellation.
Mutants were isolated and restored; they are test-sensitivity evidence, not
additional discovered production defects.

## Seed and benchmark boundaries

The maintained archive generator now supplies 90 framed inputs, including four
control modes each for synthetic single-coder 7z Deflate and LZ4 archives.
Both new payloads decode to the independently specified 224 bytes. Ordinary tests
regenerate exact archive bytes with the existing encoders, prove compression,
and verify decoded content. Omitting one new seed from the shared list fails
the permanent regeneration test; restoring it passes. The
[source fuzz contract](../../crates/rustleaks-sources/fuzz/README.md) records
construction, provenance and unchanged caps. Other coder graphs and encoded
headers need separate evidence.

The archive benchmark previously selected every fuzz fixture implicitly. The
new fuzz seeds exposed that coupling through an exact-outcome test failure.
It now selects its original 20 shared fixtures explicitly, followed by the
existing three benchmark-only fixtures, rejecting missing or duplicate IDs.
A correctness-only native driver run confirms all 23 phase names, input,
configuration, outcome and logical-work identities match the retained baseline.
Its elapsed values were not evaluated as performance evidence. No existing
benchmark threshold or workload was silently changed.

## Bounded campaigns

Final-source ASan campaigns used deep 64 KiB inputs, seed 1, at most 60 seconds
and one million executions per target, a five-second input timeout, 2 GiB RSS
and a 600-second wrapper deadline. Both completed with successful final identity
checks and no crash artifacts. The archive initial corpus contained all eight
new compressed 7z control frames.

| Target | Executions | Covered edges | Features | Final corpus files |
| --- | --- | --- | --- | --- |
| Archive | 709,266 | 10,531 | 30,815 | 3,209 |
| Git patch | 1,000,000 | 1,029 | 3,873 | 1,121 |

These are libFuzzer feedback counters, not unique cases or source coverage.
Earlier successful campaigns preceded final lint amendments and are retained
separately; this table uses the final-source campaigns only. Raw corpora, logs,
oracle probes and native profiles remain private.

## Dense scan profiling

Two native profiles completed on Apple M1 Max, macOS 26.5.2,
aarch64-apple-darwin, using the same source and executable. The existing dense
fixture has 16,384 input bytes, one rule, 256 findings and 514 work units.
Both profiles validate exact outcomes on every scan. Each requested 15 seconds
of CPU sampling around a 20-second steady loop.

The optimized profiling build includes line tables and frame pointers. Its
sampled loop includes fixture validation, outcome hashing and destruction;
configuration and engine setup finish before collection. Heap and VM snapshots
describe retained state, not allocation history or allocation-site attribution.
No competing builds, tests, fuzzing or other profiles ran during capture.
Unrelated system activity and thermal state were not controlled. The source
was dirty and is not eligible as a clean performance baseline.

The profiles contain 11,058 and 10,954 thread observations. Engine subtrees
account for 9,800 and 9,672 respectively. Within those subtrees, the following
counts are disjoint; nested frame rows must not be summed as independent samples.

| Observed work | First profile | Second profile |
| --- | --- | --- |
| Initial `find_all` subtree | 3,052 | 3,038 |
| Capture extraction outside initial matching | 2,082 | 2,058 |
| Exclusive `detect_rule`, including inlined helpers | 2,771 | 2,766 |

Dominant grouped rows in the last category display offsets mapping in the
verified binary to the `upstream_location` newline walk. Some program counters
are collapsed in the sample output, so attributing that entire category to this
helper would overstate the evidence. Repeated location lookup is a grounded
optimization hypothesis, not a separately measured helper percentage or a
demonstrated speedup.

Both before/after heap observations report 369,040 live bytes and 2,295 nodes.
That is retained-state stability during these two runs, not proof of zero
allocation churn or leak freedom. The
[measurement projection](dense-profile-2026-11-05.json) preserves counts, hashes
and scope distinctions. The [next packet](../plans/dense-location-lookup.md)
defines a bounded location-lookup experiment and ranked alternatives. It requires
new dense-specific calibration; the earlier 7.66% no-hit band is not reused.

## Validation

| Check | Result and scope |
| --- | --- |
| Integrated `just ci` | Pass: 54 targets, format, lint, documentation, host builds, eight-target compilation and committed parity |
| `just security` | Pass: advisory, vetting, dependency, owned-safety, Miri and panic-policy checks |
| Independent checkout | Pass: affected semantic, seed, Git, xtask, formatting and Clippy targets; final source matches the clean snapshot |
| `cargo xtask parity --all` | Pass on the clean snapshot: fresh pinned Go, default/all-feature quality checks, public API, package/consumers, all eight fuzz smoke targets and unchanged legacy M1 elapsed/RSS limits |
| Redacted Git history scan | Pass: all 276 commits, no findings |
| Final documentation and directory scan | Pass: maintained prose/links and redacted working tree, with no findings |
| Independent acceptance review | No unresolved material findings in implementation, evidence or the next experiment |

Initial integration checks caught a test-only lint, the benchmark fixture
coupling, and stricter compatibility-tooling lints. The latter now use a small
signed-position helper, a direct method reference and a narrowly explained
allowance for independent fuzz-control booleans. Failed attempts remain distinct from successful validation.

All native execution here is aarch64-apple-darwin. Cross-compilation is not
native runtime evidence for other targets. Dependencies, toolchains, locks,
pins, copied defaults, public signatures, unsafe policy and release requirements
remain unchanged. No source-coverage, TSan, MSan, exhaustive safety or production
speedup claim is made.

## Finite robustness coverage and declared-length policy

Validation update: 2026-11-06. The following source and regression additions
are outside the historical snapshot and results above. Clean candidate
`c7aa41adf015ebef4ba7100850c62a43d5f58079`, tree
`85a6e6b7f46353508b54b5982ccf2778c259298b`, passed the full pinned-Go differential,
including package/external-consumer, API, all eight fuzz smoke targets and
inherited performance checks. Its clean local release dry run and 28 selected Bazel
targets also passed. Final CI/security refresh passed. The
[roadmap](../ROADMAP.md#current-local-validation) preserves the related CI and
repeated-test source scopes; the [completion record](process-cpu-and-completion.md)
identifies later Rust-owned qualification and hosted delivery. This section
describes the finite matrix validated locally.

`ArchiveOptions::strict_7z_member_lengths(true)` rejects a member whose bounded
stream ends before its declared size. The default remains false because the
pinned Go backend accepts that shorter stream. The strict path emits a
recoverable decode issue and discards all buffered members of the affected 7z
archive before publication. Existing member and aggregate ceilings remain in
force. Length agreement is not an authenticity or additional CRC guarantee.

The ordinary regression matrix covers:

- Both mixed-quote rename and copy directions, different old/new path lengths,
  binary/mode/text records, exact and one-short decoded path limits, and
  aggregate file limits; incomplete or surplus hunks at EOF, hunk, file and
  commit boundaries, with complete-hunk controls.
- All nine two-coder Copy/Deflate/LZ4 combinations in single, solid and separate
  folder layouts; independent member bytes and CRC failures, total-byte
  boundaries, virtual path metadata, strict/default short EOF and callback
  stop/error propagation. Existing single-coder tests retain cancellation,
  member and entry limits, nesting and corruption controls.
- Duplicate and cyclic coder bindings, including a reachable repeated-coder
  case and disconnected cycles, rejected before member or encoded-header
  decoding. A bounded pre-fix iterator probe demonstrated repeated traversal;
  the pinned Go backend rejected or panicked on the same malformed fixtures
  without producing member bytes. Rust returns a structured corrupt-archive
  issue. Reordered acyclic Copy graphs and the pinned BCJ2 fixture exercise
  valid graph controls. Graph validation uses header-bounded linear storage and
  work; it does not silently truncate an invalid graph.
- Four encodings at depths one and two with inside, left, right, both-side and
  two-segment match overlaps; independently constructed original locations,
  unavailable rewrite spans, exact and one-short decoded/work/finding budgets,
  combined ceilings, cancellation after successful decoding, and zero budgets.
- Completed-rule partial prefixes under all six insertion and merge orders,
  baseline/ignore combinations, preserved duplicate occurrences and rejection
  of a populated foreign-policy batch without changing accepted findings.

These are finite semantic regressions, not an exhaustive parser or safety
claim. Archive names remain virtual metadata and are never extracted to the
filesystem. P3 requires an independently calibrated candidate comparison before
an optimization can be accepted. Product policy and hosted-retention
prerequisites remain as listed in the roadmap.

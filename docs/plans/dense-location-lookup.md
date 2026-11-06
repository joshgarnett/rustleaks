# Dense location lookup experiment

Status: completed without an accepted optimization. Exact semantic checks
passed, but two baseline guard calibrations failed the predeclared policy.
No candidate timings were collected; the accepted linear helper was restored.
The [outcome record](../validation/location-lookup-experiment.md) and
[calibration projection](../validation/location-calibration-2026-11-06.json)
retain the results and limits. The original protocol below is preserved.

Original rationale:
The two retained profiles describe the same dirty source and instrumented
executable on Apple M1 Max. They are not a calibrated candidate comparison.
The [validation record](../validation/source-semantics-and-dense-profiling.md)
and [measurement projection](../validation/dense-profile-2026-11-05.json)
record the source identity, observations and limits.

Use isolated baseline and candidate snapshots with independent semantic and
measurement controls. Run final validation after integration, and reserve quiet
host time for measurements.

## Evidence and ranking

The existing `core-dense-16-kib` fixture has 16,384 bytes, one rule, 256 findings
and 514 work units. Its fingerprints are input `3e812ba2e5c2f925`, configuration
`f8b26dc4f7787416` and outcome `b80de9ceab6a9984`. Both profiles conserve all
11,058 and 10,954 thread samples. These engine subsets are disjoint:

| Observed subset | First profile | Second profile |
| --- | ---: | ---: |
| Initial `find_all`, including its nested captures | 3,052 | 3,038 |
| Capture extraction outside initial `find_all` | 2,082 | 2,058 |
| Exclusive `detect_rule`, including inlined helpers | 2,771 | 2,766 |
| Other engine work | 1,895 | 1,810 |
| Total engine subtree | 9,800 | 9,672 |

Outcome-signature subtrees account for 1,108 and 1,104 samples and fixture
validation for 60 and 70. Remaining samples include destruction, timing and
inlined harness work. The hashing callsite has 1,111 samples in each profile,
including formatting/free work omitted by the narrower symbol-based count.
Nested subtree totals must not be added to the disjoint table.

1. Trial binary search in `upstream_location`. The largest exclusive grouped
   `detect_rule` rows contain 2,491 and 2,515 samples. Visible offsets fall in
   the full newline enumeration in the matching executable. Instruction bytes
   in the retained disassembly were verified against that executable. Grouped,
   truncated offsets prevent assigning every sample in those rows to the
   helper; this supports a hypothesis, not an exact helper percentage.
2. Reconsider per-finding capture reuse only as a separate experiment. Its
   2,082 and 2,058 samples provide evidence, but eliminating the second capture
   pass must preserve matching on the trimmed match slice, anchors, group
   selection and normalized invalid-byte mapping. The initial capture context
   is not automatically interchangeable.
3. Initial matcher work remains substantial, but the previous whole-span trial
   failed its acceptance criterion and was removed. These profiles do not
   reverse that rejection. Unicode normalization is another later target:
   its inclusive engine subtrees contain 892 and 869 samples, already included
   in the other-engine row.

All four heap snapshots retain 369,040 bytes in 2,295 live nodes. They do not
measure allocation rate, transient peak allocations, allocation sites or leak
freedom. Do not select an allocation optimization from those totals alone.

## Bounded implementation and exact controls

Limit production changes to private location lookup in
`crates/rustleaks-core/src/engine.rs` and its direct tests. Keep newline
collection, matcher behavior, extraction,
allowlists, decoding, budgets, public APIs and dependencies unchanged. The
existing sorted byte-offset vector is sufficient; add no persistent cache.

Use two partition points to identify the iterations that can assign fields:
the first newline strictly greater than `start`, and the first newline greater
than or equal to `end`. Retain the original predicates with `previous` equal
to the preceding newline offset, or zero for index zero. Replay applicable
assignment blocks in ascending iteration order, with the start block before
the end block when indices are equal. A zero-length span on a newline can run
the end block before a later start block; replacing this with two independent
line-number formulas changes the original result.

Preserve the empty-newline sentinel `[raw.len()]`, initial zero fields, final
`previous` and `last_line`, and fallback block exactly. In particular, preserve
the fallback's zero `start_line_index`, byte-based columns, scan of `raw[end..]`
to the next CR or LF, and final extension of `end_line_index` to at least `end`.
Do not add one to stored newline positions. Preserve direct newline trimming,
decoded candidate index adjustment, unavailable decoded byte ranges, decoded
allowlist-line selection and original-source allow-marker handling.

Before timing, compare every location field against a test-only copy of the
original helper for all valid spans over short synthetic byte strings drawn
from ordinary bytes, LF, CR and invalid UTF-8. Include empty input, no LF,
leading/trailing/consecutive LF, CR-only and CRLF, EOF, empty spans at newline
and EOF, multiline spans and suffixes without LF. Retain the pinned helper
assertions. Add explicit public scan cases for nonzero fragment start lines,
invalid bytes and multibyte text, direct matches trimmed at leading/trailing
LF, nested decoding and multiple overlapping encoded candidates. Compare full
findings, tags, ranges, line bytes, errors, completion and exact usage counts.
Exercise a deliberately wrong newline-boundary predicate to prove test
sensitivity, then restore it. Replay committed parity and the fresh pinned Go
oracle before accepting the candidate. A mismatch rejects the trial; this
packet does not authorize a compatibility exception.

## Measurement and decision procedure

Freeze isolated baseline and candidate snapshots with identical harness,
fixtures, compiler, target and build options. Record both source/tree and
executable identities. Build and validate both before quiet-host collection;
no builds, tests, fuzzing or profiling may overlap timing. Use ordinary
optimized Bazel builds without profiling flags. Retain every ordered sample
and complete marker. Dirty runs remain informational.

First collect two independent dense calibrations on the unchanged baseline,
using nine training A/A pairs, nine held-out A/A pairs and nine extra-scan
control pairs per run, with 100 iterations per process. After preparing the
baseline checkout at the absolute path below, run these commands serially:

```sh
cd /private/tmp/rustleaks-location-baseline
bazelisk run //crates/xtask:xtask -- perf calibrate --output /private/tmp/rustleaks-location-calibration-1 --workload core-dense-16-kib --pairs 9 --iterations 100
bazelisk run //crates/xtask:xtask -- perf calibrate --output /private/tmp/rustleaks-location-calibration-2 --workload core-dense-16-kib --pairs 9 --iterations 100
```

Each output directory must be new. Use the existing
`investigation-v1-steady-scan-only` scope and `empirical-paired-band-v1`
policy: twice the maximum absolute training ratio deviation plus two clock
nanoseconds divided by minimum baseline batch duration. Every held-out pair
must fit and every extra-scan control must exceed its band. Freeze the larger
of the two successful dense bands before observing candidate timings. The
earlier 7.66% band belongs to another workload and is not usable here. An
unstable or insensitive calibration stops the performance decision.

The existing calibration command compares an unchanged executable with
deliberate extra work; it does not compare two binaries. Before candidate
measurement, implement or adapt a private paired controller using the existing
prepared-build binding and investigation worker protocol. It must verify both
build identities before and after sampling and reject unbound, incomplete or
identity-mismatched rows. Collect two rounds of nine adjacent AB/BA pairs,
reverse the starting variant in round two, and retain 100 scans per process.
Compute paired gain as `1 - candidate / baseline` and paired slowdown as
`candidate / baseline - 1`. Accept the primary only if
the median paired gain exceeds the newly frozen dense band in both rounds.
Do not weaken that rule after inspecting results or pool the two rounds.

Calibrate and compare `core-mixed-16-kib`, `core-default-no-hit-16-kib` and
`core-decode-depth-5` with the same fresh-process scope, two independent
calibrations and their own frozen bands. Any guard median slowdown exceeding
its band in either round rejects the trial. Any unsuccessful guard calibration
blocks acceptance. Require exact fixture and result identity equality for primary and guards,
including findings, usage, errors and complete termination. Retain minified,
multiline, invalid-byte, positive decoded and default-positive controls as
semantic checks, and inspect their first/steady scan rows in the complete
representative suite before final acceptance. Those uncalibrated observations
support investigation, not a claim of demonstrated non-regression. A suspected
regression requires its own unchanged A/A calibration before disposition.

Keep the legacy matrix and elapsed/RSS limits unchanged. Record process RSS
separately from operation timing; the current snapshots cannot establish a
scan-allocation improvement. After integration, run `just ci`, `just security`
and `cargo xtask parity --all` on a clean committed candidate. The full
differential includes package, consumer, fuzz and existing performance checks;
do not duplicate those gates separately. Reject and remove the optimization
if semantics differ, measurements are invalid, the
primary fails either round or a calibrated guard regresses. No production
speedup, universal threshold or release qualification follows from this packet.

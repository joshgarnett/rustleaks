# Baseline observation windows

Status: complete, with an unqualified baseline. All 16 cells completed, but
three K=10 guard cells failed. No candidate comparison is authorized by this
result. The [validation record](../validation/baseline-observation-windows.md)
and [generated projection](../validation/observation-windows-2026-11-06.json)
retain the outcome. The predeclared procedure below remains unchanged.
This bounded P3 packet follows the
[stopped location trial](../validation/location-lookup-experiment.md).
It changes optional measurement tooling only. Production behavior, fixtures,
dependencies, public APIs and existing release gates remain unchanged.

## Question and stopping point

Determine whether a predeclared longer retained-engine observation provides
repeatable empirical calibration on the current native host. Complete one fixed
matrix, retain every result, and stop. Do not time an optimization, extend the
matrix, retry failures, select another host, remove outliers or tune a threshold
after observing results. A failed or inconclusive result completes this packet
with the limitation recorded; it does not trigger another experiment automatically.

The two lengths are 100 and 1,000 timed scans per ordinary worker. They are
separate observations, not prefixes extracted from a shared run. Longer windows
are a hypothesis about stability, not a demonstrated remedy for the earlier
variation.

## Measurement and wire contract

Add an explicit optional `--window-blocks` setting, bounded to 1 through 16,
to `perf calibrate`. Omission preserves the legacy protocol and policy. An
explicit value, including 1, selects scope
`investigation-v2-summed-scan-windows` and policy
`empirical-paired-window-band-v2`. Optional `--first-side a|b` is valid only
with window mode and defaults to `a`.

The fixed packet uses `perf calibrate --matrix observation-window-v2 --output
NEW_PRIVATE_DIRECTORY`. Matrix mode rejects workload, pair-count, iteration,
window-length and first-side overrides. It prepares and binds one optimized
build before starting the collection clock, then runs the schedule below
through a prepared execution path without further Bazel preparation.

Each side starts a fresh unchanged investigation worker. Configuration, engine,
fixture preparation and one validated warm scan complete before the existing
ready marker. A new bounded `window K I E` command invokes the existing
`sample(I,E)` implementation K times on that same engine. The worker emits each
raw sample immediately inside a versioned envelope with its own consecutive
block index, K, I, E and identity. A separate counted completion record supplies
checked totals. Then `quit` must produce exactly the existing finished object,
successful exit and stdout EOF. Retain all responses incrementally, including
partial transcripts on failure, with bounded private stdout and stderr.

The existing scan and sample timing code stays unchanged. Each scan has its
own timer, excluding validation, signature calculation and outcome destruction.
The window duration is the checked integer sum of those scan durations across
all K components. It is not one continuous timer. Untimed validation and
destruction still occur between scans and can affect later state. K components
are not K independent paired observations.

`Duration::as_nanos()` reports the integer nanoseconds stored in `Duration`.
Neither that representation nor exact integer summation establishes physical
clock resolution or accuracy. Record `timer_precision_bound_ns: null` and
`integer_aggregation_rounding_ns: 0`. Do not transfer the legacy two-nanosecond
batch allowance. The [Rust Duration implementation](https://raw.githubusercontent.com/rust-lang/rust/1.95.0/library/core/src/time.rs)
and [Instant contract](https://doc.rust-lang.org/std/time/struct.Instant.html)
define these narrower claims.

## Fixed matrix and decision rule

Canonical workload order is `core-dense-16-kib`, `core-mixed-16-kib`,
`core-default-no-hit-16-kib`, `core-decode-depth-5`. Collect exactly two runs
for every workload at K=1 and K=10, with I=100. Each cell contains nine
training A/A pairs, nine held-out A/A pairs and nine deliberate extra-work
pairs, in that order. E=0 everywhere except side B of the extra-work stage,
where E=1 performs twice the scans with the same expected outcome.

Run 1 visits canonical workload order and K=1 then K=10 within each workload.
Run 2 reverses workload order and visits K=10 then K=1. Within each stage,
run 1 starts AB and alternates AB/BA; run 2 starts BA and alternates BA/AB.
A and B are roles, never labels assigned by observed speed. Apply a fixed
five-second idle interval before each cell, counted in the collection deadline.
Do not add adaptive cooling or extra observations.

The complete matrix has 16 cells, 864 fresh workers, 4,752 component samples,
554,400 timed scans and 864 warm scans. Each cell has 54 workers and 6,300K
timed scans. Ordinary sides execute 100K scans; control B executes 200K.
Verify those counts independently from the retained ordered schedule.

For positive integer window totals A and B, define exact rational deviation
`d = (B - A) / A`. Freeze `T = 2 * max(abs(d))` from that cell's training
pairs before classifying its held-out and control rows. Every held-out
`abs(d)` must be at most T; every control d must be strictly greater than T.
Decisions use checked integer cross multiplication, rejecting overflow.
Decimal ratios are presentation only. There is no added timer floor.

Require both predicates and T>0 for a validated cell. Preserve T=0 exactly,
calculate both predicates, and classify it as `degenerate-training-no-gate`.
This is finite empirical evidence, not a confidence interval, clock-precision
bound, general regression tolerance or release threshold.

K=1 is descriptive only. Only the predeclared K=10 length can support a later
comparison, and only if all four workloads pass both independent K=10 runs
with complete integrity evidence for the whole matrix. Do not select whichever
length looks best, pool runs, mix lengths across guards, or let a K=1 pass
rescue K=10 failure. No candidate threshold is frozen by this packet; a later
candidate comparison requires its own reviewed protocol and source binding.

## Integrity and resource limits

Before native collection, freeze the reviewed protocol, ordered schedule,
source inventory, clean source commit, ordinary optimized Bazel executable,
compiler/build identities, controller and classifier. Bind every side to those
identities and verify them again after collection. Prepare all builds and tests
before timing. No competing builds, tests, fuzzing, profiling or benchmark
workers may overlap collection. Unrelated host activity and thermal state are
not controlled by this procedure and must not be described as controlled.

Use a 120-second worker deadline through exit, 900 seconds per cell, and
3,600 seconds for the complete collection after preparation. The effective
deadline is the minimum remaining bound. The existing supervisor uses separate
five-second reaping and pipe-cleanup deadlines and may make an additional
best-effort reaping attempt after cleanup failure. This is not a strict total
cleanup wall-time guarantee. Absolute deadline checks reject late records and
late completion; process termination remains subject to polling and
operating-system scheduling. Never accept a late sample. Record wall
starts/ends separately from summed scan duration, and retain command/response
order. Output limits remain polling bounds, not filesystem quotas.

Independently test complete valid transcripts and wrong ready metadata,
missing/duplicate/reordered/extra components, changed scope/identity/provenance,
wrong work counts, invalid numeric types, zero durations, arithmetic overflow,
exact classification boundaries, zero-band data, absent or contradictory
completion, trailing output, failed exit, timeout and output-limit cleanup.
Require exact component identity, findings, usage, completion and errors.

A protocol, provenance, arithmetic, process or deadline failure stops collection
immediately and marks remaining cells uncollected. Preserve partial evidence;
do not restart the matrix. A statistical calibration failure or degeneracy
does not discard data: finish the remaining predeclared cells within the
deadline for characterization. Neither kind of failure changes acceptance.

## Validation and completion

Run affected Bazel worker/controller tests, meaningful failing
controls, `just ci`, `just security`, and the security skill's maintained fuzz
smoke check after integration. Verify the new module inputs and optimized
worker from the clean measurement checkout. Runtime detection/configuration,
public assets and dependencies are unchanged, so this tooling-only packet
does not require a new full Go differential or package/consumer run.

Retain raw logs and transcripts privately. Generate a sanitized record with
all ordered component durations, sums, exact decision fractions, identities,
hashes and cell dispositions. Record incomplete work explicitly. Update the
roadmap and obtain independent review of implementation,
controls, native evidence and limits. A final packet disposition does not mark
the broader P3 backlog complete.

# Resource and cancellation contract

`rustleaks-core` is synchronous. `Engine::scan_fragment` is the compatibility
wrapper and uses an unlimited, never-cancelled control. Callers handling
untrusted or open-ended work should use `scan_fragment_controlled` with a
`ScanControl` and explicit `ScanBudget`.

Budgets are inclusive and aggregate across one fragment scan:

- decoded bytes count every successful decoded pass before it is scanned;
- work units count documented rule, decoder, keyword, match, required-rule,
  and proximity checkpoints; and
- finding records count materialized primary, auxiliary, and projected
  required findings.

A structured operation split across multiple fragments is outside that
aggregate. `SourceRunner::with_budget` opts into `SourceBudget` accounting
across the source operation. Other callers must supply their own operation
limits. Reusing one per-fragment budget does not create an operation-wide
limit. The caller continues to own elapsed-time cancellation.

Cancellation is cooperative. It is polled between bounded owned work units,
including between decoder candidates and encoding transforms. Regex searches,
eager enumeration of all matches for one rule, and individual transforms remain
indivisible. Match checkpoints follow the completed match list; changing the
backend does not move these checkpoints or make iteration lazy. Work-unit and
finding-record budgets do not bound the temporary eager match-span list.
Pair them with input and target byte limits. A partial
outcome contains findings only from completed top-level rules and carries
structured termination plus measured usage. Callers must not treat partial
findings as a complete fragment result. The bounded source runner discards a
partially scanned fragment rather than merging its prefix into a session batch.

| Surface | Bound or ownership |
| --- | --- |
| Regex compile | 1 MiB source, nesting 4,096, nested repeat product 1,000, 256 MiB per compiled NFA, estimated PikeVM search working set 256 MiB, optional one-pass DFA 1 MiB; limits are per expression/component |
| Configuration selection | Extension depth 2, 4,096 selected rules or rule-linked entries, 8 MiB selected rule source |
| Controlled fragment | Optional aggregate decoded-byte, work-unit, and finding-record budgets |
| Scan options | Caller-selected decode depth and optional per-target byte limit |
| Ignore input | Individual scanner token limited to 64 KiB; aggregate collection is caller-owned |
| Files | Bounded chunks, optional per-file maximum, symlink hop limit 64 |
| Archives | Default depth 8, entries 10,000, member 64 MiB, total 256 MiB, spool 64 MiB |
| Git | Patch/blob 256 MiB, stderr 1 MiB, metadata 16 MiB, path 1 MiB, files 1,000,000, hunks 2,000,000 |
| Source runner | Bounded workers/queue and 1,000,000 unique commits; optional per-fragment and operation budgets below; workers and child processes are joined/reaped |
| Templates | Source 1 MiB, actions 1,000,000, output 64 MiB, nesting 128 |
| CLI | 4,096 arguments; individual text and path values 1 MiB; normalized paths 4,096 components |
| Streaming reports | Writer capacity, cancellation, and final I/O errors are caller-owned |

Many ordinary Rust allocations remain infallible; out-of-memory may abort.
The CLI timeout is cooperative, not a hard wall-clock deadline. Streaming
sources and reports are intentionally open-ended unless their caller installs
the relevant outer policy.

## Regex compilation and retained caches

The private meta backend applies `nfa_size_limit` to each NFA it builds,
including the reverse NFA. The 256 MiB limit is not a combined-NFA or engine
heap quota. A temporary forward NFA preserves the existing PikeVM working-set
check before any search cache is allocated. It is dropped before meta
compilation from the same parsed expression. If the reverse NFA exceeds the
same limit, compilation retries without DFA acceleration to preserve forward
pattern acceptance. The source, nesting, repetition and deep-compile thread
limits remain unchanged.

Each lazy-DFA cache has a 2 MiB transition capacity and grows on demand.
Forward, reverse and fallback caches are retained by the compiled regex pool
across scans of one Engine. Concurrent searches can retain more caches, and
cloning an Engine creates additional pools while sharing compiled automata.
Pool bookkeeping, allocator overhead and aggregate configuration memory are
outside these per-component limits. The optional one-pass DFA has a 1 MiB
compile limit; failure to build it selects another capture engine. Full DFA
construction is disabled, including under downstream feature unification.

Hostile input or large Unicode classes can thrash the lazy cache or cause it
to give up. Meta falls back to bounded engines and ultimately PikeVM, so one
search remains linear in input length for a fixed pattern, but the speedup
can disappear. This is not a linear bound on an entire eager match enumeration
or a wall-clock deadline. Retained-memory and latency measurements apply only
to the measured configuration, input, concurrency and host.

Each scan creates the original-fragment newline index only when a finding
needs a location, and reuses it across decoded passes and required rules.
Each pass normalizes its current bytes for regex matching at most once,
lazily after its gates. Path, allowlist and trimmed-secret searches retain
their own haystacks and normalization. These buffers remain scan-local; they
are not retained in the Engine's search caches.

Invalid UTF-8 normalization stores one offset checkpoint per replaced source
byte instead of one index per normalized byte. Valid UTF-8 runs are copied in
bulk. Ordered whole matches use a local cursor with a bounded linear prefix
and binary search for larger jumps; capture offsets use independent binary
lookups. Each malformed byte still becomes one replacement rune, and all
reported spans refer to the original bytes.

## Private maintenance processes

The optional fuzz, security and performance tooling uses process groups on
supported Unix hosts. Child reaping, bounded process-state observation and
pipe draining share a five-second cleanup budget. The observer captures only
process-group identifiers, states and Linux thread counts, with at most 1 MiB
of stdout. Cleanup fails if it cannot verify that every visible group member
has stopped executing. Linux zombie leaders require exactly one remaining
thread; Darwin reports process termination. Orphan zombies may remain until
the host reaps them. Live, stopped and uninterruptible states do not satisfy
completion. This is supervised
cleanup on a trusted host, not process isolation against escaped groups or
malicious same-user activity. See [security controls](SECURITY_CONTROLS.md).

## Opt-in source operation budgets

`SourceRunner::new` and `SourceRunner::default` preserve the existing unlimited
scan policy. Install an explicit policy to limit original fragment bytes,
total admitted original bytes, admitted fragment count, retained source issues,
and per-fragment and operation decoded bytes, engine work, and finding records:

```rust
use rustleaks_core::ScanBudget;
use rustleaks_sources::{SourceBudget, SourceRunner};

let runner = SourceRunner::new(4, 8)?.with_budget(
    SourceBudget::unlimited()
        .max_fragment_bytes(1024 * 1024)
        .max_original_bytes(128 * 1024 * 1024)
        .max_fragments(10_000)
        .max_issues(100)
        .per_fragment(
            ScanBudget::unlimited()
                .max_decoded_bytes(1024 * 1024)
                .max_work_units(100_000)
                .max_finding_records(1_000),
        )
        .aggregate(
            ScanBudget::unlimited()
                .max_decoded_bytes(32 * 1024 * 1024)
                .max_work_units(10_000_000)
                .max_finding_records(10_000),
        ),
)?;
```

All limits are inclusive; zero is valid. Each finite aggregate engine limit
requires a finite matching per-fragment limit. The runner reserves the full
fragment allowance atomically across every aggregate dimension before scanning.
After a scan returns, it charges measured usage and returns unused reservation.
When a full reservation cannot fit while another scan is active, workers wait.
Once those scans settle, a worker can use the exact remaining capacity. A zero
allowance can still complete a fragment that does not consume that resource.
Concurrency can therefore decrease near exhaustion or when fragment ceilings
are large relative to aggregate ceilings. With sufficient capacity, scans run
concurrently. Accounted engine consumption never exceeds an aggregate ceiling;
there is no per-worker allowance added to that ceiling.

Original-byte and fragment admission happens before queueing. Those counters
include admitted fragments later abandoned in the queue or producer callback.
The existing `scanned_bytes` accessor also counts admitted error-free fragment
content, not proof that detection completed. `SourceOutcome::usage` is present
for an explicit budget and distinguishes admitted and completely scanned
fragments. Engine usage includes partial scans even though all their findings
are discarded. Finding records are charged before session suppression, including
auxiliary and projected records, so an aggregate finding-record limit also
bounds retained finding counts across workers. It does not limit the bytes in
individual finding fields.

The first exhausted budget stops production, cancels in-flight scans
cooperatively, discards queued fragments, and joins every worker. The outcome
contains `SourceTermination::BudgetExceeded` with scope, resource, limit,
consumed units and the rejected request. Other reserved scans may consume more
units before noticing cancellation, always within the shared ceiling; final
totals are in `SourceUsage`. Only complete fragments contribute findings, and
the returned subset can depend on scheduling. Finding order remains unspecified.
Equal fragment and operation ceilings are attributed to the fragment ceiling.
Reaching an issue cap alone is allowed; rejecting the next source issue returns
incomplete budget termination instead of silently reporting completion.

Worker panic takes precedence over cancellation, which takes precedence over
budget termination. A separate terminal source error remains visible. A panic
keeps that scan's full reservation conservatively charged and marks usage
inexact; dimensions without an aggregate limit have unknown additional usage.
The panicking worker's previously collected batch can also be lost. The caller's
cancellation token is never changed by an internal budget stop or panic.

At most `queue_capacity + workers + 1` error-free fragments are retained by
the scheduling path, including the producer callback's pending fragment. Source
adapters can allocate before emitting a fragment or hold additional data, so
their file, archive, Git and metadata limits still apply. Issue limits bound
counts, not diagnostic lengths. These controls do not impose a heap quota,
preempt an indivisible engine operation, or force a custom source to poll its
cancellation signal. Configure original bytes, fragment count, issues and
engine limits together for an otherwise open-ended source.

The unpublished compatibility performance runner measures packaged default
engine construction and no-keyword scans at 1 KiB, 16 KiB, and 1 MiB. Those
workloads provide reproducible inputs and exact outcome invariants, not
portable latency guarantees. Callers deciding whether to move synchronous
scans off an async executor must measure their own target, runtime,
configuration, and request distribution. The [performance measurement
contract](PERFORMANCE.md) records build identity, timing scope, and inherited
host-specific budgets.

Compressed RAR3/RAR5 and 7z dependency calls rely on unwind containment for
malformed-input panics. The 7z boundary contains both reader construction and
entry iteration. When the final binary uses `panic=abort`, those paths are
rejected as structured unsupported-archive issues before entering the
dependency; stored RAR members and other owned/safe decoders remain available.

Owned code forbids unsafe. Feature-selected dependencies can contain reviewed
unsafe internals and are documented separately. Native Linux/Windows runtime
measurement remains a nonblocking follow-up; no limit or portability claim is
derived solely from cross-compilation.

`ArchiveOptions::strict_7z_member_lengths(true)` requires every 7z member to
produce its declared uncompressed byte count. A mismatch emits a recoverable
decode issue before any member of that archive is published. The default is
false, preserving the pinned backend's short-EOF behavior. Both modes retain
member, aggregate, entry, spool and cancellation limits. Strict lengths do not
establish authenticity or add CRC verification beyond the codec's checks.
7z coder graphs reject duplicate bindings, invalid packed inputs and cycles
before constructing member or encoded-header decoders; validation work and
storage are linear in the header-bounded stream and coder counts.

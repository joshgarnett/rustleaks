# Engine internals

This page is for contributors who change the engine, the sources or the
limits. It explains how work and memory are counted, how cancellation works,
and how complete-target scanning is built. The limits that users see, and
what callers must do, are in [Resource limits](../user/resource-limits.md)
and [Complete scanning](../user/complete-scanning.md).

None of the limits below is a limit on total process memory (RSS) or on
wall-clock time. Many ordinary Rust allocations can still abort the process
when memory runs out.

## Scan control and budgets

`rustleaks-core` is synchronous. `Engine::scan_fragment` runs with no limits
and is never cancelled. `scan_fragment_controlled` takes a `ScanControl` with
an optional cancellation flag and a `ScanBudget`.

All budgets include their value and count one fragment scan:

| Budget | What it counts |
| --- | --- |
| Decoded bytes | Every successful decoded pass, before it is scanned |
| Work units | Fixed checkpoints for rules, decoders, keywords, matches, required rules and proximity checks |
| Finding records | Primary, auxiliary and projected required findings that are created |
| Finding payload bytes | The first owned byte fields of those records |
| Collected spans | Whole-match spans admitted from rules and decoders |
| Normalization bytes | Owned regex-normalized bytes and replacement offset maps |

A decoded pass charges one work unit for each segment of the previous pass
that a candidate overlaps. A candidate that overlaps none adds no unit beyond
its own, so decoder work grows with the number of candidates and overlaps,
not with candidates times earlier segments.

A partial outcome holds findings only from top-level rules that finished. It
carries a structured termination and the measured usage. A budget for one
fragment is not a budget for an operation split across many fragments. Using
the same budget for each fragment does not create an operation limit.

## Cancellation

Cancellation is cooperative. The engine polls it between bounded units of
owned work, including between decoder candidates and encoding transforms. One
regex search or one transform cannot be interrupted.

With a finite collected-span budget, each span is admitted before it is added
to the match list, and cancellation is polled between admissions. Without that
budget, match collection keeps its normal checkpoints. Work-unit and
finding-record budgets alone do not bound the temporary match list, so pair
them with source byte limits.

The final filter that removes generic-rule findings charges no work units.
With a cancellation flag it polls once for each finding it classifies and,
when any finding is generic, once for each finding it indexes. It then polls
once more for each finding, and before each comparison of a generic finding
with a non-generic finding on the same line and commit. It compares a generic
finding only with non-generic findings on the same line and commit.

The same filter removes findings named by reviewed rule overlaps (see
[Rule pack authoring](rule-pack-authoring.md#same-secret-from-two-rules)). It
charges no work units. When some finding's rule has an overlap, it indexes the
findings of kept rules by file, commit, secret and exact secret range, and
polls cancellation once for each finding it indexes and once for each finding
it checks. A finding is compared only with findings at the same index key.
When a scan is cancelled during the filter, a removed finding whose kept
finding is outside the returned prefix is put back.

File sources poll cancellation between buffered reads of at most 4,096
bytes. A blocking reader call cannot be interrupted. The CLI `--timeout` is
built on this, so it is not a hard deadline.

## Regex compilation and caches

| Item | Limit |
| --- | --- |
| Pattern source | 1 MiB |
| Nesting | 4,096 |
| Go nested repeat product | 1,000 (Go dialect only) |
| Each compiled NFA | 256 MiB |
| Estimated PikeVM search working set | 256 MiB |
| Optional one-pass DFA | 1 MiB |
| Lazy DFA cache | 2 MiB for each direction, grows on demand |

These limits apply to each expression or component, not to the whole engine.

- The private meta backend applies the NFA limit to each NFA it builds,
  including the reverse NFA. A temporary forward NFA checks the PikeVM
  working set before any search cache exists. It is dropped before the meta
  engine is built from the same parsed expression.
- The embedded default rules and the built-in packs skip the temporary
  forward NFA, which makes startup faster. The test
  `builtin_rules_pass_full_pattern_checks` runs the full check on all of
  that text. Custom configurations, custom packs and replaced default text
  always get the full check.
- If the reverse NFA is too large, compilation retries without DFA
  acceleration, so the forward pattern is still accepted.
- The `bytes-v1` dialect has no separate repeat limit. The NFA and working
  set limits still bound its expansion.
- If the one-pass DFA fails to build, another capture engine is used. Full
  DFA construction is turned off, also under downstream feature unification.
- Forward, reverse and fallback caches stay in the compiled regex pool across
  scans of one `Engine`. Concurrent searches can hold more caches. Cloning an
  `Engine` creates new pools and shares the compiled automata. Pool
  bookkeeping and allocator overhead are not counted.
- Hostile input or large Unicode classes can make the lazy DFA cache thrash
  or give up. The search then falls back to bounded engines and finally to
  PikeVM. One search stays linear in input length for a fixed pattern, but the
  speedup is lost. There is no linear bound for an eager enumeration of every
  match.

Literal-anchor analysis runs once for every compiled expression, including
allowlist and path expressions, and the result is kept with the regex. It keeps
at most 32 literal-node choices, each with at most 64 literals of at most 64
bytes. Enumeration spends at most 16,384 steps. Hitting a limit drops only
longer choices.

## Keyword automaton

The keyword automaton is separate from the regex engines. It holds the
keywords, then every native pattern that is not also a keyword (see
[Required literals](#required-literals) and [Native rule
costs](#native-rule-costs)). It is a full Aho-Corasick DFA when its patterns
total at most 16 KiB and the lengths of all their prefixes sum to at most
64 Ki bytes. Otherwise the builder chooses the kind, and that choice still
builds a full DFA for at most 100 patterns. These limits do not bound that
construction work.

At the 16 KiB limit, the DFA table is about 17 MiB, at most one kilobyte per
state. Building a state's row follows a failure chain for each byte class
without a transition, and the chain is no longer than the state's depth. Every
state is a keyword prefix, so the prefix limit bounds the sum of depths; a
long keyword counts quadratically. The default keywords total 1,755 bytes,
their prefix lengths sum to 9,339 and the longest is 34 bytes. The automaton
kind never changes which keyword hits are reported. With every built-in rule
the automaton has 940 patterns and its DFA uses about 2.3 MiB; with the
default rules alone it has 510 patterns and uses about 0.6 MiB.

Each pass runs the automaton once over the Go-lowercased pass. Only keyword
patterns charge a work unit when found. Native patterns found in the same
search answer every native lookup for the whole pass, unless
a non-ASCII rune of the pass lowercases to ASCII. Only the Kelvin sign and
`İ` (U+0130) do; the test `only_two_non_ascii_runes_lowercase_to_ascii`
checks this. Otherwise each rune lowercases to one rune, and an ASCII input
byte is always a rune of its own, so an ASCII pattern occurs in the lowered
pass exactly where it occurs in the raw pass ignoring ASCII case.

## Required literals

When the engine is built, each rule's expression is analyzed for up to four
small sets of ASCII literals such that every match contains a literal of each
set, ignoring ASCII case. The first set is the best one for the whole
expression; the others come from separate parts of a top-level concatenation.
For `lob-api-key`, the sets are `live_` or `test_`, and `lob`. A set that
only repeats the rule's keywords is left out, since the keyword gate already
checks it. After the keyword gate passes, a buffer that lacks every literal
of some set skips the expression, which could not match there.

Only ASCII literals and ASCII classes count, because Unicode case folding can
add non-ASCII forms such as the Kelvin sign for `k`. Invalid UTF-8
normalization keeps ASCII bytes, so the raw bytes give the same answer as
the normalized ones. The check charges no work. A skipped search charges no
normalization bytes, so usage can be lower than without the check, never
higher.

## Scan-local buffers

These buffers live only for one scan. They are not kept in the engine's
search caches.

- The newline index of the original fragment is built only when a finding
  needs a location. It is reused across decoded passes and required rules.
- The first pass borrows the original fragment. Each decoded pass owns its
  output buffer.
- The Gitleaks-compatible path normalizes each pass's bytes for regex
  matching at most once, lazily, after its gates.
- Native buffer-local rules normalize a buffer only when a Go content matcher
  needs it, and share it with the primary's Go helpers. Byte matchers borrow
  the raw input without normalization.
- Path, allowlist and trimmed-secret searches keep their own haystacks.
- Keyword folding for the prefilter runs when the prefilter exists. Its
  temporary bytes are dropped before rule matching. ASCII folding matches Go;
  other characters and malformed bytes keep the pinned Go Unicode behavior.
  This allocation is not counted as normalization bytes. The prefilter also
  includes keywords of selected native rules, so a selection of only byte
  rules can still allocate a full lowercase view.

## Literal-anchored search

Rules whose prefix shape is proven at compile time use anchored search.
The proof is in `crates/rustleaks-core/src/regex/literal_anchor.rs`. It
serves pure-ASCII passes, and other passes when three things hold:

- The pass is valid UTF-8.
- Lowercasing keeps every character's byte length.
- The pass has neither U+017F nor U+212A, and the rule's leading class and
  keywords match no other non-ASCII character.

U+017F and U+212A are the only non-ASCII characters that case-insensitive
matching pairs with ASCII letters. Under these conditions keyword offsets
are raw offsets and the start of every match is ASCII.

- The keyword pass records the start of each hit for keywords that these
  rules use. For a haystack of `len` bytes, each pass records at most
  `len / 64 + 1` offsets per keyword and `len / 16 + 1` across all keywords.
  A rule with a keyword past either limit uses the unanchored search.
- Recorded offsets stay until the next pass starts. Vector capacity is reused
  across passes and released when the fragment finishes. These are length
  limits, not heap limits.
- On an ASCII pass, a keyword hit is skipped when the bytes a match must have
  soon after it are missing, such as one of `= > : | ? ,` within 23 bytes
  after the keyword for `generic-api-key`. No match can use such a hit.
- Anchored search charges an upper bound on the bytes each attempt can scan.
  On an ASCII pass the bound counts one byte per character. On other passes
  it counts UTF-8 lengths and treats every non-ASCII byte as one the
  unbounded part can consume. When the charges exceed twice the haystack
  length, it falls back to the unanchored search, which reads the haystack
  forward and each match again in reverse. Both paths return the same matches and
  the same keyword work charge.
- With a finite collected-span budget, the engine uses the exact unanchored
  collector, so speculative attempts cannot use the span allowance. Without
  that budget, span usage includes abandoned anchor attempts and can differ
  between anchored and unanchored scans with the same findings.

Invalid UTF-8 and other non-ASCII input use the unanchored search.

## Normalization

Invalid UTF-8 normalization stores one offset checkpoint per replaced source
byte, not one index per normalized byte. Valid UTF-8 runs are copied in bulk.
Each malformed byte becomes one replacement character, and every reported
span refers to the original bytes. Ordered whole matches use a local cursor
with a short linear step and a binary search for larger jumps. Capture offsets
use separate binary lookups.

Rule searches normalize; the decoder does not. Its candidate scanner reads
raw bytes, since every class in its pattern is ASCII. Normalization is
admitted before allocation. Valid UTF-8 stays borrowed. An
input of T bytes with I invalid bytes charges `T + (2 + sizeof(usize)) * I`
when normalization is needed. Each separate normalization charges again. On a
64-bit target, input that is all invalid charges 11T.

Backend caches and the lowercase, newline-index and decoder buffers are not
counted. Decoder span admission bounds the number of candidates, not
allocation bytes. Decoded-byte admission happens after each transform. The
decoder keeps each accepted decoded value for the rest of the fragment, keyed
by its encoded bytes. A candidate that decodes to nothing is not kept.

## Filtering caches

Original-source helpers cache the last allow-marker result by exact byte
range, and reuse a covered suffix for trailing CR and LF lookups. Each rule
pass keeps one line-regex result per evaluated allowlist slot, keyed by the
exact slice and predicate identity. Secret-dependent checks still run for
every candidate. These caches end with their fragment or rule pass, before
decoded bytes are replaced. Work, cancellation and explanation checkpoints
keep their order.

## Finding payload

Finding-record and payload admission is atomic. It happens before the engine
copies owned finding fields, including line context, metadata, tags and
required projections. The counter measures the first copy, even when a later
filter drops the record. It does not measure vector capacity, struct storage,
allocator overhead, report output or later field changes.

For admitted payload P and R records:

- retained logical fields after redaction are at most `9P + 24R`;
- with session fingerprints, at most `10P + (D + 27)R`, where D is the number
  of decimal digits in `usize::MAX`; and
- a safe bound for temporary fields across those steps is
  `12P + (4D + 33)R`.

These formulas leave out source buffers, configuration, regex and decoder
scratch, and links to findings. Callers that add more data must bound it.

A native rule whose edges all have window `0` shares one helper list across
its findings in a buffer. That list counts once in P and R, not once for each
finding. `Finding::add_required_findings` and
`Finding::without_detected_secrets` copy a shared list into the finding they
change. Those copies are outside these bounds.

Each finding charges its complete physical line. Dense findings on one long
line can use the payload allowance quickly, even for a small input. After
admission, findings on the same original line of at least 4 KiB share one
immutable copy. A fragment-local cache holds one weak reference, so it does
not keep the line alive after the findings are dropped. A revisited line can
miss this one-entry cache. Public clones and session snapshots still copy the
line, and redaction can create separate lines.

## Native rule costs

- Byte entropy uses a fixed 256-entry `usize` histogram and one pass over the
  secret, then at most 256 binary64 terms. It allocates nothing per
  candidate. One calculation cannot be interrupted. Rejected candidates use
  no finding record or payload budget.
- `buffer-v1` relations borrow each decoded segment's bytes and keep
  coordinates inline with admitted candidates. There is no scan-wide
  candidate registry. The Go-normalized buffer is shared by the primary and
  its helpers and released after projection.
- Native keyword metadata is kept only for `buffer-v1` roots and helpers and
  for `bytes-v1` rules. It counts toward the selected-rule source limit.
- The per-target byte limit applies to each native input buffer on its own.
- Native keyword checks have a work checkpoint each. The ASCII keywords of
  every native rule and the [required literals](#required-literals) of every
  rule are native patterns. For a whole pass, the keyword automaton answers
  them (see [Keyword automaton](#keyword-automaton)). Otherwise, as for a
  decoded segment, one ASCII case-insensitive automaton over the native
  patterns runs at most once per native input buffer on the raw bytes, stops
  once every pattern has been seen, and is indivisible like one regex search.
  It is a contiguous NFA, several times smaller than a DFA, because it runs
  only on these buffers. When the keyword automaton already answered a pass
  and none of a reporting native rule's ASCII keywords occur, the engine
  charges what the keyword checks would charge, in the same order, and skips
  the rule's detection path. Explained scans always take the full path. The first keyword check on a buffer charges the
  input length, and every rule's ASCII keyword check then reads the shared
  result. Unicode searches share one lowercase string per buffer; building it
  charges two input lengths, and each search charges the folded length.
- Native line coordinates count newlines from the end of the previous
  admitted candidate in the same input, one work unit per byte counted, with
  no newline index. When matches arrive in order, which they do, one rule's
  candidates in one input cost at most the input length in total.
- A native candidate and each nested required projection use the normal
  finding-record and payload budgets. All buffers for one rule must finish
  before the rule publishes findings in a decode pass.
- Relation checks do not compare every primary with every helper. When all
  edges of a rule have window `0`, every helper in the buffer relates to every
  primary. The helper list is then projected once, charged one work unit,
  one record and its payload for each helper, and shared by all primaries.
  Each primary charges one work unit for each edge. With a line window or
  `same-candidate`, helpers arrive in match order, and a binary search finds
  the helpers that can relate to a primary. Each primary charges one work
  unit for each edge and for each helper in that run, and one record and its
  payload for each projected helper, which is copied.
- On the shared path, a primary charges the work units for all its edges
  together, before the shared list is built. The list then holds and charges
  helpers in edge order: all helpers of the first edge, then all helpers of
  the next. Near a budget limit, the order decides only which budget kind
  the termination reports. A rule that stops early publishes no findings
  either way.
- Work and memory in the engine grow with primaries plus helpers when all
  edges have window `0`, and with primaries plus projected helpers for line
  windows and `same-candidate`. Each finding still lists every related
  helper, so a caller that reads `required_findings()` on every finding, such
  as verbose CLI output, reads primaries times helpers entries when all edges
  have window `0`.
- The Mapbox predicate rejects secrets above 926 bytes, accepts at most 308
  encoded and 231 decoded bytes, and uses 539 bytes of fixed buffers. It
  charges one work unit before decoding and one before matching. These checks
  do not use the decoded-byte budget or change the decode depth.
- The Vercel predicate checks exactly 60 bytes and borrows a 470,103-byte
  generated table. Its scratch is 61 byte offsets and 60 u32 ranks, 301 bytes
  in total. It allocates nothing and has no global setup. It makes at most 121
  work checkpoints. One merge step scans at most 59 ranks and makes at most
  two binary searches over 34,471 keys of at most 48 bytes.

## Source runner budgets

`rustleaks-sources` is not published. Its `SourceRunner` reads a source in
fragments and scans them on worker threads. `SourceRunner::new` and
`SourceRunner::default` have no scan limits. `with_budget` installs a
`SourceBudget` with limits for fragment size, total original bytes, fragment
count, retained issues, and per-fragment (`per_fragment`) and operation
(`aggregate`) engine budgets:

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
                .max_finding_records(1_000)
                .max_finding_payload_bytes(8 * 1024 * 1024)
                .max_collected_spans(10_000)
                .max_normalization_bytes(16 * 1024 * 1024),
        )
        .aggregate(
            ScanBudget::unlimited()
                .max_decoded_bytes(32 * 1024 * 1024)
                .max_work_units(10_000_000)
                .max_finding_records(10_000)
                .max_finding_payload_bytes(64 * 1024 * 1024)
                .max_collected_spans(100_000)
                .max_normalization_bytes(128 * 1024 * 1024),
        ),
)?;
```

- All limits include their value; zero is valid. Each finite operation engine
  limit needs a finite per-fragment limit of the same kind.
- The limits are not a heap quota. They do not interrupt one engine step,
  and they cannot make a custom source check its cancellation flag. For a
  source that has no natural end, set original bytes, fragment count, issues
  and engine limits together.
- Before a scan, the runner reserves the full per-fragment allowance in every
  operation dimension at once. After the scan it charges the measured usage
  and returns the rest. When a reservation does not fit while other scans
  run, workers wait; then a worker may use the exact remaining capacity. So
  concurrency can drop near exhaustion. Usage never exceeds an operation
  limit, and workers do not get extra allowance each.
- Original bytes and fragment count are admitted before queueing, so they
  include fragments later dropped. `scanned_bytes` counts admitted fragments
  without errors, not proof that detection finished. `SourceOutcome::usage`
  separates admitted and completely scanned fragments. Engine usage includes
  partial scans whose findings are discarded.
- Finding records are charged before session suppression, so an operation
  finding-record limit also bounds retained findings across workers.
- The first exhausted budget stops production, cancels running scans,
  discards queued fragments and joins every worker. The outcome holds
  `SourceTermination::BudgetExceeded` with scope, resource, limit, consumed
  units and the rejected request. Equal fragment and operation limits are
  reported as the fragment limit. Reaching an issue limit is allowed;
  rejecting the next issue ends the run as incomplete.
- Scans that already hold a reservation can use more units before they see
  the cancellation. They always stay within the shared limit. The final
  totals are in `SourceUsage`.
- Worker panic wins over cancellation, which wins over budget termination. A
  separate source error stays visible. A panic keeps that scan's full
  reservation charged and marks usage inexact. Dimensions without an
  operation limit have unknown extra usage. The panicking worker's batch
  can be lost. The caller's cancellation token is never changed by the
  runner.
- At most `queue_capacity + workers + 1` fragments without errors are held by
  the scheduling path. Source adapters can hold more data, so their own limits
  still apply. Issue limits count issues, not message length.
- `SourceRunner::default` uses one worker and one queue slot. For the
  workers and queue of the `rustleaks` command, see [CLI threads and
  memory](#cli-threads-and-memory).
- The queue is one locked first-in, first-out list. A worker locks it only to
  take a fragment. While the list is empty, an idle worker parks its thread
  without holding a lock. A new fragment wakes one parked worker, and that
  worker wakes the next one if more fragments wait, so the producer pays for
  at most one wake-up at a time. A producer that finds the queue full checks
  it again without the lock. The producer is woken by the first fragment
  taken after it saw the queue full, or by a worker exit, and checks for
  cancellation every 100 microseconds while it waits. The code is
  `JobQueue` in `crates/rustleaks-sources/src/runner.rs`.
- A complete run returns findings in producer order, the same as one worker.
  After a budget stop, the returned subset and its order depend on
  scheduling.

## CLI threads and memory

This section is the one place for the thread defaults of the `rustleaks`
command and the memory that each one adds. The user guide gives the
summary in [Detection
threads](../user/resource-limits.md#detection-threads).

| Item | CLI value | Code |
| --- | --- | --- |
| Detection threads (workers) | `--jobs`, then the profile `workers` key, then `std::thread::available_parallelism` up to 12, or 1 when that fails | `MAX_DEFAULT_JOBS`, `default_runner` |
| Runner queue | Without a profile, one slot for each worker, up to 1,024. With a profile, `queue_capacity`. | `MAX_DEFAULT_QUEUE_CAPACITY` |
| `git log` processes for history | One for each worker, up to 6 | `MAX_GIT_HISTORY_PROCESSES` |
| Directory reader threads | One for each worker, up to 2 | `MAX_READ_THREADS` |

The constants are in `crates/rustleaks-cli/src/run.rs`. Their doc comments
record the measurements behind each default. Memory that grows with these
numbers:

- The runner holds at most `queue_capacity + workers + 1` fragments. See
  [Source runner budgets](#source-runner-budgets).
- Each `git log` process maps the pack files and keeps its own caches, from
  hundreds of megabytes to more than 2 GB for large histories. The output
  that waits for the parser is bounded; see [Git history
  processes](#git-history-processes).
- For R reader threads, the reader stage holds at most 9R fragments and R
  read buffers of the chunk size. See [Directory reader
  threads](#directory-reader-threads).
- Each worker keeps its own regex search caches: a forward and a reverse
  lazy DFA cache of up to 2 MiB each for every expression it searches, plus
  smaller fallback caches. These are most of the memory that grows with the
  scan. During a 12-thread `dir` scan of the gitlab tree (691 MB) with every
  built-in rule, they held more than 300 MB of the 418 MB live heap. Peak
  RSS grew by about 29 MB for each detection thread from 1 to 12 threads. A
  [required literal](#required-literals) or keyword that rules out a buffer
  means that expression is not searched and its caches stay small.

On a 36-CPU host with 12 detection threads, history scans of six public
repositories, from 5,000 to 100,000 commits, took 0.3 to 0.6 times as long
with 6 Git processes as with one. All Git processes together used about as
much memory as one Git process for the whole history, or less. Rustleaks
itself used up to about 0.45 GB more, because more fragments waited for the
workers and more Git output waited for the parser. On the same host, `dir`
scans of large public repositories were within 4 percent of their best time
at 12 threads and used about half the memory of 36 threads. A folder of
100,000 small files was no faster with more than two threads. With one
detection thread, a second reader thread made scans at most a few percent
faster for much more CPU time.

## Startup memory of the built-in rules

On one Apple M5 Ultra Mac with the optimized CLI, an empty scan
(`rustleaks stdin < /dev/null`) reached a peak RSS of about 35 MB with every
built-in rule and about 16 MB with
`--config crates/rustleaks-core/default/gitleaks.toml`. The
heap footprint peaked at about 25 MiB and 9 MiB. The difference comes from
the 547 rules and their allowlists:

- Compiled rules. A Go-dialect expression keeps its translated text and its
  literal analysis until its first search, which builds its matcher. The 56
  `bytes-v1` expressions and deeply nested expressions build their NFAs when
  the rules load, about 1.6 MiB in total.
- The keyword automaton, about 2.3 MiB (see [Keyword
  automaton](#keyword-automaton)).
- The compiled configuration: IDs, descriptions, patterns, keywords and
  allowlist entries. The CLI keeps two copies, one in the engine and one for
  path filtering and reports, about 2 MiB each.
- Work while loading: parsing the 591 KB `rustleaks-providers-v1.toml` and
  every expression. This memory is freed, but the allocator keeps most of it,
  so peak RSS stays near the highest point of loading.

## Git history processes

`GitSource::history_processes` sets how many `git log` processes may read
history at the same time. The default is one. The `rustleaks` command uses
one for each detection thread, up to 6 (`MAX_GIT_HISTORY_PROCESSES` in
`crates/rustleaks-cli/src/run.rs`). The code is in
`crates/rustleaks-sources/src/git/history.rs`.

With more than one, and with the default history options, `plan`:

1. Runs `git rev-list --full-history --all`. Without a pathspec, `git log`
   shows each commit the same way whether or not it walks the history, so
   `git log --no-walk=unsorted` gives each listed commit the same text as the
   default `git log`. The list must succeed, write no standard error, and
   hold only hexadecimal object names of one length. Checking the names also
   keeps option text out of `--stdin`, which accepts options.
2. Splits the list into batches of 250 consecutive commits.
   `GitSource::history_batch_commits` sets another size. A list of one batch
   uses one process.
3. Runs `git config --get format.pretty`, which must exit with 1. One process
   writes a blank line between two shown commits in the default format; a
   `tformat` or `oneline` format ends each commit instead.

If a check fails, the history uses one process. `--log-opts` with a value,
`--staged` and `--pre-commit` also use one process, because options such as
a path, `--follow`, `--reverse` or `-n` change which commits Git shows or how
it shows them.

`visit` starts one thread for each process. Each thread takes the next
batch, writes its commit names to the standard input of
`git log -p -U0 --diff-filter=tuxdb --no-walk=unsorted --stdin`, and passes
the output in pieces of 256 KiB. The calling thread feeds the batches in list
order to one `PatchStream`. Before the first output of a batch, it adds the
blank line that one process writes, when an earlier batch showed a commit.
A batch that shows no commit writes nothing, as one process would. So the
parser reads the same bytes as from one process, and the per-commit limits,
fragments, their order and every parse error are the same.

The end of each batch is handled like the end of one process: the final
record of the batch waits until its Git process exits successfully. When a
batch fails, the scan stops with the `GitExit` error before that record, and
the later batches are stopped. The message holds the standard error of the
failed process only. The `GitStderr` issue is emitted once, before the final
record of the history, when any batch wrote a line that is not ignored.

Bounds:

- At most `history_processes` Git processes run, and at most two batches for
  each process are queued.
- `ReorderBuffer` bounds output that waits for the parser: 4 MiB for the
  batch that the parser reads and 128 MiB for later batches together. A
  thread whose output does not fit waits with the Git pipe full, so Git
  waits too. The batch that the parser reads never waits for a later batch,
  so the parser always makes progress. Parsed pieces return to a pool.
- The commit list keeps one line of 41 or 65 bytes for each commit, up to
  10,000,000 commits. A longer list uses one process.
- `git_stderr_bytes` is one `OutputBudget` that all batch processes share.
  A warning that each process repeats counts once for each process.
- Cancellation, a stop from the consumer and an error end the visit: every
  Git child is killed and reaped, and every thread is joined before `visit`
  returns. A child that cannot be stopped or reaped fails the scan, as with
  one process.

`tests/git_history.rs` compares the events and errors of one process with
several splits on synthetic histories, and the `rustleaks` CLI tests compare
reports for several `--jobs` values.

## Directory reader threads

`DirectoryOptions::read_threads` sets how many threads open and read the
files of a directory walk. The default, 1, reads every file on the calling
thread. The `rustleaks` command uses one reader for each detection thread, up
to 2 (`MAX_READ_THREADS` in `crates/rustleaks-cli/src/run.rs`, which records
the measurement).

With more than one reader:

- The calling thread walks the tree in the same order as with one reader
  and makes every decision before a file is opened: metadata, path allowlists, the
  `.git` metadata selection, complete-mode exclusions, the size limit and
  symbolic links. Only opening a file, reading it and splitting it into
  fragments move to a reader thread, which runs the same code as one thread.
- Walk results wait in one queue in walk order: issues, files and archives.
  Only the calling thread calls the callback, and only with events from the
  head of the queue. So events, issues, errors and their order do not depend
  on the reader count. The first stop or error in walk order ends the walk,
  as it does with one reader.
- Archives and compressed streams are read on the calling thread when they
  reach the head of the queue, so a scan reads one archive at a time.
- The queue holds at most 8 entries for each reader. Each file in it holds at
  most one finished event, and its reader waits before it hands over the
  next. Each reader keeps its own nominal buffer of the chunk size. For R
  readers, this stage holds at most 9R fragments and R nominal buffers. In
  complete mode, a fragment is a whole target, up to the complete-target
  limit.
- The calling thread checks cancellation before it forwards each queued
  event, so no event reaches the callback after cancellation is seen.
  Readers check the caller's cancellation and the end of the walk at the
  same points as a file source. A reader blocked in a read call finishes
  that call first.
- A reader starts when the walk finds a file and no started reader is free,
  up to the limit. If a thread cannot start, the started readers read the
  files, or the calling thread reads them when none started. If a reader
  panics, the walk ends with a terminal source error, and the panic is raised
  again when the threads are joined.
- `tests/directory_readers.rs` compares events, findings, issues and their
  order for 1 to 8 readers on mixed trees, with a stop or an error at every
  event, with cancellation, and in complete mode. The `jobs` tests in the CLI
  suite compare reports and logs across `--jobs` values.

## Complete targets

`FileOptions::complete(maximum)` reads one eligible target to a clean end of
file before it is scanned. The CLI uses this for `--complete-profile`.

### Reads

- Each read asks for at most the remaining allowance plus one byte. Input
  exactly at the limit is accepted after end of file; seeing one more byte
  fails the target. File metadata is not the only size check.
- Data with end of file completes the target. Data with an error other than
  end of file fails it, and none of its bytes are published. A reader that
  returns zero bytes with `ReadStatus::Continue` fails as no progress; there
  is no retry. A reader that reports too many bytes also fails.
- A complete `FileSource` allows one visit. It cannot publish the rest of a
  failed attempt later.
- MIME selection looks at the first `min(length, 100000)` bytes after the
  full read. The size limit comes first, so an oversized binary file fails
  the limit instead of being skipped as binary.

### Exclusions and failures

- Intentional exclusions stay exclusions: path allowlists, directory size
  limits, symbolic links that are not followed, directory link targets, empty
  files, binary MIME types and archive depth. `SourceIssueDisposition`
  separates `Excluded` from `CoverageFailure`.
- Complete directory traversal applies a known path exclusion before it reads
  metadata, follows links or opens the file. An excluded dangling link does
  not stop later files. In normal (not complete) mode, traversal keeps its
  usual order.
- Complete TAR and ZIP traversal can skip an excluded member before copying
  or decoding it. Container, entry-count, spool, TAR header and padding, and
  ZIP header and range checks still apply. A bad CRC in an excluded ZIP member
  need not be checked. Formats with shared blocks still decode what later
  eligible members need. Path pruning still covers only first-level members.
- Directory, archive spool, member, decode, corruption and resource failures
  are terminal `SourceError` results. A failed target is never scanned.
  Earlier completed targets can stay in the result.
- `SourceRunner::fail_on_coverage_error(true)` turns a coverage-failure issue
  from any source into an incomplete result, before its fragment is scheduled.
- Runner terminations are `SourceError`, `BudgetExceeded`, `Cancelled`,
  `WorkerPanic` and `Stopped`. Only `Completed` means complete coverage.

### Archives

- A final `.tgz` suffix, in any ASCII case, is read as gzip-compressed TAR in
  complete mode. It uses one archive depth level, like `.tar.gz`. Normal
  (not complete) mode does not recognize it.
- Complete mode forces strict 7z member lengths, even if
  `ArchiveOptions::strict_7z_member_lengths(false)` was set. A short member
  fails. The default outside complete mode is `false`, which keeps the
  pinned short-EOF behavior. Outside complete mode, a caller can turn it on
  with `strict_7z_member_lengths(true)`. A length mismatch then gives a
  recoverable decode issue at the end of the short member and stops that
  archive. Earlier members, and outside complete mode the bytes of the short
  member, are already published. Strict lengths add no authenticity or CRC
  check.
- Members stream. Each plain member reaches the file scanner through a reader
  that fills every read unless the member ends, so piece boundaries do not
  depend on how a decoder splits its output. A 7z member keeps its
  decoder's chunk-sized reads: the reader keeps one chunk at a time.
  `tests/archive_streaming.rs` compares both with independent references.
- A read failure inside a member ends that member. A normal scan keeps the
  bytes before the failure and then gets the archive issue; a complete scan
  sees a read error, publishes nothing for that member, and fails with the
  archive issue. A TAR container stops after a failed member; ZIP continues
  with the next member. After a compressed TAR ends, or a compressed member
  is skipped as binary, the rest of the stream is decoded so trailers and
  checksums are still checked.
- 7z coder graphs reject duplicate bindings, invalid packed inputs and cycles
  before any decoder is built. This check is linear in the stream and coder
  counts.
- Compressed RAR3, RAR5 and 7z decoding relies on catching panics on
  malformed input. When the final binary uses `panic=abort`, those paths are
  rejected as unsupported-archive issues before the decoder runs. Stored RAR
  members and the other decoders still work.

### Coordinates and Git

- For a complete file or archive member, raw byte ranges refer to the
  target's original bytes from offset zero. Findings on the same line stay
  separate; fingerprints are not a deduplication key. Decoded findings keep
  their encoded-segment location, and their raw range is
  `FindingRange::Unavailable`.
- Git text targets are still the added lines of each hunk. Context and
  deleted lines are not scanned, and separate hunks are not joined. Raw
  ranges refer to the hunk buffer. Archive blobs from Git use complete reads
  only when the archive file options select it.
- `ScanOptions::max_target_bytes` skips a target. It is not a complete-mode
  limit and does not make a result incomplete.

### CLI profile

- Known configuration and baseline files are excluded before any read, using
  the same normalized `FilePath` values as the CLI's normal filter. Symbolic
  link aliases are not resolved. Archive members use exact decorated paths;
  excluding a container path does not exclude its members. Directory mapping
  uses the emitted spelling, including `./`.
- Skipped control files use no admitted source bytes in complete mode.
- Standard input keeps its plain text domain. Archive depth does not add a
  file name or detect archives by content.
- Archive limits apply to each archive traversal and are separate from target
  and operation admission. Link limits count exact link bytes. Each link is
  checked against its own limit and the operation limit before it is built.
  An unknown or disabled platform, a missing remote and an empty commit mean
  that no link applies. A discovery, build or admission failure makes the
  result incomplete.

## Example profile on large inputs

These scans show what the [example
profile](../user/complete-scanning.md#the-profile-file) does with some large
inputs. They are not a promise about other inputs, rules or releases. The
user guide keeps only the advice that follows from them.

How the scans were run:

- An optimized build (`bazelisk build -c opt //crates/rustleaks-cli:rustleaks`).
- All rules: the default rules plus the `rustleaks-extra-v1`,
  `rustleaks-providers-v1` and `rustleaks-connections-v1` native packs.
- `--complete-profile` with the example profile, `--max-decode-depth 5`,
  `--max-archive-depth 0` and `--base64-mode compatible`.
- Synthetic inputs with known GitHub tokens. Each row is one scan of one file,
  or of one folder where the row says so.

| Input | Size | Result | Limit that stopped the scan |
| --- | --- | --- | --- |
| A folder of 132 files with plain tokens, or of 186 files with Base64 tokens. Each file has one token, or one almost valid token, across byte 4,096. | 4,160 to 4,216 bytes per file | Complete. Every planted token was found once, on the right line. | None |
| The same, with the token across byte 65,536, 100,000, 125,000, 153,672 or 182,344 | 65,600 to 182,464 bytes per file | Stopped. Each scan reported 7 to 16 of its 50 or 72 planted tokens. | `operation_work_units`, the limit for the whole scan |
| One 64-byte JSON record per line. A token on every line, on every other line, or on no line. | 512 KiB and 2 MiB | Stopped. No planted token was reported. | `fragment_work_units`, the limit for one file |
| The same records on one long line, with tokens | 512 KiB and 2 MiB | Stopped. No planted token was reported. | `fragment_finding_payload_bytes`, because each finding keeps a copy of the whole line |
| The same records on one long line, without valid tokens | 512 KiB and 2 MiB | Stopped | `fragment_work_units` |
| One Base64 value that holds 4,096 records, encoded once or twice | 289,467 and 385,951 bytes | Stopped. No planted token was reported. | `fragment_work_units` |
| 20,000 lines, each the Base64 form of one token | 1,140,021 bytes | Stopped. No planted token was reported. | `fragment_work_units` |

The last row comes from a separate scan with the same options. A second run
of that input with a much larger profile completed. It needed about 71
million work units in one file with `--base64-mode compatible`, and about 95
million with `--base64-mode extended`. The example profile allows 10 million
for one file. With the default rules alone, the same input completed under
the example profile in both modes and needed less than 250,000 work units.

## What these limits do not bound

- Directory enumeration, configuration loading, compiled rule storage,
  allocator capacity and regex caches.
- Session decoration, redaction, fingerprints and report conversion.
- The total size of ignore-file input. One ignore-file token is limited to
  64 KiB; the caller limits the total.
- Elapsed time. Use cancellation for a time limit.

An 8 MiB source limit is not an 8 MiB memory limit. Record an exhausted
budget as incomplete coverage, not as a fast clean scan.

Owned code forbids unsafe Rust. CI runs the resource-limit tests natively on
all eight required targets. These tests do not measure time or memory. See
[Testing](testing.md#platforms).

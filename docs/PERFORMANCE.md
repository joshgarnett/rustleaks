# Performance measurement

The unpublished performance runner has 23 deterministic workloads. Normal
Bazel tests execute their outcome invariants, including report bytes. Run the
commands below from the repository root. Timing
and memory measurements use an optimized Bazel executable through xtask:

```sh
just perf-run
just perf-check
```

The run command emits JSON Lines. The check command validates the complete
matrix and enforces the unchanged inherited elapsed and RSS limits on the
recorded Apple M1 Max host class. Other hosts explicitly report that those
limits were not evaluated. Neither command changes a baseline.

For one workload with bounded untimed warmup and measured iterations:

```sh
bazelisk run //crates/xtask:xtask -- perf run --workload default-one-keyword --warmup 1 --iterations 10
```

Iterations are bounded to 1 through 10 and warmup to 0 through 10. Warmup
runs prepare a new engine; they warm process-local initialization and caches,
not a retained engine instance. The existing workload may reuse its engine
within measured iterations. Reused-engine and first-scan phase measurements
need separate workloads before making those comparisons.

## Build identity

Xtask builds `//crates/rustleaks-compat:rustleaks_perf` with
`--compilation_mode=opt --stamp=no`, resolves its executable with Bazel, and
reads the selected Rust compile actions. The report records the actual
compiler binary hash and version, target, an allowlist of compiler options,
full argument digest, compile action key, Rust action graph hash, generated argument-file hashes, lockfile hashes,
workload definition hash, executable hash, and available host identity.
The actual packaged default configuration must match its pinned SHA-256 before
building, and that verified hash is retained in the build identity.
Argument-file paths are represented by digests. Arbitrary environment values,
user paths and machine serial identifiers are not emitted. These are report metadata and are not embedded into release executables.

The source identity includes HEAD, dirty status, and a digest covering tracked
and non-ignored untracked files, including modified and deleted inputs.
Source and executable identities must remain unchanged across preparation and
measurement. A dirty run is explicitly ineligible as a clean baseline. A
clean working tree still does not establish that a binary was published or
qualified for release.

Running the benchmark executable directly emits `unbound-runner` provenance.
Only xtask binds those rows to the checked Bazel build. Its validation rejects
unbound rows and mismatched source, executable, graph, corpus, timing scope,
or outcome. Runtime `rustc` and Git output alone are not build identity.

## Timing scope and inherited limits

Schema 2 retains the legacy timing protocol, explicitly named
`legacy-v1-includes-verification`. Existing timers include finding or output
fingerprinting and, in some cases, outcome destruction. Fixture preparation
and build orchestration are outside those timers. Report logical units are
findings; scan logical units are input bytes. These values must not be
combined into a single bytes-per-second series.

The M1 Max limits were originally calibrated using Cargo release builds.
Their values and seven-process sampling procedure remain unchanged. Bazel
results are labeled by their different build identity. Accepting the build
migration requires paired original-Cargo and Bazel measurements on the same
host and legacy timing scope; passing an inherited limit alone is not a new
cross-build calibration. Collect the original reference with the existing
`cargo xtask perf check` in an untouched checkout of the pre-migration commit,
then collect the candidate with `just perf-check`. Run the two commands
serially on the same quiet host, retain their exact source/build identities,
and compare individual workload results without widening a limit. The old
command is only a legacy-reference measurement; it is not a fallback for a
failed candidate Bazel build. Future phase-only timers must use a different scope
and new calibration evidence, without silently inheriting these thresholds.

Peak RSS is measured for a fresh process and includes its initialization and
fixture setup. It is not a count of scan-only allocations. Current source
fixtures are newly written, so their timings are not cold-disk evidence.
Use quiet host time and avoid concurrent builds, fuzzing, and profiling when
collecting comparisons. Different native targets and hardware retain separate
baselines. No benchmark result is a portable latency guarantee.

## Representative phase measurements

The optional representative suite adds operation timers while retaining the 23
legacy workloads and their budgets unchanged. Run it separately from release
qualification, after all builds and fuzz work on the native host have stopped:

```sh
just perf-representative
bazelisk run //crates/xtask:xtask -- perf representative
bazelisk run //crates/xtask:xtask -- perf representative --workload core-mixed-16-kib --samples 7 --iterations 100
```

The command builds every selected executable before measurement. Each workload
runs in independent processes, with 3 through 31 process samples and 1 through
1,000 steady iterations. Defaults are seven processes and 25 iterations. A
600-second deadline bounds each child process; exceeding it rejects that sample.
Every JSON Lines phase row has schema 3, suite `representative-v1`, and scope
`representative-v1-operation-only`. These rows cannot inherit or be compared
directly with the legacy timing limits. There are no new thresholds.

Core workloads report configuration parsing and rule compilation together,
engine construction, the first scan in that process, and steady scans using the
same engine. The public configuration API combines parsing with compilation.
The first scan occurs before any scan-based fixture verification, preserving the
decoder's process-local initialization cost. Its timer is distinct from the
steady scan timer. Configuration and construction are each measured once per
process, rather than counting the same prepared engine repeatedly.

Decoder workloads compare depth zero and depth five with a nonmatching rule and
exact decoded-byte counts. They use the public scan API, so their operation is
labeled `scan-with-decoding`: normalization, keyword dispatch and scan setup are
included. This is not an isolated private-decoder measurement. Session merging
starts from prepared batches. Its timer includes consuming batch containers;
classification, cloning input findings and final session destruction are outside
that timer. JSON and SARIF serialize the existing 10,000-finding control corpus
and must match its exact legacy output size and fingerprint.

| Workload family | Coverage and logical denominator |
| --- | --- |
| `core-mixed-*` | Synthetic mixed code at 1 KiB, 16 KiB and 256 KiB; input bytes |
| `core-dense-16-kib` | Dense positive records and high finding count; input bytes |
| `core-minified-16-kib` | Long single line with multiple matches; input bytes |
| `core-utf8-invalid-16-kib` | UTF-8 and invalid source bytes; input bytes |
| `core-multiline-16-kib` | Matches spanning lines with exact byte ranges; input bytes |
| `core-many-rules-16-kib` | 128 compiled synthetic rules; input bytes |
| `core-default-*` | Pinned default no-hit, one-keyword, many-keyword and positive controls; input bytes |
| `core-decode-depth-*` | Depth-zero and depth-five decode controls; original input bytes, with decoded bytes recorded separately |
| `session-merge-10000` | 100 prepared batches; findings |
| `serialize-*` | JSON and SARIF serialization; findings, with output bytes recorded separately |
| `source-*` | Many small files and a few large files with one or four workers; input bytes and exact file counts |
| `git-repeated-blobs` | Synthetic repeated-blob history; exact history, fragment and byte counts |
| `archives-all-formats` | Supported archive formats; compressed and expanded byte counts kept separate |
| `cli-*` | Fresh CLI process startup, directory, standard input and Git commands; explicit input counts |

Existing hostile-regex, capture/entropy, larger no-keyword, deeply decoded
positive and allowlist cases remain in the legacy suite as controls. The new
suite does not duplicate their entire matrix. Source traversal/read, source
runner detection/session and complete source traversal/detection have separate
rows. Files are prepared immediately before sampling, so the filesystem state
is labeled as newly written and warm or unspecified, not cold disk. Git setup
is outside the measurement. Archive measurements use the existing source
archive test profile through a separate on-demand driver, preserving compat's
minimal source dependency. CLI rows include their explicitly named process,
configuration, scan and reporting work.

Fixture creation, expected-result construction, hashing, validation and final
outcome destruction are outside operation timers. Each operation is observed
with `black_box`; at most one measured outcome is retained at a time. Input,
configuration and outcome fingerprints plus exact work counts accompany every
phase. Normal Bazel tests validate full synthetic findings, exact locations and
byte ranges, report output bytes, zero errors and complete termination. A
skipped-input mutation and a budget-terminated scan must fail validation, so a
faster incomplete operation cannot qualify as a successful sample. Counts and
identities must remain identical across process samples.

Xtask binds the runner and auxiliary CLI/archive executables to their optimized
Bazel compile actions, compiler and argument-file hashes. It also records the
selected Git executable hash and version. Workload source files, including
source/archive fixture definitions, contribute to the definition identity.
Ambient Git configuration is excluded from the representative subprocesses.
A small fresh-process marker control measures launch-to-exit separately from
core first-scan timing. Total process wall time, user/system CPU time and peak
RSS include setup, verification, destruction and waited descendants. They are
reported separately from phase elapsed time and must not be treated as phase
allocation costs. The collector reports unavailable CPU/RSS as null on platforms
without Python resource support; allocation counts remain null because no
allocation profiler is installed by this suite.

Summary rows report the median, minimum, maximum and median absolute deviation
of per-operation elapsed time across processes, retaining raw sample values.
The median uses the upper middle order statistic for an even sample count.
No p95 is estimated from this small sample set. Use enough inner iterations to
observe a useful duration and inspect the raw samples before comparing runs.
Every saved run must end with `run-complete`; a missing final marker means the
source/executable stability checks or complete matrix did not finish. Dirty
runs remain informational and ineligible as clean baselines. Record quiet-host
conditions with retained native samples before selecting thresholds or a
profiling target. These synthetic workloads do not establish field speed.

The [initial native record](validation/evidence-and-workloads.md) documents the
2026-11-05 Apple M1 Max measurements and their limits. Its dirty candidate source
is explicitly ineligible as a clean baseline. P2 owns profiling attribution and
noise calibration before any new performance threshold or optimization.

The [profiling and calibration acceptance record](validation/deep-and-profiling.md)
contains the subsequent native CPU/retained-memory observations and two
independent calibration runs. Its measured candidate remains dirty and the
empirical bands create no release threshold.

## Adversarial core and worker measurements

The optional edge matrix varies long-line length and candidate count,
trailing-line location lookups, overlapping stopwords, sparse and dense invalid
UTF-8, empty matches, and valid
percent decoding with and without a preserved invalid prefix. Its filtering
cases retain no findings, separating repeated scans from the cost of copying
large lines into accepted findings. Independent expected work, finding-record
and decoded-byte counts are checked after every scan. Small negative controls
prove that missing suppression and incomplete scans are rejected.

Start with one steady iteration because these cases deliberately expose
expensive work:

```sh
bazelisk run //crates/xtask:xtask -- perf representative --workload edges --samples 3 --iterations 1
bazelisk run //crates/xtask:xtask -- perf representative --workload workers --samples 3 --iterations 1
```

The worker matrix scans the same 12 MiB in 768 fragments through a shared
Engine or one clone per worker, using one, four or eight persistent caller
threads. Thread startup, clone construction and result-buffer allocation are
outside scan timing. Clone setup has its own phase. The first batch searches
on the workers without coordinator warmup; subsequent batches reuse those
threads and caches. Batch wall time includes command dispatch, scanning and
result collection. Validation, hashing and destruction wait until every worker
has finished and are outside that timer. All fragment indices must occur once.

Fresh-process peak RSS includes configuration, input, clones, caches and retained
outcomes. It is not an isolated cache-memory measurement. Single-engine edge
workloads can also use the existing profiler; its complete loop includes
validation and destruction, so attribute scan costs using stacks below the
scan call. Freeze workload definitions before collecting comparison runs,
retain ordinary controls, and measure serially on a quiet host.

The [filtering and normalization measurements](validation/core-edge-performance.md)
record synthetic alpha.7 edge cases, measured fixes and remaining limits.

## Decoder, session and report workloads

The `decode-report` group adds synthetic decoder, baseline-classification,
report-serialization and configuration-compile operations:

```sh
bazelisk run //crates/xtask:xtask -- perf representative --workload decode-report --samples 3 --iterations 1
```

Decoder expectations come from the fixture generator and from the checkpoint
charges in the decoder and engine, never from engine output. Each scan's work,
decoded-byte and finding-record budgets equal its independent expectation, so
extra work ends the scan and fails the run. Report, session and configuration
oracles are independently generated bytes, per-stage suppression counts and
compiled rule and allowlist counts.

| Workload | Shape and expectation |
| --- | --- |
| `core-decode-many-base64-depth-1` | 20,000 base64 lines; one finding per line; work `6N + 4` |
| `core-decode-many-base64-depth-2` | The same lines double-encoded; findings only at depth 2; for `N > 1`, work `N * N + 10 * N + 6`, including one unit per predecessor |
| `core-decode-long-line-many-findings` | One 1 MiB line with 10,000 encoded tokens; 10,000 findings, each retaining a copy of the full line, so one scan holds about 10 GiB |
| `core-decode-long-line-allowlisted` | The same line with every finding allowlisted; no retained findings and the same work |
| `core-decode-lookalike-4-mib-depth-1` | Lockfile-like hashes and identifiers that fail decoding; no findings or decoded bytes |
| `core-decode-none-4-mib-depth-5` | Prose with no encoding candidates; two work units |
| `core-decode-nested-needle-4-mib-depth-5` | The same filler with one five-times base64 token; one `decode-depth:5` finding |
| `core-decode-hex-unicode-256-kib` | Alternating hex and unicode-escape lines; one finding per segment |
| `session-classify-baseline-10000x10000` | 10,000 findings against 5,000 exact and 5,000 near-miss baseline entries and a 10,000-entry ignore set; exact counts per suppression stage |
| `serialize-json-escape-heavy` | 1,000 findings with 64 KiB matches mixing every escape class; length from per-class expansion and exact expected bytes |
| `serialize-csv-10000`, `serialize-junit-10000` | The 10,000-finding corpus; exact expected bytes |
| `config-compile-extend-default`, `config-compile-allowlist-heavy` | `useDefault` extension and 500 single-pattern allowlists; exact counts |

Run `core-decode-long-line-many-findings` only on hosts with at least 12 GiB of
free memory. Serialization timers use an output buffer sized to the expected
report, so they exclude buffer growth; session classification times only the
classification calls.

## Source, Git, archive and CLI scale measurements

The `source-scale` group adds 26 synthetic workloads for traversal, chunking,
Git history shape, archive limits and CLI behavior. Run it with one iteration:

```sh
bazelisk run //crates/xtask:xtask -- perf representative --workload source-scale --samples 3 --iterations 1
```

Every fixture is generated in a temporary directory before its timers start.
Expected fragments, findings, counts, limit issues and stderr lines come from
the generator manifest and the documented limits, not from measured output.
Fragment boundaries come from an independent model of `FileSource`: a
100,000-byte nominal read, then read-ahead through a 4,096-byte buffered reader
until a blank line or 25,000 appended bytes. Bytes left in that buffer satisfy
the next nominal read, which is therefore short. A file with no line breaks
yields one 125,000-byte fragment and then 28,672-byte fragments, not
125,000-byte fragments. Blank lines end read-ahead early, so those files
produce many smaller fragments.

| Family | Shapes |
| --- | --- |
| `source-default-config-{1,4,8}-workers` | Packaged rules over 96 files of 128 KiB with planted tokens |
| `source-blank-lines-12-mib`, `source-no-blank-lines-12-mib` | The same rows with and without blank lines |
| `source-single-line-64-mib` | One line, with tokens inside fragments and straddling known cuts |
| `source-many-tiny-50000`, `source-deep-tree`, `source-skewed-sizes` | File count, depth 64, and one 64 MiB file beside 10,000 small files |
| `source-mostly-ignored`, `source-binary-mix` | 95% allowlisted paths; skipped application and scanned image magic |
| `git-many-tiny-commits`, `git-wide-commit`, `git-merge-and-rename`, `git-archive-blobs` | History length, width, merges, renames, copies, and archive blobs |
| `archive-high-ratio-{gzip,zstd,bzip2}` | Zero runs under the member limit, and just over it with one limit issue |
| `archive-nested-depth-{8,9}`, `archive-tar-{10000,10001}-members` | Depth and entry limits at and past the boundary |
| `archive-zstd-many-small` | 500 streams of 1 KiB; peak RSS comes from the collector |
| `cli-many-issues`, `cli-stdin-chunked`, `cli-enable-rule-startup` | Issue output, write fragmentation, and rule selection startup |

Archive and Git archive-blob workloads run through the archive test driver
because compat does not enable the `archives` source feature. Zstandard and
bzip2 fixtures are hand-built zero-run streams, since no encoder is available
without a new dependency. The bzip2 expanded size is the nearest multiple of
255 bytes. `cli-many-issues` uses sparse files, so its disk use depends on the
filesystem. These workloads are synthetic shapes and do not establish field
speed. Freeze their definitions before collecting comparison runs.

## Default-rule scan workloads

The `default-rules` group adds synthetic scan workloads at decode depth zero,
using the packaged default configuration unless a workload generates its own.
Run the group, or replace it with one workload identifier:

```sh
bazelisk run //crates/xtask:xtask -- perf representative --workload default-rules --samples 3 --iterations 1
```

| Workload family | Coverage |
| --- | --- |
| `core-admission-*-rules-4-mib` | 1, 16, 64 or 150 distinct keywords in the first 4 KiB of keyword-free filler, testing whether cost follows admitted rules times bytes |
| `core-prose-keywords-*` | Documentation text dense in generic keywords, with no assignment operator |
| `core-near-miss-*-256-kib` | 4,096 `generic-api-key` candidates, each rejected by one filter |
| `core-tiny-*-b` | 100,000 small fragments, each with a file path and commit |
| `core-all-admitted-*` | Every default keyword at least once, admitting every rule |
| `core-keyword-run-*`, `core-prefix-storm-1-mib` | Keyword runs, keywords inside base64-like blobs, and secret prefixes without valid tails |
| `core-thrash-generic-1-mib` | High-variety `generic-api-key` contexts; compare the first-scan and steady-scan phases |
| `core-multibyte-*-4-mib` | CJK and uppercase Cyrillic prose with U+212A and U+017F keyword variants |
| `core-groupless-*` | Rules without a capture group: a large private-key block and 4,096 `ghp_` tokens |
| `core-generic-filter-*` | Generic-named findings retained through the quadratic suppression pass |
| `core-minified-findings-*` | Findings on one 1 MiB line, after the last newline, and one 64 KiB secret |
| `core-realistic-*-256-kib` | Lockfile, `.env`, Kubernetes YAML, JWT log, multi-language, binary and UTF-16 content |
| `core-custom-config-*` | Generated configurations with 1,000 or 5,000 rules, a large allowlist, or 50 keywordless rules |
| `core-long-lived-diverse` | 10,000 scans per operation cycling 20 input families on one engine |
| `core-contention-*` | 16 or 32 threads on 512-byte fragments, and match-dense 4 MiB with 8 shared workers |

Expected findings, byte ranges, locations, entropy and work counts come from
each generator's plant list and from literal keyword counts over the
configuration. They are not read back from a scan. Work is one scan pass, plus
one checkpoint per overlapping keyword occurrence, per admitted rule and per
regex candidate. Keyword lowercasing, `location()` and Shannon entropy are
restated in the fixture from the pinned upstream behavior. Small tests include
a one-byte-flip positive control for each near-miss filter, so suppression that
stops working fails the fixture.

`core-long-lived-diverse` reports retained behavior through the collector's
existing fresh-process peak RSS, which covers the whole child process. It is
not an isolated cache-memory measurement. By construction,
`core-minified-findings-1024-on-1-mib` copies its 1 MiB line into each of its
1,024 findings, and `core-generic-filter-*` compares every generic finding with
every finding, which is quadratic.

## CPU and retained-memory investigation

The optional investigation commands use the same synthetic core fixtures with a
separate protocol. They require a new absolute output directory outside the
checkout, with an existing parent that has no symlink components. The examples
use macOS's canonical temporary path. Raw profiles can include local paths, so
the directory is created with mode 0700 and files with mode 0600.

```sh
bazelisk run //crates/xtask:xtask -- perf profile --output /private/tmp/rustleaks-profile --workload core-default-many-keywords-16-kib --seconds 15
bazelisk run //crates/xtask:xtask -- perf calibrate --output /private/tmp/rustleaks-calibration --workload core-default-many-keywords-16-kib --pairs 9 --iterations 5
```

Profiling builds the optimized Bazel executable with
`-Cdebuginfo=line-tables-only` and `-Cforce-frame-pointers=yes`. The selected
compile action must contain both flags. The report binds the actual compiler,
arguments, action graph, executable, source and fixture identity. This follows
the [Rust Performance Book's profiling guidance](https://nnethercote.github.io/perf-book/profiling.html)
and the [rustc codegen contract](https://doc.rust-lang.org/rustc/codegen-options/index.html).
The profiling build has scope `profile-v1-instrumented-steady-loop` and is never
used to evaluate existing performance limits or uninstrumented speed changes.

The worker loads and compiles configuration, constructs the engine and fixture,
and validates one warm scan before sending a prepared marker. On macOS, the
controller takes `heap --noContent` and `vmmap -summary` snapshots at that marker,
then collects `sample` CPU stacks while the worker repeats steady scans. Each
scan must retain the exact outcome and work counts. The sampled loop includes
validation, outcome hashing and destruction, but excludes configuration and
engine setup. A second heap/VM snapshot observes the retained process after the
loop. These are live memory observations, not allocation histories, allocation
site attribution or evidence that every allocation has been freed. Sampling
overhead is not a performance improvement or regression measurement.

Native collection currently supports macOS. Missing tools, denied attachment or
unsupported hosts receive explicit unavailable/unsupported dispositions in the
private report; an empty profile is not successful evidence. On this development
host, `sample`, `heap` and `vmmap` exist, while Instruments `xctrace` needs a full
Xcode installation. The commands do not install it. Other hosts need their own
collector and native validation before a support claim. Unix permissions are
required by the current private-output implementation.

A successful native command must also produce a recognized observation: CPU
stacks require positive thread samples and symbolized frames from the measured
executable; heap output requires live-node/byte totals and populated class rows;
VM output requires a populated region table with positive totals. Empty,
header-only, unrecognized or unusable output is classified as unavailable or
invalid. The report retains numeric observation counts and artifact hashes.

Profile duration is 3 through 30 seconds, with five additional worker seconds
to cover collector startup. A 180-second controller deadline includes snapshots
and worker shutdown. Every child is terminated and reaped on failure, and the
private output is retained. Review the actual stacks before attributing cost:
the presence of a function in source is not profiling evidence.

Worker diagnostics are limited to 64 KiB and each native output file, including
the separate CPU stack file, to 16 MiB. The controller checks all output sizes
while children run and again after exit. Polling can overshoot between checks;
these bounds are not a filesystem quota.

## Informational regression calibration

Calibration uses the ordinary optimized Bazel executable and scope
`investigation-v1-steady-scan-only`. Scan timing excludes preparation, warmup,
validation and outcome destruction. It uses three ordered stages with independent
fresh processes and alternating AB/BA order within each stage:

1. Unchanged A/A training pairs establish an empirical noise band.
2. Separate unchanged A/A pairs test that frozen band.
3. A/extra-work pairs test sensitivity to a deliberate second complete scan per
   logical iteration. The extra pass is explicit in every sample's work count;
   it is not a production-code mutation or a comparable throughput result.

The versioned `empirical-paired-band-v1` policy sets the relative band to twice
the largest absolute training pair deviation, plus a fixed two-nanosecond term divided
by the smallest baseline batch time. Every held-out A/A pair must fit that band,
and every extra-work pair must exceed it. Otherwise the report says
`unstable-or-insensitive-no-gate`. This empirical rule is not a statistical
confidence interval or a universal tolerated-regression percentage. The tool
creates no release threshold and never updates an existing baseline.
That historical allowance is a heuristic, not an established clock-error bound.
Each sample sums separately timed scans; its stored integer nanoseconds do not
establish physical timer resolution.

The defaults are nine pairs per stage and five logical iterations per process.
Pairs are bounded to 5 through 31 and iterations to 1 through 100. Collection
has a 900-second deadline after build preparation and a 120-second cap per child.
All samples must have the same source, binary, configuration, inputs, exact
outcomes and baseline work counts. Raw ordered samples and training, held-out
and control ratios remain in the private report. Repeat the whole command into
a new output directory on a quiet host before judging stability. Thermal state
and unrelated system load are not controlled by the runner and must be described
with any published evidence. The operator currently selects from the default
many-keyword, one-keyword and no-hit 16 KiB cases, mixed and dense-positive
16 KiB cases, and depth-five decode case. Other representative workloads remain
available through the existing measurement command.

## Observation-window calibration

An explicit `--window-blocks` selects a separate optional protocol. It reuses
the existing scan timers and compiled engine across 1 through 16 blocks, each
containing the selected 1 through 100 logical iterations. Each block is retained
with a worker-issued index; counts and elapsed sums are checked independently.
An explicit value of 1 still selects the new protocol. Omission preserves the
legacy calibration behavior. `--first-side a|b` controls initial pair ordering
only in window mode.

```sh
bazelisk run //crates/xtask:xtask -- perf calibrate --output /private/tmp/rustleaks-window-calibration --workload core-dense-16-kib --pairs 9 --iterations 100 --window-blocks 10 --first-side a
```

Scope `investigation-v2-summed-scan-windows` sums individual scan durations,
not a continuous window timer. Policy `empirical-paired-window-band-v2` uses
exact rational decisions: twice the largest absolute training deviation is
the band, all held-out absolute deviations must fit, and every extra-work
deviation must exceed it. No physical timer-error bound is claimed or added.
Zero training variation remains `degenerate-training-no-gate`. Invalid
arithmetic or protocol data is a failure, not a discarded timing outlier.

The fixed [observation-window packet](plans/baseline-observation-windows.md)
predeclares two lengths, four workloads, two runs and all stopping rules. Its
matrix command accepts only the named protocol and a new private destination:

```sh
bazelisk run //crates/xtask:xtask -- perf calibrate --matrix observation-window-v2 --output /private/tmp/rustleaks-window-matrix
```

It prepares one build before collection, then uses that prepared identity for
all 16 cells. The 3,600-second matrix deadline, 900-second cell deadline and
120-second worker deadline share absolute acceptance checks. Each cell includes
a fixed five-second idle interval. Parent process-group supervision bounds
termination and pipe cleanup; raw partial transcripts remain private on failure.
The matrix continues after empirical calibration failure for the remaining
predeclared characterization, but stops after any integrity or deadline failure.
There is no retry, candidate comparison, baseline update or release threshold.

The [completed matrix](validation/baseline-observation-windows.md) did not
qualify the longer length across all guards. The later
[whole-process CPU investigation](validation/process-cpu-and-completion.md)
completed with qualified controls and an explicitly rejected candidate.
Component emission and collector activity can overlap later scans, so the
window observations do not isolate a causal effect of window length.

## Whole-span matcher experiment

The first matcher experiment preserved exact outcomes but did not exceed its
predeclared primary performance band. It was rejected and removed; no production
speedup is claimed. The [validation record](validation/semantics-and-matching.md)
and [ordered measurements](validation/matcher-experiment-2026-11-05.json) retain
the isolated and integrated comparisons, complete CLI measurements, guard
slowdowns, build identities and scope limits. This experiment adds no release
threshold or required periodic timing run.

## Dense scan investigation

Two native profiles of `core-dense-16-kib` retain the existing fixture and
exact 256-finding outcome. The [validation record](validation/source-semantics-and-dense-profiling.md)
distinguishes engine subtrees, inlined finding construction and measurement-loop
work. The [location experiment](validation/location-lookup-experiment.md)
preserved tested semantics but stopped on failed baseline calibration before
candidate timing. Its helper was restored. The observation-window packet above
examines that measurement prerequisite; no production speedup or new release
threshold is accepted from profiling alone.

## Optional reports

`just perf-report` collects a bounded private report or validates existing evidence.
See [performance reporting](PERFORMANCE_REPORTING.md) for status definitions,
import limits, and the reviewed seven-day sanitized-summary retention contract.

## Large in-memory fragment workloads

The representative suite includes `core-fragments-json-*`,
`core-fragments-log-*`, and `core-fragments-invalid-*`. They use the complete
packaged default configuration, decode depth zero, one retained engine, and
synthetic 512-byte records. Thirty-two provider names are spread across each
16 KiB block. One reviewed private-key sample ends each fragment. Its complete
finding, byte ranges, line and columns, and entropy are specified independently
of detection. Literal keyword occurrences and admitted rules independently
specify the exact work count: one pass, all overlapping keyword occurrences,
one checkpoint per admitted rule, and one match checkpoint. Every fragment
must finish with one finding record, no decoded bytes and no termination.

JSON and log cases cover 16 KiB, 256 KiB, 1 MiB and 4 MiB single fragments,
and 12 MiB operations split into 16 KiB or 256 KiB fragments. Invalid-UTF-8
log cases cover a 4 MiB fragment and 12 MiB split into 16 KiB fragments.
The invalid sequences occur throughout the input, independently of the
ASCII finding. All inputs are synthetic except the existing reviewed key
fixture. These data do not reproduce private application content.

Run the complete added matrix, or replace `fragments` with an individual
workload identifier:

```sh
bazelisk run //crates/xtask:xtask -- perf representative --workload fragments --samples 3 --iterations 1
```

First-scan and steady-scan phases sum the scan calls for one complete operation.
Fixture construction, engine compilation, validation, hashing and outcome
release remain outside those timers. All fragments in an operation and both
phases reuse one engine, so its backend caches can persist. The collector
reports fresh-process medians and peak process RSS with its existing source
and optimized Bazel executable identities. Peak RSS includes setup and does
not measure retained engine memory. Use the existing `perf profile` heap and
VM snapshots with `core-default-many-keywords-16-kib` to observe a long-lived
engine containing the full default configuration and warmed search caches.

`perf check`, and therefore `cargo xtask qualify`, additionally require on
the calibrated M1 Max host a median no greater than 1.5 seconds for both first
and steady phases of every 4 MiB and 12 MiB workload, from three independent processes. The existing
compile, hostile-regex and peak-RSS limits are unchanged. The new target is
an engineering budget measured on the implementation host, not a portable
latency promise. Other hosts run the same exact invariants and report medians
without enforcing this uncalibrated latency threshold. A different host
budget requires separate measurement and review.

The [fragment throughput record](validation/core-fragment-throughput.md)
compares the backend and preprocessing stages, exact outcome invariants,
retained memory and unchanged legacy budgets.

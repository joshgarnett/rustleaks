# Performance

This page is for contributors who measure or change performance. It explains
the performance tools, what each measurement includes, and how to keep and
share results. No result on this page is a portable speed guarantee.

## Rules for measurements

- Measure on a quiet host. Do not run builds, fuzzing or profiling at the
  same time. The tools do not control thermal state or other system load.
  Describe both with any results you publish.
- Freeze the workload definitions before you collect comparison runs, keep
  the normal controls, and run the measurements one after another.
- Reused-engine and first-scan phases need separate workloads before you
  compare them.
- CPU-time comparisons need their own timing scope. A CPU-time gain does not
  show a wall-time gain.
- Compare results only from the same host, target and build identity.
- Treat a run from a dirty working tree as information only. It is never a
  clean baseline.
- A faster scan that did not finish is not a result. Every workload checks
  its exact outcome, and a skipped input or a budget stop fails the run.
- No tool changes a baseline or a threshold. Changing a threshold needs new
  calibration evidence and review. New phase-only timers need a new timing
  scope and new calibration; they do not inherit the existing budgets.
- Invalid arithmetic or protocol data is a failure, not a timing outlier to
  drop.
- Normal Bazel tests check the outcome of every workload, including report
  bytes. Timing is never part of `just test`.

## Commands

| Command | What it does |
| --- | --- |
| `just perf-run` | Runs the 23 standard workloads with an optimized build and prints JSON Lines |
| `just perf-check` | Checks the full set of standard workloads and enforces the host budgets where they apply |
| `just perf-fixtures` | Builds or verifies synthetic fixtures with independent answers |
| `just perf-representative` | Runs the representative phase measurements |
| `just perf-profile` | Captures a native CPU and memory profile (Unix) |
| `just perf-calibrate` | Measures local noise and a deliberate slowdown control (Unix) |
| `just perf-report` | Collects or checks a private performance report |

To run one standard workload with a warmup and a fixed number of iterations:

```sh
bazelisk run //crates/xtask:xtask -- perf run --workload default-one-keyword --warmup 1 --iterations 10
```

Iterations are 1 to 10 and warmup is 0 to 10. A warmup run prepares a new
engine, so it warms process setup and caches, not a kept engine. A workload
may reuse its engine across measured iterations.

## Build identity

The tools build `//crates/rustleaks-compat:rustleaks_perf` with
`--compilation_mode=opt --stamp=no` and read the Rust compile actions. Each
report records:

- the compiler binary hash and version, the target, allowed compiler options,
  a digest of all arguments, the compile action key, the Rust action graph
  hash and the hashes of generated argument files;
- lockfile hashes, the workload definition hash and the executable hash;
- the packaged default configuration hash, which must match its pinned
  SHA-256 before the build; and
- the source identity: `HEAD`, dirty status, and a digest of tracked and
  untracked files that are not ignored.

Argument file paths appear only as digests. Environment values, user paths
and machine serial numbers are not recorded. The source and executable must
not change between preparation and measurement.

Running the benchmark executable directly gives rows marked
`unbound-runner`. Only xtask binds rows to the checked Bazel build, and it
rejects unbound rows and any mismatch in source, executable, graph, corpus,
timing scope or outcome.

## Standard workloads and budgets

The 23 standard workloads use the timing scope
`legacy-v1-includes-verification`. Their timers include finding or output
fingerprinting and, in some cases, dropping the outcome. Fixture preparation
and build steps are outside the timers. Report workloads count findings; scan
workloads count input bytes. Do not combine the two into one bytes per second
series.

`just perf-check` enforces elapsed time and peak memory budgets only on the
calibrated Apple M1 Max host class, from seven process samples. Other hosts
report that the budgets were not evaluated. The budgets were first calibrated
with Cargo release builds. Bazel results carry a different build identity, so
passing a budget is not a new calibration.

`perf check`, and so `cargo xtask qualify`, also requires on that host a
median of at most 1.5 seconds for the first and steady phases of every 4 MiB
and 12 MiB `core-fragments-*` workload, from three processes. This is an
engineering budget for that host, not a promise for others.

Peak RSS is measured for a fresh process and includes setup and fixtures. It
is not a count of scan allocations. Source fixtures are newly written, so
their timings are not cold-disk results.

## Development fixtures

`just perf-fixtures` builds synthetic inputs and their answers without
running a scanner. It has five families: source and encoding boundaries,
density, many decoded secrets in one carrier, connection strings, and reader
partitions. The dense and decoded-carrier cases adapt ideas from Kingfisher
revision `01e7b817376fbf2272be8f162bd32309bf97ee1f`. No upstream code or
fixture bytes are copied.

Use a new absolute folder outside the checkout:

```sh
just perf-fixtures --family density --output /tmp/rustleaks-development-density
just perf-fixtures --verify /tmp/rustleaks-development-density
```

Each bundle keeps `inputs/<case>/` apart from `answers/` and has a hashed
inventory. Scan one case's input folder, never the bundle root or the
answers. Verification checks the full family, the seeded literals, byte
positions, geometry, reader schedules and policy fields.

- Timing eligibility is decided before any scan. Large single-line and
  decoded-carrier cases are for quality only, because full line context in
  reports can grow quadratically.
- Connection cases need a review of credential extraction and policy before
  scoring.
- Negative controls for GitHub tokens apply only to that credential family.
- A fixture that generates and verifies is correct as a fixture. It says
  nothing about scanner coverage or speed.

## Representative measurements

The representative suite adds timers for each operation. It keeps the 23
standard workloads and their budgets unchanged. Run it on its own, after all
builds and fuzzing on the host have stopped:

```sh
just perf-representative
bazelisk run //crates/xtask:xtask -- perf representative --workload core-mixed-16-kib --samples 7 --iterations 100
```

- Each workload runs in separate processes: 3 to 31 samples (default 7) and 1
  to 1,000 steady iterations (default 25). Each process has a 600-second
  deadline.
- Rows use schema 3, suite `representative-v1` and scope
  `representative-v1-operation-only`. They cannot be compared with the
  standard budgets, and they have no thresholds.
- Core workloads report configuration parsing and compiling together,
  engine construction, the first scan in the process, and steady scans with
  the same engine.
- Fixture creation, expected results, hashing, validation and dropping the
  outcome are outside the timers. Each operation goes through `black_box`.
  Input, configuration and outcome fingerprints and exact work counts go with
  every row, and must be the same across samples.
- Total process time, CPU time and peak RSS include setup and are reported
  apart from phase times. CPU and RSS are `null` where the platform does not
  support Python's `resource` module. Allocation counts are always `null`.
- Summary rows give the median, minimum, maximum and median absolute
  deviation, and keep the raw samples. The median uses the upper middle value
  for an even count. No p95 is estimated.
- Every saved run must end with `run-complete`. Without it, the run did not
  finish.

### Workload groups

Without `--workload`, the command runs every representative workload. Select
a group, or one workload ID, with `--workload`. Start large groups with
`--samples 3 --iterations 1`.

The base workloads cover core mixed, dense, minified, invalid UTF-8,
multiline and many-rule inputs; default-rule controls; decode depth 0 and 5;
session merge; JSON and SARIF output; sources; Git; archives; and CLI
commands. Select them by ID, for example `core-mixed-16-kib`.

| Group | What it covers |
| --- | --- |
| `edges` | Long lines, many candidates, stopwords, invalid UTF-8, empty matches and percent decoding |
| `workers` | 12 MiB in 768 fragments on 1, 4 or 8 threads, with a shared engine or one clone per worker |
| `decode-report` | Decoder, baseline classification, report output and configuration compile operations |
| `source-scale` | 26 workloads for traversal, chunking, Git history shape, archive limits and CLI behavior |
| `default-rules` | Default rules at decode depth 0 on keyword, near-miss, Unicode, minified, realistic and contention inputs |
| `fragments` | JSON, log and invalid UTF-8 records in fragments from 16 KiB to 12 MiB |

Expected findings, work counts, decoded bytes and limit issues come from the
fixture generators and the documented limits, never from scanner output. Small
negative controls make sure that a broken filter or an incomplete scan fails.

Notes for some groups:

- Run `core-decode-long-line-many-findings` only on a host with at least
  12 GiB of free memory.
- The `source-scale` fragment boundaries follow a model of `FileSource`: a
  100,000-byte read, then read-ahead through a 4,096-byte buffer until a blank
  line or 25,000 extra bytes. A file without line breaks gives one
  125,000-byte fragment and then 28,672-byte fragments.
- Archive workloads run through the archive test driver, because
  `rustleaks-compat` does not turn on the `archives` feature. Zstandard and
  bzip2 fixtures are hand-built zero runs, since no encoder is available
  without a new dependency.
- The `fragments` workloads end each fragment with one reviewed private-key
  sample. Every fragment must finish with one finding, no decoded bytes and
  no termination.

## Profiling and calibration

These commands need a new absolute output folder outside the checkout, whose
parent exists and has no symbolic links. The folder gets mode 0700 and files
get mode 0600, because raw profiles can include local paths.

```sh
bazelisk run //crates/xtask:xtask -- perf profile --output /private/tmp/rustleaks-profile --workload core-default-many-keywords-16-kib --seconds 15
bazelisk run //crates/xtask:xtask -- perf calibrate --output /private/tmp/rustleaks-calibration --workload core-default-many-keywords-16-kib --pairs 9 --iterations 5
```

### Profiling

- The profiling build adds `-Cdebuginfo=line-tables-only` and
  `-Cforce-frame-pointers=yes`, and uses scope
  `profile-v1-instrumented-steady-loop`. It is never used to judge speed or
  budgets.
- The worker prepares the engine and checks one warm scan, then the
  controller takes `heap --noContent` and `vmmap -summary` snapshots, collects
  `sample` CPU stacks during steady scans, and takes a second snapshot after
  the loop. These are live memory views, not allocation histories.
- `core-realistic-multi-language-256-kib` is also accepted. It checks every
  usage counter after each scan.
- Native collection supports macOS only. Missing tools, denied access or an
  unsupported host give an explicit `unavailable` or `unsupported` result.
  An empty profile is never a success. Other hosts need their own collector
  and native validation before a support claim.
- A successful observation needs real content: CPU stacks with samples and
  symbols from the measured executable, heap totals and class rows, and a
  populated VM region table.
- Profile duration is 3 to 30 seconds. The controller deadline is 180
  seconds. Worker diagnostics are limited to 64 KiB, and each native output
  file to 16 MiB. Read the actual stacks before blaming a function.

### Calibration

Calibration uses the normal optimized build and scope
`investigation-v1-steady-scan-only`. It runs three stages of fresh processes
in alternating AB and BA order:

1. Unchanged A/A pairs set a noise band.
2. Separate A/A pairs test that band.
3. A/extra-work pairs, which run a second full scan on purpose, test that the
   band can detect a slowdown.

Policy `empirical-paired-band-v1` sets the band to twice the largest training
deviation, plus two nanoseconds divided by the smallest baseline batch time.
Every held-out A/A pair must fit, and every extra-work pair must exceed the
band; otherwise the result is `unstable-or-insensitive-no-gate`. Zero
variation in the training pairs gives `degenerate-training-no-gate`. This is not
a statistical confidence interval, and it creates no release threshold.

Defaults are nine pairs per stage and five iterations per process (pairs 5 to
31, iterations 1 to 100). Collection has a 900-second deadline and 120
seconds per child. Repeat the whole command into a new folder before judging
stability. Supported workloads are the default many-keyword, one-keyword and
no-hit 16 KiB cases, the mixed and dense 16 KiB cases, and the depth-five
decode case.

`--window-blocks N` (1 to 16) selects the observation-window protocol, scope
`investigation-v2-summed-scan-windows` and policy
`empirical-paired-window-band-v2`. `--first-side a|b` sets the first side of
each pair. A fixed matrix runs 16 cells with one prepared build:

```sh
bazelisk run //crates/xtask:xtask -- perf calibrate --output /private/tmp/rustleaks-window-calibration --workload core-dense-16-kib --pairs 9 --iterations 100 --window-blocks 10 --first-side a
bazelisk run //crates/xtask:xtask -- perf calibrate --matrix observation-window-v2 --output /private/tmp/rustleaks-window-matrix
```

The matrix has a 3,600-second deadline, 900 seconds per cell and 120 seconds
per worker, with a five-second idle interval per cell. It stops after any
integrity or deadline failure. Window results do not isolate the effect of
window length.

## Reports

`just perf-report` collects a private report or checks an existing one. It is
optional and is not part of release checks or scheduled workflows.

```sh
just perf-report --output /private/tmp/rustleaks-performance-report
just perf-report --output /private/tmp/rustleaks-performance-budget --legacy-budget
```

The first command collects the standard workloads once; its times are
information only. `--legacy-budget` applies the M1 Max budgets: one untimed
warmup, seven fresh process samples, and RSS from the first three processes.
Other hosts report a skipped budget. A run on a busy host does not qualify
the budgets.

Collection has a 900-second deadline, including the build. The process tree
is ended and reaped in all cases. Captured output is limited to 16 MiB.

To summarize an existing private report without collecting timings:

```sh
just perf-report --input /private/tmp/rustleaks-profile/report.json --output /private/tmp/rustleaks-profile-summary
just perf-report --input /private/tmp/rustleaks-representative/rows.jsonl --output /private/tmp/rustleaks-representative-summary
```

Accepted inputs are this command's `collection.json`, schema 1 profile and
calibration reports, schema 2 window calibration and matrix reports, and
complete schema 3 representative JSON Lines. Inputs must be regular files
readable only by the owner, without symbolic links or hard links, and at most
16 MiB each. Representative input is limited to 8,192 rows and must include
every sample and the `run-complete` marker. Imports recompute classifications
and check hashes and identities. They cannot prove that a report was not
fabricated.

| Status | Meaning |
| --- | --- |
| `invariant-failure` | The runner reported an invariant failure, or rows failed exact outcome checks |
| `execution-failure` | The runner failed without an invariant failure |
| `qualified-regression` | Complete standard samples exceeded a budget on the calibrated host |
| `legacy-budget-passed` | Complete standard samples met the budgets |
| `skipped-legacy-host-budget` | Budgets were requested but not evaluated on this host |
| `informational-timing` | Complete timing with no budget decision |
| `unavailable-profile-tool` | Unsupported host, or a native observation was unavailable |
| `complete-profile` | Complete worker results and matching native observations |

A collection, invariant or budget failure exits with a nonzero status.
Imported reports say `verification: report-consistency-only`; new
collections say `verification: local-collector`. Every public summary says
`release_gate: false`.

### Keeping and sharing results

Raw inputs, runner output, diagnostics, build identity, hardware details and
profiles stay on the local machine. Review raw evidence before you delete it.

`summary.json` is the only file that may be shared. It holds fixed statuses,
names, identity digests, numbers and fixed profile references, and no
findings, raw profiles, paths, compiler arguments or environment values.
Check it before sharing:

```sh
just perf-report --verify-summary /private/tmp/rustleaks-performance-report/summary.json
```

A workflow that shares a summary must upload that exact file only, with
`retention-days: 7` and `if-no-files-found: error`. Never upload the private
folder, use wildcard paths, or print raw files into workflow logs. No
scheduled job runs these reports.

## Known costs

The faster scan paths add some setup and memory costs. The numbers below
compare `v0.1.0-alpha.6` with the code just before `v0.1.0-alpha.7`, on one
Apple M1 Max host. They are not portable guarantees.

- Configuration parse and compile take about 20 to 30 percent longer. The
  packaged default configuration went from about 55 ms to about 68 ms.
- Engine construction with the default configuration went from about 0.2 ms
  to about 0.7 ms.
- CLI startup with empty standard input is about 13 ms slower, from about
  61 ms to about 75 ms.
- Peak process memory for a generated 5,000-rule configuration went from
  about 49 MiB to about 119 MiB.

These costs follow from current behavior:

- Each finding charges its complete physical line against the logical payload
  budget, so dense findings on one long line use that budget quickly.
- Findings on the same original line of at least 4 KiB share one stored copy.
  Public clones and session snapshots copy the line again.
- The anchored literal search runs only on ASCII input. Non-ASCII and invalid
  UTF-8 input use the unanchored search and get none of that speedup.
- With a cancellation signal, bulk work charges poll the signal once per work
  unit. The faster single bulk charge applies only to scans without a signal.
- Hostile input or large Unicode classes can make the lazy DFA cache thrash or
  give up. The search then falls back to PikeVM. One search stays linear in
  input length for a fixed pattern, but the speedup is lost.
- There is no linear-time bound for a whole scan that enumerates every match.

Library users who decide whether to move synchronous scans off an async
executor must measure their own target, runtime, configuration and request
mix.

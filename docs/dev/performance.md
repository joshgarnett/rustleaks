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

`just perf-fixtures` builds synthetic inputs and their answers. It has five
families: source and encoding boundaries, density, many decoded secrets in one
carrier, connection strings, and reader partitions. Generation and `--verify`
do not run a scanner. Only `--check` does. The dense and decoded-carrier
cases adapt ideas from Kingfisher revision
`01e7b817376fbf2272be8f162bd32309bf97ee1f`. No upstream code or fixture bytes
are copied.

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

### Checking large fixtures against their answers

`--check` verifies a generated bundle, scans its largest cases with the CLI,
and compares each report with the answers. It is a manual check. No test,
`just ci` or qualify run starts it.

```sh
bazelisk build -c opt //crates/rustleaks-cli:rustleaks
cp "$(bazelisk cquery -c opt --output=files //crates/rustleaks-cli:rustleaks)" /private/tmp/rustleaks-opt
just perf-fixtures --family density --output /private/tmp/fx-density
just perf-fixtures --check /private/tmp/fx-density --cli /private/tmp/rustleaks-opt
```

Paths must be absolute and must not contain symbolic links, so use
`/private/tmp` on macOS. `--cli PATH` picks the CLI binary. Without it, the
check uses `bazel-bin/crates/rustleaks-cli/rustleaks`. `bazel-bin` follows the
last build, and `just perf-fixtures` builds xtask without `-c opt`, so pass
`--cli` to measure an optimized build. The first output line names the CLI
path and its SHA-256, and the summary line repeats the SHA-256.

`--profile PATH` picks another profile. The default is the example profile in
[Complete scanning](../user/complete-scanning.md#the-profile-file), kept byte
for byte in `ORIGINAL_LIMITS`. It is for diagnosis, not a default.

| Family | Scan unit | Units |
| --- | --- | ---: |
| `boundaries` | One kind and anchor: 132 raw or 186 Base64 cases, copied as `<id>.txt` into a private folder | 12 |
| `density` | Each 524,288 or 2,097,152 byte case, as `inputs/<id>/` | 24 |
| `decoded-carrier` | Each 4,096 record case, as `inputs/<id>/` | 8 |

Other families fail with "no check subset for this family". Each unit runs
one CLI process with a cleared environment, all three native packs,
`--max-decode-depth 5`, `--max-archive-depth 0`, `--base64-mode compatible`,
an empty ignore file and `--timeout 600`. Each case's answers must expect
`github-pat`.

Reports and logs stay in a private scratch folder named
`rustleaks-private-fuzz-<id>` in the system temporary folder (`TMPDIR`). The
check refuses a scratch folder inside the checkout. The folder is removed when
no unit fails. Otherwise it is kept, and the check prints the error and the
folder path to standard error. Each unit has a `unit-<n>` folder with its
report and standard error.

The check compares `(case, value, start line, decode depth)` as multisets for
the `github-pat` rule. Columns are not compared. Findings from other rules are
counted, not judged. Each unit has one outcome:

| Outcome | Condition |
| --- | --- |
| `exact` | Exit 0 or 1, `status=complete`, and the planted and reported tokens match. |
| `stopped` | Exit 2, `reason=resource_exhaustion`, a `resource` other than `none` or `unknown`, and every reported token matches a planted token's value, line and decode depth. |
| `failed` | Anything else. |

A `stopped` unit is incomplete coverage, not a pass. A unit whose standard
error or report cannot be read fails with a `problem` text. The command exits
nonzero when a unit fails. Output lines hold names and counts, never a token.

The measured outcomes are in [Resource
limits](../user/resource-limits.md#large-inputs-under-the-example-profile).
The 20,000-line Base64 row there comes from a separate scan of a synthetic
input, run by hand with the same options. No fixture family generates it, so
`--check` does not cover it.

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
| `packs` | Native rule packs at library level: startup, keyword admission, mixed input and workers |
| `cli-matrix` | Fresh CLI processes in `dir` and `git` modes on one generated repository |
| `dense` | Dense findings from 25,000 to 400,000 bytes, long lines and many findings |
| `git-shapes` | Git reader shapes: one huge hunk, many files, many branches, merges and renames |
| `filters` | Allowlist, stopword, capture group, composite rule and finding construction costs |

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

### Packs, CLI, dense, Git and filter groups

These five groups cover native rule packs, the complete profile, the CLI in
both scan modes, dense findings and Git reader shapes. No workload in them has
a budget. Unit tests run every one of them at a smaller size and check the
exact outcome, so `just test` covers them; timing stays manual. Shared
generators are in `crates/rustleaks-compat/src/perf/suite_support.rs`.

Planted values are synthetic GitHub tokens (`github-pat`), database URIs for
the connections pack rule
`rustleaks.connection-string.password.database-uri`, and fixed literals for
custom rules. Filler text comes from a fixed word list. Before a run, a check
fails if the filler holds any keyword of the selected configuration, so only
plants can produce findings. Lines and columns follow the rules in
[Reports](../user/reports.md#line-and-column-numbers).

#### `packs`

Library scans with the default configuration plus native packs, compiled
through `NativePolicy` as `--native-pack` does. Each workload reports
configuration compile, engine construction, first scan and steady scans. The
compiled rule count must equal 222 plus the `[[rules]]` tables in the pack
files. These workloads guard the shared native keyword pass, the allowlist
compile cache, matcher construction on first use and the required-literal
skip for pack rules without keywords.

| Workload | What it measures |
| --- | --- |
| `packs-startup-none`, `-extra`, `-providers`, `-connections`, `-all` | Compile, construction and a first scan of a three-line input with one GitHub token and one database URI, for no pack, each pack and all packs. The URI is a finding only with the connections pack. |
| `packs-keywords-none`, `packs-keywords-all` | 256 KiB of every keyword that holds no shorter keyword, each followed by a NUL byte, then one GitHub token line. Every such keyword occurs and the token is the only expected finding. |
| `packs-mixed-none`, `packs-mixed-all` | 1 MiB of filler lines with a GitHub token and a database URI every 64 lines. |
| `packs-workers-all-1`, `-4`, `-8` | 64 copies of a 64 KiB mixed fragment on 1, 4 or 8 persistent threads that share one engine with all packs. The timer covers dispatch, scans and result collection. |

#### `cli-matrix`

Each phase starts a fresh CLI process per iteration and checks its exit
status, JSON report, `scanned ~N bytes` line, commit count and, with a
profile, the complete-profile status line. The repository has 256 files of
16 KiB with one GitHub token each, one database URI, eight Base64 values
encoded once, four encoded six times, and a TAR file holding a TAR file that
holds one more token. It is written as a working tree and imported as three
commits, so `dir repo` and `git repo` scan the same files. A plant is
expected when its decode depth, archive depth and pack fit the flags: values
encoded six times need decode depth 6 or more, and the TAR leaf needs archive
depth 2 or more.

| Workload | Phases |
| --- | --- |
| `cli-matrix-startup-packs` | Empty standard input with no pack, each pack and all packs. |
| `cli-matrix-dir-decode-depth`, `cli-matrix-git-decode-depth` | `--max-decode-depth` 0, 5 and 8. |
| `cli-matrix-dir-archive-depth`, `cli-matrix-git-archive-depth` | `--max-archive-depth` 0 and 8. |
| `cli-matrix-dir-report`, `cli-matrix-git-report` | No report, and a JSON report written to a file, at decode depth 5. |
| `cli-matrix-dir-packs-profile`, `cli-matrix-git-packs-profile` | All packs on or off, crossed with `--complete-profile` on (one worker) or off. |
| `cli-matrix-dir-workers`, `cli-matrix-git-workers` | All packs with a complete profile of 1, 4 or 8 workers. |
| `cli-matrix-dir-size-series` | Folders of 0, 1, 16 and 128 MiB in 64 KiB files with one token each. The empty folder gives the fixed cost of a process; the others give the cost per byte. |
| `cli-matrix-dir-ignore-baseline` | No suppression, an ignore file, and a baseline. The ignore file and the baseline each hold 10,000 unrelated entries and one entry for a planted finding, which must then be missing from the report. |

The complete profile is the example from [Complete
scanning](../user/complete-scanning.md#the-profile-file) with `workers` set
to 1, 4 or 8 and `queue_capacity=8`. Git runs use
`--log-opts "--all --full-history --no-ext-diff --no-textconv --no-renames"`
and the declared Git tool. The size series writes 128 MiB to the system
temporary folder.

#### `dense`

Library scans after a warm scan outside the timers. The dense shapes adapt
the Kingfisher dense findings script (`scripts/benchmarks/dense_findings.py`
at v2.19.1). Each runs at 25,000, 50,000, 100,000, 200,000 and 400,000
nominal bytes and fills whole records up to the size. Each iteration scans
every size once, smallest first, so drift on the host affects all sizes
alike. The time ratio between neighboring sizes is near 2 for linear growth.

The shapes from `dense-planetscale-ids` to `dense-ebay-client-ids` use the
default rules plus the providers pack. Except for `dense-planetscale-pairs`,
their records match only pack support rules, which have `skipReport = true`,
so they give many candidates and no reported finding. Each of them ends with
one GitHub token line, the only expected finding.

| Workload | Shape |
| --- | --- |
| `dense-github-lines` | One GitHub token per line, default rules. |
| `dense-github-one-line` | GitHub tokens separated by spaces on one line, default rules. |
| `dense-filter-one-line` | `cloudflare = '<value>'` records on one line. Each value has entropy 1.0, below the `cloudflare-api-key` threshold of 2, except the last, which is the one expected finding. |
| `dense-base64-uris` | MySQL URIs repeated to three quarters of the size, then encoded as one Base64 string, with the connections pack at decode depth 1. Every password is a finding at line 1, column 1, because decoded findings report the columns of the encoded text. |
| `dense-long-line-sparse` | One line of 1, 4 or 16 MiB of filler words with eight GitHub tokens spread evenly. |
| `dense-planetscale-ids` | `pscale ID` and a 12-byte lowercase ID per line. |
| `dense-planetscale-loose-ids` | `pscale`, 0 to 15 separator bytes, `ID`, 0 to 15 separator bytes and a 12-byte ID per line. |
| `dense-planetscale-pairs` | A PlanetScale ID line, then a `pscale_tkn_` token line. Each token is reported twice: by the default `planetscale-api-token` rule and by the pack rule `rustleaks.association.planetscale-api-token`, which needs an ID support match anywhere in the same buffer. |
| `dense-jfrog-hosts` | One `<name>.jfrog.io` host per line. |
| `dense-clickhouse-ids` | `clickhouse ID` and a 20-byte lowercase ID per line. |
| `dense-cloudinary-names` | `cloudinary CLOUD NAME` and a 12-byte lowercase name per line. No rule has these keywords. |
| `dense-salesforce-hosts` | One `<name>.my.salesforce.com` host per line. |
| `dense-tableau-hosts` | One `<name>.online.tableau.com` host per line. |
| `dense-auth0-domains` | One to three random labels and `auth0.com` per line. |
| `dense-ebay-client-ids` | One client ID per line: two names, `PRD` and two hexadecimal parts. |
| `memory-many-findings-scan` | One fragment of 300,000 lines that each hold one finding of a custom rule. |
| `memory-many-findings-json` | The same scan, then a JSON report of all findings written through a buffered file writer. A streaming check reads the file back after the timer and keeps one bit per finding. |

The two `memory-many-findings-` workloads differ only by the report. Compare
their peak RSS to see the memory the JSON writer adds; peak RSS covers the
whole process, including the retained findings.

#### `git-shapes`

Each workload reports a phase for the Git reader alone and one for the reader
with detection, like `git-many-tiny-commits`. Expected fragments are the
added lines of each hunk that `git log -p -U0` prints for the given log options.

| Workload | Shape |
| --- | --- |
| `git-one-huge-hunk` | One file of 32,768 lines, then a commit that replaces every line, so one hunk removes and adds 32,768 lines. |
| `git-many-small-files` | 1,000 three-line files, then one commit that changes the middle line of each. |
| `git-many-branches` | 1,000 branches from one root commit, each adding one file. |
| `git-merges` | 500 feature commits, each merged into the main line. With merge diffs off, `git log` prints no merge diff. With `--diff-merges=first-parent`, each merge prints its added file again, so every plant is found twice. |
| `git-renames` | 500 files moved to a new folder with one line edited. With `--no-renames` each moved file is a new file; with `-M` only the edited line is printed. |

The Git reader runs `git log`, so the reader phase covers the history walk
and patch parsing together. No phase walks history without patches.

#### `filters`

Library scans of generated `token=<value>` lines and similar records. Values
never contain `q` or `z`, so a generated stopword (`qz0000` and up) or
allowlist pattern (`zq0000` and up) occurs only where it is planted.

| Workload | Phases |
| --- | --- |
| `filters-allowlist-build` | Configuration load and engine construction with 10, 100 and 1,000 allowlist regexes or stopwords, and with 100 rules that share one 20-entry allowlist. A probe after each phase checks that the last entry rejects a value. |
| `filters-match` | 1,000 values against 1,000 stopwords, 100 allowlist regexes and 100 global path patterns, each with an input where every value but the last is rejected and one where none is. The allowlisted path skips its whole fragment, so that phase also scans a one-line fragment outside `vendor/` as the control. |
| `filters-capture-groups` | 1,000 lines of `token=secret-NNNNNN account=user-NNNNNN` with rules of 0, 1, 2 named and 6 named capture groups. |
| `filters-composite-proximity` | 1, 10 or 40 primary and component pairs, padded with lines of 999 dots to at least 100,000 bytes. Every primary is reported with every component. |
| `filters-finding-construction` | 1,000 records of `token=`, six digits and 88 dots, one per line or all on one line. Rules accept every record, allowlist all but the last, or require a component that only the last record has. |

A composite finding keeps every component within range and does not build
combinations of components, so no workload measures combination counts.

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
  Decoder predecessor charges and native line coordinates are linear in the
  input, so this polling is too. See [Engine
  internals](engine-internals.md#cancellation).
- Hostile input or large Unicode classes can make the lazy DFA cache thrash or
  give up. The search then falls back to PikeVM. One search stays linear in
  input length for a fixed pattern, but the speedup is lost.
- There is no linear-time bound for a whole scan that enumerates every match.

Library users who decide whether to move synchronous scans off an async
executor must measure their own target, runtime, configuration and request
mix.

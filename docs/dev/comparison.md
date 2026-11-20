# Scanner comparison

This page is for contributors who compare Rustleaks with Gitleaks,
Betterleaks and Kingfisher. It explains how to run the comparison harness,
what each lane means, what the harness measures, and the limits of the
results. No result from this harness is a portable speed or quality
guarantee.

The latest recorded comparison followed
[benchmarks/comparison/PROTOCOL.md](../../benchmarks/comparison/PROTOCOL.md).
Its results are in
[benchmarks/comparison/results-2026-11.md](../../benchmarks/comparison/results-2026-11.md).

## What the harness does

The harness runs several scanner binaries on the same inputs and records:

- wall time, user CPU time, system CPU time and peak RSS for every run;
- the exit code, the number of findings and a digest of the findings;
- one-to-one matches between tools, and precision, recall and F1 against
  labels when a workload has labels;
- the host, tool versions and hashes, every flag that is not a tool default
  with its reason, and the load average before and after every run.

It never downloads, builds or updates a scanner. You give it binaries and
their SHA-256 hashes. It checks each hash before and after a run.

The harness is Python 3.9 standard-library code in
`crates/xtask/src/comparison/`. The xtask binary embeds it and runs it with
`python3 -I -`, so no Python package is needed and Python environment
variables are ignored. The program goes to Python on standard input, because
it is too large for one command-line argument on some platforms. The harness
needs a Unix host for `wait4` and process groups.

## Commands

| Command | What it does |
| --- | --- |
| `cargo xtask compare run` | Runs tools on workloads and writes a private run folder |
| `cargo xtask compare score` | Matches findings one to one, for a run folder or for two reports |
| `cargo xtask compare report` | Writes `summary.json` and `report.md` for a run folder |
| `cargo xtask compare self-test` | Runs the synthetic self-test with fake scanners |
| `just compare ARGS` | Runs `cargo xtask compare ARGS` through Bazel |

The self-test also runs in `just test` as part of the xtask unit tests.

## Inputs

### Tools manifest

The tools manifest lists the binaries to compare.
[`benchmarks/comparison/tools.example.json`](../../benchmarks/comparison/tools.example.json)
shows every field:

```json
{"schema": "rustleaks-comparison-tools-v1",
 "tools": [{"id": "gitleaks-8.30.1", "family": "gitleaks", "version": "8.30.1",
            "binary": "/abs/path/gitleaks", "sha256": "...", "build": "release",
            "regex_engine": "go-re2", "rule_count": 222,
            "rule_source": "embedded default configuration", "notes": ""}]}
```

- `family` is `rustleaks`, `gitleaks`, `betterleaks` or `kingfisher`.
- Betterleaks 1.x and 2.x have different command lines. The harness picks
  the adapter from the major version. Set `"adapter": "betterleaks-v2"` or
  `"betterleaks-v1"` to choose it yourself.
- `rule_count` and `rule_source` are optional and appear in the report. The
  harness also counts Betterleaks 2 rule IDs and reads the Kingfisher rule
  count from its report.
- For a local Rustleaks build, record the commit and build command in
  `build` or `notes`.

### Workload manifests

Workload manifests use the schema `rustleaks-comparison-workloads-v1`. Each
workload has an `id`, a `family`, the `modes` it supports (`dir`, `git`), a
`path` relative to the cache root, a `size` with input bytes, files and
commits, an optional `labels` file and a `tuned` flag. Pass `--cache-root`
for the folder that holds the inputs. Inputs are fetched or generated outside
the repository, never committed.

Input bytes for throughput come from the manifest. When the manifest gives
none, the harness counts the regular files outside `.git` itself. It never
uses a byte count printed by a tool. Git mode has throughput only when
`size.git_bytes` is set, because the tools read different Git data.

A workload can set a Git scan range in `source.params`: `git_base`,
`git_head` and `git_log_options`. Gitleaks, Betterleaks 1 and Rustleaks get
`--log-opts` (the options, or `BASE..HEAD`). Betterleaks 2 gets `--revision`
and Kingfisher gets `--branch` and `--since-commit`. A range given only as
log options cannot be passed to Betterleaks 2 or Kingfisher, so those cells
are skipped.

Rustleaks and Gitleaks load `.gitleaks.toml` and `.gitleaksignore` (and the
`.rustleaks` names) from the scan root by themselves, and Betterleaks 1
loads ignore files. The harness lists such files for each workload. Cells
whose tool would load one are skipped, because the tool would not run with
its shipped defaults. Pass `--target-config run` to run them anyway; the
report then lists them as flagged cells.

### Labels

A labels file is JSON Lines, one object per labeled item. Labels hold no
secret text. The scorer reads the text at the offsets from the input, checks
its SHA-256, and reports labels that do not check. Unknown fields are
ignored. This section is the reference for the format; the pages on
[workloads](comparison-workloads.md#labels) and
[quality inputs](comparison-quality.md#labels) describe only what their
sources add.

Every label has these fields:

| Field | Meaning |
| --- | --- |
| `workload` | Workload ID |
| `path` | Path relative to the workload folder, with forward slashes |
| `commit` | Commit ID for a Git workload, otherwise `null` |
| `start`, `end` | Byte offsets of the labeled text in the file at that commit. `end` is exclusive. Encoded and staged values use other offsets, as described below |
| `line` | One-based line of `start`. The scorer computes the line from `start` and reports a label whose `line` differs |
| `secret_sha256` | SHA-256 of the labeled bytes; for an encoded value, of the decoded value |
| `category` | Credential family, such as `vcs-token`, or the rule ID for fixtures |
| `label` | `secret` or `not-secret` |
| `source` | Where the label comes from, such as `constructed`, `credData` or `fixture` |

Optional fields:

| Field | Meaning |
| --- | --- |
| `end_line` | One-based line of the last labeled byte |
| `span` | How a finding matches the label. See the table below |
| `encoding` | `base64` or `zstd`. See below |
| `decoded_start`, `decoded_end` | For `encoding: base64`, the secret's offsets in the decoded bytes |
| `staged` | `true` when the offsets index the staged blob in the Git index, not the file in the worktree. `commit` is then `null` |
| `expected`, `expected_count` | How findings on the label count. See below |
| `reachable_from_head`, `introduced_by`, `in_binary` | Scope differences. See [Git labels and scope differences](#git-labels-and-scope-differences) |
| `home_tool` | The tool whose own example the label comes from |
| `kind`, `fixture_tool`, `fixture_rule`, `fixture_case`, `fixture_origin` | Descriptive only; the scorer does not read them |

The label is `secret` or `not-secret`. Any other value, such as `ambiguous`,
leaves the item out of precision and recall: the label is not counted as a
secret or a non-secret, and a finding on it is counted as excluded.

Kinds of label:

| Fields | Matches |
| --- | --- |
| none of the below | A finding on intersecting lines with matching text |
| `"span": "line"` | Any finding whose line range intersects the label's lines |
| `"span": "case"` | Any finding in the same file; the SHA-256 is of the whole case |
| `"encoding": "base64"` or `"zstd"` | A finding in the same file, or in the archive at that path, whose secret has the label's SHA-256, at any position |

A label without `"span": "line"` or `"span": "case"` is a value label, even
when it covers a whole line. The workload generators write `"span":
"secret"` for a value label.

Offsets for encoded values:

- `encoding: base64`: `start` and `end` cover the Base64 text in the file.
  `decoded_start` and `decoded_end` locate the secret in the decoded bytes.
- `encoding: zstd`: `start` and `end` index the decompressed member, not the
  compressed file.

`expected` changes how findings on a label count:

- `exactly_one`: one finding matches; more are over-reporting.
- `count`: `expected_count` findings match; more are over-reporting.
- `none`: every finding on the label is a false positive.

Other values, such as `exact` and `at_least_one`, count like a label without
`expected`.

Labels with the same path and commit whose byte ranges overlap form one
group, such as a whole-line label and a value label on the same line. A
finding that matches any member satisfies the whole group, so the second
label is not counted as a missed secret. A group is a secret when any member
is a secret. Its category and source come from its narrowest secret member.
Encoded labels are never grouped.

#### Git labels and scope differences

- A label belongs to `git` mode when it has a commit, an `introduced_by`
  commit, or `"staged": true` (read from the Git index). Other labels belong
  to `dir` mode.
- A finding whose secret has the SHA-256 of a secret label at another
  commit or path, such as after a rename or in a merge diff, is a duplicate,
  not a false positive.
- Labels with `"reachable_from_head": false`, `"introduced_by": "merge"` or
  `"in_binary": true` are scope differences. They have their own rows and
  are left out of the overall recall.

Set `"labels_complete": false` on a workload when its labels do not cover
every secret, as with CredData. A finding that matches no label then counts
as unknown, not as a false positive. Labels are complete by default, as in
the synthetic corpora, where any finding outside a secret label is a false
positive. For `compare score` with report files, pass `--labels-partial`
instead. A labels file named in a manifest but missing is reported as a
warning and in the workloads table.

The labeled corpora and the CredData adapter are described in
[Comparison quality inputs](comparison-quality.md), and the workload sets in
[Comparison workloads](comparison-workloads.md).

## Running a comparison

```sh
cargo xtask compare run \
  --tools /path/to/tools.json \
  --workloads benchmarks/comparison/workloads/public-repos.json \
  --cache-root /path/to/cache \
  --output /path/to/private/run-2026-11-20 \
  --lanes defaults,threads,features,shared-rules,rustleaks-2x2
```

The output folder must not exist. It is created with owner-only permissions
because raw reports contain secrets. Keep it outside the repository.

Useful options:

- `--tool ID` and `--workload ID` select a subset. Both can be repeated.
- `--modes dir,git` selects the scan modes.
- `--threads 1,4,all` sets the threads lane values. `all` means every
  logical CPU.
- `--dry-run` writes the plan to `run.json` and prints it without running
  any tool.
- `--runs N` and `--warmups N` override the run counts for a quick check.
  The report then says that the run is not a protocol run.
- `--timeout SECONDS` stops one sample. The default is 3600.
- `--max-hours HOURS` is the time budget for the whole run. The default
  is 8.

### Time limits

Every step of a run has a finite limit:

- A sample that passes `--timeout`, or whose logs or report pass their size
  limits, has its process group killed with `SIGKILL`. The kill repeats every
  second. If the process is still not collected 60 seconds after the first
  kill, the harness stops waiting and records the sample with the status
  `timeout-unreaped` or `output-limit-unreaped`.
- After a scanner exits, any process left in its group is killed and checked
  again for up to 2 seconds. A sample whose group still has processes, or
  whose group could not be checked, gets `group_survivors_after_kill`.
- The `git` shim of the instrumented run kills `git` after `--timeout`
  seconds and stops waiting 60 seconds later.
- Version and host probes stop after 20 seconds, with every process they
  started.
- No sample starts after the `--max-hours` budget is used up. A sample that
  is running then finishes or reaches its own timeout. Cells that did not
  get all their samples are listed as skipped with the reason
  `run time budget reached`, and their samples stay in `samples.jsonl`.
  `run.json` records the budget under `time_budget`, with whether it was
  reached, and the report lists it as a protocol deviation.
- Scoring stops after `--score-hours` (default 12) on `compare run` and
  `compare score`. Comparisons and quality rows not finished by then are
  listed under "Not scored" in the report. Reading a labeled file from a
  commit with `git show` stops after 10 minutes.

At the end, the harness verifies the binary hashes, scores the kept reports
and writes the report.

Scoring work is bounded by input size. Each finding is compared with at most
64 candidates: items with the same text, paired by rank in line and column
order, and then the nearest items by line and column. Hints that explain
unmatched items are computed for the first 5,000 per list, and `score.md`
lists the first 1,000 rows of each list; `score.json` has every row.

## Lanes

| Lane | Rules | Threads | Other settings |
| --- | --- | --- | --- |
| `defaults` | Each tool's defaults | Each tool's default | Nothing changed except report output and validation off. This is the headline lane. |
| `threads` | Defaults | 1, 4 and all cores | Each tool's own thread setting |
| `features` | Defaults | 4 | Decode depth 0 and 5 with archives off, then decode depth 5 with archive depth 8; Kingfisher with dedup on and off |
| `shared-rules` | 5 synthetic rules loaded into every tool | 1 and 4 | Decode and archive depth 0; Kingfisher dedup off |
| `rustleaks-2x2` | Rustleaks defaults, with and without the 3 native packs | 1 and 4 | `--complete-profile` on and off |

Only the `defaults` lane gets cold cells unless `--cold-lanes` adds more.

Each tool sets threads in its own way, and the ways are not the same:

- Rustleaks scans with one detection thread for each CPU, up to 12, by
  default. For a binary with `--jobs`, the harness passes `--jobs N` in every
  thread cell. For a binary without `--jobs`, the 1-thread cells use no
  profile, and for more than 1 thread the harness generates a
  `--complete-profile` file with high limits and the requested `workers`
  value. A profile also makes Rustleaks read each file whole. A binary
  without either option runs only the 1-thread cells, and the other cells are
  listed as skipped.
- Gitleaks and Betterleaks get `GOMAXPROCS`. Gitleaks keeps a fixed 40
  detection goroutines. Betterleaks 2 starts 4 times `GOMAXPROCS` workers.
- Kingfisher gets `--jobs`.

Decode and archive depths are explicit flags for every tool that has them.
Kingfisher has no numeric decode depth. Depth 0 turns its Base64 decoding
off, and any higher depth leaves it on. Archive depth 0 turns off its archive
extraction, which also covers SQLite, Python bytecode and PDF text.

The shared rules have no capture groups, so the secret is the whole match in
every tool. Kingfisher loads them as Betterleaks TOML with its built-in rules
off. Identity agreement in this lane shows whether the tools found the same
items before a speed ratio is read as the same work.

## Flags the harness always sets

The report lists every flag that is not a tool default, with its reason.
The harness sets these in every lane:

| Tool | Flags | Reason |
| --- | --- | --- |
| Rustleaks, Gitleaks, Betterleaks 1 | `--no-banner --no-color --report-format json --report-path FILE` | Plain logs and a JSON report in a private file |
| Betterleaks 1 | `--validation=false` | Keep live validation off |
| Betterleaks 2 | `-s --no-banner --no-color -o FILE --validate=false --analyze=false` | Same as above. `-v` means `--validate` in Betterleaks 2, so the harness never passes it. |
| Kingfisher | `--no-validate --no-update-check --format json -o FILE` | Validation and update checks make network requests |
| Kingfisher, `dir` mode | `--git-history none` | Scan the working tree only |
| Kingfisher, `git` mode | the target is `PATH/.git` | A checkout path makes Kingfisher scan the working tree and the history. The `.git` path is meant to limit it to history, like the other tools. The harness counts git-mode findings without a commit and flags the cell, so this is checked on every run. |

A cell fails when Kingfisher or Betterleaks 2 reports a validation status,
or when Kingfisher applies a different number of rules than the shared rules
lane loads.

Every tool runs with an allowlisted environment: `PATH`, a private `HOME`
and `TMPDIR`, `XDG_CACHE_HOME`, `XDG_CONFIG_HOME`, `LC_ALL=C`, `TZ=UTC` and
Git settings that ignore system and user configuration. Validation variables
such as `BETTERLEAKS_VALIDATE` never reach a tool.

## What is measured

- Wall time runs from spawn to the return of `wait4` for the scanner. It
  includes process start, rule loading, scanning and writing the report.
- User and system CPU time come from the `wait4` resource usage. On macOS
  and Linux this includes every child process the scanner waited for, such
  as `git`.
- Peak RSS comes from the same resource usage. It is the largest single
  process among the scanner and its waited-for children. It is not the sum of
  processes that ran at the same time.
- In `git` mode, each warm cell gets one extra run that is not timed. A `git`
  shim on `PATH` records the wall time, CPU time and peak RSS of each `git`
  process. Rustleaks, Gitleaks and Betterleaks 1 run `git log -p`.
  Betterleaks 2 and Kingfisher read Git in process, so their Git work is part
  of the scanner figures.
- The same instrumented run samples the resident size of the scanner process
  alone every 10 ms (`proc_pid_rusage` on macOS, `VmHWM` on Linux). The peak
  RSS of a `git` cell is often the peak of `git log -p`, not of the scanner;
  this column shows the scanner's own share. A spike shorter than 10 ms can
  be missed.
- Not measured: the combined RSS of processes that run at the same time,
  helper processes other than `git`, I/O wait and disk bytes read.
- Findings are counted from the parsed report, every record, with no
  deduplication by the harness. Reports over 64 MiB are parsed once per
  cell; later runs check only the exit code. A report over 4 GiB, or a log
  over 64 MiB, stops the run. The report limit stops only runaway output.
- Thermal state is recorded before the first and after the last measured
  run of each cell.

## Runs and statistics

- Warm cells get 1 warmup and 3 measured runs. `--runs-fast`, `--runs-slow`
  and `--long-runs` set the count for cells under 1 second, of 1 second or
  more, and of 300 seconds or more; all three default to 3, so a full
  comparison takes hours. Medians are stable at this count; confidence
  intervals are wider than with more runs.
- Cold cells start every run with an empty `HOME`, `TMPDIR` and cache
  folders, so compiled rule caches start empty. They have no warmups. The
  operating system page cache is not purged, because that needs root.
- Workload blocks run in a random order. Inside a block, the cells of each
  repetition run in a new random order. The seed is fixed and recorded.
- Each cell reports the median, the median absolute deviation (MAD), the
  minimum and the maximum, and keeps every sample.
- Ratios compare each cell with the baseline cell of its group: the
  `--baseline` tool, or else the first Rustleaks tool. The report also gives
  every pair of cells in a group. The interval is a percentile bootstrap 95
  percent interval of the ratio of medians, with 2,000 resamples and a fixed
  seed.
- A cell with 8 or more samples is split at the largest gap between sorted
  samples. It is flagged as bimodal when the gap is at least 3 times the
  larger MAD of the two sides and at least 5 percent of the median. The
  smaller side must also hold at least 15 percent of the samples.
- A cell whose findings differ between runs is marked in the report.

## Scoring

Two items match when they have the same path and commit, their line ranges
intersect, and their secret texts match. Texts match when they are equal,
or when they share at least 4 characters, as a containment or a common
substring, and the shared part covers at least half of the shorter text.
The pairing is a maximum one-to-one matching, so no other pairing matches
more items. Among maximum pairings, larger overlaps are preferred.

In `git` mode, Kingfisher reads blobs and the other tools read patches, so
the same value can belong to different commits. For `git` mode the scorer
also gives a commit-agnostic result that matches on path and secret text
only. The report shows both.

The scorer reports both directions and lists every unmatched item by path,
lines, rule, secret SHA-256 and length. It never writes the secret text.
Each unmatched item gets a hint:

| Hint | Meaning |
| --- | --- |
| `duplicate` | The same side already matched this value under another rule. |
| `span-difference` | The other side has a matching value within 3 lines, but the lines do not intersect or the text does not match. |
| `same-lines-other-value` | The other side reports a different value on the same lines. |
| `nearby-other-value` | The other side reports a different value within 3 lines. |
| `no-counterpart` | Nothing from the other side is within 3 lines. |

Hints look only at items within 3 lines or with the same text, so scoring
stays fast on large files.

Against labels, the scorer reports true positives, false negatives,
findings on `not-secret` labels, true negatives, unlabeled findings, unknown
findings, excluded findings, duplicates and over-reporting, plus scope
differences found and missed. Strict precision counts unlabeled findings,
duplicates and over-reporting as false positives. Labeled-only precision
counts only findings on `not-secret` labels. Unknown and excluded findings
count in neither.

Results are split by category, label source, path scope, reachability from
HEAD, file kind, home tool and scope difference. Test paths are paths with
a folder named `test`, `tests`, `spec`, `fixtures` or `examples`. The home
tool is the label's `home_tool` field, or the first folder of the path for
fixture labels. A finding with no label has no category or source, so strict
precision is given only overall and by path scope.

`score.json` and `score.md` carry the SHA-256 of every secret. A SHA-256 of
a short or guessable secret can be recovered by brute force, so review them
before you share them.

To compare two reports without a run folder:

```sh
cargo xtask compare score \
  --left kingfisher=/path/kingfisher.json \
  --right rustleaks=/path/rustleaks.json \
  --target /path/to/input --output /path/to/private/score
```

## Output

The run folder holds:

- `run.json`: settings, host, tools with hashes, workloads and every cell;
- `samples.jsonl`: one line for every warmup, measured and instrumented run;
- `reports/`: the report of the first good measured run of each cell, which
  contains secrets;
- `score.json` and `score.md`: matches and every unmatched item;
- `summary.json` and `report.md`: statistics, ratios, failed and skipped
  cells, and the disclosure.

`summary.json`, `report.md` and `score.md` hold no secret text and no local
binary or input paths, so they can be shared after review. `run.json` holds
local paths.

## Limits

- Results apply only to the host, tool builds and inputs that were measured.
- The harness does not control thermal state or other load on the host. It
  records the load average and counts build processes. Stop builds and other
  heavy work before a run.
- The same rule text does not guarantee the same regex meaning in every
  engine.
- The Rustleaks native packs are ported from rule sources that Kingfisher
  also bundles, most of them derived from Betterleaks. Pack results and
  Kingfisher results are therefore not independent.
- Some differences are rule policy, not misses. For example, the
  Betterleaks 1 AWS rule reports a key ID only with a nearby secret key.
- Scope differs by tool even with matched flags. The report lists the known
  differences, such as `.git` contents in `dir` mode, patches versus blobs in
  `git` mode, and pieces versus whole files.

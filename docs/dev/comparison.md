# Scanner comparison

This page is for contributors who compare Rustleaks with Gitleaks,
Betterleaks and Kingfisher. It explains how to run the comparison harness,
what each lane means, what the harness measures, and the limits of the
results. No result from this harness is a portable speed or quality
guarantee.

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
`python3 -I`, so no Python package is needed and Python environment variables
are ignored. It needs a Unix host for `wait4` and process groups.

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
uses a byte count printed by a tool.

### Labels

A labels file is JSON Lines. Each line has the workload, the path, a commit
or `null`, the byte offsets `start` and `end`, the line, the SHA-256 of the
labeled text, a category, a label (`secret` or `not-secret`) and a source,
such as `constructed` or `credData`. The scorer reads the text at those
offsets from the input, checks its SHA-256, and reports labels that do not
check. Labels without a commit are used for `dir` mode, and labels with a
commit for `git` mode.

A label is line-level when it has `"span": "line"`, or when its byte range
starts at the start of a line and ends at the end of a line. It can cover
several lines. A finding matches a line-level label when their line ranges
intersect, whatever the finding's text.

Labels with the same path and commit whose byte ranges overlap form one
group, such as a whole-line label and a value label on the same line. A
finding that matches any member satisfies the whole group, so the second
label is not counted as a missed secret. A group is a secret when any member
is a secret. Its category and source come from its narrowest secret member.

Set `"labels_complete": false` on a workload when its labels do not cover
every secret, as with CredData. A finding that matches no label then counts
as unknown, not as a false positive. Labels are complete by default. For
`compare score` with report files, pass `--labels-partial` instead.

The labeled corpora and the CredData adapter are described in
`docs/dev/comparison-quality.md`.

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

At the end, the harness verifies the binary hashes, scores the kept reports
and writes the report.

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

- Rustleaks scans with 1 worker by default. The only way to set more workers
  is a `--complete-profile` file, which also makes Rustleaks read each file
  whole. The harness generates a profile with high limits and the requested
  `workers` value. A binary without `--complete-profile` runs only the
  1-thread cells, and the other cells are listed as skipped.
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
| Kingfisher, `git` mode | the target is `PATH/.git` | A checkout path makes Kingfisher scan the working tree and the history. The `.git` path limits it to history, like the other tools. |

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
- Not measured: the combined RSS of processes that run at the same time,
  helper processes other than `git`, I/O wait and disk bytes read.
- Findings are counted from the parsed report, every record, with no
  deduplication by the harness.

## Runs and statistics

- Warm cells get 3 warmups. Cells with a warmup median under 1 second get 30
  measured runs, and longer cells get 10. Cells of 300 seconds or more get 3
  runs, and the report gives the reason.
- Cold cells start every run with an empty `HOME`, `TMPDIR` and cache
  folders, so compiled rule caches start empty. They have no warmups. The
  operating system page cache is not purged, because that needs root.
- Workload blocks run in a random order. Inside a block, the cells of each
  repetition run in a new random order. The seed is fixed and recorded.
- Each cell reports the median, the median absolute deviation (MAD), the
  minimum and the maximum, and keeps every sample.
- Ratios compare each cell with the baseline cell of its group: the
  `--baseline` tool, or else the first Rustleaks tool. The interval is a
  percentile bootstrap 95 percent interval of the ratio of medians, with
  2,000 resamples and a fixed seed.
- A cell with 8 or more samples is split at the largest gap between sorted
  samples. It is flagged as bimodal when the gap is at least 3 times the
  larger MAD of the two sides and at least 5 percent of the median. The
  smaller side must also hold at least 15 percent of the samples.
- A cell whose findings differ between runs is marked in the report.

## Scoring

Two items match when they have the same path and commit, their line ranges
intersect, and their secret texts overlap: one contains the other, or a
common substring covers at least half of the shorter text. Matching is
greedy by the largest overlap, and each item is used at most once.

The scorer reports both directions and lists every unmatched item by path,
lines, rule, secret SHA-256 and length. It never writes the secret text.
Each unmatched item gets a hint:

| Hint | Meaning |
| --- | --- |
| `duplicate` | The same side already matched this value under another rule. |
| `span-difference` | The other side has an overlapping value within 3 lines, but it fails the line or overlap test. |
| `same-lines-other-value` | The other side reports a different value on the same lines. |
| `nearby-other-value` | The other side reports a different value within 3 lines. |
| `no-counterpart` | Nothing from the other side is near it in the file. |

Against labels, the scorer reports true positives, false negatives,
findings on `not-secret` labels, true negatives, unlabeled findings, unknown
findings and duplicates. A duplicate is a finding whose label group already
matched another finding. Strict precision counts unlabeled findings and
duplicates as false positives. Labeled-only precision counts only findings on
`not-secret` labels. Unknown findings count in neither.

Results are split three ways: by category, by label source, and by path
scope. Test paths are paths with a folder named `test`, `tests`, `spec`,
`fixtures` or `examples`. A finding with no label has no category or source,
so it appears only in the overall and path scope rows.

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
- Scope differs by tool even with matched flags. The report lists the known
  differences, such as `.git` contents in `dir` mode, patches versus blobs in
  `git` mode, and pieces versus whole files.

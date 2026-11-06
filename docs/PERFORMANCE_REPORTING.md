# Optional performance reporting

The reporting command is an optional local operation. It does not change
release checks, scheduled workflows, thresholds, baselines or runner purchases.
Existing normal tests already check deterministic workload outcomes.
Informational collection and profiling are manual operations that may use
best-effort host isolation. Record host load and treat elapsed times on a busy
host as observations, not qualified wall-time comparisons. CPU-time comparisons
require their own declared scope and qualification; they do not establish
wall-time improvement.

Run from the repository root, choosing a new private directory outside the
checkout:

```sh
just perf-report --output /private/tmp/rustleaks-performance-report
just perf-report --output /private/tmp/rustleaks-performance-budget --legacy-budget
```

The first command collects one complete legacy workload matrix. Its elapsed
times are informational. The second explicitly requests the unchanged inherited
M1 Max budgets: one untimed warmup, seven fresh process samples and RSS from the
first three processes for each budgeted workload. The exact original hardware
predicate is retained and checked. Other hosts report a skipped budget. The
Cargo-to-Bazel calibration caveat in [Performance measurement](PERFORMANCE.md)
still applies. Use `--legacy-budget` only with the retained hardware predicate
and controlled collection conditions. A busy-host informational run does not
qualify those wall-time budgets. Passing an inherited limit does not establish
a new baseline.

Collection has a 900-second outer deadline, including build preparation. Its
process tree is terminated and reaped on completion or failure. The supervisor capture
is bounded to 16 MiB; retained individual files have a 16 MiB polling limit.
Polling limits can overshoot between observations and are not filesystem quotas.
No native collection runs as part of report-parser tests.

To summarize an existing private report without collecting timings:

```sh
just perf-report --input /private/tmp/rustleaks-profile/report.json --output /private/tmp/rustleaks-profile-summary
just perf-report --input /private/tmp/rustleaks-calibration/report.json --output /private/tmp/rustleaks-calibration-summary
just perf-report --input /private/tmp/rustleaks-window-calibration/matrix.json --output /private/tmp/rustleaks-window-summary
just perf-report --input /private/tmp/rustleaks-representative/rows.jsonl --output /private/tmp/rustleaks-representative-summary
```

Supported inputs are this command's `collection.json`, schema 1 native profile
and calibration reports, schema 2 observation-window calibration and fixed
matrix reports, and complete schema 3 representative JSON Lines. Inputs must be
owner-only regular files without symlink components or hard links. Each input
and matrix companion is limited to 16 MiB; representative input is also limited
to 8,192 rows. Unknown schemas fail. Representative input needs every process
sample, matching recomputed summaries and the final `run-complete` marker.

Calibration classification is recomputed using the original versioned Rust
classifier. Successful calibration remains informational. Deliberate extra-work
controls do not become production regression measurements. Matrix imports read
only the fixed `cell-00/report.json` through `cell-15/report.json` companions,
check their schedule and exact source/build/workload identities, recompute their
classifications, and hash the imported companion bytes. A digest of those fixed
references appears in the summary. Incomplete matrices fail instead of treating
completed cells as a full run.

Profile imports require matching ready/build provenance, complete worker
outcomes, and locally retained artifacts for each completed native tool. The
importer checks hashes, replays the maintained CPU/heap/VM observation parser,
and compares exact observation counts. That parser has a 15-second deadline
and a 64 KiB combined output bound. Missing tools remain unavailable; missing,
changed, empty or unusable evidence cannot produce a complete profile.

| Status | Meaning |
| --- | --- |
| `invariant-failure` | The bound runner reported a structured invariant failure or returned rows that failed exact outcome checks |
| `execution-failure` | The prepared runner failed without a structured invariant failure |
| `qualified-regression` | Complete legacy samples exceeded an unchanged elapsed or RSS limit under the retained hardware predicate |
| `legacy-budget-passed` | Complete legacy samples satisfied those limits |
| `skipped-legacy-host-budget` | Requested legacy limits were not evaluated for this host |
| `informational-timing` | Complete timing evidence with no applicable regression decision |
| `unavailable-profile-tool` | Unsupported native host or at least one unavailable native observation |
| `complete-profile` | Complete worker and matching, reparsed native observations |

A collection, invariant or budget failure returns a nonzero exit status.
Malformed, incomplete or unsupported imports fail with a private failure record.
An imported report uses `verification: report-consistency-only`; a new collection
uses `verification: local-collector`. Consistency checks detect conflicting
provenance and forged derived results. They do not authenticate a completely
fabricated report, independently repeat the execution, or prove release
qualification. Every public summary says `release_gate: false`.

## Retention and manual publication

Output directories use mode 0700 and files use mode 0600. Raw inputs, runner
output, diagnostics, complete build identity, hardware details and profiles stay
local. Imports preserve the input bytes and rely on the original owner-only
companion files; keep that source directory with the new summary. Raw evidence
is retained on failure for local investigation. Operators choose its local
retention period and remove it only after reviewing the contents.

`summary.json` is the only file eligible for a public workflow artifact. It
contains a fixed allowlist of statuses, protocol/target/workload/phase names,
identity digests, numeric measurements and fixed profile-artifact references.
It excludes raw findings, raw profile data, source paths, compiler action keys,
compiler argument strings, environment values and freeform diagnostics. Before
publishing a summary, validate the actual file:

```sh
just perf-report --verify-summary /private/tmp/rustleaks-performance-report/summary.json
```

Any manual workflow consuming this contract must upload that exact file only,
with `retention-days: 7` and `if-no-files-found: error`. Do not upload the private
directory, use wildcard artifact paths, or print raw files into workflow logs.
Review the fixed summary before publication. A scheduled invocation is a later
operator choice; this implementation enables no background or weekly job.

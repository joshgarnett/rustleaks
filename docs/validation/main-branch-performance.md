# Performance against main

Measured on 2026-11-10 on Apple M1 Max, 32 GiB RAM, macOS 26.5.2 arm64, with 10
logical CPUs and Rust 1.95.0. The production baseline is main commit
`b286eae941432e8f9af1c9b4a89a12463840773e`; the candidate is
`749430701095b4a61fbfd5a63488db0ceb34339f`.

The baseline measurement checkout, `8634683f56779ce7a6d512ed89ab9f2061e9fa96`,
changes only 21 benchmark harness and support files from main. Its production code,
dependencies, toolchain, configuration and build graph remain identical to
main. All 32 workload-definition inputs match the candidate. Both builds use
Bazel optimization level 3 with stamping disabled and report workload-definition
SHA-256 `f0331e42dd8772bed7ff9787353d311889bb0fb18c643efa181aa79091fb1efd`.

This comparison measures the complete branch change. The
[filtering and normalization](core-edge-performance.md) and
[default-rule throughput](default-rule-throughput.md) records retain their
original measured commit intervals.

The [comparison against alpha.6](alpha6-branch-performance.md) covers the
earlier starting point and includes the regex engine changes already present
in this record's main baseline.

The initial matrix records lower medians for all 117 steady-scan phases,
116 of 117 first-scan phases, and all 16 directory traversal-and-detection
phases and 16 runner phases. Engine construction and some Git and startup
operations cost more. These observations apply to the measured fixtures.

## Method

The complete representative matrix ran serially, baseline then candidate, after
builds, tests and fuzzing stopped. Each of 163 workloads supplied three fresh
processes and one iteration per measured phase, for 584 phase comparisons.
The matrix uses synthetic fixtures and checked upstream archive fixtures. The
tables below report these initial three-process medians. The
[complete CSV](main-branch-performance.csv) includes every phase's
median, minimum, maximum, median absolute deviation and elapsed change, including
configuration compilation, engine construction and first scans.

Both runs completed with clean-source provenance. Compiler identity and
options, dependency and toolchain inputs, workload definitions, configuration,
host and collector identities matched. Every phase field other than elapsed
time matched across samples and builds, including its input, configuration and
outcome fingerprints, counts, finding count, iteration count and completion
status. Each workload also executed its independent fixture assertions. This
checks the recorded phase contract; fingerprints do not constitute a separate
comparison of every raw finding field.

Core scan timers exclude fixture construction, compilation, verification and
outcome destruction. Worker timers include dispatch and result collection.
Source timings use the named traversal, detection or archive phase; CLI phases
include startup. Report workloads use their documented output-buffer setup.
The full phase definitions and reproduction commands are in
[Performance](../PERFORMANCE.md).

## Scan and session results

| Workload | Main ms | Candidate ms | Speedup |
| --- | ---: | ---: | ---: |
| Default rules, JSON, 4 MiB | 270.490 | 16.908 | 16.00x |
| Default rules, JSON, 12 MiB in 16 KiB fragments | 839.618 | 58.009 | 14.47x |
| Default rules, log, 4 MiB | 270.070 | 17.081 | 15.81x |
| Default rules, invalid UTF-8, 4 MiB | 290.998 | 259.320 | 1.12x |
| Default rules, multi-language source, 256 KiB | 4.649 | 0.913 | 5.09x |
| Default rules, `.env` assignments, 256 KiB | 4.791 | 1.935 | 2.48x |
| Default rules, prose dense in keywords, 1 MiB | 14.236 | 4.704 | 3.03x |
| 100,000 fragments of 64 bytes | 1,556.817 | 187.166 | 8.32x |
| Shared engine, 8 workers, 12 MiB | 112.734 | 8.925 | 12.63x |
| Marker-suppressed line, 4 MiB, 4,096 candidates | 11,689.450 | 4.712 | 2480.76x |
| Sparse invalid UTF-8 literal miss, 4 MiB | 36.835 | 0.322 | 114.36x |
| 20,000 base64 lines, depth 1 | 362.862 | 23.211 | 15.63x |
| 20,000 double-encoded lines, depth 2 | 1,023.376 | 30.454 | 33.60x |
| 1 MiB line, 10,000 decoded findings allowlisted | 17,314.132 | 10.056 | 1721.85x |
| 1 MiB line, 10,000 retained decoded findings | 17,781.041 | 417.118 | 42.63x |
| 65,536 generic findings plus 8,192 specific findings | 6,600.715 | 81.105 | 81.38x |
| Baseline classification, 10,000 findings and entries | 133.068 | 4.435 | 30.00x |

The larger filtering and decoding ratios come from deliberately expensive
synthetic shapes. They are not estimates of typical application throughput.
Invalid UTF-8 uses the unanchored regex path and improves less than ASCII JSON.
Accepted findings still retain full line copies.

## Reports, sources, archives and CLI

| Workload | Main ms | Candidate ms | Speedup |
| --- | ---: | ---: | ---: |
| JSON report, 10,000 findings | 10.379 | 6.108 | 1.70x |
| SARIF report, 10,000 findings | 21.626 | 10.503 | 2.06x |
| Default rules, directory, 12 MiB, 1 worker | 168.324 | 28.242 | 5.96x |
| Default rules, directory, 12 MiB, 8 workers | 24.858 | 8.386 | 2.96x |
| Single-line file, 64 MiB | 313.034 | 63.945 | 4.90x |
| Directory, 50,000 tiny files | 1,380.323 | 1,323.233 | 1.04x |
| Git, 20,000 commits, history and detection | 842.213 | 505.642 | 1.67x |
| 500 small zstd files | 353.531 | 50.998 | 6.93x |
| Gzip, 60 MiB of zeros, under limit | 751.338 | 96.252 | 7.81x |
| Bzip2, approximately 60 MiB of zeros, under limit | 427.551 | 128.723 | 3.32x |
| Zstd, 60 MiB of zeros, under limit | 281.774 | 121.587 | 2.32x |
| CLI, 10,000 size-limit warnings | 376.179 | 49.826 | 7.55x |

The directory rows include complete traversal and detection. The tiny-file
case changes little despite improvements in other source shapes. Filesystem
cache state is uncontrolled; these are observations on this host.

## Construction cost and repeat checks

Engine construction becomes more expensive. On the 4 MiB default-rule JSON
workload it rises from 0.212 to 0.671 ms, while configuration parsing and
compilation changes from 66.812 to 67.262 ms. The generated 1,000-rule engine
rises from 0.590 to 1.284 ms, and the 5,000-rule engine from 2.696 to 3.293 ms.
These setup costs are outside the scan medians above and matter when callers
repeatedly construct engines.

Eighteen selected workloads then ran in reverse order, candidate before
baseline, with seven fresh processes per side. These cover representative
gains and the initial scan, startup, Git and archive increases. The same
identity checks passed for all 65 repeated phases. The
[repeat CSV](main-branch-performance-repeats.csv) preserves every repeated
phase separately from the initial matrix.

| Repeated workload | Main ms | Candidate ms | Elapsed change |
| --- | ---: | ---: | ---: |
| Default-rule JSON, 4 MiB, steady scan | 270.607 | 16.906 | -93.75% |
| Default-rule invalid UTF-8, 4 MiB, steady scan | 289.966 | 259.374 | -10.55% |
| 20,000 base64 lines, depth 1, steady scan | 362.319 | 23.301 | -93.57% |
| 100,000 fragments of 64 bytes, steady scan | 1,546.829 | 192.709 | -87.54% |
| JSON report, 10,000 findings | 10.188 | 6.060 | -40.52% |
| SARIF report, 10,000 findings | 21.631 | 10.510 | -51.41% |
| 500 small zstd files | 352.802 | 51.111 | -85.51% |
| Default rules, directory, 12 MiB, 8 workers | 24.619 | 8.318 | -66.21% |
| Default-rule engine construction, JSON fixture | 0.215 | 0.678 | +215.38% |
| Generated 1,000-rule engine construction | 0.588 | 1.291 | +119.46% |
| Git wide commit, history and detection | 36.874 | 38.084 | +3.28% |
| LZ4 fixture expansion | 0.237 | 0.263 | +10.81% |
| Default CLI, empty stdin | 73.671 | 74.960 | +1.75% |
| Selected-rule CLI, empty stdin | 73.518 | 74.181 | +0.90% |

Git wide-commit detection retains a 1.210 ms increase, or 3.28%, with disjoint
sample ranges in both collection orders. The LZ4 fixture has a 0.026 ms higher
median, or 10.81%; default empty-stdin CLI startup has a 1.289 ms higher median,
or 1.75%. Their repeat ranges overlap, so these higher medians do not establish
statistical significance. Other small archive increases, including 0.008 ms
for the RAR3 fixture, appear in the complete repeat CSV. The timing comparisons
do not establish their causes. The initial repeated-blob parsing increase did
not recur: its repeat medians were 12.399333 and 12.399750 ms.

## CPU time and memory

These are medians of the initial three fresh-process measurements. CPU time is
user plus system time. Process CPU and peak RSS include fixture construction,
verification, destruction and waited descendants. They are not isolated scan
CPU or engine-memory measurements and must not be added across phase rows.

| Workload | Main CPU ms | Candidate CPU ms | Main peak MiB | Candidate peak MiB |
| --- | ---: | ---: | ---: | ---: |
| Default-rule JSON, 4 MiB | 667.622 | 156.743 | 49.78 | 45.14 |
| Sparse invalid UTF-8, 4 MiB | 92.730 | 22.968 | 64.27 | 20.41 |
| Dense invalid UTF-8, 4 MiB | 131.529 | 55.660 | 148.30 | 102.25 |
| 500 small zstd files | 428.340 | 122.366 | 80.70 | 24.70 |
| Shared engine, 16-thread contention, 512-byte fragments | 3,628.056 | 1,026.917 | 98.72 | 102.12 |
| 1 MiB line, 10,000 retained decoded findings | 36,581.516 | 1,910.326 | 10,075.84 | 10,070.67 |

The retained decoded-findings case still peaks near 10 GiB: faster scanning
does not remove its line-copy cost. The contention row has the largest median
RSS increase in the initial matrix, 3.406 MiB. In the separate seven-process
repeats, Git merge/rename has the largest median RSS increase, from 14.5625 to
17 MiB. Neither measurement isolates engine allocations or retained caches.

## Validation and limits

The candidate passed `just ci` with all 60 targets, `just security`, all eight
fuzz builds, and ten executions of all 55 flake-check targets. The
`cargo xtask qualify` gate passed, including eight fuzz targets with zero
artifacts. These gates cover committed parity, formatting, lint, documentation, package and consumer
checks, resource controls, the public API snapshot and the required target
compilation checks.

Native measurements apply only to macOS arm64. Cross-compilation establishes
compilation, not native runtime performance. No dependency, toolchain, copied
configuration or upstream-pin change is part of this comparison. The timings
are host observations with no new performance threshold or portable guarantee.

Initial raw collection SHA-256 values:

- Baseline: `1e9ca403d2c43ed25f5a2882d8d7d0c4e24923d5d6e9a47591a975f1e6a0a0ad`.
- Candidate: `74519a4f975bfe7762317d9f21cebfe2660bebea18093eb45583a6a956231aaf`.

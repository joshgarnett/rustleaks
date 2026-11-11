# Released scanner comparison, 2026-11-11

This collection measures released Rustleaks 0.1.0-alpha.6 and
0.1.0-alpha.8, Gitleaks 8.30.1, and Betterleaks 1.10.0 on 19 deterministic
synthetic CLI workloads. All 1,216 planned measured invocations completed.
The shared-rule result gate accepts 38 of 76 cells. Of the 38 rejected cells,
30 differ only in physical coordinates and eight miss prescribed finding
identities, with coordinate differences recorded separately.
The shipped-rule profile records successful observations for all 76 cells,
including their detection differences; that status does not establish result
equivalence. No overall ranking or aggregate speedup is calculated.

The complete [protocol](../PERFORMANCE_COMPARISON.md) defines the settings,
independent expectations, isolation, scope witnesses, and comparison gates.
This report contains the full workload matrix, including startup, clean,
held-out, and Git scope controls. It does not change production scanner code,
the accepted upstream pin, or packaged default rules.

## Releases and measured environment

| Label | Released executable | Default rule definitions | Inspected compiler |
| --- | --- | ---: | --- |
| A6 | Rustleaks 0.1.0-alpha.6 | 222 | rustc 1.95.0 |
| A8 | Rustleaks 0.1.0-alpha.8 | 222 | rustc 1.95.0 |
| GL | Gitleaks 8.30.1 | 222 | go1.24.11 |
| BL | Betterleaks 1.10.0 | 466 | go1.27.3 |

A6 and A8 are published prereleases. All executables are the published macOS
arm64 binaries. The [version manifest](cross-scanner-versions.json) records
release commits, archive and executable SHA-256 hashes, checksum evidence,
build metadata, defaults, and source links. A6, A8, and GL have byte-identical
packaged default TOML. BL has a different rule set; rule counts do not measure
detection quality. Both Go binaries use their packaged RE2 implementations.
The comparison retains each release's build choices.

The host was an Apple M1 Max with 32 GiB RAM and 10 logical CPUs, running
macOS 26.5.2, Darwin 25.5.0, Python 3.9.6, and Git 2.50.1
(Apple Git-155). The collector ran from clean commit
`4db305c4789dc6d8c6488e7b20ceb720e5a445f3`. Executable, configuration,
fixture, Git, Python, collector, generator, and source-tree identities were
unchanged at completion. The source inventory remained clean. See the
`before` and `after` records in the [summary](cross-scanner-2026-11-11/summary.json).

The process preflight checked for builds before collection. It did not provide
thermal isolation or control other host work. Recorded initial load averages
were 1.70, 4.83, and 5.33. Measurements were serial; filesystem caches were warm
or uncontrolled. Results apply to this host and collection, not cold-disk
performance or other supported targets.

## Profiles and accounting

`shared-rules` uses the common explicit rules with decode depth 1 only for
the base64 workload and archive depth 1 only for the Zstandard workload;
other depths are 0. `GOMAXPROCS=1` caps the Go scheduler in this profile.
It does not equalize source workers, OS threads, or process-tree CPU use.

`shipped-rules` keeps built-in rules, filters, and concurrency. All four
selected executables default to decode depth 5. Archive depth defaults to 0
for A6, A8, and GL and 8 for BL; the Zstandard task raises the first three
to 1 and leaves BL at 8. Rustleaks has one detection worker and one queue
slot. The Go tools have different source concurrency; BL also has a parallel
filesystem walker. These differences remain part of the measured releases.
BL credential validation was explicitly disabled. Inputs and repositories
were local and synthetic, with no live credentials or provider requests.

Each cell has one untimed warmup, one separate untimed coverage pass, and
eight measured fresh processes. Four-tool orders were `A B D C`, `B C A D`,
`C D B A`, and `D A C B`, repeated twice, with A/B/C/D corresponding to
A6/A8/GL/BL. Fixture generation and Git preparation were outside measurement.
The timer includes process startup, configuration, input reading, decoding or
archives, Git subprocess work, scanning, JSON writing, and direct-child exit.
It does not guarantee durable writes through `fsync`.

Wall and CPU values below are milliseconds. CPU is the median of each
sample's user plus system CPU, rather than the sum of two separately computed
medians. RSS is MiB (2^20 bytes), taken from the exact child's OS-reported
`wait4` maximum. It is not simultaneous aggregate process-tree peak memory,
allocation volume, or retained engine memory. Aggregate process-tree peak is
unavailable; CPU and memory attribution require particular care for Git
commands. These whole-command results are separate from the operation-only
benchmarks in [Performance measurement](../PERFORMANCE.md).

## Coverage and finding gates

A cell is one profile, workload, and tool combination. There were no timeouts,
failed measured repetitions, or incomplete cells in the recorded matrix.
The completed matrix contains 152 cells and 1,216 measured processes, plus
152 warmups and 152 coverage passes.

| Gate or observation | Shared rules | Shipped rules |
| --- | ---: | ---: |
| Measured invocations complete | 608 / 608 | 608 / 608 |
| Coverage passes complete | 76 / 76 | 76 / 76 |
| Cells accepted by their profile gate | 38 / 76 | 76 / 76 |
| Cells matching all nine prescribed finding fields | 38 / 76 | 35 / 76 |
| Cells with exact prescribed finding identities | 68 / 76 | 65 / 76 |

Shared-rule eligibility requires all nine fields: rule, path, secret hash,
start/end lines, start/end columns, commit, and decoded status. Shipped-rule
eligibility permits finding differences and records them. Its `eligible`
value must not be interpreted as an exact-result pass or permission to rank
nonequivalent results. These fields are a benchmark projection, not complete
JSON report equivalence.

All 152 coverage passes matched their prescribed marker identities, paths,
commits, decoded status, multiplicities, and exact scope-unit sets. Scanned-byte
counters matched in all 152 cells. Commit counters matched in 18 Git-mode cells;
they were unavailable in BL's six Git-mode cells and unavailable or inapplicable
in the 128 non-Git cells. Exact witnesses established BL's selected Git scopes
under the protocol without an available printed commit counter.
An untimed witness pass does not prove every byte was inspected in every
measured invocation. Witness coordinate differences remain recorded separately.

Seven shared-rule workload rows pass the strict gate for all four tools:
`files-100000`, `json-768-files`, `empty-stdin`, `tiny-clean-file`,
`tiny-clean-tree`, `mixed-clean-4mib`, and `git-current-tree-control`.
A6, A8, and GL each pass these seven cells. BL passes 17 shared cells.
The remaining 12 workload rows do not support an equivalent-result four-tool
timing ranking under this gate.

The 30 position-only failures are A6, A8, and GL on ten workload rows.
Rustleaks deliberately preserves the accepted Gitleaks column behavior,
including the frozen
[`location-second-line-includes-boundary-newline` case](../../compat/detect-corpus/outcomes-v1.jsonl).
Physical-coordinate disagreement is distinct from a regression against that
compatibility profile. The gate retains the physical-coordinate differences
instead of rewriting expectations to accept observed output.

The other eight shared failures are all four tools on `base64-20000` and
`findings-10000`. Each tool recovers 19,967 of 20,000 base64 identities and
9,990 of 10,000 dense-report identities. These are prescribed synthetic plants,
not a claim that the dense case actually emitted 10,000 findings. In the
shipped profile, base64 produces six additional identities for every tool,
while the same 33 prescribed identities remain missing.

The missing identity sets are identical across the four tools and align with
input fragment boundaries: the first cut is at 125,000 bytes, followed by
28,672-byte fragments when the reader finds no double newline. Ten dense tokens
cross cuts. Of 34 encoded lines crossing cuts, one retains enough nonpadding
base64 characters before the cut to recover its token, leaving 33 missing.
The Rustleaks [source-reader regression test](../../crates/rustleaks-sources/src/file.rs#L815)
documents this fragment schedule. The six additional shipped findings are
`generic-api-key` matches on original encoded source lines, with decoded status
false; they are not additional recovered encoded GitHub tokens. Expectations
remain unchanged, and these outcomes are not treated as complete injection
recovery.

BL's shipped rules report 3 of 4 identities in `multilanguage-256kib`,
20 of 30 in `mixed-app-16mib`, and 18 of 27 in `heldout-mixed-8mib`.
The omitted plants are standalone AWS access IDs. Its shipped
[AWS rule](https://github.com/betterleaks/betterleaks/blob/8d77e1712fb06fd14444cc648686f1d5655e28a8/config/betterleaks.toml#L845)
requires a nearby secret-access-key component. The common rule does not impose
that companion requirement. This is a shipped policy difference on synthetic
inputs, not evidence of live credential validity or real-world recall.

All counts in the following table were stable across the eight measured
samples in their cell. A6/A8/GL share the listed counts. Each entry is
**observed / missing identities / extra identities / coordinate differences**.
Coordinate differences apply to recovered identities and are separate from
identity omissions. The zero-positive controls produced no unexpected
identities in either profile.

| Workload | Prescribed | Shared A6/A8/GL | Shared BL | Shipped A6/A8/GL | Shipped BL |
| --- | ---: | --- | --- | --- | --- |
| `json-4mib` | 4 | 4 / 0 / 0 / 3 | 4 / 0 / 0 / 0 | 4 / 0 / 0 / 3 | 4 / 0 / 0 / 0 |
| `base64-20000` | 20,000 | 19,967 / 33 / 0 / 19,966 | 19,967 / 33 / 0 / 1 | 19,973 / 33 / 6 / 19,966 | 19,973 / 33 / 6 / 1 |
| `files-100000` | 100 | 100 / 0 / 0 / 0 | 100 / 0 / 0 / 0 | 100 / 0 / 0 / 0 | 100 / 0 / 0 / 0 |
| `findings-10000` | 10,000 | 9,990 / 10 / 0 / 9,990 | 9,990 / 10 / 0 / 0 | 9,990 / 10 / 0 / 9,990 | 9,990 / 10 / 0 / 0 |
| `zstd-500` | 10 | 10 / 0 / 0 / 10 | 10 / 0 / 0 / 0 | 10 / 0 / 0 / 10 | 10 / 0 / 0 / 0 |
| `git-20000` | 5 | 5 / 0 / 0 / 5 | 5 / 0 / 0 / 0 | 5 / 0 / 0 / 5 | 5 / 0 / 0 / 0 |
| `json-768-files` | 8 | 8 / 0 / 0 / 0 | 8 / 0 / 0 / 0 | 8 / 0 / 0 / 0 | 8 / 0 / 0 / 0 |
| `invalid-utf8-4mib` | 2 | 2 / 0 / 0 / 2 | 2 / 0 / 0 / 0 | 2 / 0 / 0 / 2 | 2 / 0 / 0 / 0 |
| `multilanguage-256kib` | 4 | 4 / 0 / 0 / 4 | 4 / 0 / 0 / 0 | 4 / 0 / 0 / 4 | 3 / 1 / 0 / 0 |
| `empty-stdin` | 0 | 0 / 0 / 0 / 0 | 0 / 0 / 0 / 0 | 0 / 0 / 0 / 0 | 0 / 0 / 0 / 0 |
| `tiny-clean-file` | 0 | 0 / 0 / 0 / 0 | 0 / 0 / 0 / 0 | 0 / 0 / 0 / 0 | 0 / 0 / 0 / 0 |
| `tiny-positive` | 1 | 1 / 0 / 0 / 1 | 1 / 0 / 0 / 0 | 1 / 0 / 0 / 1 | 1 / 0 / 0 / 0 |
| `tiny-clean-tree` | 0 | 0 / 0 / 0 / 0 | 0 / 0 / 0 / 0 | 0 / 0 / 0 / 0 | 0 / 0 / 0 / 0 |
| `mixed-app-16mib` | 30 | 30 / 0 / 0 / 27 | 30 / 0 / 0 / 0 | 30 / 0 / 0 / 27 | 20 / 10 / 0 / 0 |
| `mixed-clean-4mib` | 0 | 0 / 0 / 0 / 0 | 0 / 0 / 0 / 0 | 0 / 0 / 0 / 0 | 0 / 0 / 0 / 0 |
| `heldout-mixed-8mib` | 27 | 27 / 0 / 0 / 24 | 27 / 0 / 0 / 0 | 27 / 0 / 0 / 24 | 18 / 9 / 0 / 0 |
| `git-bounded-control` | 1 | 1 / 0 / 0 / 1 | 1 / 0 / 0 / 0 | 1 / 0 / 0 / 1 | 1 / 0 / 0 / 0 |
| `git-current-tree-control` | 0 | 0 / 0 / 0 / 0 | 0 / 0 / 0 / 0 | 0 / 0 / 0 / 0 | 0 / 0 / 0 / 0 |
| `git-staged-control` | 1 | 1 / 0 / 0 / 1 | 1 / 0 / 0 / 0 | 1 / 0 / 0 / 1 | 1 / 0 / 0 / 0 |

## Observations and limitations

The seven shared rows with exact outcomes show different workload costs.
For 100,000 small files, median wall times in A6/A8/GL/BL order were
2,653.67 / 2,605.61 / 4,390.78 / 3,425.48 ms. For 768 JSON files totaling
12 MiB, they were 83.41 / 29.69 / 268.98 / 85.13 ms. The clean 4 MiB mixed
tree measured 63.40 / 22.34 / 228.04 / 41.24 ms. These are separate workloads;
there is no weighting that turns them into a general scanner score.

Small-input controls expose a cost increase between Rustleaks releases.
With shipped rules, empty-input wall time rose from 66.37 ms in A6 to
79.57 ms in A8, and a 36-byte clean file rose from 66.57 to 79.61 ms.
Empty-input RSS rose from 16.81 to 31.98 MiB. Across all shipped rows,
A8 had a higher median RSS than A6 in 18 of 19 workloads; the Zstandard case
was the exception. Shared-rule empty-input medians were much closer,
9.80 and 9.89 ms. This collection does not isolate the implementation cause.

For the shipped 100,000-file workload, all four tools recovered the same 100
prescribed findings with exact coordinates. Wall medians were
8,336.99 / 2,784.57 / 3,730.72 / 4,114.59 ms, while CPU medians were
16,450.83 / 3,152.91 / 28,690.06 / 39,940.59 ms. Wall time and CPU demand
therefore give different information. Profiles change both rules and concurrency,
so differences between profiles cannot be attributed to either factor alone.

The mixed and independently seeded held-out rows remain in the report even
where coordinates or shipped detection policies differ. The decoded and dense
cases also retain missing identities. Their timing and resource values are
descriptive observations, without equivalent-result speedup claims.

Each median has eight samples. Wall ranges and median absolute deviations
(MADs) are listed below, and every numeric sample is preserved. Variation is
material in some cells: GL's shared empty-input range was 181.34 to 211.05 ms
with a 10.66 ms MAD; BL's shipped malformed-byte range was 70.28 to
132.72 ms around a 71.32 ms median. Eight samples do not establish a p95,
statistical significance, or a causal explanation for differences. A larger
suite of independently sourced inputs and controlled repeated host sessions
would be needed for broader conclusions. Synthetic injection recovery and
unexpected findings do not establish deployment precision or real-world recall.

## Workload inventory

Byte counts describe the declared inputs. Git history bytes describe selected
patch payloads, not all repository storage or every object. The full history
has 20,000 commits; the bounded control selects eight. The staged control
selects the index delta, while the current-tree control scans the clean file
rather than its historical positives. Archives contain 500 named raw-block
Zstandard streams with 1 KiB expanded members. They are not anonymous-stdin
archive measurements.

| Workload | Input bytes | Files | Selected commits | Mode |
| --- | ---: | ---: | ---: | --- |
| `json-4mib` | 4,194,304 | 1 | 0 | dir |
| `base64-20000` | 1,140,021 | 1 | 0 | dir |
| `files-100000` | 6,400,000 | 100,000 | 0 | dir |
| `findings-10000` | 410,021 | 1 | 0 | dir |
| `zstd-500` | 516,500 | 500 | 0 | dir |
| `git-20000` | 760,120 | 1 | 20,000 | git |
| `json-768-files` | 12,582,912 | 768 | 0 | dir |
| `invalid-utf8-4mib` | 4,194,304 | 1 | 0 | dir |
| `multilanguage-256kib` | 262,144 | 32 | 0 | dir |
| `empty-stdin` | 0 | 0 | 0 | stdin |
| `tiny-clean-file` | 36 | 1 | 0 | dir |
| `tiny-positive` | 62 | 1 | 0 | dir |
| `tiny-clean-tree` | 2,048 | 8 | 0 | dir |
| `mixed-app-16mib` | 16,777,216 | 2,000 | 0 | dir |
| `mixed-clean-4mib` | 4,194,304 | 500 | 0 | dir |
| `heldout-mixed-8mib` | 8,388,608 | 1,250 | 0 | dir |
| `git-bounded-control` | 328 | 1 | 8 | git |
| `git-current-tree-control` | 38 | 1 | 0 | dir |
| `git-staged-control` | 62 | 1 | 0 | git |

## Complete median results

Every numeric cell is **wall ms / CPU ms / RSS MiB**, rounded to two decimal
places from the recorded samples. A dagger (†) marks a shared cell that fails
the strict finding gate. Shipped cells are all valid observations but retain
the differences shown above. A missing dagger in the shipped table does not
assert equivalence. No values are omitted because they are unfavorable.

### Shared rules

| Workload | A6 | A8 | GL | BL |
| --- | --- | --- | --- | --- |
| `json-4mib` | 45.34 / 77.52 / 9.17 † | 13.49 / 11.58 / 9.46 † | 213.18 / 209.29 / 54.35 † | 37.74 / 33.61 / 29.93 |
| `base64-20000` | 1,178.53 / 1,484.53 / 51.18 † | 797.73 / 831.20 / 49.70 † | 585.96 / 574.43 / 160.35 † | 400.20 / 388.67 / 160.57 † |
| `files-100000` | 2,653.67 / 2,901.85 / 13.13 | 2,605.61 / 2,790.20 / 13.88 | 4,390.78 / 4,377.69 / 51.28 | 3,425.48 / 3,425.68 / 31.95 |
| `findings-10000` | 482.27 / 568.74 / 33.72 † | 346.84 / 350.74 / 28.96 † | 318.01 / 311.96 / 95.34 † | 246.10 / 239.63 / 94.36 † |
| `zstd-500` | 362.36 / 362.21 / 73.72 † | 22.60 / 19.07 / 10.19 † | 218.45 / 212.90 / 51.45 † | 52.30 / 46.86 / 31.32 |
| `git-20000` | 695.03 / 747.25 / 35.51 † | 337.31 / 357.58 / 36.11 † | 484.42 / 659.02 / 55.60 † | 320.39 / 506.72 / 31.33 |
| `json-768-files` | 83.41 / 149.48 / 10.38 | 29.69 / 28.08 / 10.63 | 268.98 / 263.33 / 52.43 | 85.13 / 79.45 / 29.34 |
| `invalid-utf8-4mib` | 42.57 / 68.60 / 11.73 † | 22.45 / 29.27 / 9.81 † | 256.65 / 251.05 / 54.91 † | 52.62 / 47.12 / 29.87 |
| `multilanguage-256kib` | 14.20 / 13.01 / 9.01 † | 11.09 / 6.68 / 9.50 † | 198.76 / 193.30 / 51.05 † | 25.70 / 20.26 / 27.14 |
| `empty-stdin` | 9.80 / 4.81 / 7.94 | 9.89 / 4.80 / 8.39 | 196.50 / 190.81 / 49.02 | 13.27 / 7.93 / 18.46 |
| `tiny-clean-file` | 9.96 / 5.01 / 8.53 | 10.10 / 5.07 / 9.02 | 194.76 / 189.36 / 48.91 | 13.26 / 8.00 / 18.59 |
| `tiny-positive` | 10.12 / 5.10 / 8.59 † | 10.26 / 5.20 / 9.09 † | 196.71 / 191.16 / 49.52 † | 23.15 / 17.71 / 26.66 |
| `tiny-clean-tree` | 10.25 / 5.48 / 8.79 | 10.19 / 5.49 / 9.27 | 195.65 / 190.10 / 49.31 | 13.66 / 8.39 / 18.90 |
| `mixed-app-16mib` | 231.14 / 445.03 / 9.63 † | 61.38 / 73.77 / 9.91 † | 336.54 / 330.78 / 52.15 † | 136.99 / 131.32 / 29.73 |
| `mixed-clean-4mib` | 63.40 / 111.43 / 9.30 | 22.34 / 22.00 / 9.57 | 228.04 / 222.35 / 51.73 | 41.24 / 35.88 / 23.39 |
| `heldout-mixed-8mib` | 120.62 / 224.58 / 9.41 † | 40.87 / 45.30 / 9.81 † | 277.83 / 272.23 / 52.35 † | 88.47 / 82.78 / 28.90 |
| `git-bounded-control` | 21.88 / 14.00 / 8.73 † | 22.25 / 14.11 / 9.28 † | 208.28 / 200.92 / 49.38 † | 49.22 / 40.38 / 27.39 |
| `git-current-tree-control` | 10.03 / 5.05 / 8.53 | 10.21 / 5.15 / 9.05 | 194.78 / 189.20 / 49.07 | 13.37 / 8.13 / 18.73 |
| `git-staged-control` | 15.55 / 10.01 / 8.56 † | 15.66 / 10.00 / 9.08 † | 201.72 / 195.14 / 49.15 † | 43.70 / 35.40 / 27.39 |

### Shipped rules

| Workload | A6 | A8 | GL | BL |
| --- | --- | --- | --- | --- |
| `json-4mib` | 561.28 / 1,040.12 / 17.54 | 99.87 / 114.11 / 32.95 | 385.24 / 392.29 / 66.44 | 60.93 / 61.15 / 39.53 |
| `base64-20000` | 2,383.49 / 3,776.70 / 61.19 | 895.49 / 955.42 / 77.34 | 967.49 / 1,018.06 / 183.20 | 762.90 / 950.28 / 307.84 |
| `files-100000` | 8,336.99 / 16,450.83 / 19.45 | 2,784.57 / 3,152.91 / 36.27 | 3,730.72 / 28,690.06 / 93.24 | 4,114.59 / 39,940.59 / 52.63 |
| `findings-10000` | 987.40 / 1,437.46 / 42.91 | 441.45 / 461.39 / 54.52 | 548.83 / 572.91 / 114.52 | 387.24 / 424.64 / 139.15 |
| `zstd-500` | 430.95 / 517.21 / 82.16 | 95.19 / 93.30 / 33.43 | 306.19 / 401.34 / 81.24 | 48.73 / 119.64 / 52.55 |
| `git-20000` | 1,105.83 / 1,845.15 / 43.78 | 425.37 / 471.30 / 60.23 | 649.29 / 1,757.28 / 86.22 | 366.49 / 939.12 / 43.80 |
| `json-768-files` | 1,510.13 / 2,928.35 / 18.95 | 129.87 / 172.05 / 34.23 | 331.03 / 630.55 / 88.12 | 52.66 / 169.08 / 46.95 |
| `invalid-utf8-4mib` | 837.66 / 1,563.97 / 20.38 | 119.42 / 149.39 / 33.12 | 375.73 / 382.50 / 67.42 | 71.32 / 69.40 / 37.66 |
| `multilanguage-256kib` | 121.21 / 165.82 / 17.22 | 81.90 / 77.92 / 32.72 | 299.61 / 322.01 / 68.38 | 38.31 / 44.64 / 38.54 |
| `empty-stdin` | 66.37 / 61.07 / 16.81 | 79.57 / 74.03 / 31.98 | 291.16 / 295.96 / 65.73 | 25.82 / 23.66 / 28.21 |
| `tiny-clean-file` | 66.57 / 61.26 / 17.02 | 79.61 / 74.30 / 32.47 | 290.69 / 295.74 / 66.37 | 35.47 / 33.08 / 34.02 |
| `tiny-positive` | 66.77 / 61.42 / 17.03 | 79.82 / 74.41 / 32.55 | 290.95 / 296.55 / 66.15 | 36.47 / 34.19 / 34.54 |
| `tiny-clean-tree` | 67.76 / 63.38 / 17.07 | 80.28 / 75.06 / 32.76 | 291.50 / 299.27 / 70.73 | 36.47 / 36.44 / 35.95 |
| `mixed-app-16mib` | 3,544.44 / 6,995.67 / 17.55 | 148.26 / 209.00 / 33.09 | 368.74 / 923.01 / 90.75 | 88.69 / 345.16 / 54.46 |
| `mixed-clean-4mib` | 929.48 / 1,778.83 / 17.36 | 96.86 / 108.10 / 32.70 | 309.76 / 454.63 / 85.82 | 44.87 / 107.97 / 44.12 |
| `heldout-mixed-8mib` | 1,818.80 / 3,552.90 / 17.54 | 117.11 / 145.37 / 32.97 | 338.10 / 664.69 / 89.34 | 56.21 / 209.69 / 48.70 |
| `git-bounded-control` | 80.09 / 71.14 / 17.05 | 92.96 / 83.97 / 32.53 | 305.99 / 312.90 / 70.30 | 63.99 / 60.29 / 36.31 |
| `git-current-tree-control` | 66.54 / 61.35 / 16.98 | 79.75 / 74.35 / 32.52 | 290.50 / 295.24 / 65.88 | 35.75 / 33.53 / 33.92 |
| `git-staged-control` | 72.87 / 66.46 / 17.04 | 86.20 / 79.63 / 32.45 | 299.64 / 303.13 / 66.06 | 57.97 / 54.03 / 35.40 |

## Wall-time variation

Each entry is **minimum to maximum; MAD**, in milliseconds, across the same
eight samples as the medians above. The summary also retains user CPU,
system CPU, and RSS minima, maxima, medians, and MADs. These ranges describe
this collection and are not confidence intervals.

### Shared rules

| Workload | A6 | A8 | GL | BL |
| --- | --- | --- | --- | --- |
| `json-4mib` | 45.05 to 45.57; 0.11 | 13.34 to 14.75; 0.11 | 211.40 to 224.95; 1.62 | 37.62 to 38.48; 0.10 |
| `base64-20000` | 1,168.14 to 1,200.47; 5.55 | 785.55 to 865.73; 9.32 | 577.29 to 590.80; 2.55 | 398.66 to 410.66; 0.92 |
| `files-100000` | 2,625.13 to 2,715.48; 22.82 | 2,565.55 to 2,677.47; 17.21 | 4,329.00 to 5,303.89; 32.04 | 3,397.23 to 3,665.04; 24.64 |
| `findings-10000` | 478.09 to 490.45; 3.23 | 340.55 to 354.66; 4.64 | 305.60 to 331.32; 7.01 | 243.02 to 249.53; 1.75 |
| `zstd-500` | 361.08 to 365.00; 0.72 | 22.39 to 22.93; 0.17 | 214.04 to 235.76; 1.68 | 51.71 to 52.86; 0.21 |
| `git-20000` | 690.48 to 704.57; 2.67 | 329.44 to 345.01; 2.21 | 470.26 to 504.44; 5.19 | 319.19 to 329.99; 1.15 |
| `json-768-files` | 83.19 to 84.88; 0.12 | 29.45 to 29.80; 0.11 | 256.29 to 275.21; 4.98 | 84.85 to 86.10; 0.22 |
| `invalid-utf8-4mib` | 42.46 to 43.11; 0.07 | 22.27 to 23.10; 0.11 | 241.75 to 266.04; 2.33 | 52.27 to 52.76; 0.10 |
| `multilanguage-256kib` | 13.96 to 14.34; 0.04 | 10.91 to 11.31; 0.03 | 184.74 to 213.49; 2.75 | 25.54 to 25.99; 0.08 |
| `empty-stdin` | 9.67 to 10.16; 0.08 | 9.83 to 10.24; 0.05 | 181.34 to 211.05; 10.66 | 13.08 to 14.45; 0.07 |
| `tiny-clean-file` | 9.83 to 10.37; 0.11 | 9.88 to 10.29; 0.05 | 182.27 to 211.12; 2.76 | 13.12 to 13.35; 0.06 |
| `tiny-positive` | 10.04 to 10.32; 0.03 | 10.12 to 10.55; 0.11 | 185.00 to 209.25; 2.79 | 23.04 to 23.33; 0.09 |
| `tiny-clean-tree` | 10.04 to 10.77; 0.06 | 10.07 to 10.56; 0.11 | 193.30 to 208.79; 0.70 | 13.41 to 13.76; 0.03 |
| `mixed-app-16mib` | 230.07 to 233.67; 0.71 | 60.10 to 69.86; 0.69 | 323.15 to 351.37; 5.25 | 136.14 to 151.07; 0.85 |
| `mixed-clean-4mib` | 63.17 to 68.48; 0.13 | 21.96 to 23.41; 0.25 | 216.33 to 232.50; 3.37 | 41.05 to 41.71; 0.15 |
| `heldout-mixed-8mib` | 120.31 to 121.39; 0.21 | 40.50 to 41.53; 0.22 | 266.64 to 288.26; 7.96 | 88.02 to 89.24; 0.28 |
| `git-bounded-control` | 20.92 to 22.11; 0.06 | 21.68 to 23.60; 0.53 | 195.61 to 223.61; 5.22 | 48.85 to 49.39; 0.12 |
| `git-current-tree-control` | 9.86 to 10.22; 0.07 | 9.95 to 10.37; 0.05 | 181.32 to 209.76; 1.50 | 13.18 to 14.44; 0.14 |
| `git-staged-control` | 15.50 to 16.52; 0.05 | 15.38 to 16.59; 0.27 | 189.52 to 220.46; 2.98 | 43.36 to 43.92; 0.17 |

### Shipped rules

| Workload | A6 | A8 | GL | BL |
| --- | --- | --- | --- | --- |
| `json-4mib` | 559.47 to 570.16; 0.93 | 99.58 to 100.35; 0.14 | 384.78 to 386.78; 0.39 | 60.54 to 62.36; 0.24 |
| `base64-20000` | 2,374.89 to 2,499.73; 6.08 | 884.15 to 1,086.62; 1.53 | 962.99 to 994.11; 4.49 | 745.39 to 804.61; 2.59 |
| `files-100000` | 8,322.15 to 8,345.36; 6.93 | 2,755.87 to 2,822.25; 5.58 | 3,546.38 to 3,919.61; 151.35 | 3,978.17 to 4,463.76; 60.24 |
| `findings-10000` | 979.16 to 1,061.13; 4.24 | 438.74 to 447.67; 1.77 | 548.35 to 554.52; 0.45 | 383.70 to 395.24; 1.29 |
| `zstd-500` | 426.00 to 435.16; 1.55 | 93.29 to 95.46; 0.20 | 305.17 to 310.18; 0.76 | 47.64 to 49.51; 0.37 |
| `git-20000` | 1,103.84 to 1,122.83; 0.84 | 422.07 to 431.18; 2.40 | 647.91 to 653.59; 1.08 | 363.79 to 371.68; 0.89 |
| `json-768-files` | 1,492.56 to 1,546.67; 13.70 | 129.09 to 142.69; 0.48 | 328.09 to 375.06; 2.15 | 51.79 to 95.52; 0.64 |
| `invalid-utf8-4mib` | 821.17 to 921.63; 14.91 | 116.02 to 161.34; 3.00 | 372.68 to 392.69; 3.01 | 70.28 to 132.72; 0.87 |
| `multilanguage-256kib` | 119.44 to 124.17; 0.53 | 81.10 to 83.05; 0.44 | 292.72 to 308.23; 1.27 | 37.68 to 77.16; 0.37 |
| `empty-stdin` | 66.20 to 67.37; 0.11 | 79.22 to 84.04; 0.18 | 288.96 to 291.91; 0.40 | 25.36 to 26.18; 0.21 |
| `tiny-clean-file` | 66.45 to 66.84; 0.12 | 79.50 to 81.07; 0.09 | 289.80 to 292.18; 0.40 | 35.31 to 35.89; 0.11 |
| `tiny-positive` | 66.58 to 66.90; 0.06 | 79.53 to 79.96; 0.11 | 290.22 to 293.15; 0.31 | 35.60 to 39.08; 0.20 |
| `tiny-clean-tree` | 67.59 to 67.99; 0.05 | 79.94 to 81.18; 0.28 | 290.60 to 293.11; 0.35 | 36.00 to 37.56; 0.22 |
| `mixed-app-16mib` | 3,537.66 to 3,552.28; 3.19 | 147.72 to 150.07; 0.30 | 367.04 to 374.18; 0.80 | 87.27 to 90.38; 0.88 |
| `mixed-clean-4mib` | 928.08 to 934.94; 1.22 | 96.61 to 97.60; 0.23 | 309.17 to 313.15; 0.45 | 43.86 to 45.93; 0.41 |
| `heldout-mixed-8mib` | 1,817.18 to 1,824.62; 1.49 | 116.55 to 121.24; 0.22 | 337.10 to 341.03; 0.53 | 55.54 to 59.42; 0.28 |
| `git-bounded-control` | 79.41 to 80.52; 0.30 | 92.37 to 93.88; 0.47 | 305.07 to 308.80; 0.91 | 63.19 to 64.58; 0.36 |
| `git-current-tree-control` | 66.40 to 66.98; 0.14 | 79.67 to 80.79; 0.07 | 289.50 to 291.40; 0.50 | 35.21 to 35.92; 0.05 |
| `git-staged-control` | 72.57 to 75.03; 0.15 | 85.51 to 87.79; 0.22 | 299.15 to 300.65; 0.21 | 57.22 to 58.43; 0.32 |

## Evidence and reproduction

- [Version manifest](cross-scanner-versions.json): release identities, hashes,
  checksum evidence, defaults, and build metadata.
- [Input identities](cross-scanner-2026-11-11/input-identities.json): generator
  seeds, input inventory hashes, workload metadata, and Git scope identities.
- [Complete summary](cross-scanner-2026-11-11/summary.json): measured settings,
  canonical commands, all samples, coverage, quality dispositions, statistics,
  and matching before/after identities.
- [Numeric samples](cross-scanner-2026-11-11/samples.csv): all 1,216 measured
  repetitions. Tool and workload indices use the summary's `tool_order` and
  `workload_order`; profiles 0 and 1 are shared and shipped respectively.
- [Completion record](cross-scanner-2026-11-11/COMPLETE.json): successful terminal
  disposition and SHA-256 hashes of the summary and numeric samples.

The [protocol's reproduction command](../PERFORMANCE_COMPARISON.md#reproduction-and-evidence)
uses explicit executable and Git paths and a new output directory. The measured
collector and generator are identified by the source commit above and by payload
hashes in the evidence. Raw scanner reports, diagnostics, and fixture finding
values remain outside the public evidence. This optional comparison is not a
release-readiness gate or a new platform-support claim.

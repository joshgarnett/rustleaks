# In-memory fragment throughput validation

Measured on 2026-11-09 using Apple M1 Max, 32 GiB RAM, macOS arm64,
Rust 1.95.0 and optimized unstamped Bazel builds. The baseline core is
`0d7ca92` (`0.1.0-alpha.6`); the workload commit is `d73840c`.
Dependency versions and the packaged default configuration are unchanged.

The existing `cargo xtask perf` representative harness supplies synthetic
JSON-like and log-like 512-byte records with 32 dispersed provider names,
at least 32 admitted rules, and one reviewed private-key fixture per fragment.
Invalid UTF-8 is distributed through two log workloads. Decode depth is zero.
Each operation reuses one default Engine and retains one outcome at a time.
Fixture construction, configuration compilation, validation and destruction
are outside scan timers. Three fresh processes supply each median.

## Scan measurements

Steady-operation medians in milliseconds. Every column retains identical
full-finding and outcome fingerprints, work units, decoded-byte counts,
finding-record counts and completion status for all 14 workloads.

| Workload | PikeVM | Pooled meta | Capture-free search | Shared preprocessing |
| --- | ---: | ---: | ---: | ---: |
| json 16 KiB | 23.960 | 1.464 | 1.379 | 1.139 |
| json 256 KiB | 358.945 | 21.810 | 20.789 | 16.923 |
| json 1 MiB | 1430.527 | 86.211 | 82.870 | 67.659 |
| json 4 MiB | 5734.154 | 344.785 | 330.674 | 270.495 |
| json 12 MiB / 16 KiB | 18457.376 | 1090.265 | 1026.602 | 837.934 |
| json 12 MiB / 256 KiB | 17249.231 | 1044.343 | 996.098 | 811.939 |
| log 16 KiB | 25.669 | 1.620 | 1.383 | 1.132 |
| log 256 KiB | 385.983 | 21.722 | 20.771 | 16.951 |
| log 1 MiB | 1540.332 | 86.505 | 82.851 | 67.733 |
| log 4 MiB | 6141.931 | 344.961 | 331.399 | 270.310 |
| log 12 MiB / 16 KiB | 19688.303 | 1090.612 | 1030.393 | 838.354 |
| log 12 MiB / 256 KiB | 18516.992 | 1042.540 | 993.900 | 812.640 |
| invalid 4 MiB | 6898.599 | 1095.026 | 942.311 | 290.303 |
| invalid 12 MiB / 16 KiB | 21197.497 | 2318.590 | 2314.455 | 881.176 |

The largest final first-operation median is 884.530 ms. All first and steady
medians meet the unchanged 1.5-second target on this host. Other hosts retain
exact outcome checks and report timing without this host-specific threshold.
No multi-pattern prefilter is added; the fragment-wide keyword gate is unchanged.

The final legacy budget gate passed all existing elapsed and peak-RSS limits:

| Workload | Median ms | Peak RSS MiB |
| --- | ---: | ---: |
| Default compile | 67.660 | 30.53 |
| One keyword | 9.593 | 33.62 |
| Hostile regex miss | 1.849 | 8.42 |
| Five decode levels | 5.821 | 10.64 |
| Directory, one worker | 66.068 | 9.41 |
| Directory, four workers | 17.649 | 11.77 |
| JSON report | 17.288 | 22.33 |

Default compilation remains below its 100 ms limit; the initial PikeVM sample
was 83.899 ms. Effective-rule validation reuses the selected compiled capture
count instead of compiling each rule again. The largest observed fragment
workload peak process RSS, for invalid UTF-8 at 4 MiB, fell from 228.09 MiB to
94.53 MiB. Those process peaks include fixtures, buffers, runtime and engine.

## Retained memory

The existing `perf profile` worker retained one default Engine with 222 rules
and 242 compiled regexes: 221 content patterns, five path patterns and 16
joined allowlist matchers. One thread repeatedly scanned its synthetic 16 KiB
many-keyword fixture. Native heap snapshots after warm-up and after 6,842
additional scans both reported 23,358,672 live allocated bytes (22.28 MiB).
The rounded physical footprint was 28.8 MiB in both snapshots.

These are whole-worker observations, including the Engine, two small input
buffers and runtime metadata, not isolated cache-byte accounting.
The worker retains its Engine between snapshots, drops each scan outcome,
and uses optimized profiling builds with line tables and frame pointers.
The observation shows stable retained memory for this workload and thread
count; it does not bound other regexes, fragment sizes, clones or concurrency.

## Compatibility, security and limits

The maintained PikeVM differential tests compare all captures, whole spans
and match existence across 3,618 regex requests, 6,770 default-rule samples
and 80 synthetic byte/empty-match cases. The final extension also compares
first-only captures. The historical Unicode-16 dispositions remain unchanged.
Original newline locations are shared across decoded passes, with explicit
newline/empty/end-of-input cases and exhaustive small-span comparison against
the previous location loop. Eager enumeration and work checkpoints remain fixed.

Lazy caches can thrash or give up on hostile input or large Unicode classes.
PikeVM fallback preserves fixed-pattern linear search, but can lose the speedup;
complete eager enumeration has no new wall-clock or linear-time guarantee.
Compilation retains the per-NFA limit, including the reverse NFA, and retries
without DFA acceleration when only the reverse limit prevents compilation.
The [dependency review](../dependency-audits/regex-meta-backend.md) records
the expanded unsafe dependency paths, component limits and pooled retention.

Validation passed: `just format`, `just parity`, `just test`, `just check`,
`just fuzz-build`, `just fuzz-smoke`, `just package-check`, `just security`,
`just ci` and `just perf-check`. All 60 CI targets passed, including the
eight-target compilation gate. All eight fuzz campaigns completed with zero
artifacts; `go_regex` replayed its 3,386 corpus files. Independent local review
has no unresolved material findings. API dispositions passed the maintained
generator check without regeneration. The cargo-vet feature inventory was
regenerated with no exemption changes.

No new dependency version, advisory, vetting or compatibility exception is
accepted. Native evidence in this record is macOS arm64 only; cross-compilation
does not establish native behavior on the other targets.

# Performance against alpha.6

Measured on 2026-11-10 on Apple M1 Max, 32 GiB RAM, macOS 26.5.2 arm64, with 10 logical
CPUs and Rust 1.95.0. The production baseline is tag `v0.1.0-alpha.6`, commit
`0d7ca9254f7ce486e4ee7c3b75395578eef28f76`; the candidate is
`7612d99c6a1ee4f462f216498d1259ff941885b1`.

The initial matrix records lower medians for all 117 steady scans, 113 of 117
first scans, and all 16 directory traversal-and-detection phases. Configuration
compilation costs more in all 117 core workloads, and several workloads use
more process memory. These observations apply to the measured fixtures.

The [comparison against main](main-branch-performance.md) retains its original
baseline and candidate attribution. This record measures the longer alpha.6
to candidate interval, including the earlier regex engine changes. Its ratios
must not be attributed solely to the later changes measured against main.

## Baseline and build identity

The clean baseline measurement checkout is
`30204cebece8f1222d6c3fedfd08a8d94cfcf23c`. Its complete diff from alpha.6
changes only 21 benchmark harness and support paths. All other tracked content
and modes retain the requested alpha.6 identity. All 32 workload-definition
inputs match the candidate, with combined SHA-256
`f0331e42dd8772bed7ff9787353d311889bb0fb18c643efa181aa79091fb1efd`.
Both executables use optimized Bazel builds with stamping disabled.

Third-party package versions, sources and checksums are unchanged, including
`regex-automata` 0.4.18. Its requested features do differ: alpha.6 enables
`std`, `syntax`, `nfa-pikevm` and `unicode`; the candidate additionally enables
`meta`, `hybrid`, `dfa-onepass`, `nfa-backtrack` and `perf`. The generated Bazel
lock records the resulting features and the added `aho-corasick` and `memchr`
dependency edges. This comparison measures that combined implementation and
feature change.

Each side's five recorded lockfile and toolchain-input hashes was checked
against its own exact committed bytes. `Cargo.lock` differs only in six
first-party workspace versions; `MODULE.bazel` differs only in the module
version. `cargo-bazel-lock.json` records those versions and the regex features
and dependency edges above. `MODULE.bazel.lock` and `rust-toolchain.toml`
match. Compiler binary identity, compiler version and options, argument-file
identities, Rust action counts, packaged default configuration, upstream pin,
workload definitions, host and collector match. Action hashes and resulting
binaries differ and remain recorded in the raw provenance.

## Method and outcome checks

The full matrix ran serially, baseline then candidate, after build activity
stopped. Each of 163 workloads supplied three fresh processes and one iteration
per measured phase, giving 584 phase comparisons. Fixtures are synthetic or
reviewed upstream archive fixtures. The tables below use these initial
three-process medians. The [complete CSV](alpha6-branch-performance.csv)
retains every phase's median, minimum, maximum, median absolute deviation and
elapsed change, including setup and first scans.

Both runs ended with `run-complete` and clean-source provenance. For 583 phases,
every phase field except elapsed time matched across builds and samples,
including input/configuration/outcome fingerprints, work counts, finding count,
iterations and completion status. The remaining phase, CLI
`cold-process-version`, intentionally prints `0.1.0-alpha.6\n` versus
`0.1.0-alpha.7\n`. Their independently derived FNV-1a-64 fingerprints are
`75328add76208e91` and `752f10dd761d896c`; every other field matches. Both
original phase objects are retained. There were no unexpected phase-contract
differences. Each workload also executed its independent fixture assertions;
fingerprints are not a separate comparison of every raw finding field.

Core scan timers exclude fixture construction, configuration compilation,
verification and outcome destruction. Worker timers include dispatch and
result collection. Source rows use the named traversal, detection or archive
operation; CLI rows include process startup. Report workloads use their
documented output-buffer setup. Files are created before measurement, and
filesystem cache state is uncontrolled. Definitions and reproduction commands
are in [Performance](../PERFORMANCE.md).

## Initial scan, source and report results

Core rows below are steady scans; directory rows include complete traversal
and detection. The large synthetic edge ratios do not estimate typical field
throughput.

| Workload | Alpha.6 ms | Candidate ms | Speedup |
| --- | ---: | ---: | ---: |
| Default rules, JSON, 4 MiB | 5,612.008 | 16.875 | 332.56x |
| Default rules, JSON, 12 MiB in 16 KiB fragments | 18,060.895 | 58.147 | 310.61x |
| Default rules, invalid UTF-8, 4 MiB | 6,715.425 | 259.368 | 25.89x |
| Default rules, multi-language source, 256 KiB | 67.475 | 0.926 | 72.87x |
| Default rules, `.env` assignments, 256 KiB | 105.343 | 2.076 | 50.75x |
| Shared engine, 8 workers, 12 MiB | 2,858.415 | 9.115 | 313.60x |
| Long-lived engine, 10,000 varied scans | 116,571.843 | 1,467.891 | 79.41x |
| 20,000 base64 lines, depth 1 | 1,520.018 | 23.304 | 65.23x |
| 1 MiB line, 10,000 decoded findings allowlisted | 17,450.538 | 10.093 | 1728.95x |
| 65,536 generic findings plus 8,192 specific findings | 21,413.698 | 82.685 | 258.98x |
| Baseline classification, 10,000 findings and entries | 133.086 | 4.337 | 30.69x |
| JSON report, 10,000 findings | 11.506 | 6.096 | 1.89x |
| SARIF report, 10,000 findings | 22.624 | 10.475 | 2.16x |
| Default rules, directory, 12 MiB, 1 worker | 400.709 | 28.253 | 14.18x |
| Default rules, directory, 12 MiB, 8 workers | 56.860 | 8.490 | 6.70x |
| Single-line file, 64 MiB | 420.467 | 64.053 | 6.56x |
| Directory, 50,000 tiny files | 1,407.112 | 1,339.515 | 1.05x |
| Git, 20,000 commits, history and detection | 842.312 | 503.052 | 1.67x |
| 500 small zstd files | 352.683 | 51.266 | 6.88x |
| Gzip, 60 MiB of zeros, under limit | 751.880 | 96.130 | 7.82x |
| CLI, 10,000 size-limit warnings | 389.073 | 49.641 | 7.84x |

## Initial setup and first-scan costs

Configuration compilation increases throughout the core matrix. Engine
construction has higher medians in 113 of 117 workloads. Setup is outside the
steady-scan times above and matters when callers repeatedly create engines.
All four initial first-scan increases are included below.

| Workload and phase | Alpha.6 ms | Candidate ms | Elapsed change |
| --- | ---: | ---: | ---: |
| Default-rule JSON, 4 MiB, config parse and compile | 55.471 | 67.488 | +21.66% |
| Default-rule JSON, 4 MiB, engine construction | 0.213 | 0.673 | +215.44% |
| Generated 5,000-rule config parse and compile | 74.856 | 96.019 | +28.27% |
| Generated 1,000-rule engine construction | 0.582 | 1.276 | +119.20% |
| Default-positive first scan | 0.112 | 0.217 | +93.35% |
| Mixed 1 KiB first scan | 0.194 | 0.242 | +24.46% |
| Allowlisted lockfile path, 256 KiB, first scan | 0.019 | 0.035 | +85.78% |
| Decode depth zero, first scan | 0.201 | 0.211 | +4.98% |
| Default CLI, empty stdin | 61.507 | 74.946 | +21.85% |
| Selected-rule CLI, empty stdin | 61.600 | 74.208 | +20.47% |

## Reverse-order repeats

Ten selected workloads then ran in reverse order, candidate before baseline,
with seven fresh processes per side and one iteration per phase. They cover
representative gains, configuration and startup costs, two first-scan increases,
and workloads with increased RSS. All 33 repeated phase contracts matched
except elapsed time. The [repeat CSV](alpha6-branch-performance-repeats.csv)
retains every repeated phase separately from the initial matrix.

| Repeated workload and phase | Alpha.6 ms | Candidate ms | Elapsed change |
| --- | ---: | ---: | ---: |
| Default-rule JSON, 4 MiB, steady scan | 5,611.748 | 16.913 | -99.70% |
| Cloned engines, 8 workers, 12 MiB, steady scan | 2,545.463 | 8.279 | -99.67% |
| Default-rule no-hit, 16 KiB, steady scan | 0.136 | 0.030 | -78.32% |
| Mostly ignored directory, traversal and detection | 31.160 | 2.621 | -91.59% |
| Default-rule JSON, config parse and compile | 55.343 | 68.434 | +23.65% |
| Default-rule JSON, engine construction | 0.216 | 0.686 | +218.48% |
| Generated 5,000-rule config parse and compile | 75.494 | 96.330 | +27.60% |
| Allowlist-heavy configuration compilation | 62.162 | 81.925 | +31.79% |
| Default-positive first scan | 0.116 | 0.222 | +91.07% |
| Allowlisted lockfile path, 256 KiB, first scan | 0.017 | 0.034 | +97.84% |
| Default CLI, empty stdin | 61.851 | 75.125 | +21.46% |
| Selected-rule CLI, empty stdin | 61.444 | 74.150 | +20.68% |
| Git wide commit, history and detection | 39.724 | 37.679 | -5.15% |

Every row shown above has disjoint repeat sample ranges. The cold compilation,
construction and startup increases recur in the reversed collection order,
as do the two selected first-scan increases. The remaining two initial
first-scan increases were not repeated. These small samples do not establish
statistical significance or explain individual causes.

The Git wide-commit phase's initial 2.9% increase reversed to a 5.2% decrease,
so these measurements do not establish a persistent slowdown.

The RSS increases also recur: the generated 5,000-rule workload rises from
49.09 to 118.72 MiB, eight cloned workers from 51.39 to 81.41 MiB, and the
mostly ignored directory from 40.70 to 69.47 MiB. These are medians of separate
whole-process repeats, not isolated engine memory measurements.

## Initial process CPU time and memory

CPU time is user plus system time. These three-process medians include fixture
construction, verification, destruction and waited descendants. Peak RSS is
whole-process evidence, not isolated engine memory or allocation counts.
Process measurements must not be added across phase rows.

| Workload | Alpha.6 CPU ms | Candidate CPU ms | Alpha.6 peak MiB | Candidate peak MiB |
| --- | ---: | ---: | ---: | ---: |
| Default-rule JSON, 4 MiB | 11,326.463 | 156.646 | 33.09 | 45.25 |
| Generated 5,000-rule configuration | 239.768 | 130.372 | 49.28 | 118.97 |
| Shared engine, 8 workers, 12 MiB | 45,825.695 | 297.600 | 48.27 | 74.58 |
| Cloned engines, 8 workers, 12 MiB | 43,156.274 | 293.768 | 51.53 | 81.36 |
| Long-lived engine, 10,000 varied scans | 233,433.115 | 3,333.095 | 18.53 | 41.42 |
| Sparse invalid UTF-8, 4 MiB | 240.934 | 23.206 | 63.75 | 20.45 |
| 500 small zstd files | 425.252 | 125.830 | 80.69 | 24.73 |
| 1 MiB line, 10,000 retained decoded findings | 37,111.294 | 1,980.741 | 10,094.83 | 10,070.72 |

The generated 5,000-rule workload has the largest initial median RSS increase,
69.69 MiB. Default-rule JSON scanning also uses more process memory despite
its lower CPU time. The retained decoded-findings workload still peaks near
10 GiB because findings retain full line copies. These measurements do not
isolate the contribution of regex caches or other engine allocations.

## Validation and limits

This comparison validates complete benchmark collections, exact committed
identities and the phase contracts described above. It does not claim a new
CI, security, fuzz or release-qualification run. The prior production gates
reported in [the main comparison](main-branch-performance.md) apply to
`749430701095b4a61fbfd5a63488db0ceb34339f`; the measured candidate
`7612d99c6a1ee4f462f216498d1259ff941885b1` differs only in documentation and
performance evidence, with identical production code and workload definitions.

Native timings apply only to this macOS arm64 host. Three initial samples,
even with selected repeats, do not establish statistical significance or
portable performance guarantees. No new performance threshold is introduced.

Initial raw collection SHA-256 values:

- Alpha.6 baseline: `920085cb578dfb8d8cfe394a9597577ad90bba45aa255e6d08bb3aff24a30b0d`.
- Candidate: `7e0c7d2be661e913349a4e718cd719f58bc68ae3b1ddba8a7e1709b17aac087c`.

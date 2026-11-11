# Filtering and normalization performance

Measured on 2026-11-10 on Apple M1 Max, 32 GiB RAM, macOS 26.5.2 arm64,
10 logical CPUs, Rust 1.95.0, using optimized unstamped Bazel builds.
The baseline is `8138192b004a62923c2fb093477b81b36b7d288a`: alpha.7
production code plus the frozen workload definitions. The measured candidate
is `e877fcde1c226a19e61c69d434c96856506c9b0d`. Later commits adjust test
scheduling, test literal syntax and benchmark dispatcher syntax without
changing detector behavior, workload data, timing boundaries or oracles.
The comparison tables remain attributed to that measured commit. Dependency
versions, regex
features, public API and packaged default configuration are unchanged.

## Measurement boundaries

The existing `cargo xtask perf` harness supplies 29 synthetic edge workloads,
14 default-rule fragment workloads and six worker workloads. Three fresh
processes supply each median. Edge and ordinary cases use one steady iteration;
worker cases use three. Scan timers exclude fixture construction, configuration
compilation, outcome validation and destruction. First-scan results are also
validated. No real application input is used.

Filtering cases deliberately retain zero findings, isolating repeated scanning
from the required copying of lines into accepted findings. Their independent
oracles check candidate work and zero retained records. Literal-miss
normalization controls omit keywords, forcing the regex input path; their
numbers do not represent default-rule throughput. Empty-match controls
exercise eager enumeration. Percent cases distinguish valid decoding from an
invalid byte preserved outside the decoded segment.

The workload-definition SHA-256 is
`c354b50bf4a063cd5eb84fdef6a8712a2c553a427253ff37d3a710e9b295338d`.
All baseline and combined-candidate runs completed with clean-source provenance
and unchanged workload identity. Full finding/outcome fingerprints, work units,
decoded bytes, record counts and completion status match the baseline for every measured phase.

Measurements ran serially. Background macOS services were active near the
initial baseline, so the edge baseline was repeated after the candidate run.
For example, the repeated 4 MiB marker case took 11,661 ms versus 12,107 ms
initially; dense-invalid normalization took 57.783 ms versus 60.050 ms. These
variations do not explain the large improvements. Across all edge cases,
repeated medians ranged from 86.0% to 100.2% of the initial values. Worker
baselines were not repeated, so their smaller before/after differences should
not be attributed entirely to the implementation. Ordinary baseline controls
were collected again in that final repeat. Small percentage changes are
host observations, not portable guarantees.

## Scan results

Steady-scan medians in milliseconds. Edge baselines below use the initial run.

| Synthetic case | Alpha.7 | Candidate |
| --- | ---: | ---: |
| Marker-suppressed long line, 4 MiB / 4,096 candidates | 12,107.356 | 4.671 |
| Line allowlist, 256 KiB / 1,024 candidates | 385.403 | 0.648 |
| Line allowlist with invalid UTF-8, 256 KiB | 1,127.490 | 0.661 |
| Overlapping stopwords, 256 KiB | 35.907 | 3.525 |
| Matches after the last newline, 256 KiB | 118.159 | 0.227 |
| ASCII literal miss, 4 MiB | 19.002 | 0.260 |
| Sparse invalid UTF-8 literal miss, 4 MiB | 37.728 | 0.329 |
| Dense invalid UTF-8 literal miss, 4 MiB | 60.050 | 15.794 |
| Empty matches with invalid UTF-8, 64 KiB | 2.509 | 2.216 |
| Valid percent decoding, 4 MiB / depth 1 | 175.861 | 151.542 |
| Percent decoding with preserved invalid prefix, 4 MiB / depth 1 | 221.347 | 146.751 |

Ordinary controls use the existing dispersed-keyword JSON/log workloads and
full finding oracle, default configuration and decode depth zero:

| Workload | Alpha.7 | Candidate |
| --- | ---: | ---: |
| JSON, 4 MiB | 270.493 | 252.529 |
| JSON, 12 MiB / 16 KiB fragments | 837.991 | 785.357 |
| JSON, 12 MiB / 256 KiB fragments | 811.935 | 757.997 |
| Log, 4 MiB | 269.853 | 252.534 |
| Log, 12 MiB / 16 KiB fragments | 837.744 | 785.365 |
| Log, 12 MiB / 256 KiB fragments | 810.310 | 758.665 |
| Invalid UTF-8, 4 MiB | 290.193 | 261.420 |
| Invalid UTF-8, 12 MiB / 16 KiB fragments | 881.196 | 811.458 |

All candidate ordinary 4 MiB and 12 MiB steady medians remain below
1.5 seconds on this host. The largest ordinary first-scan median is 815.144 ms.

## Attribution and memory

Native profiles and targeted comparisons identified repeated marker scans,
overlapping stopword enumeration, Go lowercasing and invalid-byte offset-map
construction. Profile loops include validation and destruction, so their elapsed times are not used
as scan medians.

The fixes were measured separately before the combined run:

- Boolean first-hit stopword search reduced the 256 KiB overlap case from
  35.907 to 5.858 ms. The helper selecting a particular stopword retains its
  previous ordering.
- Compact replacement checkpoints reduced sparse-invalid 4 MiB scans from
  37.728 to 19.877 ms before preprocessing changes. An exploratory
  uncommitted binary-search mapping regressed the dense empty-match case from
  2.509 to 3.966 ms; a local ordered cursor removed repeated searches. The final combined case is faster
  than the original baseline. Capture endpoints retain independent lookups.
- Per-scan marker/tail memoization and per-rule line-regex memoization reduced
  the 4 MiB marker case to 23.466 ms and the invalid line-allowlist case to
  1.836 ms before preprocessing changes.
- Borrowing the original fragment, omitting lowercase work when no keyword
  matcher exists, and using ASCII fast paths with the pinned Go Unicode
  fallback produced the combined results above.

Reported RSS is the median of three fresh-process peaks. It includes fixtures,
compiled rules, buffers, caches and outcomes. It is not isolated engine or
lazy-DFA cache accounting.

| Workload | Alpha.7 MiB | Candidate MiB |
| --- | ---: | ---: |
| Marker-suppressed 4 MiB | 24.20 | 16.22 |
| Sparse invalid UTF-8, 4 MiB | 64.19 | 20.23 |
| Dense invalid UTF-8, 4 MiB | 148.14 | 102.09 |
| Percent decoding with invalid prefix, 4 MiB / depth 1 | 80.06 | 26.72 |

The worker matrix retains a default Engine across batches, with 222 rules and
242 compiled regexes. Every batch scans the same 12 MiB in 768 fragments.
Caller-owned persistent threads share an Engine or each retain a clone.
Dispatch, scanning and result collection are timed; startup and clone creation
are separate. This adds no concurrency or implicit threads to the core.

| Engine use / workers | Alpha.7 ms | Candidate ms | Candidate peak RSS MiB |
| --- | ---: | ---: | ---: |
| Shared / 1 | 867.247 | 785.038 | 61.28 |
| Shared / 4 | 224.171 | 208.192 | 71.48 |
| Shared / 8 | 114.234 | 105.356 | 85.64 |
| Cloned / 1 | 839.555 | 783.007 | 61.88 |
| Cloned / 4 | 222.325 | 207.833 | 74.67 |
| Cloned / 8 | 112.376 | 104.661 | 92.23 |

This workload scales with a shared Engine; cloning gives little additional
throughput and increases process memory. It provides no evidence requiring an
explicit cache pool. The earlier
[retained-memory observation](core-fragment-throughput.md#retained-memory)
remains evidence for its original candidate only.

## Related scanner techniques

[Gitleaks stopword filtering](https://github.com/gitleaks/gitleaks/blob/v8.30.1/config/allowlist.go)
and [detect-secrets wordlist filtering](https://github.com/Yelp/detect-secrets/blob/v1.5.0/detect_secrets/filters/wordlist.py)
stop after finding a match. That approach fits Rustleaks' boolean stopword path.
[detect-secrets scan filtering](https://github.com/Yelp/detect-secrets/blob/v1.5.0/detect_secrets/core/scan.py)
also motivates sharing pure line predicates. Rustleaks caches exact borrowed
line slices while preserving each allowlist's surrounding conditions.

[Nosey Parker's matcher](https://github.com/praetorian-inc/noseyparker/blob/v0.24.0/crates/noseyparker/src/matcher.rs)
shares compiled rules with per-matcher scratch. The worker results above favor
retaining the existing pooled meta engine here.
[TruffleHog's keyword matcher](https://github.com/trufflesecurity/trufflehog/blob/main/pkg/engine/ahocorasick/ahocorasickcore.go)
caps retained lowercase buffers at 1 MiB; this change instead removes
unnecessary allocation and retains exact Go lowercase behavior.

Fixed keyword windows or overlapping chunks, such as those in
[Trivy's secret scanner](https://github.com/aquasecurity/trivy/blob/main/pkg/fanal/secret/scanner.go),
do not establish equivalent arbitrary fragment-wide matching. No such window,
new multi-pattern prefilter, native engine or copied scanner code is added.

## Compatibility, security and remaining limits

The independent old-normalizer reference checks every byte pair, individual
bytes, malformed sequences and valid Unicode, including literal replacement
characters. Location regressions compare the previous loop and retain newline,
empty-input and tail behavior. Allowlist tests cover condition composition,
invalid bytes and decoded-pass lifetimes. Existing PikeVM differential and
frozen-corpus checks remain enabled. Work, cancellation, explanation order and
eager match enumeration are unchanged.

Line memoization stores only exact-range results within the existing scan and
rule-pass lifetimes. Replacement checkpoints scale with invalid input bytes;
they are still unbounded without caller input limits. Dense accepted findings
can still copy large lines repeatedly. Percent decoding remains a material
cost. Lazy-DFA thrashing or give-up can still remove acceleration; no new
wall-clock deadline or whole-scan linear-time guarantee is claimed.

Validation passed: `just ci` (all 60 targets, including parity and the
eight-target compile matrix), `just security`, formatting and focused core,
engine and performance-harness tests. The final clean candidate
`ea1bfff6368a1efeff4697519a339770df5fc12c` passed `cargo xtask qualify`,
including strict lint, default/all-feature tests, MSRV, Miri, frozen evidence,
public API, package and external Cargo/Bazel consumers, dependency policy,
panic policy, fuzzing and performance budgets. All eight fuzz targets completed
with zero artifacts; `go_regex` replayed 3,386 corpus files. No differential
divergence or new security exception was observed. Independent source, security
and measurement review found no unresolved material issue.

The final legacy latency and peak-RSS budgets passed:

| Workload | Median ms | Peak RSS MiB |
| --- | ---: | ---: |
| Default compile | 69.132 | 30.78 |
| One keyword | 5.159 | 32.98 |
| Hostile regex miss | 0.669 | 8.39 |
| Five decode levels | 3.280 | 10.81 |
| Directory, one worker | 10.417 | 9.23 |
| Directory, four workers | 10.754 | 9.19 |
| JSON report | 17.167 | 22.52 |

The same final gate rechecked required ordinary fragment medians after the
benchmark syntax cleanup: 4 MiB took 252.791–261.319 ms and 12 MiB took
758.469–811.568 ms. All first and steady medians passed the 1.5-second limit.
Native measurements apply to macOS arm64; compile-only target checks do not
establish native runtime support.

Concurrent repetitions exposed a pre-existing CLI corpus startup observation
race: the fixed one-second timeout can expire before a copied helper writes
its PID file. All ten concurrent baseline repetitions also failed this field.
A private ten-case diagnostic observed four missing PID files; the six recorded
children were no longer live. The CLI corpus target now uses exclusive Bazel
scheduling. Frozen requests, timeout values, cleanup assertions and expected
observations are unchanged. This reduces test contention; it does not eliminate
external host load or turn a missing PID into successful cleanup evidence.
All other 54 targets passed ten repetitions in the initial `just flake-check`;
the corrected CLI target then passed all ten repetitions and a clean-clone
replay. Subsequent syntax-only lint cleanup passed strict quality and focused
Bazel checks.

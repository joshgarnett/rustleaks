# Evidence retention and representative workload validation

Validation date: 2026-11-05. Base source commit:
`48042081719bac70800d8416595941336b2314b8`.

This record covers S1 and P1 in the [development roadmap](../ROADMAP.md).
The candidate includes the S0/F1/P0 foundation. Its dirty source status makes
these measurements ineligible as a clean performance baseline. The source
identity precedes this documentation-only evidence record.

## Environment and scope

Native execution used a MacBookPro18,2 with Apple M1 Max, 32 GB memory and ten
logical processors. Rust/Cargo were 1.95.0, Bazel 9.2.0, Bazelisk 1.29.0 and
Just 1.58.0. Validation selected the already installed Go 1.26.10. Fuzzing used
the existing pinned nightly-2026-08-21 and cargo-fuzz 0.13.2 with ASan.
No dependency, toolchain, copied default configuration, Gitleaks pin, production
scanner behavior or public API changed.

## Acceptance checks

| Check | Result | Scope |
| --- | --- | --- |
| `just ci` | Pass | All 47 Bazel test targets, format, lint, documentation, host builds, eight-target compilation and committed parity |
| `just security` | Pass | Dependency/advisory/vet/unsafe policy, selected Miri cases and archive panic policy |
| `just fuzz-smoke` | Pass | All eight bounded ASan targets; successful implicit bundle removed |
| Retained run and replay | Pass | All eight targets retained privately; selected config replay matched source and executable identity |
| Corpus minimization, review, promotion and import | Pass | Ten synthetic config units, 857 bytes; exact reviewed corpus hash acknowledged before import |
| Deliberate failure, crash minimization and reproduction | Pass | Isolated harness assertion retained; corrected minimizer returned a four-byte reproducer; reproduction matched the binary and intended assertion |
| Fresh checkout | Pass | Benchmark invariants, archive fixtures and xtask tests; corrected minimization regression rerun after overlay |
| Redacted worktree and history scans | Pass | Maintained relative-root commands; zero findings, including 276 historical commits |
| Representative measurements | Pass | Seven process samples, 28 workloads and 103 phases |
| Legacy performance limits | Pass | All 23 outcomes and unchanged inherited M1 elapsed/RSS limits |
| Independent review | Complete | No unresolved material findings; raw samples, projection hashes and reported arithmetic independently checked |

The fresh checkout had an independent Bazel output tree and a byte/mode/symlink
verified overlay of the candidate source. It did not repeat the entire target
matrix; main-checkout CI supplies that compilation evidence. Native claims in
this record apply only to aarch64-apple-darwin.

## Private fuzz evidence

Bundles and logs were retained outside the source tree. Every inspected bundle
directory was mode 0700 and file mode 0600. Public output contained target,
classification, counts and bundle identifiers. Raw artifacts and diagnostics
were not added to the repository or uploaded. The exercised output path included
spaces. Reviewed config inputs contained synthetic parser seeds and mutations.
Minimization completed without reducing that ten-unit corpus.

Ordinary tests cover retention and cleanup, preparation/spawn failure, exact
identity checks, stale or changed corpus rejection, symlink/hardlink/traversal
rejection, log limits, timeout and descendant termination, early-parent exit,
and reviewed promotion. Unix private execution is supported on Linux/macOS;
Windows is explicitly unsupported by this operator. Combined child logs are
capped at 4 MiB. Corpus/artifact limits are checked periodically and can overshoot
between checks; they are not a filesystem quota. Existing target input, runtime
and RSS budgets remain in force.

The actual minimization exercise found a tooling defect: passing `-max_len` to
the pinned libFuzzer crash minimizer conflicted with its own input-length
initialization and caused an assertion. The corrected command omits that flag
only for crash minimization, after validating the input against the target cap.
A regression checks all eight targets and five operations, retaining the normal
caps and time/RSS bounds. The repeated isolated exercise minimized successfully
and reproduced the deliberate assertion with the exact binary. The artificial
assertion was never integrated into production or maintained fuzz targets.
No production scanner defect was demonstrated by this exercise.

## Native measurement record

After validation jobs stopped, the maintained representative command collected
seven fresh-process samples per workload with 25 requested steady iterations.
Construction and actual first scans occur once per process. The completed record
contains 28 workloads, 103 phases and 721 phase samples. Process observations
are stored once per workload/sample, avoiding duplication across phases.

| Workload and operation | Median ms |
| --- | ---: |
| Default rules, 16 KiB no-hit steady scan | 0.115 |
| Default rules, 16 KiB one-keyword steady scan | 0.797 |
| Default rules, 16 KiB many-keyword steady scan | 105.250 |
| Default configuration parsing and compilation, no-hit case | 58.773 |
| 64 small files, complete traversal/detection, one worker | 2.496 |
| 64 small files, complete traversal/detection, four workers | 2.951 |
| Few large files, 1 MiB total, complete traversal/detection, one worker | 14.275 |
| Few large files, 1 MiB total, complete traversal/detection, four workers | 6.361 |
| JSON serialization of 10,000 findings | 12.325 |
| SARIF serialization of 10,000 findings | 24.373 |

The many-keyword fixture includes 64 independent default keywords and produces
zero findings. Its measured cost makes keyword-triggered rule work a useful P2
profiling candidate, without attributing that cost to a specific function yet.
The small-file end-to-end median is higher with four workers, despite a lower
runner-only detection/session median. Profile the complete operation before
changing scheduling; source timing subtraction would not isolate detection.
Larger files show a different worker-count result. These are observations on
fixed synthetic fixtures, not calibrated optimization claims.

The legacy check then passed every unchanged inherited elapsed and 48 MiB RSS
limit. Its timing scope remains separate from these operation-only measurements.

All operation samples verified exact outcomes, complete status, zero errors and
unchanged work counts. The ordinary archive test also replays all 23 benchmark
fixtures without timing. Mutation controls reject skipped input and incomplete
scans. Raw repeated samples and a safe projection of build/source identities
are retained in the [measurement record](representative-performance-2026-11-05.json).
The full raw JSONL remains private, bound by its SHA-256. Canonical build-record
hashes bind fields omitted from the projection.

Operation timers exclude fixture creation, validation, hashing and final outcome
destruction. CPU and RSS describe the whole child process and waited descendants,
including setup and verification; they are not phase allocation measurements.
Fixtures were newly written, so these are not cold-disk measurements. Short
microsecond phases remain visible through aggregate elapsed times and do not
support precise ranking. Seven samples do not establish a p95, noise threshold,
portable throughput guarantee or profiling attribution. No threshold was added
and no inherited limit was relaxed.

## Scope limits

This record covers S1 and P1 only. S2 deep-security operations, P2 profiling
and noise calibration, and P3 optimizations have separate evidence requirements.
Their current status and the selected native policy are recorded in the roadmap.
Hosted private storage and publication are outside this implementation scope.

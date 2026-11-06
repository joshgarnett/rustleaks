# Semantic correctness and matching validation

Validation date: 2026-11-05. Base source commit:
`48042081719bac70800d8416595941336b2314b8`.

This record covers a bounded S3 production-contract investigation and the first
P3 matching experiment in the [roadmap](../ROADMAP.md). Four production defects
were corrected. The span-only matcher experiment was rejected and removed.
The broader S3 property matrix and further P3 candidates remain open.

The local validation snapshot identifies the final code at commit
`2da963ab8d7deea80c4643844555a7186e9611be`, tree
`0b4ed63d52a322939fabb988edfd8d9cb3143fea`. It matched all 781 source entries,
including bytes, modes and symlink targets. This source identity excludes the
subsequent validation documentation and does not establish release qualification.

## Production corrections

| Boundary | Defect and correction | Evidence |
| --- | --- | --- |
| Engine and findings | Removing a known secret could join surrounding bytes into another known secret. Preserve already-clean results, then clean any remaining known sequences with a forward suffix buffer. | The model regression failed before the fix. It covers retained fields, required findings, invalid bytes, nested joins and a bounded small-word enumeration. Coordinates and source mappings remain unchanged. |
| Files and directories | A runner-owned receiver kept a full queue connected after every worker failed. Drop that receiver after worker creation. | A deterministic regression covers one and four failed workers with queue capacity one. The old code needed watchdog cancellation; the fixed code returns `WorkerPanic` and joins every worker without that rescue. |
| Reports and CLI | Joining tags after an empty first tag introduced leading whitespace without CSV quoting. Quote the resulting field. | Eight exact cases match fresh pinned-Go output; the regression failed before the fix. |
| Reports and CLI | JUnit escaping replaced legal DEL and emitted several replacements for one forbidden Unicode scalar. Consume the whole decoded scalar and preserve legal DEL. | Five exact cases match fresh pinned-Go output; the regression failed before the fix. |

These map to existing rows in the [threat model](../THREAT_MODEL.md).
The secret-removal fallback uses one extra buffer proportional to the retained
field length, and avoids repeated whole-buffer passes for nested joins.
`Finding::redacted` retains its separate Go-compatible behavior. Removing known
secret sequences does not classify unrelated sensitive metadata or zeroize
memory. The worker test injects failure through real queue orchestration; no
external input that makes the engine panic was demonstrated. CSV remains a data
interchange format without spreadsheet-formula neutralization.

Inspection of decoded locations, controlled-scan finalization, partial-result
handling and session policy found no further demonstrated defect. This is a
bounded inspection result, not exhaustive semantic coverage.

## Matcher experiment and rejection

The earlier [profile and calibration](deep-and-profiling.md) identified PikeVM
execution as the main cost in the selected keyword-heavy workload. The trial
used whole-span searches without collecting subcaptures, while retaining the
existing capture path, full-input anchor context and invalid-byte mapping.
It added no NFA, persistent cache, dependency, public signature or cancellation
boundary. Exact Go cases and a deliberately incorrect sliced-input control
checked the trial's semantic assumptions.

Native measurements used Apple M1 Max, MacBookPro18,2, 32 GiB, ten logical CPUs,
macOS 26.5.2 and aarch64-apple-darwin. Rust 1.95.0 and the ordinary optimized
Bazel build were used. Both variants had identical benchmark and collector
sources, compiler options, target, rules and workload definitions. The
integrated trial was frozen at commit
`9f11c2da769a7be8d63e8321243db1058b01ea10`, tree
`e036d17dda104f7f476535d03d7393fabf71b77f`.

Each comparison used two rounds of nine adjacent alternating pairs, with the
starting variant reversed in the second round. Steady phases used five
iterations per process. The focused comparison covered the primary and positive
control in 72 processes; the integrated comparison covered 13 workloads in 468
processes. All 540 processes completed and passed the declared exact-result, work-count
and input-identity checks. Config diagnostics were checked against each
variant's exact path. No competing builds, tests, fuzzing or profiles
ran during collection. External activity, thermal state and filesystem cache
state were not controlled.

The primary scanned 16 KiB containing 64 independent default-rule keywords,
with 222 rules, zero findings and 2,053 work units. Its predeclared acceptance
criterion required the median paired gain to exceed 7.66% in both rounds. That
conservatively rounds the larger prior empirical band; it is not a confidence
interval or a new release threshold.

| Comparison | Round 1 median paired gain | Round 2 median paired gain |
| --- | --- | --- |
| Isolated matcher, primary steady scan | 3.78% | 4.09% |
| Integrated trial, primary steady scan | 3.54% | 2.56% |
| Integrated trial, complete CLI process | 1.99% | 1.65% |

Every primary result fell below the criterion. The threshold was unchanged.
The matcher implementation and its experiment-only tests and fuzz assertion
were restored to the frozen accepted bytes. The four production corrections
and validation-tool repairs remain. No production speedup is claimed.

The [measurement record](matcher-experiment-2026-11-05.json) retains ordered
pair timings, per-process CPU/RSS, invariant work counts, fingerprints, build
identities and raw-artifact hashes. Repeated sample fields are stored once per
workload; original responses and the complete validated projection remain
private. The projection was checked against raw samples, response hashes and
independently recomputed medians.

The guard phases were uncalibrated and did not all improve. For example,
four-worker runner-only detection was slower in both rounds for many small
files (3.89% and 2.51%) and few large files (5.73% and 6.75%). Complete traversal
and detection had different results. These are retained observations from the
rejected trial, not accepted tradeoffs or established causal diagnoses. CPU
and peak RSS describe the complete child process, including setup and teardown;
they do not measure phase-local allocations. The CLI check retained and exactly
validated the one expected minimum-version warning from the pinned config.

## Validation

| Check | Result | Scope |
| --- | --- | --- |
| Final integrated Bazel gate | Pass | All 50 targets, format, lint, documentation, host builds, eight-target compilation and committed parity |
| Final repeated-test gate | Pass | All 45 first-party targets, ten repetitions each |
| Final security policy | Pass | Advisory, vetting, dependency, unsafe, Miri and panic-policy checks |
| Final full differential | Pass | Clean committed final code, fresh pinned Go, package/consumer, fuzz and unchanged legacy performance checks |
| Final redacted self-scans | Pass | Final source, documentation and unchanged history |
| Independent acceptance review | Pass | Final source, measurements, rejection decision and validation scope |

The experimental candidate had already passed the complete differential gate,
including public API, external consumers, all eight fuzz targets and the
unchanged legacy elapsed/RSS limits. That result is distinct from the final
restored-source validation above.

Two additional 60-second ASan campaigns on the experimental candidate completed
238,071 regex executions and 1,542 fragment executions with no crash artifacts.
Those counters are not unique test cases or source coverage. They qualify only
that candidate; the rejected matcher and its span-equivalence fuzz assertion
are absent from the final source. An earlier attempt was retained as failed
because its final identity check detected concurrent source changes.

The existing Cargo quality path needed explicit CLI/Git test-tool bindings and
child-local isolation of inherited Git settings. Unix uses the declared Bazel
Git tool; Windows retains its installed `git.exe` policy with absolute-path,
version and hash checks. No process-global environment was changed. Selection
and command-binding regressions passed locally; native Windows execution was
not performed. Pedantic tooling lint diagnostics were also corrected without
changing benchmark timers or thresholds.

Fresh Go verification passed with unchanged `go.mod`, `go.sum`, revision and
default configuration. No checksum exception was accepted.

All native evidence here is for aarch64-apple-darwin. Cross-compilation does not
establish other targets' runtime support. No new TSan, MSan or source-coverage
claim is made. Dependencies, toolchains, copied defaults, the Gitleaks pin,
public signatures, release requirements and publication state are unchanged.

## Scope limits and follow-up evidence

This record does not establish the broader decode-offset, malformed-byte span,
budget-monotonicity, partial-outcome or session-isolation properties. The
[property validation record](semantic-properties.md) covers the subsequent
finite matrices and reader/Git control separation. Deeper Git/archive semantic
cases and comparison-tracing or additional sanitizer experiments require
separate evidence.

P3 has no accepted optimization from this experiment. Use the retained profiles
and measurements to choose the next hypothesis. Dense-positive scans and
complete source runs across worker counts need their own profile before
changing capture consumption or scheduling. The existing P4 reporting packet
and F2's policy prerequisites remain unchanged.

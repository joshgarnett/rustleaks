# Foundation validation

Validation date: 2026-11-05. Base source commit:
`48042081719bac70800d8416595941336b2314b8`.

This record covers the S0, F1 and P0 implementation in the
[development roadmap](../ROADMAP.md). The measured candidate had dirty source
status and is ineligible as a clean performance baseline. These results do not
establish release qualification or native execution on targets other than this
host.

## Environment

The native host was a MacBookPro18,2 with Apple M1 Max, 32 GB memory and the
existing ten-core calibration class. Rust/Cargo were 1.95.0, Bazel 9.2.0,
Bazelisk 1.29.0 and Just 1.58.0. The ambient Go version differed from the
repository pin; selecting the already installed Go 1.26.10 for validation made
`just doctor` pass. No toolchain or dependency pin changed.

## Acceptance checks

| Check | Result | Scope |
| --- | --- | --- |
| `just ci` | Pass | All 46 Bazel test targets, format, lint, docs, host builds, eight-target compilation and committed parity |
| `just security` | Pass | Advisory/dependency/vet/unsafe policy, selected Miri cases and archive panic policy |
| `just fuzz-smoke` | Pass | All eight maintained bounded ASan targets; regex corpus initialized with 3,620 executions and archive corpus with 83 |
| Archive corpus generation and check | Pass | 82 versioned frames, exact generated tree, source/provenance/license metadata |
| Archive direct ASan replay | Pass | Retained private artifact path; 83 executions including corpus initialization |
| Focused archive harness tests | Pass | All six tests, including every format/control combination and real decoded contents |
| Quality corpus/baseline generation and replay | Pass | Maintained Rust generator, exact artifact checks, evaluator golden/mutation/partial/disclosure controls |
| `just quality-eval` | Pass | Public recipe output equals the generated baseline bytes |
| `just perf-run` and `just perf-check` | Pass | All 23 outcomes, actual Bazel provenance and unchanged inherited M1 limits |
| Fresh checkout | Pass | Compat library/docs/benchmark tests, archive harness, xtask tests, build/docs contracts and quality-baseline replay |
| Redacted worktree self-scan | Pass | Maintained `dir .` invocation; zero remaining findings |
| Redacted history self-scan | Pass | Maintained `git .` invocation; zero remaining findings |
| Repository boundary diff | Pass | Core and production source code, dependency manifests/locks, toolchains, copied defaults and pin unchanged |
| Independent implementation review | Complete | Material findings resolved; final validation evidence and arithmetic checked |

The fresh checkout used a separate Bazel output tree and byte-verified candidate
files. It did not repeat the entire eight-target matrix; that compilation is
covered by the main checkout's CI result. Cross-compilation is compilation
evidence only. The benchmark invariant test took about 83 seconds in the main
unoptimized test build and 87 seconds in the fresh checkout; it is now part of
the routine test graph.

The first archive run exposed a test-limit mismatch: the selected compressed
RAR3/RAR5 fixtures declare 128 KiB dictionaries. Raising only the harness member
cap to 128 KiB, with aggregate output still 128 KiB, made the real-decoding and
callback tests pass. Production archive limits did not change. Benchmark
preparation also gained an actual default-configuration SHA check and a
same-length mutation rejection test.

Four reviewed synthetic generator literals received exact rule/path/line
self-scan fingerprints, and the existing README fingerprint followed its line
shift. No broad path exclusion was added. The history scan confirmed that no
additional historical suppression was needed.

A final scan also classified Bazel action fingerprints in temporary benchmark
logs as generic API keys. Those reviewed hash values were benign provenance
data. The logs remain private; no additional source exclusion or fingerprint
was added for them. The roadmap records the example for later precision
experiments.

## Detection quality observations

The 19-case synthetic catalog completed every full-default scan. It produced
12 exact-location true positives, one reviewed-negative false alert, one
exact-location false negative, one unknown alert and one unlocated alert.
The exact-location false negative is a detected decoded value whose location
mapping is unavailable. All 12 case-distinct expected values were recognized;
that measure is not occurrence coverage. Individual-rule results use their
explicitly scoped positive denominators.

These labels and small counts are structural controls, not an estimate of
operational precision or recall. The false-alert case remains evidence for a
later quality experiment; no production detection rule was changed to hide it.
See the [corpus contract](../../compat/quality-corpus/README.md) and
[generated baseline](../../compat/quality-corpus/baseline-v1.json).

## Benchmark build migration

The original committed Cargo helper ran in an isolated base checkout. The
candidate used the new optimized Bazel path. All 23 workload identities,
logical sizes, finding/output counts and outcome fingerprints matched exactly.
All seven inherited budget definitions retained their original values.

After builds, security checks and fuzz campaigns finished, each workload had one
untimed warmup per binary, then seven fresh-process samples per binary in
alternating Cargo/Bazel order. RSS uses the first three samples as in the
existing sampler. Source contents and both executables were checked unchanged
across sampling. The timing scope remains `legacy-v1-includes-verification`.

| Workload | Cargo median ms | Bazel median ms | Inherited limit ms | Cargo peak MiB | Bazel peak MiB |
| --- | ---: | ---: | ---: | ---: | ---: |
| `default-compile` | 56.209 | 55.842 | 100 | 30.47 | 16.11 |
| `default-one-keyword` | 49.519 | 49.080 | 600 | 30.47 | 19.83 |
| `regex-hostile-miss` | 14.360 | 14.384 | 30 | 30.45 | 7.83 |
| `decode-five-level` | 7.271 | 7.250 | 10 | 30.47 | 9.80 |
| `source-directory-1` | 67.517 | 68.054 | 150 | 30.47 | 9.11 |
| `source-directory-4` | 17.777 | 18.081 | 75 | 30.47 | 11.08 |
| `report-json` | 17.100 | 17.660 | 30 | 30.47 | 21.88 |

Both builds met every inherited elapsed and 48 MiB RSS limit. The
[measurement record](foundation-performance-2026-11-05.json) retains raw samples,
binary/source/build identities, host, protocol and limits. Measurement identity
precedes this documentation-only evidence record.

This establishes a bounded build transition on one host. It does not claim a
scanner optimization, a new portable calibration, or field throughput. RSS
includes initialization and provenance work; the original runner also invokes
Git and rustc for provenance. Neither memory column is a scan-only allocation
measurement. P1/P2 still own representative phase measurements, profiling and
noise calibration.

## Scope limits

This record covers S0, F1 and P0 only. S1 private failure retention, S2 deeper
campaigns, P1/P2 measurement expansion, native rules and production
optimizations have separate evidence requirements and current status in the
roadmap. No production scanner defect was demonstrated or changed by this
foundation implementation.

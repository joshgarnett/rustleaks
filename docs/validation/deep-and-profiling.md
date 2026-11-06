# Deep-run and profiling validation

Validation date: 2026-11-05. Base source commit:
`48042081719bac70800d8416595941336b2314b8`.

This record covers S2 and P2 in the [development roadmap](../ROADMAP.md).
The candidate has dirty source status. Source contents, tool and build
identities bind the private evidence; these results do not establish a clean
release baseline or publication qualification.

## Environment and boundaries

Native execution used the same Apple M1 Max, 32 GB MacBookPro18,2 as the initial
representative measurements. Rust/Cargo 1.95.0, Bazel 9.2.0, Bazelisk 1.29.0,
Just 1.58.0 and the installed pinned Go 1.26.10 passed the tool check. Fuzzing
and Miri used the existing nightly-2026-08-21. No dependency, toolchain, copied
default configuration, Gitleaks pin, production library/CLI source or hosted
workflow changed. New shared test support is included by the core package's
existing test-file rules and passed package/consumer validation.

The native profiling tools were the installed macOS sample, heap and vmmap
utilities. Xcode Instruments was unavailable under CommandLineTools. Matching
LLVM 23 coverage tools for the pinned fuzz nightly were also unavailable;
installed Apple LLVM 21 tools were not substituted. No new tool was installed.

## Validation results

| Check | Result | Scope |
| --- | --- | --- |
| Integrated Bazel gate | Pass | All 50 targets, formatting, lint, documentation, host builds, eight-target compilation and committed parity |
| Package and external consumers | Pass | Published core package inputs and clean Cargo/Bazel consumers |
| Focused structured drivers | Pass | Six core, nine source and five report case rows; larger drivers selected explicitly |
| Private operator regressions | Pass | Profiles, stage dispositions, deadlines, stale evidence, strict import and live-corpus removal controls |
| Fresh checkout | Pass | Independent Bazel tree, exact source overlay and selected-target deep operation |
| Longer deep operation | Pass | Existing security gate, dependency evidence, structured drivers, two additional Miri cases and all eight ASan targets |
| Deadline exercises | Pass | Preparation expiry and active campaign termination retain incomplete evidence |
| Ordinary fuzz smoke | Pass | Existing caps, seed defaults, all eight targets and successful scratch cleanup |
| Native CPU/memory investigation | Pass | Verified profiling build, usable stack and retained-memory observations |
| Repeated calibration | Pass | Two independent training/held-out/slowdown-control runs |
| Legacy performance limits | Pass | Existing outcome matrix and inherited elapsed/RSS limits |
| Redacted self-scans | Pass | Current worktree; prior history evidence reused at unchanged HEAD and scanner/ignore policy |
| Independent review | Complete | No unresolved material findings; source reconstruction, private permissions, raw bindings and reported arithmetic independently checked |

Independent validation used byte/mode/symlink verified candidate source and
separate build outputs. That source retains dirty-candidate qualification.
Cross-compilation is compilation evidence only; this record claims native
execution only on aarch64-apple-darwin.

## Optional deep operation

The full pass completed in 587.837 seconds with all eight requested fuzz targets
successful and no crash artifacts. LibFuzzer reported 3,869,270 executions in
aggregate, not unique test cases. All policy, structured, additional Miri and
identity-verification stages passed. The dependency comparison reported no
changes relative to the fresh-checkout snapshot; it remained labeled
`unchanged-comparison-only`.

| Target | Reported executions | Final corpus files |
| --- | ---: | ---: |
| `go_regex` | 217,568 | 5,056 |
| `config` | 39,766 | 1,181 |
| `fragment_scan` | 1,969 | 243 |
| `session` | 1,000,000 | 1,394 |
| `archive` | 715,596 | 3,197 |
| `reader_schedule` | 3,722 | 118 |
| `git_patch` | 890,649 | 971 |
| `template` | 1,000,000 | 1,043 |

The [deep-run record](deep-security-2026-11-05.json) retains projected stage,
profile, corpus, tool, source and comparison evidence. The fresh checkout also
completed a selected-config deep pass with explicit nonselected/capability
skips. A one-second preparation deadline returned an incomplete report after
1.030 seconds. A separate ten-second wrapper deadline terminated an active
Git-parser campaign and retained its failed outcome.

After the full pass, a six-file metadata-only correction made direct fuzz
bundles record requested/inherited wrapper deadlines before preparation and
the effective supervisor timeout for each child. Replay reconstructs mutation
settings under a fresh invocation deadline. This correction was checked by
final CI, fresh-checkout tests, ordinary smoke and a renewed active-deadline
exercise: the retained request says ten seconds, the target says sixty-second
libFuzzer budget, and the supervisor records the remaining 8.499-second child
budget and `runner-timeout` outcome. The command took 11.242 seconds including
Bazel startup, preparation and cleanup.

The earlier full pass is bound to its pre-correction source identity, not the
final source bytes. Its complete source is reconstructible from the preserved
measurement snapshot and six recorded before files. All eight actual ASan
binary hashes were verified unchanged afterward. The deep-run projection
retains the before/after file hashes and this disposition. Profiling and
calibration use the corrected source. Their source identities precede only the
final documentation and evidence files.

The validated pass used explicit 60-second libFuzzer time budgets and up to
1,000,000 executions per selected target, with a 1,800-second outer deadline.
A target may reach its execution cap before its time budget. The default
600-second target budget and two-hour outer budget were not run in full.
Smoke retains its existing 4–16 KiB caps. Deep admits 64 KiB inputs and applies
matching internal harness limits. Larger structured cases separately validate
archive expansion, depth, entry and aggregate limits, decoded-byte budgets,
8,192 findings and template boundaries. Their case map and limitations are in
[the structured-case contract](../SECURITY_STRESS.md).

Fuzz counters describe instrumented edges/features and executions. They are
not source-line coverage or a percentage of a codec tested. Source coverage
was explicitly skipped for missing matching LLVM tools. Requested mandatory
stages must pass; a timeout, failed campaign or required capability skip cannot
be reported as success. Corpus growth and original/final hashes were retained
privately. The dependency comparison is a change detector, not a new audit or
approval receipt.

A longer campaign exposed a live-corpus monitor race: libFuzzer removes units
while reducing its corpus, and a file disappearing after directory enumeration
was incorrectly treated as a corpus-policy failure. A retained diagnostic
confirmed the missing-file error with corpus counts and bytes below all limits.
The fix tolerates only that transient live-entry condition. Stable inventories,
imports, symlink/type checks and all other I/O and resource failures remain
strict. Deterministic removal and surviving-limit controls cover the regression.
Monitor diagnostics are retained privately and hash-bound.

The dependency reporter also needed an absolute manifest path for the installed
cargo-geiger. Its command regression covers checkout paths containing spaces.
Neither issue was a production detection or archive-decoding defect. Initial
campaign stops are retained as failed evidence rather than overwritten by the
successful reruns.

All raw bundles stayed outside the source tree under restrictive local
permissions. No evidence was uploaded. Fuzz child RSS is capped at 2 GiB;
trusted builds, policy tools and Miri have deadline/output bounds, not a
whole-pass memory quota. Live corpus/output monitoring is periodic and may
overshoot between checks. Cleanup has a bounded grace period and does not
claim containment of a deliberately escaped process.

## Native profiling and calibration

The keyword-heavy synthetic fixture scans 16 KiB through 222 default rules,
contains 64 independent keywords, and produces zero findings with 2,053 work
units. The worker completed 172 scans in its twenty-second profiling loop;
fifteen-second CPU collection yielded 10,916 thread sample observations.

| Exclusive leaf site | Samples | Share of observed thread samples |
| --- | ---: | ---: |
| PikeVM `epsilon_closure` | 4,539 | 41.58% |
| PikeVM `next` | 3,249 | 29.76% |
| PikeVM `search_imp` | 1,479 | 13.55% |
| `memmove` | 1,222 | 11.19% |
| `memcpy` stub | 271 | 2.48% |

The three PikeVM sites account for 84.89% of exclusive observations. The call
graph places 1,492 of the 1,493 copying observations beneath epsilon closure;
these are the same leaf observations, not additional samples. In pinned
regex-automata 0.4.18, epsilon closure copies capture slots into the next-state
table. The owned `GoRegex::find_all` in `crates/rustleaks-core/src/regex/mod.rs`
delegates to `captures_all` and then retains whole-match spans; the content
scanner calls it from `engine.rs`. Avoiding capture-state work in that initial
span search is a grounded P3 experiment. Exact match selection, empty-match
progression, invalid-byte mapping and all existing outcomes must remain intact.
This profile does not establish the correct implementation or predict a gain.

Both heap snapshots reported 33,536 live nodes and 5,432,848 bytes. Rounded VM
resident totals changed from 225.3 MiB to 221.9 MiB, with 1,828 regions and
unchanged virtual size. No retained-heap growth was observed at these two
specific points; the VM decrease is not a production memory improvement.

Each independent calibration run used nine training A/A pairs, nine held-out
A/A pairs and nine explicit extra-work pairs, for 108 process records across
the two runs. Both held-out sets fit their independently trained bands, and
every extra-work pair exceeded its band.

| Run | Empirical relative band | Largest held-out absolute deviation | Median extra-work increase |
| --- | ---: | ---: | ---: |
| 1 | 7.66% | 1.47% | 100.54% |
| 2 | 3.82% | 2.38% | 100.19% |

The control performs two complete scans per logical iteration. Its approximately
100% increase validates detection of that deliberate added work; it does not
establish sensitivity to small regressions below these observed bands. The
[profiling/calibration record](profiling-calibration-2026-11-05.json) contains
ordered raw samples, recalculated policy decisions, exclusive sample counts,
memory observations and bounded provenance. Full raw reports remain private
and are bound by hashes. All inherited legacy elapsed and 48 MiB RSS limits
subsequently passed under their original timing scope.

The CPU build is optimized with verified line tables and frame pointers. Its
results are a distinct measurement mode from uninstrumented timing. The worker
prepares and validates the fixture before collection; the sampled steady loop
includes scan, validation, hashing and result destruction. Rankings use the
collapsed exclusive leaf table, not summed inclusive stack counts. They are
sample observations, not exact CPU-time percentages.

Heap and VM snapshots describe retained live state before and after the loop.
They do not measure allocation churn, establish a leak, or attribute allocation
sites. Empty, header-only, zero-count and wrong-image outputs are rejected as
unusable evidence. Native files and worker diagnostics have live and final size
checks; polling overshoot is documented.

Calibration uses the ordinary optimized binary and alternating pairs. Each run
separates training A/A pairs, held-out A/A pairs, and an explicit redundant-scan
slowdown control. Extra operations are recorded. The empirical training band is
not a confidence interval or a portable percentage threshold. Raw ordered
samples are retained and each repeated run is assessed independently without
widening its band after seeing the held-out results. Background host activity
and thermal state remain outside the runner's control; collection excluded
competing builds, tests, fuzzing and scans.

No release performance threshold was introduced and no inherited limit was
relaxed. Production optimization belongs in a later packet with matching exact
outcomes, quality checks and repeatable gains. Hosted schedules and private
storage have separate requirements. Current implementation status, including
the selected native detection policy, is recorded in the roadmap.

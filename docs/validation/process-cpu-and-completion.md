# Process CPU experiment and bounded scope completion

Validation date: 2026-11-06. Result: `cpu-candidate-rejected`. All 180 scheduled
processes across 20 cells completed and passed independent directory auditing.
The complete-CLI criterion failed in the first candidate round. The production
linear location helper is retained; no optimization or practical speedup is
accepted.

## Comparison result

All unchanged A/A and deliberate extra-work sensitivity predicates passed.
Every margin was fixed at 5%. Values below are median paired changes in completed
child user-plus-system CPU cost, including setup, validation and destruction.
Negative values indicate lower measured CPU cost for that candidate workload.

| Workload | Round 1 | Round 2 | Fixed criterion |
| --- | ---: | ---: | --- |
| Dense core, 16 KiB | -17.0869% | -12.5779% | Both pass |
| Complete eight-file CLI | -4.2669% | -5.6845% | Round 1 fails |
| Mixed core, 16 KiB | +0.4674% | +0.6883% | Both guard predicates pass |
| Default no-hit, 16 KiB | -0.0080% | -0.9073% | Both guard predicates pass |
| Decode depth five | +2.9311% | +3.6152% | Both guard predicates pass |

CLI round 1 did not meet the required median below -5%. Its range was -10.7327%
to -0.4545%, with median absolute deviation of 3.8124 percentage points. Neither
the second round nor the dense-core result can rescue that failure. Decode CPU
cost increased in all ten pairs, despite its medians staying inside the allowed
5% guard. Passing guards therefore do not establish absence of regressions.

Peak RSS was assessed separately. Dense-core candidate medians were lower in
round 1 and higher in round 2. CLI round 1's candidate maximum was 14,942,208
bytes versus 13,975,552 baseline bytes. These are whole-process observations,
not allocation measurements or a demonstrated memory improvement.

The [measurement projection](process-cpu-2026-11-06.json) retains all 180 samples,
20 cells, exact ratios, dispersion, work counts and source/build identities.
Independent auditing reconstructed raw requests/output, CPU arithmetic,
identities, exits, reaping, cleanup, deadlines and final predicates. Independent
review confirmed the rejection and found no unresolved material issue. The raw
report SHA-256 is
`ff6f0caee84d5f8d4bea4ef515f8de30989cb275823a08d4aff4e15f6cb22d42`.
A separate precollection validation failure produced no selection samples and
is retained outside this completed result.

## Sources and semantic controls

Both clean snapshots derive from
`7166f517d12f21fb830195078714c5bc368f92f0`:

| Variant | Commit | Tree |
| --- | --- | --- |
| Linear baseline | `cbd7f2fe7caafc8c57bf7433c427f0129392fee6` | `cb49b64f95b856b32c12acae78c574c9adf8264d` |
| Location candidate | `0df8e53babfe715894272af5e8857cf7627dcc95` | `ac8a7c3c8b3f4a367174fd44b10d9361de0c602b` |

Both contain identical equivalence controls. Their production difference is
limited to the location helper; normalized compile topologies match. The
candidate uses binary searches and at most two field-assignment iterations,
without adding an allocation or persistent cache. All location fields matched
for 730,605 spans over 21,845 inputs. A deliberately wrong boundary failed;
the restored candidate passed. Twenty-two public format, Clippy, regression,
location, decoding, controlled-scan and native-policy targets passed. These
finite checks do not waive the failed CPU criterion.

## Targeted profile

The baseline ran the dense 16 KiB fixture on Apple M1 Max,
aarch64-apple-darwin, macOS 26.5.2. Xcode CPU Profiler 16.0 (17F113) recorded the
target process for a requested 15 seconds. The optimized build used line tables
and frame pointers, separately from the ordinary CPU comparison build.
Its executable SHA-256 is
`7310b0ca093bd1cc55f81729c1b6e3a428fdb6f7f84ed54b9f72d39a8e5d46c5`.

The fixture has 16,384 bytes, one synthetic rule, no keywords, 256 exact findings
and 514 work units. The 20-second worker loop completed 12,344 validated scans;
that count is not limited to the profiler window. Both processes exited and
were reaped. An earlier idle capture is retained and excluded from analysis.

All 47,396 exported rows belong to the target; one has zero weight. The
denominator is 45,803,348,460 target sampled cycle-weight units. Selected
disjoint families are:

| Observed family | Target sampled cycle weight |
| --- | ---: |
| Regex whole-match discovery | 26.419% |
| Location body and confirmed inline loop instructions | 22.463% |
| Secret recapture | 17.987% |
| Go-compatible Unicode lowercase | 8.005% |

Named location samples account for 12.400%; exact-executable disassembly
corroborates another 10.063% at four inline loop instructions. Other generic
iterator samples were not assigned without that evidence. The observed engine
frame contains 88.964% of target weight; 11.036% is harness work outside it.
Inclusive subtrees overlap and cannot be added. Regex discovery and recapture
together remain the largest observed family.

These sampled weights describe one instrumented dense-fixture capture on a
busy host. They are not elapsed time, process CPU seconds or predicted savings.
The retained sample XML hash is
`dc70c85481b38c1a06f3656bf23f13811c2c1c3ac9c60c12f20a00da9a49a569`;
profile binding hash is
`491b15dee7616d985e5945050875f71803d08ef7835bbe8a09c37430b8591574`.

## Fixed CPU procedure and limits

Policy `paired-process-cpu-v1` measures `wait4` user plus system CPU for a
completed child. Startup, executable hashing, configuration, fixture/engine
setup, warm and measured scans, validation, reporting and destruction are
included. Waited children follow operating-system accounting; controller CPU
is excluded. Wall/scan timers are diagnostic only. Host activity, cache pressure,
frequency and core placement remain uncontrolled.

For each of the five workloads, the fixed schedule has five unchanged A/A
pairs, three deliberate extra-work pairs and five candidate pairs in each of
two rounds. Adjacent pairs alternate AB/BA; controls and round 2 reverse order.
Each ordinary core worker performs 1,200 scans and each extra-work worker 1,500;
CLI controls use nine files instead of eight. Totals are 144 core workers,
176,400 measured scans, 144 warm scans, 36 CLI invocations and 291 CLI files.
Separate readiness probes never enter the decision.

For positive costs, `d = (CPU_B - CPU_A) / CPU_A`. Ratios use exact arithmetic
over recorded values. A/A sanity requires median absolute paired change
`median(abs(d)) <= 5%` and at least four of five pairs within +/-10%. Before controls/candidates,
`M = max(5%, 2 * median(abs(d)))` is fixed. Extra-work sensitivity requires
median `d > M` and all three `d > 0`. In each candidate round, dense core and
complete CLI need median `d < -M` and at least four improving pairs; every guard
needs median `d <= M`. Rounds cannot be pooled. These practical criteria are
not confidence intervals or portable release thresholds.

The collection deadline is 900 seconds including final verification, with
300 seconds per workload cell and 120 seconds per child. Integrity or resource
failure stops collection; empirical failure cannot shorten or extend the fixed
schedule. No observations were discarded or acceptance thresholds changed.
The result makes no wall-time, throughput, latency, energy, allocation or
cross-platform improvement claim. Earlier [matcher](semantics-and-matching.md),
[location](location-lookup-experiment.md) and
[observation-window](baseline-observation-windows.md) records remain intact.

## Qualification and completed scope

Delivery of the feature, hardening and live-oracle-retirement implementation
and this result is tracked in
[PR 116](https://github.com/joshgarnett/rustleaks/pull/116). The measured snapshots
above retain their separate identities. This record closes the bounded CPU
investigation with rejection, without adopting the helper or initiating another
experiment.

Retirement source `828def79855f53a01baf9dc4b608835321834c64` passed 60 CI targets,
security and 55 first-party targets repeated ten times. Sixteen uncached
regression/tooling targets passed with Go unavailable on PATH and no sibling
checkout. `ebaeddbc5bdae6c5f96a04f16eaf491c5d76adca` passed complete clean Rust
qualification and a local no-upload release dry run, including strict lint,
default/all-feature tests, MSRV, Miri, exact API, external Cargo/Bazel consumers,
bounded resources, eight fuzz smoke targets and inherited performance limits.
The Windows archive expectation correction passed focused and hosted checks.
Source `7166f517d12f21fb830195078714c5bc368f92f0` passed the complete
[hosted CI run](https://github.com/joshgarnett/rustleaks/actions/runs/42286132468),
including all eight native target lanes and the Required aggregate. Both CodeQL
analyses also passed. Final documentation retains that source-specific scope.
Historical Go observations, defaults, corpus bytes and attribution remain
unchanged; new expectations are independently specified and replayed by Rust.

P4 collector smoke at `cd56919ecced57e5450a073deb1e2bac737b24e1` completed all
23 informational rows, cleanup and summary verification. Profile import/reparse
also passed. Synthetic controls cover median/RSS decisions, deliberate slowdown,
A/A classification, incomplete inputs, unknown hosts and disclosure limits.
The busy-host collector is not a wall-budget result. Manual public summaries
require seven-day retention; no schedule or release threshold was added.

All fifteen selected [roadmap](../ROADMAP.md) packets have bounded dispositions:
F0-F4 policy, independent quality, three-family rules, layout/explanations and
triage; S0-S4 fuzz reachability, private reproducers, deep checks, the finite
robustness matrix and source budgets; P0-P4 benchmark integration, representative
workloads, profiling/calibration, this rejected CPU candidate and optional
reporting. Completion does not exhaust future research or hostile-input cases.

The exact `compile_action_key` false-positive context remains future quality-
corpus/context-filter work; existing hash/build-identifier controls do not cover
it. Checksum computation, live verification, network/cloud integrations, plugins,
new language bindings, extra sanitizers and hosted schedules remain outside the
selected scope. F3 checksum status stays `Unknown`.

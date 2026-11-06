# Location lookup experiment

Validation date: 2026-11-06. Base source commit:
`48042081719bac70800d8416595941336b2314b8`.

The binary-search location trial preserved the tested semantics, but baseline
calibration failed for two guards. The predeclared policy therefore stopped
the experiment before candidate timing. The accepted linear helper is restored
byte for byte. No production defect, speedup or slowdown was demonstrated by
this trial. P3 remains open in the [roadmap](../ROADMAP.md).

## Source and semantic evidence

The accepted source inventory contained 794 entries. Two isolated, clean
measurement snapshots contained identical tests and build wiring and differed
only in the production location helper:

| Variant | Local commit | Tree |
| --- | --- | --- |
| Linear reference | `6dc1ee8f545a8e27301a3128c789fcaca7e10570` | `4e656b0de29bd3e24a48322ae44641ac0e89c533` |
| Binary-search candidate | `0af069efeaef8d381fe76d9cd6779bb8b6175ec5` | `353d81bf5a8df3645cbb2a1a4e7c5ddb45cfd743` |

The candidate selects two partition points in the existing newline offsets and
replays the applicable assignment blocks in their original order. A private
test compared all six location fields with the original helper over 21,845
synthetic strings and 730,605 valid spans. A deliberately wrong end-boundary
predicate failed the test. Both snapshots passed focused Bazel tests and
ordinary optimized builds; the candidate passed all ten committed parity
targets. The experiment-only copied helper and its exhaustive comparison remain
in the private candidate snapshot, not in the restored production source.

The retained public integration test specifies 21 independent cases in four
tests: 18 findings and three suppressions. Fresh Go 1.26.10 execution at the
pinned Gitleaks revision agrees with their full byte-safe findings. Cases cover
nonzero fragment start lines, invalid and multibyte input, CR/LF boundaries,
trimmed matches, nested and overlapping decoded candidates, line allowlists,
original allow markers, exact completion and usage. A wrong newline comparison
fails two tests. These finite controls establish test sensitivity and the
specified outcomes, not exhaustive semantic equivalence.

## Calibration outcome

The [original packet](../plans/dense-location-lookup.md) required two successful
baseline calibrations for the primary and each guard before freezing any band
or collecting candidate timings. Each run retained nine training A/A pairs,
nine held-out A/A pairs and nine deliberate extra-work pairs. Ordinary processes
timed 100 scans; the extra-work side timed 200. All 432 ordered process rows
and 880 artifact hashes are retained in the generated
[projection](location-calibration-2026-11-06.json).

| Workload | First diagnostic band | Second diagnostic band | Disposition |
| --- | ---: | ---: | --- |
| Dense 16 KiB | 7.8798% | 7.7506% | Both calibrations pass |
| Mixed 16 KiB | 15.4798% | 27.1003% | Both calibrations pass |
| Default no-hit 16 KiB | 18.1438% | 156.1502% | Second sensitivity check fails |
| Decode depth five | 38.2132% | 4.2164% | Second held-out check fails |

The second no-hit run includes an unchanged-code training pair of 11,608,421
and 20,671,707 nanoseconds, a 78.0751% deviation. The policy's doubled maximum
training deviation and timer floor produce the 156.1502% band. Its held-out
pairs fit, but none of the nine extra-work controls exceeds that band. In the
second depth-five run, held-out deviations of +4.5640%, -7.1242% and +51.4600%
exceed its 4.2164% band. Every row remains in the evidence.

The initial serial batch stopped after the no-hit failure. The remaining two
depth-five runs completed baseline characterization only; they were not retries
and did not reopen acceptance. No bands were frozen, no candidate binding or
timed sample was collected, and no candidate comparison round ran. These are
diagnostic baseline bands, not accepted regression thresholds. The cause of
the variation remains unknown. Collection ran on Apple M1 Max without competing
builds, tests or fuzzing; unrelated host activity and thermal state were not
controlled.

The private controller verifies source, compiler, executable, build arguments,
fixture, result and complete termination identities. Nine synthetic control
groups pass. A subsequent baseline-only export exposed an omitted environment
value in Bazel JSON. Its one-lookup repair maps omission to null, matching the
maintained Rust binding while preserving explicit empty strings. The corrected
native export passes; the failed export and original scripts remain private.
That parser defect is separate from the calibration failures and does not
invalidate or reverse their classification. Native candidate comparison remains
unexercised.

## Test readiness repair

Final CI exposed a process-test startup race: the 200 ms deadline could expire
before the descendant created its heartbeat file. The helper returned the
expected timeout, then the test unconditionally read the absent file. A gated
startup control reproduces that failed assumption deterministically.

The test now uses the existing monitor callback to establish bounded fixture
readiness and observe two descendant writes before releasing the parent. The
timeout case retains its 200 ms process deadline. Normal exit uses a separate
five-second completion watchdog including the three-second readiness bound.
Immediate and deliberately delayed startup exercise both endings. Heartbeat
stability after cleanup and direct-child reaping assertions remain. Production
process code is unchanged. This test checks cleanup after observed activity,
not maximum callback latency.

## Final validation

The restored final source is identified by clean validation snapshot commit
`49db95919a580a592c9d4d7cf9790d357b8cfada`, tree
`dbc490c324f18fab1de20ee0cbd4f4c656531878`. Its 797 entries were verified by
bytes, modes and symlink targets. This identity excludes the final validation
documentation. The measurement snapshots retain their separate identities.

| Check | Result and scope |
| --- | --- |
| Integrated `just ci` | Pass: 55 targets, format, lint, documentation, host builds, eight-target compilation and committed parity |
| `just security` | Pass: advisory, vetting, dependency, owned-safety, Miri and panic-policy checks |
| Independent checkout | Pass: retained public location tests, xtask unit tests, formatting and Clippy |
| `cargo xtask parity --all` | Pass on the clean restored snapshot: fresh pinned Go, default/all-feature quality checks, public API, package/consumers, all eight fuzz smoke targets and unchanged legacy M1 elapsed/RSS limits |
| Documentation and redacted scans | Pass: maintained prose/links, working tree and all 276 history commits; no scan findings |

The original CI failure and deterministic failing startup control remain
separate from the successful repaired checks. The private native-export failure
and corrected export likewise remain distinct. Neither defect is counted as a
production-engine bug. Independent review found no unresolved material issue
in the retained tests, source restoration, calibration classification or
provenance repair. The final documentation delta is checked separately from the
frozen validation snapshot.

All 81 runtime source entries and 24 protected manifest, lock, toolchain, pin
and copied-default entries match the accepted inventory. Prior accepted changes
remain intact. No dependency, public API, release obligation, compatibility
exception or publication changed. Native
execution here is aarch64-apple-darwin; cross-compilation does not establish
runtime support for other targets. These bounded checks do not prove absence
of defects or establish a production performance improvement.

## Remaining measurement work

A new baseline-only protocol must precede another optimization comparison.
Predeclare observation lengths, process ordering, workload identities, collection
deadlines and stopping rules before collecting data. The current CLI caps
iterations at 100; longer observations need an explicitly versioned protocol.
If aggregating existing samples, specify whether workers are shared, retain
every component, verify exact ordinary and extra-work scan counts, and derive
the timer-floor correction from the actual aggregation structure. Control
missing or duplicate samples, identity changes, incomplete termination and
arithmetic boundaries independently before native collection.

Retain two complete calibrations for each workload and each predeclared length,
including unsuccessful results. Do not discard outliers, retry until success,
or choose a threshold after seeing candidate timings. Longer windows or another
host are hypotheses, not demonstrated remedies. A different host requires its
own identities and calibration. Only successful primary and guard calibration
under a separately reviewed protocol can qualify a later candidate comparison.

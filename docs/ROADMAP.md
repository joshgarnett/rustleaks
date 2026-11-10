# Development roadmap

This tracker covers detection quality, security and robustness, and performance.
The [packet specification](plans/detection-security-performance.md) defines
scope, source evidence, acceptance criteria, and validation for each packet.
Status describes implementation and evidence, not release availability.

## Implemented capabilities

The earlier validation records cover seven production corrections in
known-secret removal, source-worker failure cleanup, CSV/JUnit reporting, Git
paths and hunk positions, and observed 7z cancellation. The
[semantic correctness record](validation/semantics-and-matching.md) and
[source semantics record](validation/source-semantics-and-dense-profiling.md)
identify the concrete regressions and validation scopes.

Independent quality evaluation, fuzz reachability and private reproduction,
optional deep-security checks, representative benchmarks and native profiling
are implemented. The [opt-in native policy](DETECTION_POLICY.md), three-family
rules pilot, bounded explanations, layout annotations, [triage](TRIAGE.md),
source budgets and finite robustness extensions have completed their bounded
acceptance scopes. The [completion record](validation/process-cpu-and-completion.md)
identifies the qualification evidence and delivery pull request. The new
robustness changes reject cyclic 7z coder graphs and provide opt-in
declared-length enforcement. The current default
profile, copied configuration and upstream pin remain unchanged.

The [fragment throughput](validation/core-fragment-throughput.md),
[filtering and normalization](validation/core-edge-performance.md) and
[default-rule throughput](validation/default-rule-throughput.md) records
accept measured production optimizations. Earlier, the span-only matcher trial
missed its criterion, the location comparison stopped before candidate timing,
and the fixed observation-window matrix did not qualify every guard. The
[window record](validation/baseline-observation-windows.md) preserves all results.
The subsequent [whole-process CPU comparison](validation/process-cpu-and-completion.md)
completed with qualified controls but rejected the candidate after its first
complete-CLI round missed the criterion. The production helper remains unchanged.

## Packet status

| Packet | Work | Status | Prerequisites | Evidence and remaining checks |
| --- | --- | --- | --- | --- |
| F0 | Native profile and extension contract | Complete | Default-preserving opt-in implementation | [Native contract](DETECTION_POLICY.md), exact API, package/external-consumer and compatibility evidence; qualified delivery recorded in the [completion record](validation/process-cpu-and-completion.md) |
| F1 | Independent accuracy evaluator and corpus | Complete | None | Hand-counted scoring tests, unknown/partial/duplicate controls, reproducible full-ruleset and per-rule baseline |
| F2 | Three-family opt-in rules pilot | Complete | F0 identity contract; F1 baseline | [Three bounded rules](../crates/rustleaks-core/default/rustleaks-extra-v1.md), generated 72-case comparison, quality checks and qualified delivery; explicit format gaps and one reviewed duplicate retained |
| F3 | Bounded explanations and offline validators | Complete | F0 identity contract; F1 | [Historical layout validation](validation/offline-validation.md), bounded diagnostics, disclosure and compatibility checks; checksum remains `Unknown` and findings remain visible |
| F4 | Triage and embedding workflows | Complete | F1; F0/F3 identity and outcome contracts | [Review records and occurrence-preserving groups](TRIAGE.md), stale-state, report, embedding and external-consumer checks; qualified delivery |
| S0 | Archive fuzz reachability | Complete | None | Independent format/control selectors, reproducible framed seeds, real decoding and callback-mode tests for supported formats |
| S1 | Private reproducers and corpus retention | Complete | S0 | Private run/replay/minimize/review/promote/import, real synthetic failure reproduction, command regression and bounded process tests pass |
| S2 | Optional deep-security profile | Complete | S0; S1 | All eight deeper campaigns pass, 20 structured cases, additional Miri, dependency comparison and recorded deadline exercises |
| S3 | Semantic robustness campaigns | Complete | S0; S1 for infrastructure | Finite archive/Git/decode/budget/session matrix, cyclic coder rejection and opt-in 7z lengths; local Rust qualification, historical differential evidence and hosted native checks |
| S4 | Operation-wide source budgets | Complete | Explicit source-run policy | Shared accounting, partial outcomes, one/many-worker and cleanup controls; repeated-test and hosted checks; qualified delivery |
| P0 | Authoritative benchmark integration | Complete | None | Bazel runner/tests, real build provenance, preserved invariants and legacy timing scope, unchanged inherited M1 limits with migration evidence |
| P1 | Representative performance workloads | Complete | P0 | 28 workloads, 103 phases and seven native samples per phase; exact outcomes and unchanged legacy limits pass |
| P2 | Profiling and regression calibration | Complete | P0; P1 | Usable native CPU/retained-memory evidence and two independently validated A/A/slowdown-control runs |
| P3 | Measured hotspot optimizations | Complete | Qualified primary and guard measurements | [Fixed CPU investigation](validation/process-cpu-and-completion.md) completed with explicit candidate rejection; production helper unchanged and no optimization accepted |
| P4 | Optional periodic performance reporting | Complete | P0-P2; sanitized retention contract | [Bounded collection/import and manual summary retention](PERFORMANCE_REPORTING.md), actual collector/profile-import/reparse/summary controls and qualified delivery |

Statuses are `Planned`, `In progress`, `In review`, `Complete`, or `Blocked`
with a concrete prerequisite. `In review` means implementation is present with
remaining scoped validation, hosted qualification or merge still outstanding. Only
completed required checks and resolved material review findings support
`Complete`.

All 15 selected packets have completed their bounded acceptance scopes.
P3 closes with a rejected candidate, not a production optimization. The
[completion record](validation/process-cpu-and-completion.md) binds the result
and delivered implementation. The S3 finite matrix remains specified in the
[source semantics record](validation/source-semantics-and-dense-profiling.md).
These dispositions do not establish that future candidates meet their criteria. The acceptance sections below retain results for their identified
source snapshots; they do not qualify subsequent changes without the applicable
checks.

## Current local validation

The live Go oracle is retired. Current qualification checks frozen evidence
integrity and Rust regressions without Go or a sibling Gitleaks checkout.
Defaults, corpus bytes, attribution and historical Go observations remain
unchanged; current Rust output is not used to create expected baselines.

Retirement source `828def79855f53a01baf9dc4b608835321834c64` passed 60 CI targets,
security checks and all 55 first-party targets repeated ten times. A clean clone
passed 16 uncached regression/tooling targets with Go unavailable on its command
PATH and no sibling checkout. Candidate
`ebaeddbc5bdae6c5f96a04f16eaf491c5d76adca` adds test-only lint corrections with
focused formatting, Clippy and xtask unit checks passed. Complete clean Rust
qualification also passed with Go unavailable on PATH and no sibling checkout,
including default/all-feature tests, strict lint, MSRV, Miri, public API,
package consumers, bounded resources, eight fuzz smoke targets and inherited
performance limits. Final hosted qualification and the delivered source are
recorded in the [completion record](validation/process-cpu-and-completion.md).

The following source-bound results predate retirement and retain their original
Go differential scope.

The clean runtime candidate `c7aa41adf015ebef4ba7100850c62a43d5f58079`, tree
`85a6e6b7f46353508b54b5982ccf2778c259298b`, passed the full pinned-Go differential,
default/all-feature quality checks, exact public API checks, packaging and
external Cargo/Bazel consumers, all eight fuzz smoke targets, and unchanged
inherited performance limits. Its clean local release dry run and 28 selected
Bazel targets also passed. These results do not publish a package or release.

The 59-target CI gate and all 54 first-party targets repeated ten times passed
at `4fd49b0d8c1f5f49ca89527bf15b3b0d0c53761d`. Subsequent changes corrected
lint-only imports and test assertions; focused follow-up checks passed. The
final 59-target CI and security refresh passed at
`84256b85cb3a7440d8f719641035a5612419469f`. Later Rust-owned qualification and
qualified delivery retain their separate source identities.
Native runtime evidence is for aarch64-apple-darwin; target compilation does not
establish runtime qualification elsewhere.

P4 native collector smoke passed at
`cd56919ecced57e5450a073deb1e2bac737b24e1`: all 23 informational workload rows,
process cleanup and sanitized-summary verification completed. Native profile
import and artifact reparse also passed. This busy-host collection establishes
collector correctness, not a wall-time budget result or speedup.

Final P3 controls covered 730,605 spans, detected the deliberately wrong
boundary and passed 22 public targets. A targeted cycle-weighted profile and
the fixed 180-process CPU comparison are recorded in the
[completion record](validation/process-cpu-and-completion.md). The first CLI
round failed the fixed improvement criterion; the candidate was rejected.

## Foundation acceptance record

| Boundary | Required evidence | Current result |
| --- | --- | --- |
| S0 | Ordinary archive harness tests, generated-seed validation and fuzz smoke | Pass; all six tests and all eight fuzz targets |
| F1 | Evaluator golden/mutation tests, corpus regeneration check and current baseline | Pass; 19-case baseline retained with explicit metric scope |
| P0 | Runner tests, exact workload invariants, provenance rejection tests and paired build migration evidence | Pass; all 23 outcomes match and both builds meet unchanged inherited limits |
| Combined graph | `just ci`, relevant security checks and clean-clone validation | Pass; exact scopes in the acceptance record |
| Independent review | Fresh review of integrated implementation and evidence; resolve material findings | Complete; no unresolved material findings |
| Repository boundaries | No unapproved dependency, toolchain, default configuration, publishable core API or publication change | Verified unchanged |

The [foundation acceptance record](validation/foundation.md) contains exact
validation scopes, observations, limits and benchmark migration evidence. A skipped host budget or pending hosted
job is not a pass. A completed local batch does not create a release or approve
publication.

## Evidence retention and workload acceptance

| Boundary | Required evidence | Current result |
| --- | --- | --- |
| S1 private execution | Synthetic failure/success/timeout, descendant cleanup, bounded logs, permissions and retained evidence | Pass; actual retained failure, minimization and exact reproduction |
| S1 corpus workflow | Exact replay, safe import, minimized-corpus identity and explicit reviewed promotion | Pass; reviewed synthetic corpus and stale/unsafe input controls |
| P1 workload correctness | Exact outcomes, work denominators, phase boundaries, setup/verification separation and skipped-input controls | Pass; every sample complete, ordinary archive fixtures and mutation controls |
| P1 native measurements | Bound build/input identity, raw repeated samples, scope-correct CPU/RSS and native host record | Pass; Apple M1 Max, dirty candidate explicitly ineligible as a clean baseline |
| Combined validation | Relevant Bazel CI, security, fuzz, fresh-checkout and redacted self-scan evidence | Pass; exact scopes in the acceptance record |
| Independent review | Fresh review of implementation and evidence; resolve material findings | Complete; no unresolved material findings |

The [acceptance record](validation/evidence-and-workloads.md) documents the
private operator exercises, corrected minimizer argument defect, checks and
native measurement limits. The [measurement record](validation/representative-performance-2026-11-05.json)
retains the samples and projected provenance.

This batch adds no required deep-security campaign or new performance threshold
to release qualification. Hosted private artifact transport remains a separate
decision. The existing legacy benchmark limits remain unchanged.

## Deep-run and profiling acceptance

| Boundary | Required evidence | Current result |
| --- | --- | --- |
| S2 bounded execution | Whole-run deadline, serial campaigns, private evidence and a disposition for every requested target | Pass; preparation and active-campaign deadline evidence retained |
| S2 larger inputs | Profile caps reach harnesses; structured cases cross smoke limits and check exact bounded outcomes | Pass; 64 KiB fuzz inputs and 20 explicit larger boundary cases |
| S2 coverage and dependency evidence | Actual fuzz feedback, source-coverage support disposition, locked-graph and advisory/vet/unsafe comparison | Pass with explicit source-coverage skips for missing matching LLVM tools; no dependency delta |
| P2 native profiling | Separate optimized profiling build, usable CPU stacks and accurately scoped memory observations | Pass; native Apple M1 Max observations, without allocation-history claims |
| P2 regression calibration | Alternating unchanged-code training and held-out samples, deliberate slowdown control and versioned local policy | Pass; both held-out sets within their bands and every extra-work pair detected |
| Combined validation | Relevant Bazel CI, security, fuzz, package and fresh-checkout checks; private-output and boundary review | Pass; exact scopes and metadata amendment in the acceptance record |
| Independent review | Independent review of implementation and measured evidence; resolve material findings | Complete; source lineage, permissions, campaign/profiling/calibration data and final checks independently verified |

The [acceptance record](validation/deep-and-profiling.md) links the retained
deep-run and profiling/calibration projections. The longer deep pass used
explicit 60-second target budgets; the default ten-minute budgets were not run
in full. No hosted schedule or new release timing threshold was introduced.

## Completed investigation scope

The bounded S3 production-contract investigation and the first P3 matcher
experiment are recorded in [semantic correctness and matching validation](validation/semantics-and-matching.md).
The four corrections are retained. The matcher and its experiment-only tests
and fuzz assertion were restored to accepted source after the performance
criterion failed. The [measurement record](validation/matcher-experiment-2026-11-05.json)
retains all ordered paired timings, exact invariants and uncalibrated guard
observations. Later bounded robustness and CPU dispositions are recorded
separately; these historical observations are unchanged.

The selected implementation and investigation are complete. The
[baseline observation-window packet](validation/baseline-observation-windows.md)
remains an unqualified historical result. The later CPU protocol completed with
candidate rejection; no threshold was transferred or relaxed. Future capture,
scratch, normalization or source-scheduling work requires its own profiling,
semantic controls and measurement contract.

P4 retains seven-day retention for manually published sanitized summaries.
No schedule or new release threshold was enabled.

New network verification, external storage, dependencies, compatibility
exceptions, paid infrastructure and publication remain outside this scope.

## Deferred product decisions

Live verification and revocation require a separately reviewed network boundary
and explicit credential authorization. Cloud/container integrations, new public
packages, Python/Wasm bindings, runtime plugins and learned filters require a
concrete consumer need, safety design, and measured benefit. They are outside
the completed fifteen-packet scope. The current pinned profile remains the default
under the selected opt-in native extension policy.

## Additional coverage follow-ups

The reader/Git harness correlations are resolved for versioned inputs. Ordinary
tests prove independent control effects and successful 129-hunk parsing with
cancellation disabled; the maintained runner seeds both smoke and deep
campaigns. Legacy inputs retain their original coupled mappings. This improves
reachability without establishing a production parser or scheduler defect.
See the [property validation record](validation/semantic-properties.md) for
reserved-prefix compatibility and remaining observation limits. Comparison
tracing and additional sanitizer experiments remain separately scoped work.

The exact benign Bazel `compile_action_key` context remains future quality-
corpus and contextual-filter work. Existing generic hash and build-identifier
controls do not claim to cover it. The scanner classified those provenance
hashes as generic API keys; any contextual filter still needs positive and
held-out recall checks. Temporary execution logs remain outside the source
tree without a new scan exclusion.

The native records distinguish runner-only detection from complete source
traversal and detection. The rejected P3 trial retained that distinction and
recorded guard slowdowns as well as improvements. Use a dedicated profile and
appropriate noise calibration before attributing those differences or changing
production scheduling.

The first P2 profile measured 84.89% of exclusive leaf observations in three
PikeVM execution methods. Nearly all observed copying sat beneath epsilon
closure. Avoiding subcapture collection in the initial whole-span search was
then tested in isolation and in the integrated candidate. Its primary gains
were below the predeclared 7.66% criterion in every round, so the production
matcher remains unchanged. This does not close the other P3 hypotheses.

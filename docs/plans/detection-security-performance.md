# Detection quality security and performance

Assessment date: 2026-11-05
Assessed commit: 48042081719bac70800d8416595941336b2314b8

The design retains the pinned compatibility profile and defines independently evaluated, explicitly selected Rustleaks extensions, bounded security tooling, and reproducible performance measurement.

This specification records the source assessment at the commit above. Current delivery status and validation evidence are maintained in [the roadmap](../ROADMAP.md). Workflow definitions establish configured checks rather than the success of hosted runs. Observed behavior, documented capabilities, proposals, and measurement hypotheses are distinguished below. Source paths are relative to the repository root. Source line references describe the assessed commit and may move as implementation proceeds.

## Current implementation status

F0, F2-F4 and S3-S4 have passed local integrated validation and remain in review
pending hosted checks and merge. Their
current contracts are the [native policy](../DETECTION_POLICY.md),
[pilot rule pack](../../crates/rustleaks-core/default/rustleaks-extra-v1.md),
[triage contract](../TRIAGE.md), [resource limits](../RESOURCE_LIMITS.md) and
[finite robustness matrix](../validation/source-semantics-and-dense-profiling.md).
The [local validation record](../ROADMAP.md#current-local-validation) binds the
clean source that passed generated API and quality checks, external consumers,
full compatibility, fuzz smoke, package dry run and selected Bazel targets.
Earlier results retain their exact source scope, including historical Go
comparisons. Current qualification is Rust-owned: retirement CI/security,
55 first-party targets repeated ten times and 16 uncached clean-clone targets
without Go on PATH or a sibling checkout passed. Complete clean Rust
qualification also passed after the test-only lint corrections. Hosted checks
and merge remain pending. Defaults and frozen corpus bytes are unchanged.
The F3 pilot implements historical-layout validation with checksum `Unknown`;
checksum computation and finding suppression are outside that pilot.

P3 retains earlier helper semantics, public checks and profile attribution;
current source/build bindings and new CPU-time comparison remain pending.
Primary and guard qualification remain prerequisites to accepting an
optimization. P4 native collector smoke completed all 23 informational rows,
cleanup and summary verification; profile import/reparse also passed. These
results establish no wall-time budget or speedup. Its manual public-artifact
contract requires seven-day retention and enables no schedule. Historical source
observations and the acceptance criteria below retain their original scope;
implemented code alone does not establish completed validation or release
availability.

## Design contract

Preserve synchronous byte-oriented core detection, Send + Sync, exact byte spans, structured partial outcomes, and the default graph without I/O, background threads, async runtimes, native libraries, source adapters, or reports. Keep existing copied defaults and pinned Go evidence unchanged. Native extensions must have distinct policy/version identity and tests; changes to existing supported behavior require the current complete Rust qualification procedure. See AGENTS.md; docs/ARCHITECTURE.md:38-67; docs/COMPATIBILITY.md:12-22.

The current implementation scope is recorded in the roadmap. Dependency/toolchain/rules_rust changes, copied-default or pin changes, compatibility or security exceptions, credential use, publication, paid services, and GitHub settings changes retain their repository approval boundaries.

Each implemented capability requires a scoped diff, independent positive and negative evidence, exact validation results, documented limits, and compatibility classification. Performance results must not improve by silently dropping findings, skipping inputs, truncating reports, or treating an incomplete scan as successful.

## Features and detection quality

At the assessed commit, Rustleaks has keyword filtering, regex matching, entropy, allowlists, composite rules, decoding, exact byte findings, baselines/ignores, cooperative budgets, and workspace Git/archive/report/CLI adapters. Only rustleaks-core is public. Evidence: README.md:15-17,69-80; docs/ARCHITECTURE.md:19-48; docs/COMPATIBILITY.md:16-22.

### Primary-source design references

- Gitleaks documents rules, allowlists, baselines and source modes: https://github.com/gitleaks/gitleaks . Its pinned profile defines existing compatibility; independent quality evaluation measures the separate occurrence and attribution criteria below.
- Betterleaks documents rule-defined HTTP validation, contextual expressions and token-ratio filtering: https://github.com/betterleaks/betterleaks . Evaluate static rule improvements and filtering ideas; do not assume Rustleaks can import all semantics or that those filters improve its precision.
- TruffleHog documents verification and verified/unverified/unknown result states: https://github.com/trufflesecurity/trufflehog . This is a useful state-model reference for a later optional verification adapter, not evidence that unmatched or inactive findings are harmless.
- detect-secrets documents baseline auditing and labels and warns that its optional gibberish detector can ignore ordinary-word secrets: https://github.com/Yelp/detect-secrets . These references inform review-record semantics and filter failure cases.
- Kingfisher documents synchronous Rust scanner libraries, Python embedding and a native build boundary: https://raw.githubusercontent.com/mongodb/kingfisher/main/docs/LIBRARY.md . The Rustleaks core boundary remains defined by this repository's architecture and compatibility contracts.
- Titus documents Go embedding, browser/Burp interfaces and container/binary analysis: https://raw.githubusercontent.com/praetorian-inc/titus/main/README.md . Nosey Parker's notice records its retirement in favor of Titus: https://raw.githubusercontent.com/praetorian-inc/noseyparker/main/README.md .
- GitHub's supported-pattern inventory distinguishes provider types and capabilities, including limited validity-check support: https://docs.github.com/en/code-security/reference/secret-security/supported-secret-scanning-patterns . Keep structural validity, detection confidence and active verification distinct.

These primary sources were inspected on the assessment date. They do not supply measured Rustleaks quality or performance evidence. GitHub's inventory identifies formats and capabilities; it is not a redistributable ruleset.

Rule-source preference: start with pinned static deltas from Gitleaks and MIT-licensed Betterleaks (https://raw.githubusercontent.com/betterleaks/betterleaks/main/LICENSE). Apache-2.0 projects such as detect-secrets and Kingfisher can inform later rule review, but imported ancestry and per-file terms must be checked; Kingfisher's catalog itself imports other sources (https://mongodb.github.io/kingfisher/rules/builtin-rules/). Do not treat a project's top-level license as proof that every imported rule can be copied unchanged. TruffleHog's repository identifies AGPL-3.0, so its implementations are not an automatic source for this MIT-licensed project with separately licensed copied material.

### F0 Define the extension contract before changing detection semantics

Deliver an exact distinction between the existing pinned profile and opt-in native rule/validation policies. Identify versioned rule-pack IDs, collision/override behavior, compatible report behavior, and migration rules. Keep the current default profile and frozen historical evidence under Rust regression protection. Evaluate a separate TOML rules-pack input using existing loader semantics before adding new syntax or a new crate. Existing default behavior remains unchanged; intentional native behavior is explicitly selected and versioned.

Acceptance: every proposed new behavior has an owning layer, explicit selection mechanism, compatibility disposition, and positive/negative tests specified. Existing profile output remains identical. Any public API addition must have a concrete consumer example and package-check plan. The [native policy](../DETECTION_POLICY.md) implements explicit selection, bounded TOML composition, strict native-field validation, collision rejection and exact configuration identity. Local integrated API, package/consumer and compatibility evidence passed; hosted checks and merge qualification remain pending.

### F1 Build independent detection-quality evaluation

The current default-rule replay is an oracle compatibility test with 6,770 cases, not an estimate of real-world precision. The test asserts 6,368 ordinary positives, 342 ordinary negatives, 28 path positives and 32 path negatives and selects each sample's individual rule. Evidence: crates/rustleaks-core/tests/default_rule_corpus.rs:34-56,116-119.

Create a versioned manifest with case ID, generator/source revision and license, reviewed synthetic-data provenance, byte content/path, secret-family label, expected occurrence and exact spans, encoding, difficulty stratum, and split. Separate provider-format validity, live validity, and security relevance. Include known negatives such as hashes, UUIDs, placeholders, documentation, build output and random identifiers only when their labels are grounded; include realistic synthetic positives in the same contexts so context exclusions cannot pass by hiding all examples. Cover paired credentials, encodings, invalid UTF-8, multiline tokens, partial scans, duplicates and generic-rule overlap. Hold out template/family variants from tuning. Unknown or disputed labels stay unknown and are reported separately, not counted as false positives or negatives. Never collect live credentials or private repositories.

Evaluate the full ruleset as well as individual rules. Match expected detections one-to-one at occurrence/span level; separately report provider attribution and duplicate alerts. Emit TP, FP, FN, precision TP/(TP+FP), recall TP/(TP+FN), reviewed-negative alert density, corpus size/composition, unknown rate, completion rate, and per-family results. Zero denominators are undefined, not 100%. Do not compare precision across different sample prevalence or claim field accuracy from synthetic data. Incomplete outcomes are explicit failures/coverage loss, never clean scans. Any incomplete outcome prevents a passing aggregate quality status; retain its expected-positive inventory and a missing-work ledger rather than silently dropping it from the evaluation. Keep source/rule provenance in reports and omit raw secrets.

Acceptance: evaluator golden tests reproduce hand-calculated TP/FP/FN and unknown/incomplete counts, including a deliberately missed positive. The current detector baseline may report errors; the harness must describe them accurately, not force all candidate detections to pass. Mutation controls deliberately remove a rule, broaden a rule, duplicate a finding, and mark a partial scan complete, and the evaluator detects each defect. Produce a current baseline before any detector change. A later rules/filter packet must preserve existing held-out positives and show its exact added coverage or reduction in false alerts on this corpus. No universal percentage target is invented before baseline data exists.

### F2 Evaluate and ship a small opt-in rules-pack pilot

Implementation: `rustleaks-extra-v1` contains independently authored rules for all three families, explicit format limits, provider references and a 72-case full-default/full-native comparison. Azure rules add provider attribution; MongoDB also adds exact occurrence coverage. The documented single provider-overlap duplicate is retained. The generated report and local integrated quality checks substantiate the bounded corpus result; hosted checks and merge qualification remain pending.

Freeze the initial experiment at three candidate families: Azure Service Bus/Event Hub connection strings, Azure App Configuration connection strings, and MongoDB credential URIs. Dedicated definitions exist in Betterleaks' catalog (https://raw.githubusercontent.com/betterleaks/betterleaks/main/config/betterleaks.toml), while corresponding dedicated IDs are absent from the current packaged rules. This is a catalog observation, not measured evidence of missed secrets. Ground format cases in Microsoft Service Bus properties (https://learn.microsoft.com/en-us/javascript/api/%40azure/service-bus/servicebusconnectionstringproperties?view=azure-node-latest), Microsoft App Configuration connection setup (https://learn.microsoft.com/en-us/azure/service-connector/how-to-integrate-app-configuration), and MongoDB connection formats (https://www.mongodb.com/docs/manual/reference/connection-string/). Cover field order, escaping, URI percent encoding, empty credentials, template-only values and actual secret spans. Crates.io tokens remain later format discovery until issuer formats and current generic overlap are established. Check the entire current ruleset, including generic coverage. Candidate discovery must establish exact token structure from primary provider documentation, available parser semantics, existing detection overlap, license and update source. A missing dedicated rule ID alone is not a recall gap. Prefer a rule expressible in the existing TOML format with keyword anchors, precise secret groups, bounded context and near-miss negatives. Add a rule only when the pilot proves incremental detection or more useful provider attribution without unacceptable duplicate alerts.

Pin imported material to an immutable revision and hash, preserve attribution and applicable licenses, record a refresh owner/procedure and review date, and reject unknown rule syntax. Do not bulk-copy GPL/AGPL scanners' detector implementations into the MIT project. License suitability is a source-review gate, not an assumed permission based on public availability. Reimplementing a documented provider format must use independently written tests and retain factual source citations.

Acceptance: full-ruleset comparison documents each candidate's baseline, changed TP/FP/FN and duplicate count; exact raw/decoded spans and invalid-byte behavior pass; every new pattern has grounded positive, negative, allowlist and boundary cases. Require zero unexpected losses of existing labeled positives and zero new false alerts on the fixed reviewed negative suite. These are proposed corpus acceptance gates, not deployment-rate promises. Keep candidates experimental if they need a broader accuracy tradeoff, and remove or defer those with no demonstrated gain. Any dependency, default-config change or publication waits for separate approval.

### F3 Add bounded explanations and conservative offline validation

Implementation: the native envelope carries at most 65,536 source-omitting decision records. Disabled diagnostics perform no offline checks. Historical GitHub classic PAT layout and checksum assessments are separate; checksum remains `Unknown`, and annotations never suppress findings. Local integrated disclosure, partial-outcome and legacy-equivalence checks passed; hosted checks and merge qualification remain pending.

First add an opt-in explanation channel with bounded records and deterministic reason codes: rule selection, keyword/structure match, entropy threshold, allowlist decision, offline-validator result, budget termination, and policy/rule-pack identity. Expose typed evidence rather than invented probability scores. Omit source bytes, token values and snippets by default. Metadata still has disclosure implications; provide narrow consumer projections. Explanations must not alter legacy findings/serialization, and disabled explanations should avoid retaining extra content.

The offline pilot assesses the issuer-documented historical GitHub classic PAT layout (https://github.blog/engineering/platform-security/behind-githubs-new-authentication-token-formats/). Layout results are valid, invalid or unknown under an explicit versioned contract. Checksum status remains unknown because the inspected issuer sources do not specify all reproducible checksum parameters. Layout validity does not establish checksum validity or activation. Malformed/truncated keys, expired JWTs and missing companion fields can remain meaningful exposure evidence; do not classify them safe merely because a validator cannot verify them.

Pilot typed, allowlisted, offline validators only where a documented checksum, length, alphabet, or component relationship establishes a useful distinction. Start with annotation/shadow evaluation. Use valid/invalid/unknown states; unsupported versions, unavailable context, and parse ambiguity stay unknown. Do not drop findings simply because a token is unverified. Turning validator failure into suppression requires F1 held-out evidence and explicit native-policy selection. Generic entropy, stop words, token-efficiency heuristics or generated/vendor-path exclusions must never be enabled globally on intuition. Existing allowlists and composites should be tried before introducing a validator DSL or executable plugins.

Acceptance: byte findings and compatibility serialization unchanged when disabled; explanation output does not contain sentinel secrets even for nested/decoded/partial findings; limits hold under many matches; all asserted-invalid decisions have positive and near-miss coverage; held-out recall does not regress. Any public API is exercised by an external consumer. A later confidence tier must have a documented evidence definition and measured calibration; it must not be advertised as a probability without data.

### F4 Improve triage and embedding workflows

Implementation: versioned records bind policy, actual scan options and caller-provided immutable source identity, with finite reasons and caller-time expiry. Review and grouping preserve every finding and the actual completion state. Bounded report readers/writers and executable embedding examples accompany the core API; local integrated package, consumer and report checks passed; hosted checks and merge qualification remain pending.

Build on existing baselines and ignores. Add review records with rule-pack/policy identity, reason, expiry and stale-suppression reporting; show newly introduced findings separately from acknowledged findings without calling acknowledged findings safe. Group related provider/generic detections for presentation while preserving every underlying occurrence and its exact span. Keep grouping keys process-local or explicitly keyed and access-controlled; do not emit unsalted hashes of low-entropy secrets as supposedly safe identifiers. Add examples that compile an engine once, share it across caller-managed workers, set scan budgets, inspect partial outcomes, and project safe diagnostics.

Acceptance: repeated review is deterministic; line shifts, rule upgrades, policy changes, expired suppressions and encoded occurrences have tests; grouping cannot suppress an unrelated occurrence; review artifacts avoid raw credentials and warn through the documented data contract when source metadata is retained. Existing baseline semantics remain available unchanged. Distribution of workspace-only CLI/report/source crates is a separate future product/release decision.

Live verification and revocation are deferred. They require a separately reviewed network adapter, explicit egress/credential authorization, fixed provider origins, SSRF and redirect controls, time/rate budgets, verified/inactive/unknown states, redacted diagnostics and mock-only default tests. No network, credentials or revocation enters core detection. Broad cloud connectors, runtime plugins and machine-learning filters are likewise deferred until measured demand and a threat-model decision justify them.

## Security and robustness

Existing controls include eight fuzz targets, ASan smoke, nightly longer campaigns, weekly campaigns and coverage, Miri, advisory/license/vet/unsafe checks, CodeQL and Scorecard. Evidence: docs/SECURITY_CONTROLS.md:7-63,172-199; .github/workflows/ci.yml:76-138; nightly.yml:57-92; weekly.yml:19-85. These controls should be improved rather than duplicated.

### S0 Repair archive fuzz reachability

Observed: the first byte selects `control % 16`, while bits 0, 1 and 2 pre-cancel, cancel on first callback, or stop on first callback. Every odd format selection is pre-cancelled. ArchiveSource checks cancellation before reading. Enumerating all 256 control bytes confirms ZIP, RAR, GZ, XZ, BR, SZ, ZST and LZ never enter their decoder through this harness; only TAR and BZ2 permit unrestricted callbacks. This does not establish a production decoder vulnerability or absence of other tests. Evidence: archive.rs:23-46,62-90; crates/rustleaks-sources/src/archive.rs:205-233.

Separate format selection from behavior controls, using independent bytes or explicit per-format targets. Preserve and separately test pre-cancel, mid-stream cancel and stop modes. Update the seed generator/encoding contract rather than silently changing existing seed interpretation. Use valid reviewed/synthetic fixtures for every supported format and codec variant, including nonempty payloads and multi-entry archives where supported.

Acceptance: an ordinary deterministic Bazel test exercises every format in normal mode and proves it reaches the intended parser and emits expected synthetic content; all control modes are independently reachable. A mutation that recouples selectors must fail. Unsupported codec paths have explicit dispositions. Run the affected source tests, fuzz build and smoke after integration. Longer campaigns follow this repair, not precede it.

### S1 Preserve private reproduction evidence and corpus progress

Observed: corpus and artifacts live beneath ScopedTempDir; its Drop removes the tree on ordinary success and failure unwinding. Each run copies seeds anew. The nightly/weekly fuzz jobs have no explicit private crash retention/persistent corpus path. Evidence: main.rs:2397-2407,2473,2535-2578 and those workflow files. This prevents a reliable preserve/reproduce loop through this runner; it does not prove any past crash was lost.

Add a dedicated retention policy for fuzz runs, not a global change to every temporary directory. On failure, preserve input and diagnostics before cleanup with restrictive local permissions; record revision, lock hashes, target/features, exact toolchain, sanitizer, command, seed, dictionary hash, corpus hash, termination reason and artifact hash. Capture raw libFuzzer output privately with an output cap, since it may print crashing bytes. Use tested process-tree termination and reaping on timeout, not only direct-child termination; the current timeout helper and existing alternative cleanup helper are in crates/xtask/src/tooling/support.rs:116-187,269-297. Do not infer an actual orphan from the helper design alone. Corpus imports must reject symlinks and out-of-tree paths. Public output should give classification, counts and identifiers only. Successful evolved corpora may be minimized and promoted only after provenance/content review. Keep trusted corpus imports separate from untrusted pull-request output to prevent cache poisoning.

Acceptance: injected synthetic crash, timeout with descendants, command failure and success cases prove expected retention/cleanup and exact replay; public logs contain no sentinel payload; changing corpus/rules/toolchain invalidates incompatible cache keys. A deterministic repro can be minimized and promoted into an ordinary Bazel regression. A public GitHub artifact is not private vulnerability storage. Until approved private storage exists, retain the full bundle locally and run deep hosted campaigns only with an explicitly reviewed secure retention design. Do not provision credentials or a storage service in this packet.

### S2 Add an optional deep-security profile with honest scope

Observed: nightly increases run/time limits to 120 seconds per target; weekly uses 600 seconds but invokes the same target list and 4-16 KiB libFuzzer caps, with additional caps inside harnesses. The weekly name alone does not provide larger-input coverage. Evidence: nightly.yml:87-92; weekly.yml:50-55; main.rs:2474-2533; archive harness:19-22,43.

The deep operator should compose the existing security gate, selected extended fuzz campaigns, fuzz-corpus coverage, structured large-input tests, explicitly selected additional Miri cases, and a dependency-evidence delta report. Snapshot the last-reviewed source/locked graph, features/targets, advisory database revision, vet coverage/exemptions and unsafe-change signals; report uncovered deltas without certifying them automatically. Favor approved peer evidence for already-covered dependencies, following current policy.

Introduce explicit smoke, extended and deep profiles with target selection, seed, per-input timeout, RSS cap, input/member/aggregate limits, and a whole-run deadline. Increasing libFuzzer max_len must be paired with the harness's own cap. Initial proposed deep budget: at most two local hours total, one campaign process at a time, up to ten minutes per selected target with time reserved for build/replay/reporting. These are starting operating choices, not measured sufficiency or an approved hosted spend. Calibrate after the first successful run and report actual execution, early termination and skipped targets. Keep the same toolchain/dependencies initially.

Use small fast mutation targets plus separate larger structured stress tests for archive expansion, nested decoding, many tiny entries, large match counts and rule/config limits. Make resource exhaustion a classified result, not a timeout hidden as success. Add fuzz coverage reports per target/codec and a traceability table from threat boundary to entry point, seed, invariant, sanitizer and deterministic regression. Ordinary test coverage does not substitute for fuzz coverage. The Rust Fuzz Book describes using corpus coverage to identify missing paths (https://rust-fuzz.github.io/book/cargo-fuzz/coverage.html) and structure-aware targets to reach deeper states (https://rust-fuzz.github.io/book/cargo-fuzz/structure-aware-fuzzing.html). Use structure-aware generation where random bytes otherwise never reach deep parser states; review any new generator dependency before adding it.

Acceptance: the profile runs locally from a clean checkout with reproducible metadata, bounded process lifetime/memory and retained private evidence; every requested target is pass/fail/skipped with a reason. Larger-input tests demonstrably cross smoke caps and exercise boundary values without unbounded jobs. Reports include corpus growth, coverage where supported, crash/timeout/OOM classification, and unresolved items. Initial monthly manual use plus boundary-change triggers is a proposal; choose a hosted schedule only after runtime and retention are established. This adds no deep campaign to every release.

### S3 Target semantic robustness beyond crashes

Implementation: the finite matrix adds mixed-quote Git paths and malformed-hunk boundaries; all nine two-coder Copy/Deflate/LZ4 combinations in single, solid and separate folders; malformed coder graphs; overlapping decode spans and combined budgets; and session insertion/merge permutations. Cyclic 7z graphs are rejected before decoding. Optional strict declared-length checks discard the affected archive before publication while default short-EOF behavior remains unchanged. The [coverage record](../validation/source-semantics-and-dense-profiling.md) separates this implementation from the earlier validated snapshot. Local robustness and full differential checks passed on the recorded clean candidate; hosted checks and merge qualification remain pending.

Prioritize decode offset composition, exact raw spans under malformed UTF-8, scan-budget monotonicity, partial-outcome completeness, recursive redaction, source worker cleanup, session state isolation, Git parser boundaries, and archive codec variants missed by adapter-only seeds. Add deterministic metamorphic properties where there is a real invariant; do not assume arbitrary chunk partitioning is semantically equivalent when the documented reader policy cannot preserve an unbounded match. Use Rust replay of frozen historical cases for the existing supported profile; new native behavior has independently specified Rust expectations.

Retain ASan and bounded Miri as complementary tools. Do not claim Miri proves absence of undefined behavior or that forbidding owned unsafe covers unsafe dependencies. TSan/MSan require a pinned supported experimental lane and evidence before becoming a claim or required check. OSS-Fuzz eligibility/application is a future adoption decision and external action, not required for this plan; its published acceptance criteria require established significance (https://google.github.io/oss-fuzz/getting-started/accepting-new-projects/). Miri documents its executed-path limitations (https://github.com/rust-lang/miri), and Rust sanitizer support is target-specific (https://doc.rust-lang.org/beta/unstable-book/compiler-flags/sanitizer.html). Compare enabled versus disabled libFuzzer comparison tracing in one bounded experiment before changing the current --no-trace-compares default; this review did not establish which is better for these targets.

Acceptance: each new property has a demonstrated failure control, deterministic Bazel replay and mapped threat row; native/platform claims match actual executed hosts; unsupported tools are clearly skipped. Periodic report tracks the exact locked dependency delta, relevant advisories/vet changes and reachable feature graph rather than treating unsafe line counts as safety proof. No exception is added automatically.

### S4 Design opt-in operation-wide budgets for source consumers

Implementation: `SourceRunner::with_budget` selects `SourceBudget` limits for per-fragment and aggregate decoded bytes, work and finding records, plus original bytes, fragment admissions and retained issues. Each finite aggregate engine dimension requires a finite per-fragment reservation ceiling. Shared reservations settle actual usage and refund unused capacity; partial fragments are discarded and all workers joined. Producer buffering and individual metadata remain outside those counters. Local accounting, cancellation, panic and cleanup checks passed, including the repeated-test gate; hosted checks and merge qualification remain pending.

At the assessed commit, the runner creates ScanControl::cancellable without applying ScanBudget (runner.rs:344), while aggregate operation limits are documented as caller-owned (docs/RESOURCE_LIMITS.md:16-19; README.md:75-80). This is an integration opportunity and documented limitation, not a confirmed vulnerability.

The source-run policy carries per-fragment work/decoded/finding budgets plus aggregate bytes, findings and work across workers. Its contract defines admission, accounting, cancellation, completed-fragment publication, and structured partial outcomes. Reserve work atomically or centrally so workers cannot multiply an aggregate limit; bound both queues and retained findings. Defaults preserve compatibility. A cooperative budget is not a hard wall-time or OOM guarantee.

Acceptance: one/many-worker runs cannot exceed documented totals except explicitly bounded in-flight work; completion/partial status and cleanup remain truthful; all worker-count comparisons preserve finding identity/order where contracted. Approval is required before a changed default or accepted compatibility exception. Do not bundle hard process isolation or a new async runtime into this packet.

## Performance

An existing deterministic rustleaks-perf runner checks output fingerprints and workload provenance. perf check runs inside full parity; timing/RSS checks are skipped except on an exact Apple M1 Max MacBookPro18,2/32 GB/10-core host. The helper invokes Cargo release builds despite an existing Bazel binary target, and the binary's inline tests are not in compat's all_tests. Evidence: crates/xtask/src/main.rs:2072-2180,2224-2242,2313-2371,3094; crates/rustleaks-compat/BUILD.bazel:22-43. No current speed numbers or confirmed bottleneck ranking were measured during this assessment.

### P0 Make the existing harness authoritative and trustworthy

Add proposed `just perf-run` and `just perf-check` backed by an optimized Bazel-built runner. Add the runner's invariant tests to Bazel and preserve existing workload identities/fingerprints. Keep build/fixture preparation outside timed scans. Record the compiler actually used to build the binary, target, optimization flags, dependency/feature graph, executable hash, source revision plus dirty state, rules/corpus hashes, CPU/OS, worker count and measurement mode. Current runtime `rustc -Vv` and `git rev-parse HEAD` observations alone do not prove binary build provenance (perf runner:255-281).

Acceptance: clean checkout can run the same invariants through Bazel; wrong rules/corpus/outcome/build provenance is rejected; dirty local experiments are labeled and cannot overwrite a clean baseline. Legacy M1 budget results remain available with their original conditions. Moving from Cargo to Bazel or changing measurement boundaries requires remeasuring old and candidate code with the same new harness; do not transplant incompatible thresholds or relax them to make a regression pass. Include clean-clone graph validation for the new build wiring.

### P1 Separate phases and add representative workloads

Measure cold process startup, TOML parse/compile, engine construction, warm core scanning, decoding, session merging, source traversal/Git, archive expansion and report serialization separately, plus end-to-end CLI runs. Warm scanning reuses the same compiled engine. Separate first scan from steady state: Decoder::new initializes static encoding-regex state even when decode depth is zero (engine.rs:429; decoder/mod.rs:172-179). Keep expected-result serialization/hashing outside timed detection and use black_box so work is observed. Declare whether outcome destruction is inside the timer, and avoid unbounded result retention to move destruction outside it. Criterion documents these timing-loop tradeoffs (https://bheisler.github.io/criterion.rs/book/user_guide/timing_loops.html). RSS from a new process may include configuration and fixture setup; label it total process peak, not scan-only allocation cost. Profiling memory allocations is a separate observation.

Include 1 KiB, 16 KiB and larger fragments; no-keyword/one-keyword/many-keyword cases; hit-heavy, no-hit and realistic synthetic mixed code; UTF-8/invalid bytes; minified long lines/multiline matches; decode depth; many rules; high finding counts; Git histories with repeated blobs and many commits; many small files and a few large files; supported archive formats with reported compressed and expanded bytes; and JSON/SARIF reporting. Existing workloads are retained as controls, and only missing scenarios are added. Every workload has fixed input hashes, exact expected results, limits and completion status.

Collect wall and CPU time, bytes/sec with stated denominator, files/commits/sec where meaningful, peak RSS, allocation counts/bytes when a profiler supports them, and per-phase counts. Use multiple independent process samples and sufficiently long inner iterations; report median and dispersion. Estimate p95 only with a declared adequate sample count, never from seven points. Keep cold/warm filesystem states and worker counts separate. Use native platform-specific baselines; cross-compilation is not measurement. No competing builds, fuzzing or profiling may run on the measurement host during sampling. Synthetic benchmark composition is not a field-speed claim.

Acceptance: output equivalence and complete scan status are mandatory for every sample; provenance makes incomparable samples obvious. Add a deliberately skipped-input control so timing cannot reward less work. Produce baseline data on at least one explicitly recorded native machine before choosing a performance threshold or hotspot to optimize.

### P2 Profile first and calibrate regression detection

Create a separate optimized profiling build with line tables and frame pointers where supported, preserving uninstrumented release measurements for speed comparisons. Retain profiles locally with synthetic inputs. The Rust Performance Book documents CPU/heap profiling, line tables and frame pointers (https://nnethercote.github.io/perf-book/profiling.html); use equivalent Bazel settings, not its Cargo command examples. On a supported Linux host, Valgrind DHAT can investigate allocation churn and retained memory without modifying production allocation (https://valgrind.org/docs/manual/dh-manual.html). Verify tool/host support before claiming a successful profile. Profile CPU stacks first, then allocations/retained memory where indicated. Capture compiler/process setup separately so it does not dominate a supposedly warm scan profile. Treat profiler overhead and sanitizer overhead as distinct measurement modes.

For regression checks, start with reports on shared CI and controlled local comparisons, not a fixed percentage gate on noisy hosts. Use alternating baseline/candidate runs on the same hardware, input, build mode, rules and graph; preserve raw samples, thermal/load conditions and repeated independent runs. Calibrate a noise band from unchanged-code A/A runs, then define the tolerated regression per workload in versioned policy. A detected regression must reproduce beyond that band; never update the baseline merely to pass. Keep existing hard budgets until explicitly migrated. Allocation/operation-count signals can supplement elapsed time, but do not replace end-to-end latency and throughput.

Acceptance: capture a usable CPU profile and memory investigation for a selected workload, publish a ranked list tied to observed stack/allocation evidence, and demonstrate a synthetic slow-down is detected while unchanged A/A runs behave as calibrated. If no stable hardware is available, retain informational reports and state that gating remains unavailable; do not block unrelated work or invent stable timing.

### P3 Optimize only the measured high-cost paths

- engine.rs:427-435 copies raw bytes then lowercases each pass. Investigate borrowing unchanged input and reusing normalization only if it matters in the profile; preserve Go Unicode/invalid-byte semantics.
- engine.rs:551-556 rebuilds the original newline index per eligible rule. Investigate one lazily built index per fragment and exact location reuse.
- regex/mod.rs:379-438 eagerly gathers capture vectors; matching creates search state, and engine match extraction can rematch. Investigate single-pass capture consumption and bounded caller/per-worker scratch, retaining empty-match progression, capture groups and source mapping. Preserve intentional newline trimming and anchored rematching (engine.rs:1180-1183); naive reuse of captures need not be equivalent. Scratch must have a total memory bound across rules and workers, rather than retaining every regex's maximum cache.
- engine.rs:872-912 generic filtering and sources runner.rs:70 unique-commit accounting have nested/linear searches. Index only after finding scale and profile justify the memory cost.
- CLI run.rs:235 uses SourceRunner::default(), whose worker/queue bounds are 1/1 (runner.rs:415-420), despite library worker configuration. Benchmark explicit 1/2/4 worker settings before exposing a CLI option or changing defaults. Preserve S4 aggregate budgets and account for per-worker scratch, ordering, I/O contention and cancellation.

For each candidate, submit one hypothesis, workload, baseline profile, isolated implementation and before/after measurements. Prefer removing duplicated work before replacing regex engines, adding SIMD/native dependencies, parallelizing core or introducing persistent caches. Cache keys for any later incremental scan must include bytes, rules/options/decoder/profile identity and relevant metadata; cache storage has a separate secret-handling design. No cache is in the initial optimization scope.

Acceptance: improvement reproduces beyond the calibrated noise band, exact findings/errors/partial status and held-out quality remain unchanged, and memory/cancellation tradeoffs are documented. Reject the optimization if the gain disappears under end-to-end measurement or it regresses required cases without an approved tradeoff. No numeric speedup is promised in advance.

### P4 Add optional periodic performance reporting

Implementation: the [optional reporting command](../PERFORMANCE_REPORTING.md) collects a bounded legacy matrix or imports supported retained reports. It recomputes derived classifications, separates invariant/execution failure, qualified legacy regression, informational timing, skipped budgets and profile availability, and emits a fixed sanitized summary. Manual public artifacts must contain only the verified summary and use seven-day retention. Native collector smoke completed all 23 informational rows, cleanup and summary verification; native profile import/reparse also passed. Hosted qualification and merge remain pending; no automatic schedule or new release gate is added.

Acceptance: each run distinguishes invariant failure, measured regression, budget not evaluated, unavailable host/tool and completed profile. Retain bounded raw samples, source/build/corpus identity and profile references; use only synthetic/reviewed inputs and avoid unnecessary environment/path disclosure. Reproduce a deliberate slowdown and unchanged-code noise behavior. No paid runner procurement or external service is included. Current release latency must not grow merely because this optional profile exists.

## Dependencies and validation

Feature dependencies are explicit: native policy precedes native rules and validators; independent quality evidence precedes rule/filter admission; source budgeting defines shared accounting; performance changes require qualified measurements.

Run commands from the repository root. New interfaces described by a packet become available only when that packet is implemented; the roadmap and current justfile establish their status.

Current focused checks to select according to the packet:

```sh
bazelisk test //crates/xtask:xtask_unit_test
bazelisk test //crates/rustleaks-core:engine_test //crates/rustleaks-core:controlled_scan_test
bazelisk test //crates/rustleaks-core:default_rule_corpus_test //crates/rustleaks-core:detect_corpus_test //crates/rustleaks-core:allowlist_test //crates/rustleaks-core:config_test
bazelisk test //crates/rustleaks-sources:all_tests
bazelisk test //crates/rustleaks-report:all_tests //crates/rustleaks-cli:all_tests
```

After related changes are integrated, run the applicable final gates:

```sh
just ci
```

`just ci` covers format, lint, documentation, builds, target compilation, first-party tests and committed parity. Add `just security` for security/graph/boundary changes and `just fuzz-smoke` for parser/regex/decoder/hostile-input changes when the full Rust qualification gate is not needed. Add `just package-check` for public API/default assets/features/manifests/dependencies; use the release dry-run only for publish metadata/package-content changes. Build-graph changes need clean-clone validation under the build-maintenance skill.

A change to supported detection/config/rule behavior requires complete Rust qualification on a clean, committed candidate. No Go installation or sibling checkout is required. Run from the root:

```sh
cargo xtask qualify
```

That full qualification already includes package and fuzz checks; do not repeat those gates unnecessarily. Native extensions must leave the supported profile green and add their independent quality tests; existing obligations are not silently waived. New benchmark and fuzz targets must be represented in the maintained graph and normal deterministic regressions.

Completion requires the stated acceptance evidence, successful required checks, resolved material review findings, and an explicit disposition for every candidate. Pending checks are not successful validation.

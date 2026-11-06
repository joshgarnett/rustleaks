# Security controls

This file is the operator contract for local security checks and hosted
automation. Run commands from the repository root with the checked-in
lockfiles unchanged.

## Local commands

| Command | Purpose |
| --- | --- |
| `just security` | Run cargo-deny, a fresh RustSec audit, locked cargo-vet policy, exact dependency graphs, first-party unsafe policy, cargo-geiger inventory, pinned Miri, and the `panic=abort` archive policy check. |
| `just fuzz-build` | Compile all eight cargo-fuzz targets from their locked standalone manifests. |
| `just fuzz-smoke` | Copy reviewed seeds to temporary corpora and run bounded 16-run AddressSanitizer smoke campaigns with format dictionaries, timeouts, length caps, RSS caps, a recorded mutation seed (default 1), and private temporary artifact paths. |
| `just parity` | Replay the full committed compatibility corpus through Bazel. |
| `just ci` | Run the local Bazel format, lint, documentation, build, eight-target compile, unit, integration, and committed-corpus test graph. Run security, fuzz, package, and release gates separately as listed here. |
| `just package-check` | Build an extracted package and clean external Cargo and Bazel consumers. |
| `just release-dry-run` | Run package checks and Cargo's locked no-upload publish dry run. |

`just security` requires these exact host tools:

- `cargo-audit-audit 0.22.2`
- `cargo-deny 0.19.9`
- `cargo-geiger 0.13.0`
- `cargo-vet 0.10.2`
- Miri from `nightly-2026-08-21`

Fuzz commands require `cargo-fuzz 0.13.2`. The repository's ordinary Rust
toolchain is pinned in `rust-toolchain.toml`; the declared MSRV is Rust 1.95.
The security gate checks exact tool versions and fails on drift.

The RustSec check intentionally updates its advisory database. It is not an
offline check. The other dependency decisions remain bound to `Cargo.lock`.

## Fuzz matrix

| Workspace | Target | Main boundary |
| --- | --- | --- |
| `rustleaks-core/fuzz` | `config` | TOML, rule extension, allowlists, composite rules, size and reload invariants |
| `rustleaks-core/fuzz` | `go_regex` | Go translation, compilation, captures, empty matches, invalid bytes, repeated matching |
| `rustleaks-core/fuzz` | `fragment_scan` | Decoders, locations, arbitrary bytes, overlaps, redaction, limits, and deterministic rescans |
| `rustleaks-core/fuzz` | `session` | sorting, deduplication, baselines, ignore behavior, and scan-session state |
| `rustleaks-sources/fuzz` | `archive` | archive formats, traversal, links, expansion, entry counts, and nesting |
| `rustleaks-sources/fuzz` | `reader_schedule` | chunk partitioning, short reads, errors, cancellation, and source scheduling |
| `rustleaks-sources/fuzz` | `git_patch` | in-memory patch parsing, quoting, renames, copies, binary changes, submodules, integers, and line endings |
| `rustleaks-report/fuzz` | `template` | template parsing, evaluation, escaping, output limits, and deterministic rendering |

The default cargo-fuzz Clang configuration supplies AddressSanitizer on the
verified Apple Silicon macOS host. The targets are designed for x86-64 and
ARM64 Unix-like cargo-fuzz hosts. Hosted automation must verify each scheduled host before
claiming support. MemorySanitizer and ThreadSanitizer do not have a supported
lane in the current graph and must be recorded as unsupported jobs unless a
reproducible pinned lane is established.

For a longer local run, retain the same corpus, dictionary, maximum input
length, timeout, RSS limit, and artifact privacy used by `fuzz-smoke`, then
increase `-runs` or `-max_total_time`. Never use environment credentials,
developer files, private repositories, or live tokens as seeds.

### Private local fuzz evidence

`just fuzz-smoke` runs all eight targets with the existing defaults: 16 runs,
20 seconds per target, five seconds per input, 2048 MiB RSS, and the matrix's
4-16 KiB input limits. `RUSTLEAKS_FUZZ_RUNS` and
`RUSTLEAKS_FUZZ_MAX_TOTAL_TIME` retain their existing upper bounds of 1,000,000
and 600. `RUSTLEAKS_FUZZ_SEED` selects an explicit nonzero 32-bit seed and
defaults to 1. Each target also has an external deadline of its time budget
plus 120 seconds. Build and preparation commands have separate bounded
deadlines and private diagnostics.

The runner creates a dedicated directory with mode 0700 and writes files with
mode 0600. Children start through a fixed argument-preserving shell wrapper
with umask 077. Stdout and stderr are captured through pipes into private
files with a strict combined 4 MiB limit per command. A failed command, output
failure, output limit, timeout, or preparation error retains the bundle. A
process group receives a termination signal on every exit, including a
successful parent exit, and the direct child is reaped. Unix cleanup also
requires an observed group with no live members. On Linux, a zombie leader is
accepted only with exactly one remaining thread, because sibling threads can
outlive the leader. Darwin's zombie state describes process termination.
The fixed `/bin/ps` observer has a 1 MiB stdout limit, and observation,
reaping and pipe draining share the five-second cleanup budget. Missing,
failed or malformed observations and members that remain live cause a cleanup
failure. An uninterruptible or stopped process is not accepted as terminated.
The observer requires group/state fields and, on Linux, the `nlwp` thread count.
It runs only during cleanup, without collecting command lines or environment
values. The runner retains the existing trusted-host assumption
for its initial group signal; it is not a sandbox against malicious same-user
processes or processes deliberately escaping their group. An escaped process
holding a pipe is reported as a cleanup failure.

Normal output contains only classifications, target names, counts and bundle
identifiers. Without `--output`, successful smoke bundles are removed; failed
bundles remain in the host's canonical temporary directory under
`rustleaks-private-fuzz-IDENTIFIER`. Temporary storage can be removed by the
operating system. Select an explicit new directory outside the checkout to
retain successful corpus progress or keep evidence on durable local storage.
The parent directory must already exist. No bundle is uploaded or copied to a
public GitHub artifact. On an ephemeral hosted runner, local retention does
not establish durable private crash storage. Deep hosted campaigns still
require an explicitly reviewed secure retention design before expansion.

The current private runner supports Linux and macOS. Windows is explicitly
unsupported: Unix mode bits do not establish Windows ACL protection, and a
Windows process-tree/ACL implementation needs its own evidence. This does not
change the production target matrix.

Each private manifest records source revision and actual source-tree hash,
lock hashes, default-rule hash, compiler version and binary hash, cargo-fuzz
version, host, sanitizer, features, manifest/dictionary/seed identities,
explicit libFuzzer options and random seed, initial and final corpus hashes,
artifact hashes, bounded log hashes, and the termination classification.
The compiled target binary hash is recorded when available. Cache identity
includes the environment, target, corpus and limits. Replay rejects changed
source/rules/locks/toolchain/seeds/dictionaries before execution and records a
failure if its rebuilt binary differs. Commands are reconstructed from the
maintained target matrix; saved command strings are never executed. Matching
inputs and options establish a reproducible invocation, not a guarantee that
ASan failures or time-limited coverage evolution are deterministic.

The bundle records the normalized operation, target selection, profile source
and wrapper deadline before preparation begins. Child records distinguish the
requested supervisor maximum from the effective remaining timeout, separately
from libFuzzer's mutation-time limit, and flag deadline-constrained commands.
Explicit local deadlines, profile defaults and inherited remaining budgets are
labeled separately. Replay restores saved mutation limits under a fresh
invocation deadline; it never reuses elapsed wall-clock time from the source
bundle. Use `--deadline-seconds` to request a new replay wrapper limit.

The following macOS examples use a non-symlink temporary path. On Linux,
choose an existing absolute parent without symlink components. Retained
inputs, manifests and diagnostics must be inspected privately.

```sh
just fuzz run --output /private/tmp/rustleaks-fuzz-run
just fuzz replay /private/tmp/rustleaks-fuzz-run config --output /private/tmp/rustleaks-fuzz-replay
just fuzz minimize /private/tmp/rustleaks-fuzz-run config --output /private/tmp/rustleaks-fuzz-minimized
```

`replay` restores the original corpus and options from a run or prior campaign
replay. `minimize` accepts only a
successful run and performs bounded libFuzzer coverage merging (`-merge=1`)
into a new corpus. `reproduce BUNDLE TARGET ARTIFACT_SHA256 --output NEW_PATH`
replays a retained artifact once. `tmin` takes the same arguments and performs
bounded crash minimization (`-minimize_crash=1`). These operations retain their
own output; they do not modify the source bundle. A crash is still a failure
when reproduced successfully as a crash. Sanitizer output remains private.

To reuse progress, review the minimized corpus and its provenance privately,
then run `just fuzz promote BUNDLE TARGET --output NEW_PATH
--reviewed-sha256 HASH` with the exact `final_corpus.sha256` from that target's
manifest. This is the caller's assertion that content and provenance were
reviewed, not an automated safety audit or a cryptographic approval. Promotion
is refused in CI and writes only a new local reviewed corpus and receipt.
Import it with `just fuzz run --output NEW_PATH --corpus REVIEWED_PATH`.
Only its matching target receives the import; all targets retain the trusted
seed corpus. Unreviewed PR output must stay outside the reviewed store and
must never automatically generate a review receipt or share a writable cache
with trusted runs.

Imports reject symlinks in path components, hard links, subdirectories,
traversal, modified contents and stale provenance. Corpora and artifacts are
limited to 16,384 files and 64 MiB each, with each file bounded by the target's
input cap. Live size checks run every 100 milliseconds and again on exit;
they can overshoot between observations and are not a filesystem quota.
Remove obsolete local bundles only after reviewing their retained contents.
For a regression, reduce a crash to nonfunctional synthetic bytes, add an
ordinary deterministic Bazel test for the violated invariant, and complete
the normal review and validation gates. Local corpus promotion does not
authorize committing a crash input or publishing a vulnerability.

When a campaign fails, record the dated nightly, cargo-fuzz version, target,
features, seed, dictionary, and libFuzzer options. Reproduce and minimize the
failure, classify it, fix it, add a normal deterministic regression that also
runs through Bazel, and replay every committed corpus. Treat a failure that
cannot be reproduced as possible state leakage or nondeterminism.

## Dependency review

The cargo-vet policy accepts version-specific `safe-to-deploy` audit paths
imported from configured trusted peers by default, without a local re-audit or
separate approval for each selected record. Local source audits are required
only for packages or version deltas that remain uncovered. The configured
trusted peers are Bytecode Alliance, Google, ISRG, Mozilla, and Zcash. Adding,
removing, or changing a configured peer remains a reviewed policy change.
`supply-chain/imports.lock` retains only the audit records cargo-vet selects
from those sources for the locked graph. Publisher-wide trust and wildcard
audits are not accepted. This is a peer-first evidence policy. It is not a
local-first or local-only evidence policy.

`supply-chain/inventory-v1.json` mechanically reconciles every locked
third-party package with its local full audit, peer-imported audit, or exemption.
Its summary reports exact local-audit, peer-import-source, peer-covered-package,
exemption-record, and distinct exempted crate-name counts. Regenerate and check
it with:

```sh
cargo xtask generate vet-inventory
cargo xtask generate vet-inventory --check
```

Use a cargo-vet exemption only after configured peer evidence and a truthful
local review cannot establish the required criterion, and only with explicit
maintainer approval. An exemption must not cover a known concern reachable in
the maintained runtime graph. A target- or feature-scoped exemption may cover
a package-wide audit gap when the review establishes that the concern is
confined to code outside the maintained targets and selected features. The
cargo-vet exemption record remains package-level; its scope note documents the
project decision and does not narrow cargo-vet resolver semantics.

Every exemption records:

- an owner and the exact package version in the exemption record;
- the locked graph, target, feature, and consumer scope relevant to the
  decision;
- a factual rationale for the uncovered criterion and its reachability;
- a resolution condition, such as a fixed registry release or qualifying
  audit; and
- a review date, except for the standing decision below.

Reopen the decision when the package version or source, selected features,
supported targets, consumers, source distribution, or reachability changes, or
when new audit or advisory evidence appears. `just security` rejects a missing,
malformed, or expired review date for ordinary exemptions.

The approved standing exemption for `compcol 0.7.8` uses
`review-on=boundary-change` without a calendar expiry. It covers only the
reviewed registry source, exactly `alloc` and `rar2` in the workspace feature
union and Bazel resolution, and the eight maintained 64-bit targets. The vet
gate enforces those boundaries and excludes the dependency from every core
feature selection. Existing package and release-archive checks constrain
distribution: the published core package excludes compcol, and binary release
archives contain only the executable, README, LICENSE, and NOTICE. The
decision does not cover redistribution of unselected codec sources. Any scope
change requires re-review; calendar renewal alone is unnecessary. No other
undated exemption is accepted.

A vet exemption provides policy coverage, not an audit, and must not be used
to lower the required criterion. Replace exemptions
with minimized peer-imported audits where available and local audits only for
the remaining gaps. Adding or changing an imported peer remains an explicit
maintainer trust decision. Completed package worksheets are under
`docs/dependency-audits/`.

The exact normal dependency graph, direct build scripts, native code, and safe
API reasoning are documented in [`DEPENDENCY_SAFETY.md`](DEPENDENCY_SAFETY.md)
and [`DEPENDENCIES.md`](DEPENDENCIES.md). `cargo-geiger` is used only as a
dependency-delta inventory. Its common unsafe-bearing package set and reviewed
target-specific additions are enforced by `xtask`; it is not a security
conclusion.

The committed public API snapshot is the exact workspace baseline. For every
release candidate, maintainers must run `cargo-semver-checks` for each public
crate and supported feature profile against the latest published release when
one exists, then perform manual API review. Before the first publication, the
snapshot provides the only release baseline; afterward it does not replace the
comparison with the registry version.

## Repository self-scan

Scan the worktree and Git history with Rustleaks before release. The root
`.rustleaks.toml` extends the pinned default rules and prunes only generated
compatibility corpora, the two generated API traceability indexes, copied
compatibility fixtures, Git metadata, and local build output. The root
`.rustleaksignore` lists reviewed fingerprints for individual synthetic
examples and generated hashes.
GitHub secret scanning excludes only the generated compatibility corpora,
copied fixtures, and the accepted pinned default configuration listed in
`.github/secret_scanning.yml`. Repository validation requires that exact list;
generator source, examples, and ordinary documentation remain scanned.
Do not broaden the path exceptions or add a fingerprint without inspecting the
redacted rule, path, line, and source context. The maintained local commands
are:

```sh
bazelisk build //crates/rustleaks-cli:rustleaks
bazel-bin/crates/rustleaks-cli/rustleaks dir . --redact --no-banner --timeout=300
bazel-bin/crates/rustleaks-cli/rustleaks git . --redact --no-banner --timeout=600
```

A reported value must not be copied into an issue, log, or commit message.
Triage it privately, determine whether it is synthetic or live, revoke it if
needed, and follow [`INCIDENT_RESPONSE.md`](INCIDENT_RESPONSE.md).

## Hosted automation cadence

Hosted workflows must translate the following exact local boundaries into secretless,
least-privilege jobs. It must pin actions to reviewed full commit SHAs and must
not execute untrusted pull request code from `pull_request_target`,
`workflow_run`, or a privileged release context.

| Cadence | Required work |
| --- | --- |
| Pull request | `just ci`, `just fuzz-build`, `just fuzz-smoke`, cargo-deny, locked cargo-vet, dependency review on graph changes, current stable and MSRV, and the matching native platform slice. Keep RustSec freshness in a network-enabled secretless job. `just ci` includes committed parity. |
| Nightly | Longer high-risk fuzz campaigns, increased property cases, frozen-evidence integrity and Rust regression replay, fresh RustSec, newest-allowed dependency resolution in a noncommitting checkout, and repository self-scan. |
| Weekly | Scheduled CI supplies pinned Miri, unsafe inventory, cargo-vet, RustSec, and all available native target lanes. The weekly fuzz job raises execution/time budgets while retaining smoke input/harness caps; it does not run the optional deep profile. Its separate Bazel coverage review measures ordinary tests, not fuzz source coverage. CodeQL and OpenSSF Scorecard remain independently scheduled. |
| Release candidate | A secretless manual dry run bound to the exact current `main` commit and version; parallel `just ci`, complete Rust qualification, `just security`, extended AddressSanitizer fuzzing, and worktree and history scans; package, external-consumer, docs.rs, and no-upload checks; and twice-built native artifacts with byte comparison, checksums, target SBOMs reconciled with the Bazel graph, provenance, and attestations. |

The protected publication workflow accepts only a current `main` commit, a
matching version, and a successful retained release dry run. It compares the
source package byte for byte before requesting a crates.io OIDC token. No
long-lived registry token belongs in GitHub Actions or local release
configuration.

Rustleaks does not currently apply to OSS-Fuzz. OSS-Fuzz accepts established
projects based in part on remote attack exposure and the number of users or
dependent projects. Rustleaks processes untrusted input but, as an initial
alpha release, does not yet have evidence that it meets the established-project
criterion. Continue the maintained scheduled fuzzing and reassess eligibility
after adoption evidence exists. Submitting to OSS-Fuzz remains a separately
approved external action. Until then, scheduled CI runs the maintained fuzz
targets.

## Protected files

Hosted ownership and required-check rules must cover changes to at least:

- `.github/workflows/`, release configuration, and `CODEOWNERS`;
- `Cargo.toml`, `Cargo.lock`, every crate manifest, `rust-toolchain.toml`, and
  all fuzz manifests;
- `MODULE.bazel`, `MODULE.bazel.lock`, `cargo-bazel-lock.json`, `.bazelrc`,
  every `BUILD.bazel`, `justfile`, and `crates/xtask/`;
- `deny.toml`, `supply-chain-exceptions.toml`, and `supply-chain/`;
- `SECURITY.md`, this control file, the threat model, incident procedure,
  `.rustleaks.toml`, `.rustleaksignore`, dependency policy, resource limits,
  compatibility profile, public API
  snapshots, corpora, generators, and fixture inventories; and
- package, release, checksum, SBOM, provenance, and attestation inputs.

An eligible independent approval is required only when the live ruleset or the
maintainer explicitly requires one. A sole-maintainer ruleset may omit a
mandatory approving review because GitHub does not allow authors to approve
their own pull requests. The complete branch diff, required checks, unresolved
conversations, mergeability, and boundary-specific evidence remain mandatory;
repository-owner bypass is not a substitute for any of them.

GitHub secret scanning, push protection, private vulnerability reporting,
branch protection, protected release environments, trusted publishing, and
artifact attestations are external settings. Their absence is a release
blocker, not something a local check can silently waive.

## Optional local deep profile

`just security-deep` is an on-demand local review; it is not part of release
qualification, pull-request CI, or a hosted schedule. It retains its report
and private evidence on both success and failure. Run from the repository root:

```sh
just security-deep --output /private/tmp/rustleaks-deep-review
just security-deep --output /private/tmp/rustleaks-deep-short --seconds 60 --deadline-seconds 1800
just security-deep --output /private/tmp/rustleaks-deep-comparison --baseline /private/tmp/rustleaks-deep-review/dependency-snapshot.json
```

The initial operating policy permits at most two hours for the entire pass and
one active campaign at a time. `--deadline-seconds` can reduce that bound;
`--seconds` selects 1 through 600 seconds per target. Source/tool identity,
security checks, build preparation, structured tests, Miri, campaign execution
and coverage collection share the deadline. Each child receives the remaining
budget, followed by a shared five-second process and pipe cleanup budget. Pending requested
stages become explicitly skipped when time expires, and the overall pass is
incomplete. An ordinary successful smoke bundle is still removed; a deep report
is retained even when its output directory was selected automatically.

The pass runs the unchanged `security-check`, captures dependency comparison
evidence, builds the three `security_stress_test` targets through Bazel, and
executes their ignored `security_stress_driver` tests directly. It additionally
runs the existing nested-decoder range-mapping and canonical session-ordering
unit cases under the pinned Miri toolchain. Miri evidence covers those executed
paths only. Fuzz targets then run serially through the same private runner used
by smoke, followed by optional corpus coverage.

| Campaign profile | Mutation runs | Per-target seconds | Input and harness policy |
| --- | ---: | ---: | --- |
| `smoke` | 16 | 20 | Existing 4 through 16 KiB target caps and harness budgets |
| `extended` | 1,000,000 | 120 | Existing smoke input and harness caps; more mutation opportunity |
| `deep` | 1,000,000 | 600 | 64 KiB target inputs and explicitly enlarged test-only harness budgets |

Either the run count or time can stop a campaign. Corpus initialization may
execute more units than the requested mutation count. The deep operator defaults
to `deep`; `--profile` can select any row, and `--targets config,archive` can
select a subset. All eight targets retain a pass/fail/skipped record, including
those not selected. Direct `just fuzz run` accepts the same profile and target
selection plus bounded `--runs`, `--seed`, `--seconds`, and
`--deadline-seconds` controls. Omitting these options preserves the ordinary
smoke environment overrides and defaults.

The versioned profile record includes input, per-input timeout, RSS, archive
member/total/spool/entry/depth, decoded-byte/work/finding, and template limits.
Deep archives use 64 KiB input/spool, 1 MiB members, 4 MiB total expansion and
256 entries. Every deep target receives a generated synthetic seed larger than
its smoke input cap; seed and corpus hashes bind the actual bytes. Additional
structured tests exercise larger archives, nested decoding, match counts,
configuration selection and template limits. These test results are reported
separately from fuzz coverage. The [structured test map](SECURITY_STRESS.md)
documents their exact cases and limits. Production limits and default behavior
do not change.

ASan campaign children retain the 2 GiB RSS limit and five-second per-input
limit. Combined stdout/stderr remains capped at 4 MiB per child. Trusted compiler,
Bazel, dependency-policy and Miri processes receive time and output bounds, not
a whole-pass memory quota. Bazel preparation uses batch mode, and the produced
stress test binaries run directly under bounded process-group handling. The
existing limitation for deliberately escaped process groups remains; the local
operator is not an operating-system sandbox. It clears ambient environment
values except the existing path/home/toolchain-location allowlist, then sets
only the required workspace, profile and target-directory values. It does not
require the retired Go oracle or change a toolchain.

### Comparison and coverage evidence

`dependency-snapshot.json` binds source/tool identity, all workspace and fuzz
locks, the selected host's all-features Cargo graph, declared compile targets,
vet inventory and policy hashes, the observed dependency unsafe inventory, and
the default RustSec database revision after the security gate. Cargo feature
resolution and Bazel lock identities are separately labeled; neither proves
native support on unexecuted targets. Path-owned package identifiers are
normalized for comparisons between checkouts.

`--baseline` selects prior comparison evidence. Without it, the report says
`unreviewed-initial`. Changed components and added/removed/changed dependency
records remain `unreviewed-delta`; matching records are comparison-only. A
snapshot, successful gate or unchanged unsafe count does not constitute a new
dependency audit or approve an exception. The command never rewrites a baseline
or accepts a dependency change automatically.

Each campaign records numeric libFuzzer edge/feature/execution feedback, corpus
growth, artifact count and exit/timeout/OOM classification without copying
payloads into the report. These feedback counters are not source line coverage.
`--coverage auto` additionally attempts source coverage only when matching
`llvm-cov` and `llvm-profdata` are already installed with the pinned nightly.
Missing matching tools produce an explicit capability skip; `--coverage required`
makes that condition fail, and `--coverage off` records an operator-selected
skip. No tool or component is installed automatically, and failed or timed-out
coverage is never a pass.

Source coverage uses a private bounded source copy and the first 128 final
corpus inputs in deterministic hash order. Reports include the number omitted,
compiler/tool/binary/input identities and LLVM totals; detailed per-file and
codec source records remain private. Its instrumentation disables the sanitizer
and is separate from the ASan campaign. Raw coverage output is monitored against
512 MiB and 16,384 files; checks can overshoot between observations and are not
a disk quota. Build caches remain outside that output budget. The procedure
follows the Rust Fuzz Book's [corpus coverage workflow](https://rust-fuzz.github.io/book/cargo-fuzz/coverage.html),
which measures the corpus supplied to the instrumented binary.

| Threat boundary | Entry point and synthetic larger-input evidence | Recorded invariant |
| --- | --- | --- |
| Rules/configuration | `go_regex`, `config`; shared deep seeds and core stress driver | Bounded parse/compile outcome and selected-rule limits |
| Engine/decoders/session | `fragment_scan`, `session`; larger bytes, nested decodes and finding-budget cases | Deterministic outcomes, measured usage and explicit partial termination |
| Archives | `archive`; framed larger member and source stress driver | Actual member consumption, nesting/entry/aggregate boundaries and structured issues |
| Readers/Git | `reader_schedule`, `git_patch`; larger schedules and structured patches | Bounded consumption, parser results and preserved byte accounting |
| Templates | `template`; larger source and report stress driver | Source/action/output limits and complete or structured failed rendering |

An initial monthly manual run and runs after boundary changes are useful
operating proposals. Hosted scheduling and artifact transport require a separate
reviewed private-retention design. Review and minimize any local failure before
turning it into a synthetic ordinary regression; this command grants no public
artifact or disclosure approval.

The [native acceptance record](validation/deep-and-profiling.md) documents the
validated local run, its explicit source-coverage skips and the retained
deadline/corpus evidence. It does not qualify a hosted retention design.

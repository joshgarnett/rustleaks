# Security checks

This page is for maintainers. It describes the local security checks, fuzzing,
the larger structured tests, dependency review, the repository self-scan, the
hosted schedule and the protected files. Run every command from the
repository root with the committed lockfiles unchanged.

## Local commands

| Command | What it does |
| --- | --- |
| `just security` | Runs cargo-deny, a fresh RustSec audit, locked cargo-vet policy, exact dependency graphs, the first-party unsafe policy, the cargo-geiger inventory, pinned Miri and the `panic=abort` archive check |
| `just fuzz-build` | Builds all eight cargo-fuzz targets from their locked manifests |
| `just fuzz-smoke` | Runs short AddressSanitizer campaigns on copies of the reviewed seeds |
| `just fuzz` | Runs private local fuzz campaigns and corpus operations (Unix) |
| `just security-deep` | Runs the optional deep security profile (Unix) |
| `just parity` | Replays the committed compatibility corpus |
| `just ci` | Runs format, lint, docs, build, the eight-target compile check and all tests. It does not run the security, fuzz, package or release checks |
| `just package-check` | Builds the extracted package and clean external Cargo and Bazel consumers |
| `just release-dry-run` | Runs the package checks and Cargo's locked publish check without upload |

`just security` needs these exact host tools:

- `cargo-audit 0.22.2`, which reports its version as `cargo-audit-audit 0.22.2`
- `cargo-deny 0.19.9`
- `cargo-geiger 0.13.0`
- `cargo-vet 0.10.2`
- Miri from `nightly-2026-08-21`

The fuzz commands need `cargo-fuzz 0.13.2`. The normal Rust toolchain is
pinned in `rust-toolchain.toml`, and the MSRV is Rust 1.95. The security check
fails when a tool version differs.

The RustSec check updates its advisory database, so it needs the network.
All other dependency decisions are bound to `Cargo.lock`.

## Fuzzing

| Workspace | Target | Main boundary |
| --- | --- | --- |
| `rustleaks-core/fuzz` | `config` | TOML, rule extension, allowlists, composite rules, size and reload checks |
| `rustleaks-core/fuzz` | `go_regex` | Go translation, compiling, captures, empty matches, invalid bytes, repeated matching |
| `rustleaks-core/fuzz` | `fragment_scan` | Decoders, locations, arbitrary bytes, overlaps, redaction, limits, repeat scans |
| `rustleaks-core/fuzz` | `session` | Sorting, deduplication, baselines, ignores and session state |
| `rustleaks-sources/fuzz` | `archive` | Archive formats, traversal, links, expansion, entry counts and nesting |
| `rustleaks-sources/fuzz` | `reader_schedule` | Chunking, short reads, errors, cancellation and scheduling |
| `rustleaks-sources/fuzz` | `git_patch` | Patch parsing, quoting, renames, copies, binary changes, submodules, numbers and line endings |
| `rustleaks-report/fuzz` | `template` | Template parsing, evaluation, escaping, output limits and repeat rendering |

The default cargo-fuzz Clang setup provides AddressSanitizer on the verified
Apple Silicon macOS host. The targets are designed for x86-64 and ARM64
Unix-like hosts. A hosted job must verify each scheduled host before claiming
support. MemorySanitizer and ThreadSanitizer have no supported lane; record
them as unsupported unless a reproducible pinned lane exists.

For a longer local run, keep the corpus, dictionary, maximum input length,
timeout, RSS limit and artifact privacy of `fuzz-smoke`, and raise `-runs` or
`-max_total_time`. Never use environment credentials, developer files,
private repositories or live tokens as seeds.

When a campaign fails, record the nightly date, cargo-fuzz version, target,
features, seed, dictionary and libFuzzer options. Reproduce and minimize the
failure, classify it, fix it, add a deterministic regression test that runs
in Bazel, and replay every committed corpus. Treat a failure that cannot be
reproduced as possible state leakage or nondeterminism.

### Private local fuzz evidence

`just fuzz-smoke` runs all eight targets with these defaults: 16 runs, 20
seconds per target, five seconds per input, 2,048 MiB RSS, and input limits of
4 to 16 KiB. `RUSTLEAKS_FUZZ_RUNS` (at most 1,000,000) and
`RUSTLEAKS_FUZZ_MAX_TOTAL_TIME` (at most 600) raise the run count and time.
`RUSTLEAKS_FUZZ_SEED` sets a nonzero 32-bit seed; the default is 1. Each
target also has an outer deadline of its time budget plus 120 seconds.

Output privacy:

- The runner creates a folder with mode 0700 and writes files with mode 0600.
  Children start through a fixed shell wrapper with umask 077.
- Standard output and error go to private files, at most 4 MiB per command.
- A failure, an output limit, a timeout or a preparation error keeps the
  bundle. Without `--output`, a successful smoke bundle is deleted, and a
  failed bundle stays in the temporary folder as
  `rustleaks-private-fuzz-IDENTIFIER`.
- To keep successful corpus progress, pass a new folder outside the checkout
  whose parent exists.
- Normal output shows only classifications, target names, counts and bundle
  IDs. No bundle is uploaded or copied to a public artifact. A hosted runner's
  local storage is not durable private crash storage.

The runner supports Linux and macOS. Windows is not supported, because Unix
mode bits do not set Windows ACLs.

Each private manifest records:

- the source revision and tree hash, lock hashes and default rule hash;
- the compiler version and binary hash, cargo-fuzz version, host, sanitizer
  and features;
- the manifest, dictionary and seed identities, libFuzzer options and random
  seed; and
- corpus hashes before and after, artifact hashes, bounded log hashes and the
  result.

Replay rejects changed source,
rules, locks, toolchain, seeds or dictionaries before it runs, and records a
failure if the rebuilt binary differs. Commands are rebuilt from the target
matrix; saved command strings are never run. Matching inputs give a
reproducible invocation, but AddressSanitizer failures and time-limited
coverage growth can still differ between runs.

Replay restores saved mutation limits under a new deadline. It never reuses
elapsed time from the source bundle. `--deadline-seconds` sets a new replay
limit.

Output and input paths must not contain a symbolic link in any part of the
path. A link could send private output to another place. The examples use
`/private/tmp` on macOS, because `/tmp` is a link there. On Linux, choose an
existing absolute parent folder without links.

```sh
just fuzz run --output /private/tmp/rustleaks-fuzz-run
just fuzz replay /private/tmp/rustleaks-fuzz-run config --output /private/tmp/rustleaks-fuzz-replay
just fuzz minimize /private/tmp/rustleaks-fuzz-run config --output /private/tmp/rustleaks-fuzz-minimized
```

- `replay` restores the original corpus and options from a run or a replay.
- `minimize` accepts only a successful run and merges coverage (`-merge=1`)
  into a new corpus.
- `reproduce BUNDLE TARGET ARTIFACT_SHA256 --output NEW_PATH` replays one
  kept artifact once.
- `tmin` takes the same arguments and minimizes a crash
  (`-minimize_crash=1`).

These operations write their own output and never change the source bundle.
A crash that reproduces is still a failure. Sanitizer output stays private.

To reuse progress, review the minimized corpus and its provenance privately,
then promote it:

```sh
just fuzz promote BUNDLE TARGET --output NEW_PATH --reviewed-sha256 HASH
just fuzz run --output NEW_PATH --corpus REVIEWED_PATH
```

`HASH` is the exact `final_corpus.sha256` from that target's manifest.
Promotion is the caller's statement that the content was reviewed. It is not
an automatic audit. Promotion is refused in CI. Only the matching target gets
the imported corpus; every target keeps the trusted seeds. Unreviewed pull
request output must stay out of the reviewed store. It must never create a
review receipt automatically or share a writable cache with trusted runs.

Imports reject symbolic links in the path, hard links, subfolders, traversal,
changed content and stale provenance. Corpora and artifacts are limited to
16,384 files and 64 MiB each, and each file to the target's input limit. Size
checks run every 100 milliseconds and at exit; they can overshoot between
checks and are not a file system quota.

Delete old local bundles only after you review what they contain.

For a regression, reduce the crash to synthetic bytes, add a deterministic
Bazel test for the broken rule, and pass the normal review and checks.
Promoting a corpus does not authorize committing a crash input or publishing
a vulnerability.

### Process cleanup

The fuzz, security and performance tools run children in process groups on
Unix. Every exit, including success, sends the group a termination signal and
reaps the direct child.

- Reaping, observing process state and draining pipes share a five-second
  cleanup budget.
- The observer runs the fixed `/bin/ps` with at most 1 MiB of output. It
  reads only group IDs, states and, on Linux, the `nlwp` thread count. It
  never collects command lines or environment values.
- Cleanup fails unless every visible group member has stopped. On Linux, a
  zombie group leader is accepted only with exactly one thread left; on
  Darwin, the zombie state means the process ended. Live, stopped and
  uninterruptible processes do not count as ended. Orphan zombies can remain
  until the host reaps them.
- A process that escapes its group and holds a pipe is reported as a cleanup
  failure.

This is supervised cleanup on a trusted host. It is not a sandbox against
malicious processes of the same user.

## Deep security profile

`just security-deep` is an optional local review. It is not part of release
qualification, pull request CI or a hosted schedule. It keeps its report and
private evidence on success and failure.

```sh
just security-deep --output /private/tmp/rustleaks-deep-review
just security-deep --output /private/tmp/rustleaks-deep-short --seconds 60 --deadline-seconds 1800
just security-deep --output /private/tmp/rustleaks-deep-comparison --baseline /private/tmp/rustleaks-deep-review/dependency-snapshot.json
```

The whole pass has at most two hours and runs one campaign at a time.
`--deadline-seconds` can lower that limit, and `--seconds` sets 1 to 600
seconds per target. Each child gets the remaining time plus a shared
five-second cleanup budget. When time runs out, the remaining stages are
marked skipped and the pass is incomplete.

The pass:

1. runs `security-check` unchanged;
2. records dependency comparison evidence;
3. builds the three `security_stress_test` targets and runs their ignored
   `security_stress_driver` tests;
4. runs the nested-decoder range mapping and session ordering unit tests
   under the pinned Miri, which covers only those paths;
5. runs the fuzz targets one after another through the private runner; and
6. optionally measures corpus coverage.

| Profile | Mutation runs | Seconds per target | Input and harness limits |
| --- | ---: | ---: | --- |
| `smoke` | 16 | 20 | 4 to 16 KiB inputs and normal harness budgets |
| `extended` | 1,000,000 | 120 | Same limits as smoke |
| `deep` | 1,000,000 | 600 | 64 KiB inputs and larger test-only harness budgets |

A campaign stops at its run count or its time. Setting up the corpus can
run more units than the requested count. The deep command defaults to
`deep`; `--profile` selects another row and `--targets config,archive`
selects a subset. Every target gets a pass, fail or skipped record. `just
fuzz run` accepts the same profile and target options, plus `--runs`,
`--seed`, `--seconds` and `--deadline-seconds`.

Deep archives use 64 KiB input and spool, 1 MiB members, 4 MiB total
expansion and 256 entries. Each deep target gets a generated synthetic seed
larger than its smoke input limit. Production limits and defaults do not
change.

Fuzz children keep the 2 GiB RSS limit, the five-second input limit and 4 MiB
of output each. Compiler, Bazel, dependency policy and Miri processes have
time and output limits, but no memory limit for the whole pass. The command
clears the environment except for path, home and toolchain location values,
then sets only the workspace, profile and target folder values. It is not an
operating system sandbox.

### Comparison and coverage

`dependency-snapshot.json` binds the source and tool identity, all workspace
and fuzz locks, the host's all-features Cargo graph, declared compile
targets, vet inventory and policy hashes, the observed dependency unsafe
inventory and the RustSec database revision. Neither the Cargo feature
resolution nor the Bazel lock proves support on targets that did not run.

Without `--baseline`, the report says `unreviewed-initial`. With it, changed
components and dependency records are `unreviewed-delta`. A snapshot, a
passing check or an unchanged unsafe count is not a dependency audit and
does not approve an exception. The command never rewrites a baseline.

Each campaign records libFuzzer edge, feature and execution counts, corpus
growth, artifact count and the exit, timeout or out-of-memory result, without
payloads. These counts are not source coverage. `--coverage auto` measures
source coverage only when matching `llvm-cov` and `llvm-profdata` are already
installed with the pinned nightly. Without them, `auto` records an explicit
skip for the missing tool. `--coverage required` fails without them.
`--coverage off` records a skip chosen by the operator. Nothing is installed
automatically. Failed or timed-out coverage is never a pass.

Source coverage uses a private copy of the source and the first 128 final
corpus inputs in hash order. The report gives the number of inputs left out,
tool and binary identities and LLVM totals. Records for each file stay
private. Its build turns off the sanitizer. Raw coverage output is checked
against 512 MiB and 16,384 files. The method follows the
Rust Fuzz Book's
[corpus coverage workflow](https://rust-fuzz.github.io/book/cargo-fuzz/coverage.html).

Review and minimize any local failure before you turn it into a synthetic
regression test. This command grants no public artifact or disclosure
approval. A monthly manual run and a run after each boundary change are
useful. Hosted scheduling needs a separate reviewed design for private
storage.

## Larger structured tests

Each `security_stress_test` target in core, sources and reports has small
ordinary tests and an ignored `security_stress_driver`. The deep profile runs
the drivers; ordinary tests do not. Driver output holds case IDs, counts and
classifications, never raw findings. A failed driver is a failed stage. The
person who runs the drivers sets the outer time limit; cancellation inside a
controlled scan stays cooperative.

LibFuzzer edge and feature counts are feedback, not source coverage. Source
coverage needs the matching LLVM tools and a coverage replay. Ordinary Bazel
tests do not replace source coverage.

The shared limits and larger seeds are in
`crates/rustleaks-core/tests/support/campaign_profile.rs`, outside the
library. `RUSTLEAKS_FUZZ_PROFILE=deep` selects the deep harness profile; the
private runner sets and records it. Unknown profiles fail at startup.

| Boundary | Case | What it shows | Limit of the claim |
| --- | --- | --- | --- |
| Regex and fragment input | Match suffix beyond the old input limit | Exact end span on full input; truncated smoke input has no match | No new Go parity claim |
| Configuration | Rule after an 8 KiB comment; selected rule and source byte limits | Rule kept; limits accepted at the value and rejected one above | Selection limits do not bound every configuration allocation |
| Nested decoding | Three encoded layers in a controlled scan | Complete at the measured decoded-byte budget; one less gives a structured partial result | Not full decoder coverage |
| Many findings | Controlled scan with 8,192 occurrences | Exact count at the finding limit; one less rolls back the rule | Operation budgets across fragments are not covered |
| Session metadata | Large finding and baseline classification | Metadata length kept and baseline suppression works | Not every session state |
| Archive input | 32 KiB stored member | Whole member emitted and compared | Stored TAR only |
| Archive expansion and nesting | Zlib member, nested TAR, many entries, total size | Member, depth, entry and total limits with structured issues | No claim for other codecs |
| Reader scheduling | 8,192 scheduled reads | Exact read, payload and emitted byte counts | Arbitrary chunk equivalence is not assumed |
| Git parser | 512 added lines beyond 16 KiB | Larger input and a fixed parser result | No per-line counter or source coverage claim |
| Templates | Large literal source, 16 findings, repeated actions | Exact source, action and output limits with structured errors | Safe template profile only |

All inputs are fixed synthetic values. Source cases stay below 6 MiB, with at
most 4 MiB of emitted archive bytes. The deep member limit is 1 MiB, depth 4
and 256 entries.

| Threat boundary | Entry points | Recorded result |
| --- | --- | --- |
| Rules and configuration | `go_regex`, `config`, deep seeds, core stress driver | Bounded parse and compile, selected rule limits |
| Engine, decoders and sessions | `fragment_scan`, `session`, larger inputs and finding budgets | Fixed outcomes, measured usage, explicit partial result |
| Archives | `archive`, larger members, source stress driver | Member use, nesting, entry and total limits, structured issues |
| Readers and Git | `reader_schedule`, `git_patch`, larger schedules and patches | Bounded reads, parser results, byte accounting |
| Templates | `template`, report stress driver | Source, action and output limits, complete or structured failure |

## Dependency review

cargo-vet accepts `safe-to-deploy` audits for exact versions imported from
trusted peers: Bytecode Alliance, Google, ISRG, Mozilla and Zcash. No local
re-audit or separate approval is needed for each imported record. Local audits
are needed only for packages or version changes that remain uncovered.
Changing the peer list is a reviewed policy change. `supply-chain/imports.lock`
keeps only the records cargo-vet selects for the locked graph.
Publisher-wide trust and wildcard audits are not accepted.

`supply-chain/inventory-v1.json` maps every locked third-party package to its
local audit, peer audit or exemption, and reports the counts. Regenerate and
check it with:

```sh
cargo xtask generate vet-inventory
cargo xtask generate vet-inventory --check
```

### Exemptions

Use a cargo-vet exemption only when peer evidence and an honest local review
cannot establish the criterion, and only with maintainer approval. An
exemption must not cover a known concern that the maintained runtime graph
can reach. An exemption scoped to targets or features may cover a gap in a
package-wide audit when the review shows that the concern is only in code
outside the maintained targets and features. The cargo-vet record stays
package-wide; its scope note records the project decision.

Every exemption records:

- an owner and the exact package version;
- the locked graph, target, feature and consumer scope of the decision;
- a factual reason for the missing criterion and its reachability;
- a condition for removing it, such as a fixed release or an audit; and
- a review date, except for the standing decision below.

Reopen the decision when the package version or source, features, targets,
consumers, source distribution or reachability change, or when new audit or
advisory evidence appears. `just security` rejects a missing, malformed or
expired review date on an ordinary exemption.

The standing exemption for `compcol 0.7.8` uses `review-on=boundary-change`
and has no calendar expiry. It covers only the reviewed registry source, the
`alloc` and `rar2` features in the workspace feature union and Bazel
resolution, and the eight maintained 64-bit targets. The vet check enforces
these limits and keeps the crate out of every core feature selection. The
published core package excludes `compcol`, and binary release archives
contain only the executable, README, LICENSE and NOTICE. The decision does
not cover redistribution of unselected codec sources. Any scope change needs
a new review. No other exemption without a date is accepted.

An exemption is policy coverage, not an audit, and must not lower the
required criterion. Replace exemptions with peer audits where available, and
with local audits for the rest. Completed worksheets are in
[`docs/dependency-audits/`](../dependency-audits/).

cargo-geiger is only an inventory of dependency changes. Its expected unsafe
package set is enforced by `xtask`; it is not a security conclusion. See
[Dependencies](dependencies.md).

### Public API

The committed public API snapshot is the exact workspace baseline. For every
release candidate, run `cargo-semver-checks` for each public crate and feature
profile against the latest published release, then review the API by hand.
Before the first publication, the snapshot is the only baseline.

## Repository self-scan

Scan the worktree and Git history with Rustleaks before a release. Pull
requests run the worktree scan, and the nightly workflow runs both scans.

- The root `.rustleaks.toml` extends the default rules and skips only
  generated compatibility corpora, the two generated API traceability
  indexes, copied fixtures, the native rule pack test fixtures, Git
  metadata and build output. In the providers pack provenance record and
  the native coverage review record it allows only Git revision lines, and
  in the release license index only SHA-256 hash lines. A directory scan
  skips every file that matches an allowlist path, so only the Git history
  scan applies these line rules.
- The root `.rustleaksignore` lists reviewed fingerprints of synthetic
  examples and generated hashes. A worktree fingerprint includes the line
  number, so update it when an edit moves the reviewed line.
- GitHub secret scanning skips only the generated corpora, copied fixtures and
  the pinned default configuration listed in `.github/secret_scanning.yml`.
  Repository checks require that exact list. Generator source, examples and
  documentation are scanned.

Do not widen the path exceptions or add a fingerprint without reading the
redacted rule, path, line and context.

```sh
bazelisk build //crates/rustleaks-cli:rustleaks
bazel-bin/crates/rustleaks-cli/rustleaks dir . --redact --no-banner --timeout=300
bazel-bin/crates/rustleaks-cli/rustleaks git . --redact --no-banner --timeout=600
```

Never copy a reported value into an issue, log or commit message. Triage it
privately, find out whether it is synthetic or live, revoke it if needed, and
follow the [incident response](incident-response.md) procedure.

## Hosted schedule

Hosted workflows turn these local checks into jobs without secrets and with
the least privilege. Actions are pinned to reviewed full commit SHAs.
Untrusted pull request code never runs from `pull_request_target`,
`workflow_run` or a privileged release context.

| When | Work |
| --- | --- |
| Pull request | `just ci`, the worktree self-scan, `just fuzz-build`, `just fuzz-smoke`, cargo-deny, locked cargo-vet, dependency review on graph changes, current stable and MSRV, and the native platform lanes. RustSec runs in a separate job with network access and no secrets |
| Nightly | Longer fuzz campaigns, more property cases, frozen evidence and Rust replay, fresh RustSec, newest allowed dependency resolution in a checkout that is not committed, and the repository self-scan |
| Weekly | Pinned Miri, unsafe inventory, cargo-vet, RustSec and all native target lanes. The weekly fuzz job raises run and time budgets but keeps the smoke input limits; it does not run the deep profile. A Bazel coverage review measures ordinary tests, not fuzz coverage. CodeQL and OpenSSF Scorecard run on their own schedules |
| Release candidate | A manual dry run without secrets for the exact `main` commit and version. See [Releasing](releasing.md) |

The protected publication workflow accepts only a current `main` commit, a
matching version and a successful kept dry run. It compares the source
package byte for byte before it requests a crates.io OIDC token. No
long-lived registry token belongs in GitHub Actions or local configuration.

Rustleaks does not apply to OSS-Fuzz yet. OSS-Fuzz accepts established
projects, based partly on attack exposure and the number of users. Reassess
after there is evidence of adoption. Applying is a separately approved
external action. Until then, scheduled CI runs the fuzz targets.

## Protected files

Repository ownership and required checks must cover changes to at least
these files:

- Automation: `.github/workflows/`, release configuration and `CODEOWNERS`.
- Cargo: `Cargo.toml`, `Cargo.lock`, every crate manifest,
  `rust-toolchain.toml` and all fuzz manifests.
- Bazel and tools: `MODULE.bazel`, `MODULE.bazel.lock`,
  `cargo-bazel-lock.json`, `.bazelrc`, every `BUILD.bazel`, `justfile` and
  `crates/xtask/`.
- Dependency policy: `deny.toml`, `supply-chain-exceptions.toml` and
  `supply-chain/`.
- Security documents: `SECURITY.md`, this page, the threat model, the
  incident procedure and the dependency policy.
- Scanning policy: `.rustleaks.toml`, `.rustleaksignore`, the resource
  limits and the compatibility policy.
- Evidence: public API snapshots, corpora, generators and fixture
  inventories.
- Release inputs: package, release, checksum, SBOM, provenance and
  attestation inputs.

An independent approving review is required only when the live ruleset or
the maintainer asks for one. GitHub does not let authors approve their own
pull requests, so a ruleset for a sole maintainer may leave out a required
approval. The full branch diff, required checks, open conversations,
mergeability and boundary evidence are still required. An owner bypass does
not replace any of them.

GitHub secret scanning, push protection, private vulnerability reporting,
branch protection, protected release environments, trusted publishing and
artifact attestations are external settings. If one is missing, that blocks a
release; a local check cannot waive it.

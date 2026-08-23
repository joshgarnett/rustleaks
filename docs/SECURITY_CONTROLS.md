# Security controls

This file is the operator contract for local security checks and hosted
automation. Run commands from the repository root with the checked-in
lockfiles unchanged.

## Local commands

| Command | Purpose |
| --- | --- |
| `just security` | Run cargo-deny, a fresh RustSec audit, locked cargo-vet policy, exact dependency graphs, first-party unsafe policy, cargo-geiger inventory, pinned Miri, and the `panic=abort` archive policy check. |
| `just fuzz-build` | Compile all eight cargo-fuzz targets from their locked standalone manifests. |
| `just fuzz-smoke` | Copy reviewed seeds to temporary corpora and run bounded 16-run AddressSanitizer smoke campaigns with format dictionaries, timeouts, length caps, RSS caps, and private temporary artifact paths. The target invariants are deterministic even though libFuzzer may choose a random mutation seed. |
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
toolchain is pinned in `rust-toolchain.toml`; the declared MSRV is Rust 1.85.
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

When a campaign fails, record the dated nightly, cargo-fuzz version, target,
features, seed, dictionary, and libFuzzer options. Reproduce and minimize the
failure, classify it, fix it, add a normal deterministic regression that also
runs through Bazel, and replay every committed corpus. Treat a failure that
cannot be reproduced as possible state leakage or nondeterminism.

## Dependency review

The cargo-vet policy is self-contained and imports no third-party trust. Its
initial graph uses 63 bootstrap exemptions with this metadata on every entry:

- owner: Rustleaks maintainers;
- scope: locked all-features workspace;
- rationale: initial bootstrap exemption pending source audit; and
- review date: 2026-11-23.

`just security` rejects a missing, malformed, or expired review date. A vet
exemption is temporary coverage, not evidence that source was audited. Replace
exemptions with local audits as review work is completed. Adding peer imports
is a separate trust decision and requires explicit maintainer review.

The exact normal dependency graph, direct build scripts, native code, and safe
API reasoning are documented in [`DEPENDENCY_SAFETY.md`](DEPENDENCY_SAFETY.md)
and [`DEPENDENCIES.md`](DEPENDENCIES.md). `cargo-geiger` is used only as a
dependency-delta inventory. Its current exact unsafe-bearing package set is
enforced by `xtask`; it is not a security conclusion.

The public API snapshot is the pre-publication SemVer baseline. Before a
release candidate, maintainers must run `cargo-semver-checks` for every public crate
and supported feature profile against an actual prior release when one exists,
then require manual API review. A snapshot alone cannot compare to a release
that has not been published.

## Repository self-scan

Scan the worktree and Git history with Rustleaks before release. The root
`.rustleaks.toml` extends the pinned default rules and prunes only generated
compatibility corpora, the two generated API traceability indexes, copied
compatibility fixtures, Git metadata, and local build output. The root
`.rustleaksignore` lists reviewed fingerprints for individual synthetic
examples and generated hashes.
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
| Nightly | Longer high-risk fuzz campaigns, increased property cases, batched Go differentials, fresh RustSec, newest-allowed dependency resolution in a noncommitting checkout, and repository self-scan. |
| Weekly | Slower archive and large-input campaigns, pinned Miri, supported sanitizers, corpus minimization and coverage review, unsafe inventory review, cargo-vet exemption reduction, CodeQL, and all available native target lanes. |
| Release candidate | A clean extended campaign with no unresolved crash, timeout, memory, sanitizer, invariant, advisory, vetting, or parity finding; `just security`; `just ci`; `just release-dry-run`; SemVer comparison; exact-target SBOMs reconciled with the Bazel graph; checksums and attestations. The CI gate includes committed parity, and the release dry run includes package consumers. |

OSS-Fuzz is not configured. Until eligibility and project ownership are
reviewed, scheduled CI must run the same targets.

## Protected files

Hosted ownership rules must require review for changes to at least:

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

GitHub secret scanning, push protection, private vulnerability reporting,
branch protection, protected release environments, trusted publishing, and
artifact attestations are external settings. Their absence is a release
blocker, not something a local check can silently waive.

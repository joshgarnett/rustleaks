# Release process

Rustleaks has not published a crate or release. This document defines the
maintained local qualification boundary and the conditions that must exist
before publication. It does not authorize a release.

## Candidate identity

One candidate must have an approved version, exact commit and tree, clean
worktree, matching workspace manifests and changelog, and one consistent
Gitleaks revision and default-config hash across the package and compatibility
evidence. Only `rustleaks-core` is currently publishable.

Selecting a version, creating a GitHub release, publishing a crate, changing a
release setting, enabling trusted publishing, or using a credential requires
explicit maintainer approval for that action.

## Local qualification

Run from a clean clone of the candidate:

```sh
cargo fetch --locked
just ci
just security
just fuzz-smoke
just release-dry-run
```

The fetch hydrates the exact locked registry inputs used by the deliberately
offline package and external-consumer checks. It does not change a manifest or
lockfile.

`just ci` covers maintained prose and links, Rustdoc, the committed parity
tests, all first-party tests, and compile-only evidence for the eight declared
targets. `just release-dry-run` includes package archive inspection, clean
external Cargo and Bazel consumers, and the locked no-upload Cargo publication
check.

The publishable package metadata also selects docs.rs-compatible warning-denied
documentation for all features. The protected hosted dry run repeats that
interface and retains the exact `.crate` archive plus its file list.

Run `cargo xtask parity --all` with the exact pinned Gitleaks checkout at
`../gitleaks` when compatibility inputs or behavior changed. Complete SemVer
comparison against the latest published release is required once a prior
release exists.

## Non-publishing release candidate

After a candidate is merged to `main`, dispatch `Release Dry Run` with the full
40-character candidate commit. The protected `release` environment first
requires approval and rejects any commit other than the current `origin/main`.
The workflow does not receive a registry token and fails if either conventional
crates.io token variable is present.

The workflow runs the package consumers, docs.rs build, full fresh differential,
security policy, extended AddressSanitizer fuzzing, worktree and history scans,
and native artifact matrix. Every native job builds the CLI twice with isolated
Bazel output roots, requires byte-identical binaries, runs help and redacted
scan smoke tests, and emits:

- `rustleaks-0.1.0-alpha.1-<target>.tar.gz`;
- `SHA256SUMS` for the archive, SBOM, and provenance predicate;
- a target-filtered CycloneDX 1.6 SBOM with registry package checksums and an
  exact Cargo-to-Bazel graph reconciliation;
- an unsigned SLSA v1 dry-run provenance predicate;
- a GitHub-native signed SLSA provenance attestation for the archive, verified
  against the exact `main` commit and release workflow;
- a reproducibility proof and machine-readable release manifest.

The retained source package is generated twice into isolated Cargo target
directories, compared byte for byte, and receives the same signed provenance
verification.

GNU manifests record the highest required `GLIBC_X.Y` symbol version measured
from the exact binary. Musl artifacts must contain no ELF interpreter or
dynamic `NEEDED` entry. macOS release builds omit nondeterministic Mach-O UUIDs
before the linker creates any required ad-hoc signature. No other artifact
difference is normalized.

## External evidence and blockers

Before the first publication, the repository still needs:

- one successful protected dry run for the exact accepted candidate, including
  every source and native artifact, its signed provenance attestation, and the
  independently scheduled CodeQL result;
- reviewed crates.io trusted publishing for the first package;
- the final approval packet described below.

Cross-compilation is not native evidence. A local dry run, package archive, or
successful command does not grant publication approval.

The incident procedure was exercised without a live report or credential on
2026-08-24. The record is in
[`INCIDENT_RESPONSE_EXERCISE.md`](INCIDENT_RESPONSE_EXERCISE.md).

## Exact publication and rollback plan

The first publication contains one crate, `rustleaks-core 0.1.0-alpha.1`, so
there is no inter-crate publication ordering. After explicit publication
approval, the intended tag is `v0.1.0-alpha.1` and the GitHub release name is
`Rustleaks 0.1.0-alpha.1`. The release attaches the eight target archives,
their checksum files, CycloneDX SBOMs, reproducibility proofs, manifests, and
verified GitHub provenance attestations from the approved candidate run.

Publication must use a reviewed crates.io trusted-publishing configuration in
the protected `release` environment. Do not add a long-lived registry token as
a fallback. Immediately after publication, verify the registry owner and
metadata, download and hash the `.crate`, build the documented external Cargo
and Bazel consumers against the registry version, verify every GitHub artifact
attestation and checksum, install the CLI archives on their native targets,
and rerun the help and representative redacted scan.

If registry metadata, package contents, checksums, attestations, native smoke
tests, or public API differ from the approval packet, stop further publication,
remove or quarantine GitHub release assets, and follow the incident procedure.
Yank the crates.io version when continued new resolution creates risk. Yanking
does not delete the package and does not replace a fixed release, advisory, or
coordinated disclosure. A tag or GitHub release that points to the wrong tree
must not be silently moved; publish a factual correction only after incident
review and a new explicit approval.

## Approval packet

Before any external mutation, present the exact version, commit and tree,
packages and artifacts, archive contents, native target evidence, command
results, public API comparison, compatibility and security risks, checksums,
SBOM reconciliation, provenance, requested external actions, and rollback or
yanking plan. Stop when a required gate is missing, failing, pending, stale, or
unexplained.

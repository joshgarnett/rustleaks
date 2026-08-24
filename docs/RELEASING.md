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
just ci
just security
just fuzz-smoke
just release-dry-run
```

`just ci` covers maintained prose and links, Rustdoc, the committed parity
tests, all first-party tests, and compile-only evidence for the eight declared
targets. `just release-dry-run` includes package archive inspection, clean
external Cargo and Bazel consumers, and the locked no-upload Cargo publication
check.

Run `cargo xtask parity --all` with the exact pinned Gitleaks checkout at
`../gitleaks` when compatibility inputs or behavior changed. Complete SemVer
comparison against the latest published release is required once a prior
release exists.

## External evidence and blockers

Before the first publication, the repository still needs:

- refreshed native build, test, feature, parity, example, and CLI evidence for
  the exact release candidate on every claimed target;
- an exercise of the private reporting and incident-response procedure;
- publication automation within the protected environment;
- reviewed crates.io trusted publishing;
- checksums, target-specific SBOMs reconciled with Cargo and Bazel inputs,
  provenance, and attestations for actual artifacts; and
- a documented rollback, advisory, and crates.io yanking procedure exercised
  without publishing.

Cross-compilation is not native evidence. A local dry run, package archive, or
successful command does not grant publication approval.

## Approval packet

Before any external mutation, present the exact version, commit and tree,
packages and artifacts, archive contents, native target evidence, command
results, public API comparison, compatibility and security risks, checksums,
SBOM reconciliation, provenance, requested external actions, and rollback or
yanking plan. Stop when a required gate is missing, failing, pending, stale, or
unexplained.

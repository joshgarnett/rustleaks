---
name: rustleaks-release
description: Prepare and audit a Rustleaks release candidate, including versions, package contents, external consumers, artifacts, checksums, SBOMs, dry runs, and publication approval boundaries. Use for release preparation or release review; never treat it as authorization to publish.
---

# Rustleaks release

Read `docs/RELEASING.md`, `docs/SECURITY_CONTROLS.md`,
`docs/COMPATIBILITY.md`, `SECURITY.md`, `CHANGELOG.md`, workspace manifests,
and `compat/public-api/README.md`. Establish the proposed version and exact
commit. Selecting a version, creating a release, publishing a crate, changing
release settings, or using a credential requires explicit maintainer approval.
A dry run does not grant publication approval.

## Qualify the candidate

Confirm that the worktree and index are clean, version fields and changelog
agree, package metadata and licenses are complete, the upstream revision and
config hash match all evidence, and no release blocker in `SECURITY.md` or the
release document remains open.

Run the maintained local gates:

```sh
just ci
just security
just fuzz-smoke
just release-dry-run
```

`just release-dry-run` includes `just package-check`, which must exercise the
extracted `rustleaks-core` package through clean external Cargo and Bazel
consumers. Inspect the normalized archive for required source, default config,
README, license, and notice files, and for unwanted workspace or private
material.

Require the matching native target, feature, parity, example, CLI, MSRV,
SemVer, and extended security evidence defined by the release document. Do not
promote compile-only target results to support. Do not invent an artifact,
checksum, SBOM, attestation, or native result that the current release workflow
does not produce.

## Reconcile artifacts

For every actual release artifact, record its target, inputs, build command,
toolchain, features, size, and SHA-256 checksum. Reconcile the maintained
checksum files, CycloneDX SBOMs, Cargo-to-Bazel graph evidence, reproducibility
proofs, provenance predicates, and GitHub attestations produced by the exact
candidate workflow. Verify only artifacts and metadata produced by that run.
Keep signing keys and tokens out of the repository and logs.

Stop before publication and present an approval packet containing the exact
commit and tree, version, packages and artifacts, native evidence, gate
results, compatibility and security risks, checksums, SBOM reconciliation,
provenance, proposed external actions, and rollback or yanking plan. Publish
only the specifically approved package or release through the reviewed
workflow. Existing crates use trusted publishing. Because crates.io cannot
bootstrap trusted publishing for a new crate, an initial publication may use
only an explicitly approved short-lived token procedure followed by immediate
revocation and trusted-publisher configuration. Verify the public result
without modifying unrelated GitHub state.

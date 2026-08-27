# Incident-response exercise

This record covers a pre-publication release-integrity exercise performed on
2026-08-24. It was a tabletop and tooling exercise, not a security incident.
No live credential, private report, published crate, tag, or release was used.

## Scenario and evidence

Two optimized Apple Silicon CLI builds used the same source tree, lockfiles,
Bazel version, Rust toolchain, target, and features but different isolated
Bazel output roots. The binaries had equal lengths and first differed in the
Mach-O load commands. Their UUIDs differed, and the dependent ad-hoc signature
bytes also differed.

The exercise treated this unexplained integrity difference as a release
blocker. The two binaries, their SHA-256 digests, build commands, source tree,
and output-root distinction were retained in private temporary storage while
the cause was investigated. No artifact was uploaded or described as
reproducible.

## Containment and diagnosis

Publication, tagging, and release creation remained disabled. Comparison of
Mach-O metadata isolated the first difference to `LC_UUID`; string inspection
found no embedded output-root path. A release-only linker setting suppressed
the nondeterministic UUID. Normal development and compatibility builds were not
changed.

The scenario exercised release suspension, evidence hashing, exact-input
reproduction, minimal cause isolation, scope review, and the rule that an
unexplained difference cannot be normalized away. A real incident still
requires a named coordinator, a separate technical reviewer, private evidence
handling, and any provider-side containment appropriate to its facts.

## Recovery proof

The two isolated optimized builds were repeated with the release setting. The
resulting binaries were byte-identical. The release tool then independently
created and compared complete bundles, including each archive, checksum list,
target CycloneDX SBOM, Cargo-to-Bazel dependency reconciliation, SLSA v1
dry-run provenance predicate, reproducibility proof, and exact archive
contents.

The regression is enforced by the exact-candidate release dry run, which builds
every native target twice and fails before artifact upload when bytes differ.
macOS jobs also require the release binary to omit a Mach-O UUID. The workflow
contains no publication command or registry credential.

## Follow-up

- Run the release dry run against the final accepted candidate on all eight
  native targets.
- Verify GitHub-native signed provenance before publication approval.
- Rehearse registry metadata verification and yanking decisions against the
  documented plan without publishing a crate.
- Repeat this exercise after a material release, ownership, CI, or reporting
  change.

---
name: rustleaks-release
description: Prepare and check a Rustleaks release candidate by following docs/dev/releasing.md, and stop at each publication approval. Use for release preparation or release review; never treat it as authorization to publish.
---

# Rustleaks release

Follow the checklist in [Releasing](../../../docs/dev/releasing.md). It is the
only copy of the release procedure. This skill lists the approval rules and
the facts agents get wrong.

## Approval

- The release actions under [Approval
  boundaries](../../../AGENTS.md#approval-boundaries) and in
  [Releasing](../../../docs/dev/releasing.md) need explicit maintainer
  approval.
- A local or hosted dry run does not authorize publication.
- Each external action needs its own approval: the crate (`publish.yml`), the
  GitHub release (`release.yml`) and the package manager push
  (`packages.yml` with `publish` set).
- An approval names the version and action, and the candidate commit and
  dry run ID where the workflow takes them. When any of these changes, ask
  again. When the maintainer approved the exact unchanged action, do not ask
  a second time.
- Local checks and the dry run publish nothing and use no secret, so they need
  no environment approval.

## Facts to keep in mind

- Cargo writes the worktree commit into `.cargo_vcs_info.json`. Package bytes
  built on a topic branch are not valid for the squash commit on `main`. Check
  the candidate after it is merged.
- When the exact candidate already has a passing hosted dry run, do not rerun
  every local check before publishing. Do the revalidation step in Releasing
  instead.
- Start again if the candidate, version, lockfiles, workflows, package bytes
  or release inputs change, or if a kept dry run artifact expires.
- A compile-only target result is not support for that target.
- Do not claim an artifact, checksum, SBOM, attestation or native result that
  the release workflow does not produce.
- Keep tokens and signing keys out of the repository and logs.

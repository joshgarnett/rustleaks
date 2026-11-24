---
name: rustleaks-release
description: Prepare and check a Rustleaks release candidate by following docs/dev/releasing.md, and stop at each publication approval. Use for release preparation or release review; never treat it as authorization to publish.
---

# Rustleaks release

Follow the checklist in [Releasing](../../../docs/dev/releasing.md). It is the
only copy of the release procedure. This skill lists the approval rules and
the facts agents get wrong.

## Approval

[Approvals](../../../docs/dev/releasing.md#approvals) in Releasing lists the
actions that need maintainer approval and what each request must name. A
local or hosted dry run does not authorize publication. When the maintainer
approved the exact unchanged action, do not ask a second time.

## Facts to keep in mind

- Cargo writes the worktree commit into `.cargo_vcs_info.json`. Package bytes
  built on a topic branch are not valid for the squash commit on `main`. Check
  the candidate after it is merged.
- [Revalidate just before
  publishing](../../../docs/dev/releasing.md#5-revalidate-just-before-publishing)
  says when to reuse results and when to start again, including when a kept
  dry run artifact expires.
- A compile-only target result is not support for that target.
- Do not claim an artifact, checksum, SBOM, attestation or native result that
  the release workflow does not produce.
- Keep tokens and signing keys out of the repository and logs.

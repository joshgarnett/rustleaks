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
- The Go module uses the release version. The Python package uses its PEP
  440 form: `0.3.0-alpha.1` is `0.3.0a1` (see
  [Python version](../../../docs/dev/releasing.md#python-version)). The
  version check covers `bindings/go/library.go`, `RUSTLEAKS_PYTHON_VERSION`
  in `bazel/rust_crate.bzl`, `bindings/python/pyproject.toml` and
  `bindings/python/src/rustleaks/_version.py`.
- A pre-release is not pushed to the Homebrew tap or Scoop bucket while
  they hold a stable release; its Go module and Python package are
  published as usual.
- `Publish Go Module` and `Publish Python Package` publish the files of the
  dry run's `rustleaks-bindings-<version>-packages` artifact; they build
  nothing. Each push to `joshgarnett/rustleaks-go` and each PyPI upload is a
  separate approval.
- A Go version or tag in `rustleaks-go` and a PyPI file name can never be
  replaced. Fix a bad one with a new version (and a Go `retract`), never by
  moving a tag.

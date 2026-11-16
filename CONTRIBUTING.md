# Contributing

Rustleaks is in alpha development. This file is the single source for the
issue, commit and pull request rules. People and agents follow the same
rules.

Every contribution must keep the functional guarantees in the
[compatibility policy](docs/user/gitleaks-differences.md#compatibility-policy)
and the boundaries between the core engine, source adapters, reports,
compatibility tools and CLI described in the
[architecture](docs/dev/architecture.md). Rustleaks owns its help, usage,
error wording, logs and other presentation, and may change them with reviewed
test expectations.

## Issues

### What belongs in an issue

An issue describes one current problem that someone can act on. Open an issue
only for:

- a defect: Rustleaks behaves incorrectly and you can reproduce it;
- a compatibility gap: a functional difference from the pinned Gitleaks
  revision; or
- a feature proposal: a concrete capability or workflow change with a clear
  outcome.

Do not open an issue for a tracker, log, status report, plan or roadmap. Put
one problem in each issue. Close an issue when it is resolved or no longer
current. Report security vulnerabilities through [the security
policy](SECURITY.md), not in an issue.

### Before opening an issue

Search the existing issues and choose the defect, compatibility-gap or
feature form. Give the exact Rustleaks revision, target, feature set,
commands and the smallest synthetic reproducer that the form asks for.

A compatibility report compares against Gitleaks commit
`b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b` and names the functional
difference, such as a finding, span, fingerprint, report field or exit code.
A difference only in help, usage, error wording or log text is not a
compatibility gap. Report it as a defect or a feature proposal.

Never put a live credential, raw finding, exploit, private repository content
or non-public vulnerability detail in an issue.

### Issue labels

The issue forms set the title prefix (`bug: `, `compat: ` or `feat: `) but do
not apply labels. A maintainer applies labels during triage.

| Label | Use |
| --- | --- |
| `bug` | Rustleaks behaves incorrectly. Use for `bug: ` issues and for `compat: ` issues where supported behavior differs. |
| `enhancement` | A new capability or improvement. Use for `feat: ` issues and for `compat: ` issues about behavior that Rustleaks does not support yet. |
| `documentation` | The problem or change is in documentation only. |
| `dependencies` | The issue concerns a dependency, such as an advisory or a required update. |
| `question` | The reporter must give more information before work can start. |
| `good first issue` | Small, well-defined work that suits a new contributor. |
| `help wanted` | The maintainer welcomes an outside contribution. |
| `duplicate` | Another issue already covers the problem. Link it and close this issue. |
| `wontfix` | The maintainer decided not to make the change. Explain why and close the issue. |
| `invalid` | The report is not a Rustleaks problem or does not follow this policy. Close the issue. |

Dependabot adds `dependencies` and an ecosystem label (`rust`,
`github_actions` or `rust_toolchain_package_manager`) to its pull requests.
Do not apply the ecosystem labels to issues. Add `accessibility` to an issue
when the problem is a barrier for people with disabilities.

## Local workflow

Install Bazelisk and Just 1.53.0, as in CI. The Rust toolchain comes from
`rust-toolchain.toml`, and `.bazelversion` pins Bazel. `just doctor` reports
the selected versions and changes nothing. No Go installation or Gitleaks
checkout is needed. Security checks need the exact tools listed in
[Security checks](docs/dev/security-checks.md).

Just is the public command interface, and Bazel is the build authority. Run
`just --list` to see the recipes. Start with a focused Bazel target, for
example:

```sh
bazelisk test //crates/rustleaks-core:engine_test
bazelisk test //crates/rustleaks-cli:cli_test
```

Then run the broader command that fits the change:

| Change | Command |
| --- | --- |
| Formatting | `just format` |
| Prose, links, Clippy, Rustdoc, build and the eight-target compile check | `just check` |
| Any code | `just test` |
| Timers, cancellation, subprocesses, directory traversal, temporary paths or concurrency | `just flake-check` (all ten runs must pass) |
| Compatibility evidence | `just parity` and `cargo xtask regression-check` |
| Public API, manifests, features, packaged assets or release inputs | `just package-check` |
| Parser, matcher, decoder, source, report, CLI, resource limit or fuzz input | `just fuzz-build` and `just fuzz-smoke` |
| Supported compatibility behavior or its evidence | `cargo xtask qualify`, from a clean, committed tree |

Before opening a pull request, run:

```sh
just ci
just security
```

Package checks run Cargo consumers offline. In a fresh clone, run
`cargo fetch --locked` once before `just package-check` or
`just release-dry-run`.

Keep functional assertions apart from performance budgets. See
[Testing and parity](docs/dev/testing-and-parity.md) for how to add and
register tests.

Cross-compilation proves only that the code compiles. It does not establish
runtime support for a target.

Use Cargo only for package metadata, crates.io packaging, `cargo xtask`, and
the named security, fuzz, Miri and MSRV tools. Never use Cargo to work around
a failed Bazel action. `just deps-repin` is the only command that regenerates
the Cargo, crate-universe and Bazel module lockfiles.

## Compatibility and test data

- Do not change the upstream revision, the packaged default configuration,
  frozen corpora, fixtures, the public API snapshot or safe Rust dispositions
  on their own. Follow [Updating upstream](docs/dev/updating-upstream.md).
- Historical Go corpora never change. Their generation commands describe the
  retired process and do not run.
- New regression tests need findings, spans, fingerprints, report fields,
  exit codes and error classes that are specified independently, positive and
  negative cases, and stable names. Never generate these expected values from
  current Rust output.
- Explain every intended functional difference, and add a test that fails
  when the contract is broken.
- A presentation change, such as help, usage, error wording or log text,
  updates the affected test expectation. A reviewer checks the new text
  against the stated intent. When it replaces frozen CLI evidence, record it
  as a [presentation
  disposition](docs/dev/testing-and-parity.md#presentation-dispositions) in
  `compat/presentation-dispositions.toml`.
- Use synthetic or reviewed upstream test values. Keep copied bytes, modes,
  symbolic links, provenance, hashes, licenses and attribution.
- Keep suspected findings and fuzz crash artifacts private until their
  contents are reviewed.

## Commits

Every commit subject uses this grammar:

```text
<type>(<scope>)!: <description>
```

- The scope and `!` are optional.
- The description is imperative and in the present tense, starts with a
  lowercase word or a project identifier as grammar requires, has no final
  period, and is at most 72 characters.
- Use `!` only for an intended breaking change, and add a
  `BREAKING CHANGE: ...` footer that explains the affected API and the
  migration.
- Use the standard Git `Revert "..."` subject only for a real revert, and keep
  its explanation of the reverted commit.

Choose the narrowest type:

| Type | Use |
| --- | --- |
| `feat` | Add user-visible capability or public behavior. |
| `fix` | Correct behavior, compatibility, security or reliability. |
| `perf` | Improve measured performance without changing supported behavior. |
| `refactor` | Change internal structure without changing behavior. |
| `test` | Add or correct tests, corpora, fixtures or test infrastructure. |
| `docs` | Change documentation only. |
| `build` | Change Cargo, Bazel, toolchains, packaging or build inputs. |
| `ci` | Change automation workflows or CI configuration. |
| `style` | Apply formatting only, with no change in meaning. |
| `chore` | Narrow maintenance that fits no other type. |

When useful, choose the narrowest stable lowercase scope: `core`, `sources`,
`report`, `cli`, `compat`, `xtask`, `bazel`, `deps`, `docs`, `ci` or
`release`. Omit the scope for a change that crosses many areas. Never use a
goal, agent, review round, ticket or temporary task as a scope.

Add a body, after a blank line, when the reason, compatibility effect,
security constraint or a non-obvious decision will matter later. Add only
true trailers. Never invent issue links, sign-offs, co-authors or review
credits.

Each commit is one reviewable logical state:

- Keep behavior changes with their direct tests, generators with their
  generated files, and manifest changes with the lockfile changes they need.
- Separate unrelated documentation, dependency, build and behavior work.
- Do not commit build output, local settings, credentials, raw audit notes or
  planning files.

Before committing:

1. Inspect `git status --short`, `git diff`, `git diff --cached` and
   `git ls-files --others --exclude-standard`.
2. Stage explicit paths or hunks.
3. Inspect the complete staged diff.
4. Run the relevant checks and `git diff --cached --check`.

## Pull requests

Fill in the pull request template: the resulting behavior, the reason, the
exact checks you ran, the functional compatibility or security impact, any
presentation changes, and real linked issues.

The pull request title follows the commit subject grammar, because pull
requests are squash merged.

Do not merge while required checks, required reviews or blocking review
conversations are incomplete. An approving review is required only when the
live repository ruleset requires one or the maintainer asks for an
independent review. For a pull request by the sole maintainer, a missing
self-approval is not a blocker. Do not create a self-approval for a
sole-maintainer pull request.

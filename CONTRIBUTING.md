# Contributing

This file is the single source for the issue, commit and pull request rules.
People and agents follow the same rules.

Every contribution follows the [repository
contract](AGENTS.md#repository-contract) and the boundaries between crates in
the [architecture](docs/dev/architecture.md).

## Issues

### What belongs in an issue

An issue describes one current problem that someone can act on. Open an issue
only for:

- a defect: Rustleaks behaves incorrectly and you can reproduce it, for
  example a configuration, report, exit code or command that does not work
  as documented, or a secret that Rustleaks misses; or
- a feature proposal: a concrete capability or workflow change with a clear
  outcome.

Do not open an issue for a tracker, log, status report, plan or roadmap. Put
one problem in each issue. Close an issue when it is resolved or no longer
current. Report security vulnerabilities through [the security
policy](SECURITY.md), not in an issue.

### Before opening an issue

Search the existing issues and choose the defect or feature form. Give the
exact Rustleaks revision, target, feature set, commands and the smallest
synthetic reproducer that the form asks for.

A difference from Gitleaks is not a defect by itself. [Moving from
Gitleaks](docs/user/moving-from-gitleaks.md) lists the known differences.
Report one when it makes Rustleaks miss a secret or breaks a configuration,
report or command that Rustleaks documents.

Never put a live credential, raw finding, exploit, private repository content
or non-public vulnerability detail in an issue.

### Issue labels

The issue forms set the title prefix (`bug: ` or `feat: `) but do not apply
labels. A maintainer applies labels during triage.

| Label | Use |
| --- | --- |
| `bug` | Rustleaks behaves incorrectly. Use for `bug: ` issues. |
| `enhancement` | A new capability or improvement. Use for `feat: ` issues. |
| `experiment` | An idea worth trying, such as a performance change, that must be measured before it is adopted. Add it next to `enhancement`. |
| `documentation` | The problem or change is in documentation only. |
| `dependencies` | The issue concerns a dependency, such as an advisory or a required update. |
| `question` | The reporter must give more information before work can start. |
| `good first issue` | Small, well-defined work that suits a new contributor. |
| `help wanted` | The maintainer welcomes an outside contribution. |
| `duplicate` | Another issue already covers the problem. Link it and close this issue. |
| `wontfix` | The maintainer decided not to make the change. Explain why and close the issue. |
| `invalid` | The report is not a Rustleaks problem or does not follow this policy. Close the issue. |
| `accessibility` | The problem is a barrier for people with disabilities. |

Dependabot adds `dependencies` and an ecosystem label, such as `rust` or
`github_actions`, to its pull requests. Do not apply the ecosystem labels to
issues.

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
| Formatting check (it does not change files) | `just format` |
| Documentation only | `just docs-check` |
| Prose, links, Clippy, Rustdoc, build and the eight-target compile check | `just check` |
| Any code | `just test` |
| Timers, cancellation, subprocesses, directory traversal, temporary paths or concurrency | `just flake-check` (all ten runs must pass) |
| Public API, manifests, features, packaged assets or release inputs | `just package-check` |
| Publish metadata or package contents | `just release-dry-run` (it includes `just package-check`) |
| Parser, matcher, decoder, source, report, CLI, resource limit or fuzz input | `just fuzz-build` and `just fuzz-smoke` |
| Public API snapshot, MSRV or a release candidate | `cargo xtask qualify`, from a clean, committed tree |

Before opening a pull request, run:

```sh
just ci
just security
```

Package checks run Cargo consumers offline. In a fresh clone, run
`cargo fetch --locked` once before `just package-check` or
`just release-dry-run`.

### Clean-clone checks

Some changes, such as dependency and build updates, need the clean-clone
checks. In a fresh clone of the branch, run:

```sh
cargo fetch --locked
just ci
just security
```

Do not make a functional test depend on timing. See
[Testing](docs/dev/testing.md) for how to add and
register tests.

[Platforms](docs/dev/testing.md#platforms) says what cross-compilation
proves and what a target support claim needs.

Use Cargo only for package metadata, crates.io packaging, `cargo xtask`,
`cargo fetch --locked`, `cargo public-api`, `cargo-semver-checks`, and the
named security, fuzz, Miri and MSRV tools. Never use Cargo to work around
a failed Bazel action. `just deps-repin` is the only command that regenerates
the Cargo, crate-universe and Bazel module lockfiles.

## Test data

Follow [Rules for tests](docs/dev/testing.md#rules-for-tests) and
[Test data](docs/dev/testing.md#test-data). In addition:

- A change to a built-in rule file follows
  [Rule authoring](docs/dev/rule-authoring.md).
- Regenerate the public API snapshot as described in
  `testdata/public-api/README.md` when the `rustleaks-core` API changes.

## Changelog

Add an entry to `CHANGELOG.md`, under `## [Unreleased]`, when a change:

- changes findings, spans or fingerprints, which also needs a Rust test;
- changes report fields, exit codes or error classes;
- changes a built-in rule file, including the Gitleaks-based rules in
  `gitleaks.toml`; or
- changes anything else that users or library callers can see, such as a
  command, flag, limit or public API.

Write the entry for users: say what changed and what they may need to do.
Rule-specific cases that need an entry are in
[Rule authoring](docs/dev/rule-authoring.md).

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
`report`, `cli`, `ffi` (the C ABI crate), `eval`, `xtask`, `bazel`, `deps`,
`docs`, `ci`, `security` (the security policy and checks) or `release`.
Omit the scope for a change that crosses many areas. Never use a goal,
agent, review round, ticket or temporary task as a scope.

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
exact checks you ran, the functional or security impact, any
presentation changes, the changelog entry, and real linked issues. Explain
every intended functional change.

The pull request title follows the commit subject grammar, because pull
requests are squash merged.

Merge only by squash. Do not merge while required checks or blocking review
conversations are incomplete. The required checks are strict, so a branch
behind `main` must be updated before it can merge. The ruleset on `main`
requires no approving review. Get one only when the maintainer asks for an
independent review. Never approve your own pull request.

# Contributing

Rustleaks is in alpha development. Contributions must preserve the pinned
compatibility profile and the boundaries between the core engine, source
adapters, reports, compatibility tools, and CLI.

## Before opening an issue

Search existing issues and choose the defect, compatibility-gap, or feature
form. Provide the exact Rustleaks revision, target, feature set, commands, and
smallest synthetic reproducer needed by that form. Compatibility reports must
compare against Gitleaks commit
`b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b` and identify the field-level
difference.

Never put a live credential, raw finding, exploit, private repository content,
or non-public vulnerability detail in an issue. Follow [the security
policy](SECURITY.md) for sensitive reports.

### What belongs in an issue

An issue describes one current problem that someone can act on. Open an issue
only for:

- a defect: Rustleaks behaves incorrectly and you can reproduce it;
- a compatibility gap: a functional difference from the pinned Gitleaks
  revision; or
- a feature proposal: a concrete capability or workflow change with a clear
  outcome.

Do not open an issue for a tracker, log, status report, plan, or roadmap. Put
one problem in each issue. Close an issue when it is resolved or no longer
current. Report security vulnerabilities through [the security
policy](SECURITY.md), not in an issue.

### Issue labels

The issue forms set the title prefix (`bug: `, `compat: `, or `feat: `) but
do not apply labels. A maintainer applies labels during triage.

| Label | Use |
| --- | --- |
| `bug` | Rustleaks behaves incorrectly. Use for `bug: ` issues and for `compat: ` issues where supported behavior differs. |
| `enhancement` | A new capability or improvement. Use for `feat: ` issues and for `compat: ` issues about behavior that Rustleaks does not support yet. |
| `documentation` | The problem or change is in documentation only. |
| `dependencies` | The issue concerns a dependency, such as an advisory or a required update. |
| `question` | The reporter must provide more information before work can start. |
| `good first issue` | Small, well-defined work that suits a new contributor. |
| `help wanted` | The maintainer welcomes an outside contribution. |
| `duplicate` | Another issue already covers the problem. Link it and close this issue. |
| `wontfix` | The maintainer decided not to make the change. Explain why and close the issue. |
| `invalid` | The report is not a Rustleaks problem or does not follow this policy. Close the issue. |

Dependabot adds `dependencies` and an ecosystem label (`rust`,
`github_actions`, or `rust_toolchain_package_manager`) to its pull requests.
Do not apply the ecosystem labels to issues. Add `accessibility` to an issue
when the problem is a barrier for people with disabilities.

## Local workflow

Install Bazelisk and Just 1.53.0, matching the maintained CI setup. Use the Rust
toolchain selected by `rust-toolchain.toml`; the repository pins Bazel in
`.bazelversion`. `just doctor` reports the selected versions without installing
or changing anything.
Rust regression and qualification checks need neither a Go installation nor a
sibling Gitleaks checkout. Security checks require the exact tools listed in
[the security controls](docs/SECURITY_CONTROLS.md).

Just is the public command interface, and Bazel is the build authority. Use
`just --list` to see maintained recipes. Start with a focused Bazel target:

```sh
bazelisk test //crates/rustleaks-core:engine_test
bazelisk test //crates/rustleaks-sources:all_tests
bazelisk test //crates/rustleaks-report:parity_tests
bazelisk test //crates/rustleaks-cli:cli_test
```

Then run the affected broader command:

- `just format` for formatting;
- `just check` for prose, links, formatting, Clippy, Rustdoc, build, and all
  eight declared target compile checks;
- `just test` for every first-party Bazel test;
- `just flake-check` for ten uncached executions of every first-party test;
- `just parity` for the committed compatibility replay;
- `just package-check` for package contents and external Cargo/Bazel
  consumers; and
- `just security`, `just fuzz-build`, and `just fuzz-smoke` for
  security-sensitive or hostile-input changes.

Package checks deliberately run Cargo consumers offline. Hydrate the exact
locked registry dependencies once before `just package-check` or `just
release-dry-run` in a fresh clone:

```sh
cargo fetch --locked
```

Before opening a pull request, run:

```sh
just ci
just security
```

`just ci` includes maintained prose, links, Rustdoc, the committed parity
tests, all first-party tests, and the compile-only target matrix. Run
`just package-check` when public APIs, manifests, features, packaged assets, or
release inputs change. Run both fuzz recipes when parser, matcher, decoder,
source, report, CLI, resource-limit, or fuzz inputs change. Use
`cargo xtask regression-check` to verify frozen evidence and Rust replay, and
`cargo xtask qualify` from a clean, committed candidate for changes to supported
compatibility behavior or its evidence. Qualification includes package,
external-consumer, fuzz, Miri, and performance checks.

Run `just flake-check` after changing timers, cancellation, subprocesses,
filesystem traversal, temporary paths, or concurrency. A test must pass all
ten executions. Keep functional assertions separate from performance budgets;
the dedicated performance gate measures latency from fresh samples.

Cross-compilation is compile-only evidence. It does not establish native
runtime support for a target.

Cargo remains authoritative for standard package metadata and crates.io
packaging. It is also used by `xtask` and named security, fuzz, Miri, and MSRV
tools. Do not use Cargo as a fallback for a failed Bazel action.
`just deps-repin` is the only public command that regenerates Cargo,
crate-universe, and Bazel module lockfiles.

## Compatibility and test data

Do not update the upstream revision, packaged default configuration, frozen
corpora, fixtures, public API snapshot, or safe Rust dispositions in isolation.
Follow [the upstream update procedure](docs/UPDATING_UPSTREAM.md). Historical
Go corpora remain immutable; their generation commands describe the archived
workflow and are no longer executable maintenance instructions. New Rust
regressions need independently specified expected bytes, errors and spans,
positive and negative cases, and stable identities. Do not generate accepted
expectations from current Rust output. Explain every intentional difference
and add evidence that fails when the contract is violated.

Use synthetic or reviewed upstream test values. Preserve copied bytes, modes,
symlinks, provenance, hashes, licenses, and attribution. Keep suspected
findings and fuzz crash artifacts private until their contents are reviewed.

## Commit standard

Every commit uses this Conventional Commit subject grammar:

```text
<type>(<scope>)!: <description>
```

The scope and `!` are optional. The description must be imperative and present
tense, start with a lowercase word or project identifier as grammar requires,
contain no final period, and remain at most 72 characters. Use `!` only for an
intentional breaking change and add a `BREAKING CHANGE: ...` footer explaining
the affected API and migration.

Use the standard Git-generated `Revert "..."` subject only for a real revert,
and preserve its explanation of the reverted commit.

Choose the narrowest type:

| Type | Use |
| --- | --- |
| `feat` | Add user-visible capability or public behavior. |
| `fix` | Correct behavior, compatibility, security, or reliability. |
| `perf` | Improve measured performance without changing supported behavior. |
| `refactor` | Change internal structure without changing behavior. |
| `test` | Add or correct tests, corpora, fixtures, or test infrastructure. |
| `docs` | Change documentation only. |
| `build` | Change Cargo, Bazel, toolchains, packaging, or build inputs. |
| `ci` | Change automation workflows or CI configuration. |
| `style` | Apply formatting only, with no semantic change. |
| `chore` | Perform narrow maintenance that fits no more specific type. |

Use the narrowest stable lowercase scope when useful: `core`, `sources`,
`report`, `cli`, `compat`, `xtask`, `bazel`, `deps`, `docs`, `ci`, or
`release`. Omit the scope for a truly cross-cutting change. Do not use a goal,
agent, review round, ticket, or temporary task as a scope.

Use a commit body when the reason, compatibility effect, security constraint,
or non-obvious decision will matter later. Separate it from the subject with a
blank line. Add only true trailers. Never invent issue links, signoffs,
co-authors, or review attribution.

Keep one reviewable logical state per commit. Keep behavior changes with direct
tests, generators with generated artifacts, and manifest changes with required
lockfile changes. Separate unrelated documentation, dependency, build, and
behavior work. Do not commit build output, local settings, credentials, raw
audit notes, or planning files.

Before committing, inspect `git status --short`, `git diff`,
`git diff --cached`, and `git ls-files --others --exclude-standard`. Stage
explicit paths or hunks, inspect the complete staged diff, run the appropriate
validation, and run `git diff --cached --check`.

## Pull requests

Explain the resulting behavior, rationale, exact validation, compatibility or
security impact, and real issue linkage in the pull request template. The pull
request title follows the commit subject grammar because pull requests are
squash merged. Do not merge while required checks, required reviews, or
blocking review conversations are incomplete. An approving review is required
only when the live repository ruleset requires one or the maintainer explicitly
requests independent review; absence of a self-approval is not a blocker for a
sole-maintainer pull request.

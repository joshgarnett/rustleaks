# Contributing

Rustleaks is an unpublished alpha. Contributions must preserve the pinned
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

## Local workflow

Install Bazelisk and Just 1.58.0. The Justfile uses syntax that older releases
can reject before `just doctor` starts. Use the Rust toolchain selected by
`rust-toolchain.toml`; the repository pins Bazel in `.bazelversion`. `just
doctor` reports the selected versions without installing or changing anything.
Full differential checks also require Go and the exact pinned Gitleaks checkout
at `../gitleaks`. Security checks require the exact tools listed in [the
security controls](docs/SECURITY_CONTROLS.md).

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
`cargo xtask parity --all` for a change to supported compatibility behavior or
generated oracle evidence.

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
Follow [the upstream update procedure](docs/UPDATING_UPSTREAM.md). Explain
every intentional difference and add evidence that fails when the contract is
violated.

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
squash merged. Do not merge while required checks, reviews, or conversations
are incomplete.

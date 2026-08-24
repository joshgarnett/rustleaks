---
name: github-commit
description: Inspect, validate, stage, and commit Rustleaks working-tree changes with the repository's Conventional Commit contract. Use for local commit creation, not code review, pull request creation, or merging.
---

# Rustleaks commits

Create one intentionally staged, reviewable logical state per commit. Preserve
unrelated user changes and published history. Use `github-review` for a
substantive review and `github-pr` after the branch is ready.

## Inspect and group

Run all four inspections before staging:

```sh
git status --short
git diff
git diff --cached
git ls-files --others --exclude-standard
```

Read every new file directly because it is absent from `git diff`. Classify
every changed file and hunk. Keep behavior with direct tests, generators with
their generated artifacts, and manifests with required lockfiles. Separate
unrelated documentation, dependency, build, and behavior changes. Exclude
caches, build output, local settings, credentials, raw findings, and temporary
goal or audit records.

Do not use `git add .` or `git add -A` unless every affected path was read and
belongs to the same commit. Stage explicit paths or hunks. Do not discard,
stash, or overwrite unrelated work.

## Validate the staged state

Run the narrowest relevant repository command before committing. Verified
examples include:

```sh
just docs-check
bazelisk test //crates/rustleaks-core:engine_test
bazelisk test //crates/rustleaks-sources:all_tests
bazelisk test //crates/rustleaks-report:parity_tests
bazelisk test //crates/rustleaks-cli:cli_test
```

Use `just ci` and `just security` for pull-request-ready changes. Add
`just package-check`, both fuzz recipes, or `cargo xtask parity --all` only for
the boundaries named in `CONTRIBUTING.md` and the applicable Rustleaks
maintenance skill. Bazel is authoritative for normal build and test work;
Cargo does not bypass a failed Bazel action. Report only commands that passed
against the staged content.

Inspect the complete staged diff, then run:

```sh
git diff --cached
git diff --cached --check
```

Verify that required tests, generated files, lockfiles, licenses, provenance,
and attribution are included. Adding or updating dependencies, toolchains,
`rules_rust`, the Gitleaks pin, or copied default configuration requires prior
maintainer approval.

## Write the message

Use `<type>(<scope>)!: <description>`. The optional scope and `!` remain inside
the grammar. The description is imperative and present tense, starts with a
lowercase word or project identifier as grammar requires, has no final period,
and is at most 72 characters.

Choose the narrowest type: `feat`, `fix`, `perf`, `refactor`, `test`, `docs`,
`build`, `ci`, `style`, or `chore`. Use `chore` only when no other type fits.
Choose a stable scope only when useful: `core`, `sources`, `report`, `cli`,
`compat`, `xtask`, `bazel`, `deps`, `docs`, `ci`, or `release`. Omit a scope
for a cross-cutting change. Never use a goal, agent, review round, issue number,
or temporary task as a scope.

These subjects use verified repository history and boundaries:

```text
test(sources): refresh CLI runtime provenance
build(deps): replace tree hashes with boundary checks
docs(security): record hosted repository controls
```

Use `!` only for an intentional breaking change and add a
`BREAKING CHANGE: ...` footer that explains the affected API and migration.
Use a body for lasting reasons, compatibility effects, security constraints,
or non-obvious decisions. Add only true trailers. Do not invent issue links,
signoffs, co-authors, or reviews; prefer issue-closing references in the pull
request.

## Commit and verify

Create the commit only when requested. Do not amend, rebase, force-push, or
rewrite published or shared history without explicit permission. After the
commit, inspect:

```sh
git show --stat --oneline HEAD
git status --short
```

Confirm the commit contains the intended group and the remaining tree contains
only understood work.

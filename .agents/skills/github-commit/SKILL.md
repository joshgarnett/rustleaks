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

Do not split files required for the commit to build or validate. Favor a small
number of coherent commits over artificial file-by-file history. Incremental
branch commits remain useful review and debugging checkpoints even though pull
requests are squash merged; each checkpoint must still be understandable and
reviewable.

When the changes are associated with a real issue, inspect it with
`gh issue view <issue-number>` and check that the commit group is consistent
with its intent and acceptance criteria. Do not invent linkage.

Do not use `git add .` or `git add -A` unless every affected path was read and
belongs to the same commit. Stage explicit paths or hunks. Do not discard,
stash, or overwrite unrelated work.

## Validate the staged state

Run the narrowest relevant repository command before committing. The
[local workflow](../../../CONTRIBUTING.md#local-workflow) table names the
command for each kind of change. Focused examples:

```sh
just docs-check
bazelisk test //crates/rustleaks-core:engine_test
bazelisk test //crates/rustleaks-sources:all_tests
bazelisk test //crates/rustleaks-report:parity_tests
bazelisk test //crates/rustleaks-cli:cli_test
```

Use `just ci` and `just security` for pull-request-ready changes, and the
other commands only for the boundaries named in `CONTRIBUTING.md` and the
applicable Rustleaks maintenance skill. Bazel is the authority for normal
build and test work; Cargo does not bypass a failed Bazel action. Report only
commands that passed against the staged content.

Validation that reads the working tree cannot prove the finalized staged state
while unstaged tracked changes are present. Preserve unrelated work, but use an
isolated clean worktree for the staged content or report that validation as not
established; never silently attribute a mixed-tree result to the staged group.

Inspect the complete staged diff, then run:

```sh
git diff --cached
git diff --cached --check
```

Verify that required tests, generated files, lockfiles, licenses, provenance,
and attribution are included. Changes listed under [Approval
boundaries](../../../AGENTS.md#approval-boundaries) need maintainer approval
first. Never hand-edit generated corpora, inventories, snapshots, or
lockfiles; use the maintained generator or regeneration command.

## Write the message

Follow [Commits](../../../CONTRIBUTING.md#commits) in `CONTRIBUTING.md` for
the subject grammar, types, scopes, breaking changes, reverts, bodies and
trailers. Describe the resulting repository state, not the activity used to
reach it. Never use an issue number or ticket identifier as a scope.

These subjects come from repository history:

```text
feat(cli): write Rustleaks help, usage and error text
test(cli): skip shell syntax checks on Windows hosts
docs: adopt a standalone compatibility policy
```

Do not include goal status, agent narration, review history, raw command logs
or planning references in the body. Prefer issue-closing references in the
pull request.

## Commit and verify

Create the commit when the user requests a commit or asks to take the change
through a pull request or merge. Do not amend, rebase, force-push, or rewrite
published or shared history without explicit permission. After the commit,
inspect:

```sh
git show --stat --oneline HEAD
git status --short
```

Confirm the commit contains the intended group and the remaining tree contains
only understood work. When validation applies to the finalized staged tree and
there are no unstaged tracked changes, record `git write-tree` before the
commit and confirm it equals `git rev-parse HEAD^{tree}` afterward; a matching
tree does not need retesting solely because the commit identifier changed.

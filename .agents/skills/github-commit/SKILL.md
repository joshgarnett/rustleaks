---
name: github-commit
description: Inspect, check, stage and commit Rustleaks working-tree changes with the repository's commit rules. Use for local commit creation, not code review, pull request creation or merging.
---

# Rustleaks commits

[Commits](../../../CONTRIBUTING.md#commits) in `CONTRIBUTING.md` holds the
subject grammar, types, scopes, commit contents and the steps before
committing. Follow it. This skill adds what agents get wrong.

## Stage

- Run the four inspections in CONTRIBUTING.md before staging. Read every new
  file directly, because `git diff` does not show it.
- Stage explicit paths or hunks. Use `git add -A` only when you read every
  changed path and all of it belongs in the commit.
- Leave caches, build output, local settings, credentials, raw findings and
  audit or planning notes out of the commit.
- Never discard, stash or overwrite unrelated work.
- Changes listed under [Approval
  boundaries](../../../AGENTS.md#approval-boundaries) need maintainer
  approval first.

## Check

Run the command that the [local
workflow](../../../CONTRIBUTING.md#local-workflow) table names for the
change, for example:

```sh
just docs-check
bazelisk test //crates/rustleaks-core:engine_test
```

A check that reads the working tree does not prove the staged state while
unstaged tracked changes exist. Check the staged content in a clean worktree,
or report the check as not done. Report only commands that passed.

## Write and commit

Describe the resulting state, not the work done to reach it. Never use an
issue number or ticket as a scope. Subjects from repository history:

```text
feat(cli): write Rustleaks help, usage and error text
perf(sources): hand work to idle workers without a shared receiver lock
docs: adopt a standalone compatibility policy
```

Commit only when the user asks for a commit, a pull request or a merge. Do
not amend, rebase, force-push or rewrite published history without explicit
permission. After the commit, run `git show --stat --oneline HEAD` and
`git status --short` to confirm the commit holds the intended group.

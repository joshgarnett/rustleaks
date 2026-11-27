---
name: github-review
description: Review Rustleaks working-tree changes, a complete branch diff or a GitHub pull request and report findings backed by evidence. Use for code review and review before a pull request, not commit, pull request or merge execution.
---

# Rustleaks review

Review is separate from committing, opening a pull request and merging. Do
not do those unless the user asks. A read-only review posts nothing to
GitHub. Use `gh pr review` only when the user asks for that exact submission,
and never approve your own pull request. The merge rules are in [Pull
requests](../../../CONTRIBUTING.md#pull-requests).

## What to read

- Working tree: `git status --short`, `git diff`, `git diff --cached` and
  `git ls-files --others --exclude-standard`, then read each new file.
- Branch: the complete diff from `git merge-base HEAD origin/main`, not only
  the last commit.
- Pull request: `gh pr view`, `gh pr diff` and `gh pr checks`, and each
  linked issue that defines the intent.

## What to check

In order: correctness, security, data loss, concurrency, error semantics,
public API, the [repository
contract](../../../AGENTS.md#repository-contract) (no lost secret, each
finding change tested and in the changelog), cleanup, performance, test
quality, maintainability and documentation.

For this repository, also check:

- the [invariants](../../../AGENTS.md#invariants), including the synchronous
  in-memory core, the ban on unsafe code in owned crates other than
  `rustleaks-ffi`, and a `SAFETY:` comment on every unsafe block there;
- that expected findings, spans, fingerprints, report fields, exit codes and
  error classes come from the intended behavior, not from current output;
- that a presentation change has an updated expectation that matches its
  stated intent; and
- for Bazel, target boundaries, visibility, direct dependencies and
  generated files.

Use the matching `rustleaks-*` skill when the change crosses its boundary.
Run a focused target, such as
`bazelisk test //crates/rustleaks-core:engine_test`, when it tests the
concern. Never claim an unrun command passed.

## Report

Give each finding a severity (`critical`, `high`, `medium` or `low`), the file
and line, the defect, why it matters and a fix when useful. Separate blocking
findings from suggestions. Do not block on style. If there are no findings,
say so. Always state what was reviewed, which checks passed on that state,
and what was not checked.

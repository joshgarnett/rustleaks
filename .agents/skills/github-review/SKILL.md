---
name: github-review
description: Review Rustleaks working-tree changes, a complete branch diff, or a GitHub pull request and report evidence-based findings. Use for code review and pre-PR review, not commit, PR, or merge execution.
---

# Rustleaks review

Treat review as a separate engineering task. Inspect intent, complete changed
content, surrounding code, tests, and repository invariants. Do not create a
commit, pull request, review submission, or merge unless the user separately
requests the matching workflow.

An evidence-based local review can qualify a sole-maintainer change when the
live ruleset requires no approving review. Do not attempt to approve your own
pull request or represent local review as an eligible GitHub approval.

## Select one mode

### Working tree

Inspect unstaged, staged, and untracked content:

```sh
git status --short
git diff
git diff --cached
git ls-files --others --exclude-standard
```

Read every relevant new file directly.

### Branch

Determine the default and base branch from repository and remote evidence;
normally this repository uses `origin/main`. Refresh read-only remote refs when
needed. Record the merge base, then review the complete diff and useful commit
context, not only the latest commit:

```sh
git merge-base HEAD origin/main
git diff <merge-base>..HEAD
git log --oneline <merge-base>..HEAD
```

### Pull request

Inspect the pull request, complete diff, and checks with GitHub CLI:

```sh
gh pr view <pr-number>
gh pr diff <pr-number>
gh pr checks <pr-number>
```

Inspect each linked issue with `gh issue view <issue-number>` when it defines
intent or acceptance criteria. A read-only review does not post to GitHub. Use
`gh pr review <pr-number> --approve`, `--comment`, or `--request-changes` only
when the current user request explicitly authorizes that exact submission.

## Review the relevant boundary

Prioritize correctness, security, data loss, concurrency, error semantics,
public API and pinned Gitleaks compatibility, cleanup, meaningful performance,
test quality, maintainability, documentation, and enforced style in that
order when applicable.

For Rust, inspect relevant ownership and lifetime assumptions, unnecessary
cloning, panic and ignored-result paths, integer and path handling, platform
assumptions, cancellation and resource budgets, `Send + Sync`, and the owned
crates' unsafe prohibition. Preserve exact bytes, findings, spans, errors, and
the synchronous in-memory core boundary. For Bazel, inspect target boundaries,
visibility, direct dependencies, hermeticity, feature representation,
generated artifacts, and nearby BUILD conventions. Apply the matching
Rustleaks maintenance skill when the change crosses its specialized boundary.

Verify suspected defects against surrounding code and existing tests when
practical. Run focused targets such as
`bazelisk test //crates/rustleaks-core:engine_test` only when they materially
test the reviewed concern. Do not claim an unrun command passed.

## Report findings first

For every finding, provide `critical`, `high`, `medium`, or `low` severity; the
file and precise location; the defect; why it matters; and a concrete
remediation direction when useful. Separate blocking findings from
non-blocking suggestions. Do not inflate severity, invent findings, or block
on subjective style.

If there are no meaningful findings, say so directly. In all cases, state:

- which mode, base, commit range, paths, or pull request was reviewed;
- which commands or checks succeeded against that state; and
- what was not validated and why.

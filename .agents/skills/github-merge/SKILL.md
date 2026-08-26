---
name: github-merge
description: Assess final Rustleaks pull request readiness and perform an explicitly authorized squash merge. Use for merge decisions and execution, not issue, commit, review, or PR authoring.
---

# Rustleaks merges

Merge only a fully qualified pull request with explicit user authorization.
Authorization may name the exact pull request or cover a named change being
taken through an end-to-end pull request workflow. It remains valid while
checks run if the head diff, target branch, and requested scope do not
materially change. Readiness inspection alone does not authorize a merge, and
merge authorization does not authorize remote branch deletion.

## Prove readiness

Inspect the current pull request state, complete diff, checks, linked issues,
reviews, conversations, and repository protections:

```sh
gh pr view <pr-number>
gh pr diff <pr-number>
gh pr checks <pr-number>
```

Use structured `gh pr view --json` fields and read-only `gh api` queries when
needed to establish state rather than inferring it from prose. Confirm every
condition:

- the pull request is open, is not a draft, and targets `main`;
- the complete change matches its title, body, and linked issue intent;
- the title satisfies the `github-commit` Conventional Commit grammar;
- every check required by the live ruleset is present and successful, with no
  required job pending, skipped unexpectedly, cancelled, stale, or failing;
- an eligible approving review exists when the live ruleset requires one or
  the maintainer explicitly requested independent review;
- every blocking review conversation is resolved, along with any conversation
  whose resolution is required by the live ruleset;
- GitHub reports the pull request mergeable and not conflicted or blocked;
- issue-closing references are correct;
- `just ci`, `just security`, and every boundary-specific final validation
  required by `CONTRIBUTING.md` passed against the reviewed state; and
- no branch protection, check, review, conversation, or other requirement is
  being bypassed.

Refuse to merge when required evidence is missing or uncertain. In particular,
refuse a draft, failing, pending, stale, closed, conflicted, blocked, or
unmergeable pull request. A branch being behind its base blocks the merge only
when the live ruleset requires an update or intervening base changes invalidate
the reviewed result. Do not invent an approving review or require one when the
live ruleset allows a sole-maintainer merge. Report each unmet condition and
the evidence needed to clear it. Do not use the repository owner's bypass,
force, or a local merge as a substitute for a failed requirement.

## Merge only by squash

After every condition passes and the user authorization still covers the
unchanged candidate, the permitted merge command is:

```sh
gh pr merge <pr-number> --squash
```

Never use `--merge`, `--rebase`, or a bypass flag. Afterward, verify the final
pull request state and accepted commit with `gh pr view <pr-number>`. Remote
branch deletion is a separate GitHub mutation and requires separate authority
plus an observed repository convention; never delete an unrelated branch.

---
name: github-merge
description: Assess final Rustleaks pull request readiness and perform an explicitly authorized squash merge. Use for merge decisions and execution, not issue, commit, review, or PR authoring.
---

# Rustleaks merges

Merge only a fully qualified pull request and only with an explicit current
request to merge that exact pull request. Readiness inspection is read-only;
it does not authorize the merge or remote branch deletion.

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
- the strict `main` contexts `Required`, `Analyze (rust)`, and
  `Analyze (actions)` are present and successful, with no required job pending,
  skipped unexpectedly, cancelled, stale, or failing;
- at least one eligible approving review exists and required review policy is
  satisfied;
- every review conversation is resolved;
- GitHub reports the pull request mergeable and not conflicted or blocked;
- issue-closing references are correct;
- `just ci`, `just security`, and every boundary-specific final validation
  required by `CONTRIBUTING.md` passed against the reviewed state; and
- no branch protection, check, review, conversation, or other requirement is
  being bypassed.

Refuse to merge when any evidence is missing or uncertain. In particular,
refuse a draft, behind-base, failing, pending, unreviewed, unresolved, stale,
closed, conflicted, blocked, or unmergeable pull request. The live ruleset's
current zero-approval and optional-conversation settings do not weaken these
requirements. Report each unmet condition and the evidence needed to clear it.
Do not use the repository owner's bypass, auto-merge, force, or a local merge
as a substitute.

## Merge only by squash

After every condition passes and the current user explicitly authorizes the
exact merge, the only permitted merge command is:

```sh
gh pr merge <pr-number> --squash
```

Never use `--merge`, `--rebase`, or a bypass flag. Afterward, verify the final
pull request state and accepted commit with `gh pr view <pr-number>`. Remote
branch deletion is a separate GitHub mutation and requires separate authority
plus an observed repository convention; never delete an unrelated branch.

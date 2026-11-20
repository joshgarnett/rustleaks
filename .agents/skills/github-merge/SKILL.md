---
name: github-merge
description: Check final Rustleaks pull request readiness and perform an explicitly authorized squash merge. Use for merge decisions and execution, not issue, commit, review or pull request authoring.
---

# Rustleaks merges

[Pull requests](../../../CONTRIBUTING.md#pull-requests) in `CONTRIBUTING.md`
holds the merge rules. Follow it.

## Authority

Merge only with explicit user authorization. It may name the pull request or
cover a named change taken through the whole pull request workflow. It stays
valid while checks run if the head diff, base branch and scope do not
change. Checking readiness does not authorize a merge, and a merge does not
authorize deleting the remote branch.

## Check readiness

```sh
gh pr view <pr-number>
gh pr diff <pr-number>
gh pr checks <pr-number>
```

Use `gh pr view --json` and read-only `gh api` calls for state instead of
reading it from prose. Merge only when:

- the pull request is open, not a draft, and targets `main`;
- the diff matches the title, body and linked issues;
- the title follows the [commit grammar](../../../CONTRIBUTING.md#commits);
- every required check passed and none is pending, cancelled or skipped
  without reason;
- the branch is up to date with `main`, because required checks are strict;
- every blocking review conversation is resolved;
- GitHub reports the pull request as mergeable; and
- `just ci`, `just security` and the checks that CONTRIBUTING.md requires for
  the changed boundary passed on the reviewed state.

The ruleset requires no approving review, so an empty review list is not a
blocker unless the maintainer asked for an independent review. Do not ask
for or create a self-approval. Report each unmet condition and what would
clear it. Never use the owner's bypass, a force push or a local merge in
place of a failed requirement.

## Merge

```sh
gh pr merge <pr-number> --squash
```

Never use `--merge`, `--rebase` or a bypass flag. Afterward, confirm the
state with `gh pr view <pr-number>`. Delete a remote branch only with
separate authorization.

---
name: github-issue
description: Investigate, draft, create or edit Rustleaks GitHub issues, including duplicate searches and done-when criteria. Use for issue work, not implementation, commits, reviews, pull requests or merges.
---

# Rustleaks GitHub issues

Follow [Issues](../../../CONTRIBUTING.md#issues) in `CONTRIBUTING.md`. It
says what belongs in an issue, which form to use, what counts as a
compatibility gap, and how labels work. Do not open an issue for a tracker,
log, status report or plan.

## Investigate first

The repository is `joshgarnett/rustleaks`. Search before drafting:

```sh
gh issue list --state all --search "<distinct problem terms>"
gh pr list --state all --search "<distinct problem terms>"
gh issue view <issue-number> --comments
```

Compare an existing issue with the current tree, the compatibility policy
and the relevant tests before you treat it as current. Never invent an issue
number.

## Draft

Use the matching form under `.github/ISSUE_TEMPLATE/` and keep its required
fields and title prefix (`bug: `, `compat: ` or `feat: `). A difference
listed in [Differences from
Gitleaks](../../../docs/user/gitleaks-differences.md) is intended and is not
a compatibility gap. Use only synthetic or reviewed public data.

State the problem, the wanted outcome, when it is done, the exact revision
and environment, and checks already run. In a pull request, use
`Closes #<issue-number>` when the change resolves the issue and
`Refs #<issue-number>` otherwise.

## Authority

Reading and drafting need no approval. Creating, editing, closing, labeling,
assigning or commenting on a real issue needs a user request for that exact
action. Without it, stop with the draft. After an action, run
`gh issue view <issue-number>` and report the URL and state.

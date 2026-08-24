---
name: github-issue
description: Investigate, draft, create, or edit Rustleaks GitHub issues, including duplicate searches and acceptance criteria. Use for issue work, not implementation, commits, reviews, pull requests, or merges.
---

# Rustleaks GitHub issues

Use issues to establish intent and acceptance criteria when the work benefits
from a durable problem record. Do not require an issue for trivial work. Keep
implementation, commits, reviews, pull requests, and merges in their matching
skills.

## Investigate first

Confirm the remote is `joshgarnett/rustleaks`, then inspect existing issues and
related pull requests before drafting or changing anything:

```sh
gh issue list --state all --limit 20
gh issue list --state all --search "<distinct problem terms>"
gh issue view <issue-number> --comments
```

Use `gh pr list --state all --search "<distinct problem terms>"` when a prior
change may already address the request. Never invent an issue number. Compare
an existing issue with the current tree, pinned Gitleaks profile, and relevant
tests before treating its description as current.

## Use the repository forms

Read the applicable file under `.github/ISSUE_TEMPLATE/` and retain its
required fields:

- `defect.yml` for reproducible incorrect Rustleaks behavior;
- `compatibility.yml` for a field-level difference from Gitleaks commit
  `b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b`; and
- `feature.yml` for a capability or maintained-workflow proposal.

Preserve the form's verified title prefix: `bug: `, `compat: `, or `feat: `.

State the observable problem or need, desired outcome, acceptance criteria,
constraints, exact revision and environment when applicable, and validation
already run. Use the repository terms `rustleaks-core`,
`rustleaks-sources`, `rustleaks-report`, `rustleaks-cli`, compatibility
evidence, and `xtask` only when they match the actual boundary. Use synthetic
or reviewed public data. Keep live credentials, raw findings, private
repository content, exploit details, and non-public vulnerabilities out of an
issue; route sensitive reports through `SECURITY.md`.

Link dependencies or blockers only after inspecting both issues. Use
`Closes #<issue-number>` later in a pull request only when the change fully
resolves the issue; use `Refs #<issue-number>` for a non-closing relationship.

## Respect authority

Reading and drafting are local or read-only. Creating, editing, closing,
reopening, labeling, assigning, or commenting on a real issue requires the
current user request to authorize that exact GitHub mutation. Stop with the
draft when it does not. After an authorized mutation, re-open the issue with
`gh issue view <issue-number>` and report the resulting URL and state.

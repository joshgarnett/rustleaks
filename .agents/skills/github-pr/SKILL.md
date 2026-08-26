---
name: github-pr
description: Assess, create, or update a Rustleaks pull request from a complete branch diff with truthful validation and issue linkage. Use for PR preparation and mutation, not issue authoring, commit creation, substantive review, or merging.
---

# Rustleaks pull requests

Prepare one logical change for review. Use `github-issue` for issue content,
`github-commit` for local commits, `github-review` for substantive pre-PR
review, and `github-merge` for final readiness and merge execution.

## Establish the candidate

Confirm the repository, current branch, default base, working tree, and
existing pull request state:

```sh
gh repo view
git branch --show-current
git status --short
gh pr status
```

Do not open a pull request from `main`. Determine the base from live repository
evidence, normally `main`, and inspect the complete branch change from its
merge base:

```sh
git merge-base HEAD origin/main
git diff <merge-base>..HEAD
git log --oneline <merge-base>..HEAD
```

Observed topic branches use narrow prefixes such as `ci/`, `fix/`, and
`docs/`, but no repository file mandates a branch grammar. Do not invent or
enforce one.

Compare the complete change with each linked issue and the stated intent.
Resolve substantive findings through `github-review`. Do not describe the
branch as ready while unrelated changes, missing generated artifacts, or
unexplained failures remain.

## Validate and write the pull request

Before opening a pull request, run the repository-required local gates:

```sh
just ci
just security
```

Add the conditional package, fuzz, fresh parity, or maintenance gates required
by `CONTRIBUTING.md` for the changed boundary. Record exact successful commands
and explain a required command that was not run. Never copy a result from a
different tree or claim an unrun command passed.

The title becomes the permanent squash commit subject. Apply the
`github-commit` grammar and verified scopes. Follow
`.github/pull_request_template.md` with `Summary`, `Rationale`, `Validation`,
`Compatibility and security`, and `Issues` sections. Use
`Closes #<issue-number>` only when the pull request fully resolves that real
issue; use `Refs #<issue-number>` otherwise. Do not invent issue linkage.

## Respect authority and verify

Read-only inspection and a local draft do not authorize a push or pull request
mutation. A request to create or update a pull request, or to take a named
change through an end-to-end pull request workflow, authorizes the ordinary
push and pull request create or edit operations needed for that workflow. It
does not authorize a force-push, protection bypass, unrelated edit, or remote
branch deletion. Prefer:

```sh
git push --set-upstream origin <branch>
gh pr create --base main --title "<title>" --body-file <body-file>
gh pr edit <pr-number> --title "<title>" --body-file <body-file>
```

Do not force-push or bypass protections. After an authorized create or edit,
verify the title, base, head, body, draft state, URL, and checks with:

```sh
gh pr view <pr-number>
gh pr checks <pr-number>
```

For `main`, reconcile every context required by the live ruleset and confirm
that the maintained CI and native target lanes expected for the changed
boundary ran. Report missing, pending, stale, or failing checks as such, not as
completed validation.

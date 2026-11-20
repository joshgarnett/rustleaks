---
name: github-pr
description: Check, create or update a Rustleaks pull request from a complete branch diff with accurate check results and issue links. Use for pull request preparation and changes, not issue authoring, commit creation, substantive review or merging.
---

# Rustleaks pull requests

[Pull requests](../../../CONTRIBUTING.md#pull-requests) in `CONTRIBUTING.md`
holds the rules. Use `github-commit` for commits, `github-review` for review
and `github-merge` to merge.

## Prepare

Never open a pull request from `main`. Review the complete branch change from
its merge base with `origin/main`, not only the last commit:

```sh
git merge-base HEAD origin/main
git diff <merge-base>..HEAD
git log --oneline <merge-base>..HEAD
```

Do not call the branch ready while it has unrelated changes, missing
generated files or unexplained failures. No branch naming rule exists; do not
invent one.

## Check and write

Run `just ci` and `just security`, and add the package, fuzz or maintenance
checks that the [local workflow](../../../CONTRIBUTING.md#local-workflow)
table requires for the changed boundary. List the exact commands that passed
and explain any required check that did not run. Never copy a result from a
different tree.

The title becomes the squash commit subject, so it follows the [commit
grammar](../../../CONTRIBUTING.md#commits). Fill in every section of
`.github/pull_request_template.md`. Link only real issues.

## Authority

Reading and a local draft do not authorize a push. A request to create or
update a pull request, or to take a named change through the pull request
workflow, authorizes the normal push and `gh pr create` or `gh pr edit`. It
does not authorize a force push, a bypass, unrelated edits or deleting a
remote branch.

```sh
git push --set-upstream origin <branch>
gh pr create --base main --title "<title>" --body-file <body-file>
```

Afterward, check the title, base, body and checks with `gh pr view` and
`gh pr checks`. Report pending or failing checks as such.

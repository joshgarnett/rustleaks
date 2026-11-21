# Using Rustleaks in CI and Git hooks

This guide is for people who run Rustleaks automatically: in a CI pipeline,
in GitHub Actions, or in a Git hook before each commit.

## Exit codes in automation

With the defaults, findings and errors both exit with 1. If your pipeline must
tell them apart, choose another value for findings, for example
`--exit-code 3`. Do not use 2 or 126. See [Exit
codes](cli-reference.md#exit-codes) for every code.

A missing or unreadable baseline file does not fail the scan, and every
earlier finding is reported again. See [Baselines](configuration.md#baselines).
Check the log if a baseline scan reports more than you expect.

## GitHub Actions

This workflow installs a release build, scans the full history, and uploads
the results to GitHub code scanning.

```yaml
name: Secret scan

on:
  push:
  pull_request:

permissions:
  contents: read
  security-events: write

jobs:
  rustleaks:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v7
        with:
          fetch-depth: 0

      - name: Install Rustleaks
        env:
          GH_TOKEN: ${{ github.token }}
          VERSION: 0.1.0-alpha.12
        run: |
          stem="rustleaks-${VERSION}-x86_64-unknown-linux-gnu"
          gh release download "v${VERSION}" --repo joshgarnett/rustleaks \
            --pattern "${stem}.tar.gz" --pattern "${stem}.SHA256SUMS"
          sha256sum --check --ignore-missing "${stem}.SHA256SUMS"
          tar -xzf "${stem}.tar.gz"
          echo "${PWD}/${stem}" >> "${GITHUB_PATH}"

      - name: Scan
        run: >
          rustleaks git . --no-banner --redact
          --report-format sarif --report-path results.sarif

      - name: Upload SARIF
        if: always() && hashFiles('results.sarif') != ''
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: results.sarif
```

Notes:

- `fetch-depth: 0` fetches the full history. The default checkout has only the
  last commit.
- `--redact` keeps secret values out of the uploaded SARIF file.
- The SARIF file names the tool `gitleaks`. See [SARIF](reports.md#sarif).
- The upload step runs even when the scan step fails, for example because it
  found secrets.
- For stronger supply-chain safety, pin each action to a full commit SHA.

### Scan only the commits in a pull request

`--log-opts` passes options to `git log`. To scan only the new commits of a
pull request, run the workflow only on `pull_request` and use this step in
place of the Scan step above:

```yaml
      - name: Scan pull request commits
        run: >
          rustleaks git . --no-banner --redact
          --log-opts="${{ github.event.pull_request.base.sha }}..${{ github.event.pull_request.head.sha }}"
          --report-format sarif --report-path results.sarif
```

## Scanning a range of history

By default `rustleaks git` scans every commit reachable from any branch or
tag. `--log-opts` replaces the `git log` options. See
[git](cli-reference.md#git) for the default options and how Rustleaks splits
the value. Examples:

```sh
# Commits on the current branch since main
rustleaks git . --log-opts="main..HEAD"

# The last 20 commits on the current branch
rustleaks git . --log-opts="-n 20"

# All branches, from one date
rustleaks git . --log-opts="--all --since=2026-01-01"
```

## Pre-commit hooks

`rustleaks git` has two flags for checking changes that are not committed yet:

| Flag | What it scans |
| --- | --- |
| `--staged` | Changes in the Git index, which is what the next commit will contain (`git diff --staged`). |
| `--pre-commit` | Changes in the working tree that are not staged yet (`git diff`). |

If you give both flags, Rustleaks scans the staged changes. Findings from these
modes have no commit, so their fingerprints have the form
`file:rule-id:line`.

For a hook that runs before each commit, use `--staged`.

### A plain Git hook

Save this as `.git/hooks/pre-commit` and make it executable
(`chmod +x .git/hooks/pre-commit`):

```sh
#!/bin/sh
exec rustleaks git --staged --no-banner --redact --verbose
```

Git stops the commit when the hook exits with a code other than 0.
`--verbose` prints each finding so you can see what to fix. To commit anyway
after review, add a `rustleaks:allow` comment to the line or add the
fingerprint to `.rustleaksignore`. See [Configuration](configuration.md).

### The pre-commit framework

With [pre-commit](https://pre-commit.com), add a local hook to
`.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: rustleaks
        name: rustleaks
        entry: rustleaks git --staged --no-banner --redact --verbose
        language: system
        pass_filenames: false
```

`rustleaks` must be on the `PATH` of every developer who uses the hook.

## Links to findings

For a history scan, Rustleaks can add a web link to each finding. It reads the
URL of the repository's remote with `git ls-remote --get-url` and builds the
link from the host name.

| Host | Platform |
| --- | --- |
| `github.com` | GitHub |
| `gitlab.com` | GitLab |
| `dev.azure.com`, `visualstudio.com` | Azure DevOps |
| `gitea.com`, `code.forgejo.org`, `codeberg.org` | Gitea |
| `bitbucket.org` | Bitbucket |

For a self-hosted server, set the platform yourself with `--platform`, for
example `--platform gitlab`. `--platform none` turns links off and does not
run `git ls-remote`. See [git](cli-reference.md#git) for every value.

Links appear in the `Link` field of reports and in `--verbose` output.
`--staged` and `--pre-commit` scans have no links.

## Other useful flags

| Flag | Use |
| --- | --- |
| `--no-banner` | Hide the banner in logs. |
| `--log-level LEVEL` | `trace`, `debug`, `info` (the default), `warn`, `error` or `fatal`. |
| `--timeout N` | Stop after N seconds. A scan that times out exits with 1, or with 2 under `--complete-profile`, and reports only what it found so far. |
| `--baseline-path FILE` | Report only findings that are not in an earlier JSON report. See [Baselines](configuration.md#baselines). |
| `--complete-profile FILE` | Fail with exit code 2 unless the scan covered all of its input. See [Complete scanning](complete-scanning.md). |

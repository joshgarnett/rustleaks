# Getting started

This guide is for people who want to run the `rustleaks` command. If you want
to call the scanner from Rust code, read [Using rustleaks-core](library.md).

These guides describe the current source. Features listed under Unreleased in
the [changelog](../../CHANGELOG.md) are not in 0.1.0-alpha.9. To use them now,
[build from source](#build-from-source).

## What Rustleaks is

Rustleaks finds secrets, such as API keys and passwords, in files, Git history
and standard input. It reads Gitleaks configuration files. See [Differences
from Gitleaks](gitleaks-differences.md).

## Install

### From a GitHub release

Each release on the
[releases page](https://github.com/joshgarnett/rustleaks/releases) has one
archive for each supported target. All releases are currently marked as
pre-releases.

| Target | Archive |
| --- | --- |
| Linux x86_64 (glibc) | `rustleaks-VERSION-x86_64-unknown-linux-gnu.tar.gz` |
| Linux ARM64 (glibc) | `rustleaks-VERSION-aarch64-unknown-linux-gnu.tar.gz` |
| Linux x86_64 (musl) | `rustleaks-VERSION-x86_64-unknown-linux-musl.tar.gz` |
| Linux ARM64 (musl) | `rustleaks-VERSION-aarch64-unknown-linux-musl.tar.gz` |
| macOS Intel | `rustleaks-VERSION-x86_64-apple-darwin.tar.gz` |
| macOS Apple silicon | `rustleaks-VERSION-aarch64-apple-darwin.tar.gz` |
| Windows x86_64 | `rustleaks-VERSION-x86_64-pc-windows-msvc.tar.gz` |
| Windows ARM64 | `rustleaks-VERSION-aarch64-pc-windows-msvc.tar.gz` |

`VERSION` is the release version without the leading `v`, for example
`0.1.0-alpha.9`. The release tag is `vVERSION`.

Each archive contains one folder named like the archive, without `.tar.gz`.
The folder holds the `rustleaks` program (`rustleaks.exe` on Windows),
`README.md`, `LICENSE`, `NOTICE` and a `licenses` folder.

Next to each archive, the release has these files with the same name start:

- `.SHA256SUMS`, the checksums;
- `.attestation.jsonl`, the GitHub attestation bundle;
- `.cdx.json`, a CycloneDX SBOM;
- `.provenance.json`, `.manifest.json` and `.reproducibility.json`, which
  describe how the archive was built; and
- `.source-relink.json`, for the Linux glibc targets only.

The release also has one `rustleaks-VERSION-corresponding-source.tar.gz`
archive with source material for the Linux glibc builds.

This example installs the Linux x86_64 build with the GitHub CLI:

```sh
VERSION=0.1.0-alpha.9
TARGET=x86_64-unknown-linux-gnu
STEM="rustleaks-${VERSION}-${TARGET}"
gh release download "v${VERSION}" --repo joshgarnett/rustleaks \
  --pattern "${STEM}.tar.gz" \
  --pattern "${STEM}.SHA256SUMS" \
  --pattern "${STEM}.attestation.jsonl"
sha256sum --check --ignore-missing "${STEM}.SHA256SUMS"
gh attestation verify "${STEM}.tar.gz" --repo joshgarnett/rustleaks \
  --bundle "${STEM}.attestation.jsonl"
tar -xzf "${STEM}.tar.gz"
"./${STEM}/rustleaks" version
```

On macOS, use `shasum -a 256 --check --ignore-missing` instead of `sha256sum`.
On Windows, run `Get-FileHash -Algorithm SHA256 FILE` in PowerShell and
compare the hash with the line for the archive in the `.SHA256SUMS` file.
`tar -xzf` also works on Windows 10 and later.

Move the program to a folder on your `PATH` if you want to run it as
`rustleaks`.

The `rustleaks` command is not published on crates.io. Only the
`rustleaks-core` library is published there.

### Build from source

Building from source needs [Bazelisk](https://github.com/bazelbuild/bazelisk)
and Git. Bazelisk downloads the Bazel version that the repository selects.

```sh
git clone https://github.com/joshgarnett/rustleaks.git
cd rustleaks
bazelisk build //crates/rustleaks-cli:rustleaks
./bazel-bin/crates/rustleaks-cli/rustleaks version
```

Contributors should read [CONTRIBUTING.md](../../CONTRIBUTING.md) for the full
tool setup.

### Git

The `git` command runs the `git` program that it finds on your `PATH`.
Install Git before you scan a repository. The `dir` and `stdin` commands do
not need Git.

## First scans

Rustleaks has three scan commands.

| Command | What it scans |
| --- | --- |
| `rustleaks dir [path]` | A folder or a single file. `file` and `directory` are other names for `dir`. |
| `rustleaks git [repo]` | The history of a Git repository, or its staged or unstaged changes. |
| `rustleaks stdin` | Bytes read from standard input. |

The path defaults to the current folder.

Scan the files in the current folder:

```sh
rustleaks dir .
```

Scan every commit in the current repository:

```sh
rustleaks git .
```

Scan the output of another command:

```sh
cat app.log | rustleaks stdin
```

All three commands use the default rules unless you give a configuration. See
[Configuration](configuration.md).

## Reading the output

A scan prints a banner, log lines and a summary on standard error. Add
`--no-banner` to hide the banner. With no findings, the summary looks like
this:

```text
info scanned ~74 bytes (74 bytes) in 7ms
info no leaks found
```

When there are findings, the last line says how many:

```text
warn leaks found: 1
```

Add `-v` (`--verbose`) to print each finding on standard output. This example
also uses `--redact`, which hides the secret value:

```sh
rustleaks dir . --verbose --redact
```

```text
Finding:     REDACTED
Secret:      REDACTED
RuleID:      aws-access-token
Entropy:     3.246439
File:        app.txt
Line:        2
Fingerprint: app.txt:aws-access-token:2
```

Without `--redact`, the `Finding` and `Secret` lines show the matched text.
Git findings also show the commit, author, email, date and, when Rustleaks
can build one, a link to the line. To hide only part of each secret, see
[`--redact`](cli-reference.md#reports-and-output).

To save findings in a file, add `--report-path` and a format:

```sh
rustleaks dir . --report-path findings.json
rustleaks dir . --report-format sarif --report-path -
```

`-` writes the report to standard output. See [Reports](reports.md) for all
formats and fields.

## Exit codes

A scan exits with 0 when it finds nothing and with 1 when it finds secrets.
It also exits with 1 when it fails. See [Exit codes](cli-reference.md#exit-codes)
for every code and for how to tell findings and errors apart.

## Getting help

`rustleaks help` lists the commands, the flags, the configuration order and
the exit codes. `rustleaks help git` shows the flags and examples for one
command. `rustleaks completion bash` prints a shell completion script. The
`help` and `completion` commands are not in 0.1.0-alpha.9. See the [command
reference](cli-reference.md) for every command and flag.

## Next steps

- [Command reference](cli-reference.md): every command, flag, environment
  variable and exit code.
- [Configuration](configuration.md): rules, allowlists, ignore files and
  baselines.
- [Reports](reports.md): JSON, CSV, JUnit, SARIF and template reports.
- [Using Rustleaks in CI](ci.md): GitHub Actions and pre-commit hooks.
- [Native rule packs](native-rule-packs.md): optional extra rules.
- [Complete scanning](complete-scanning.md): scans that must cover every byte
  or fail.
- [Resource limits](resource-limits.md): built-in limits and what happens when
  a scan reaches one.
- [Differences from Gitleaks](gitleaks-differences.md): what to expect if you
  move from Gitleaks.
- [Using rustleaks-core](library.md): the Rust library.

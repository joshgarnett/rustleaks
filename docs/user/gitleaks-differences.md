# Differences from Gitleaks

This guide is for people who move from Gitleaks to Rustleaks, or who run both.
It lists what stays the same, what is different, and what Rustleaks adds.

Rustleaks is an independent project. It is not affiliated with or endorsed by
Gitleaks. See [NOTICE](../../NOTICE) for attribution.

## Compatibility policy

Rustleaks is backward compatible with one pinned Gitleaks revision: commit
`b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b` (`v8.30.0-27-gb58d3f1`). It
implements the configuration features of Gitleaks 8.30.0. The packaged
default rules are the Gitleaks default configuration at that revision, with
SHA-256 `e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf`.
The Gitleaks name only names the compatibility target. It does not mean that
Rustleaks is an official Gitleaks release.

Compatibility covers these points:

- Gitleaks configuration files load and mean the same thing.
- The same input and configuration give the same findings, including rule
  ID, match, secret, file, line and column, commit details and fingerprints.
- Ignore files, baselines and allow comments keep working.
- The Gitleaks commands, flags, environment variables and file names (such
  as `.gitleaks.toml` and `.gitleaksignore`) that Rustleaks supports keep
  working.
- Exit codes do not change.
- Error classes and output streams do not change. Each error keeps its
  class, and each kind of output goes to the same stream.
- JSON, CSV, JUnit, SARIF and template reports keep their field names, types
  and meanings.

Rustleaks owns its help text, usage and error wording, banner, log and
summary lines, other diagnostic output, and the order of JSON keys and CSV
columns. It can change them. Each such change updates a test expectation,
and a reviewer checks the new text against the stated intent.

A change to any point in the list above needs maintainer approval, a
changelog entry and tests that show the new behavior.

Contributors can find how this policy is tested in [Testing and
parity](../dev/testing-and-parity.md).

## What works the same

- **Configuration.** Gitleaks TOML files work without changes, including
  `[extend]`, allowlists, required rules and `minVersion`. The default rules
  are the Gitleaks default configuration at the pinned revision. See
  [Configuration](configuration.md).
- **Findings.** For the same input and configuration, Rustleaks reports the
  same rule IDs, matches, secrets, files, lines, columns, commit details,
  entropy, tags and fingerprints. Columns are counted as in Gitleaks. See
  [Line and column numbers](reports.md#line-and-column-numbers).
- **Ignore files.** `.gitleaksignore` files work, with the same fingerprint
  format.
- **Baselines.** A JSON report from Gitleaks at the pinned revision works as a
  baseline.
- **Allow comments.** `gitleaks:allow` on a line hides its findings.
- **Reports.** JSON, CSV, JUnit, SARIF and template reports have the same
  fields. See [Reports](reports.md).
- **Exit codes.** 0 for no findings, the `--exit-code` value for findings
  (1 by default), 1 for errors and 126 for an unknown long flag.
- **Help and completion.** The `help` command and the `completion` command for
  bash, zsh, fish and PowerShell work as in Gitleaks, but the help text uses
  Rustleaks wording. `completion` accepts `--no-descriptions` and ignores it.
  Both commands are not in 0.1.0-alpha.9.
- **Report tool name.** SARIF and JUnit reports name the tool `gitleaks`. The
  SARIF `semanticVersion` is the fixed value `v8.0.0`, as in Gitleaks. GitHub
  code scanning tracks alerts by tool name, so alert history continues after
  you switch.

## Rustleaks names and Gitleaks names

Rustleaks has its own names for files, variables, flags and comments. The
Gitleaks names still work.

| Rustleaks name | Gitleaks name | When both are present |
| --- | --- | --- |
| `RUSTLEAKS_CONFIG` | `GITLEAKS_CONFIG` | The Rustleaks name wins. |
| `RUSTLEAKS_CONFIG_TOML` | `GITLEAKS_CONFIG_TOML` | The Rustleaks name wins. |
| `.rustleaks.toml` | `.gitleaks.toml` | The Rustleaks name wins. |
| `.rustleaksignore` | `.gitleaksignore` | Rustleaks reads both and uses all entries. |
| `rustleaks:allow` | `gitleaks:allow` | Either one hides findings on the line. |
| `--rustleaks-ignore-path` | `--gitleaks-ignore-path` | Same flag. |
| `--ignore-rustleaks-allow` | `--ignore-gitleaks-allow` | Same flag. |

See [Configuration order](cli-reference.md#configuration-order) for the full
order of configuration sources.

## Commands and flags that differ

### Not supported

- The `detect` and `protect` commands. Use `rustleaks git` to scan history,
  `rustleaks dir` to scan files, and `rustleaks git --staged` or
  `rustleaks git --pre-commit` to scan changes that are not committed. See
  [Using Rustleaks in CI and Git hooks](ci.md).
- The `--diagnostics` and `--diagnostics-dir` flags.
- Colored output. `--no-color` is accepted and has no effect, because
  Rustleaks never prints color.
- Sprig and other helper functions in report templates. Rustleaks supports a
  small, safe part of the Go template language. See
  [Templates](reports.md#templates).
- The optional Gitleaks `gore2regex` build. Rustleaks follows the standard Go
  regular expression behavior.

### Added in Rustleaks

These flags are not in 0.1.0-alpha.9.

- `--native-pack`, which adds optional rule packs. See [Native rule
  packs](native-rule-packs.md).
- `--base64-mode extended`, which finds more Base64 text. See
  [Decoding](configuration.md#decoding).
- `--complete-profile`, which fails a scan that did not cover all of its
  input. See [Complete scanning](complete-scanning.md).
- `--scan-git-metadata` for `dir`, which also scans the text metadata files
  in `.git` folders. See [Git metadata](cli-reference.md#git-metadata).

### Version

`rustleaks version` and `rustleaks --version` print the Rustleaks version,
such as `0.1.0-alpha.9`, not a Gitleaks version. A configuration with a
`minVersion` newer than 8.30.0 still loads, but Rustleaks prints a warning,
because it may not support newer settings.

### Help, errors and logs

Help pages, usage text, error messages, the banner and log lines use Rustleaks
wording and layout. Do not parse them in scripts. Use exit codes and reports.

### Errors that Rustleaks handles more strictly

In a few error cases, Rustleaks stops or fails where Gitleaks does not:

- `dir` and `stdin` reject extra path arguments.
- `--exit-code` must be a whole number from -2147483648 to 2147483647. Other
  values fail before the scan starts.
- When Git fails, for example because the folder is not a Git repository,
  the scan exits with 1. Rustleaks still writes the report if you asked for
  one.
- Rustleaks opens the report file only at the end of the scan. A scan that
  fails early does not create or empty the report file.
- A configuration file larger than 16 MiB fails to load, and the scan exits
  with 1. This includes a `.gitleaks.toml` in the scanned folder and each
  `[extend]` file. The largest packaged configuration is under 1 MiB.

## Detection details

- `--base64-mode compatible`, the default, decodes Base64 the same way as
  Gitleaks. `--base64-mode extended` can find secrets that Gitleaks misses,
  so its findings can differ.
- `dir` skips `.git` folders by default, as Gitleaks does.
  `--scan-git-metadata` also scans their text metadata files, so its findings
  can differ.
- Rustleaks uses newer Unicode tables than the Go version that Gitleaks used
  (Unicode 15). For characters added to Unicode after version 15, case
  folding and Unicode character classes in rules can give different results.
  ASCII text is not affected.

### Archives

Gitleaks at the pinned revision reads archives as streams, copies a ZIP or 7z
archive that is not a file on disk to a temporary file, and sets no limit on
archive size or entries. `--max-archive-depth` is its only archive limit.

Rustleaks also reads archives as streams, and a member that both tools read
in full gives the same findings. These points differ:

- Rustleaks limits the entries of one archive, the size of one member, the
  total decompressed bytes of one archive, and its temporary storage. When a
  limit is reached, Rustleaks prints a warning and skips the rest of the
  member or archive, so it can report fewer findings for a very large archive
  or a decompression bomb. A complete scan then fails with exit code 2. See
  [Archives](resource-limits.md#archives) for the limits.
- Rustleaks holds a RAR member, a Snappy or MinLZ stream and some headers in
  memory, up to 64 MiB, and skips larger ones with a warning.
- Rustleaks keeps temporary copies of up to 1 MiB in memory instead of in a
  file. Its temporary files have no name, or are deleted when closed.
- An archive file from Git history that is larger than its limit is skipped
  with a warning, and the scan continues.

## Features that Gitleaks does not have

- [Native rule packs](native-rule-packs.md): 320 extra rules, including helper
  rules, for service provider tokens, connection strings and other secrets.
- [Complete scanning](complete-scanning.md): a scan that fails with exit code 2
  unless it scanned all of its input within the limits you set.
- [Git metadata](cli-reference.md#git-metadata): an opt-in `dir` scan of the
  text files in `.git` folders, such as `config`, `hooks` and `logs`, without
  the object store.
- [The rustleaks-core library](library.md): the detection engine as a Rust
  crate, with budgets, cancellation, sessions and review records.

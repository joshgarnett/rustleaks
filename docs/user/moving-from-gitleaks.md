# Moving from Gitleaks

This guide is for people who use Gitleaks and want to switch to Rustleaks.
It lists what keeps working, the Rustleaks names to use in new setups, and
where Rustleaks behaves differently.

Rustleaks is an independent project. It started from Gitleaks commit
`b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b` (`v8.30.0-27-gb58d3f1`), but it is
not affiliated with or endorsed by Gitleaks and does not aim to give the same
output. See [NOTICE](../../NOTICE) for attribution.

## What keeps working

- **Configuration files.** A configuration written for Gitleaks 8.30.0 or
  earlier loads without changes, including `[extend]`, allowlists, required
  rules and `minVersion`. See [Configuration](configuration.md).
- **Ignore files and baselines.** `.gitleaksignore` files and JSON reports
  used as baselines work, with the same fingerprint format. See [Ignore
  files](configuration.md#ignore-files) and
  [Baselines](configuration.md#baselines).
- **Allow comments.** `gitleaks:allow` on a line hides its findings.
- **Reports.** JSON, CSV, JUnit, SARIF and template reports keep their
  fields. Templates cannot use Sprig or other helper functions. See
  [Reports](reports.md).
- **Exit codes.** 0 for no findings, the `--exit-code` value for findings
  (1 by default), 1 for errors and 126 for an unknown long flag. See [Exit
  codes](cli-reference.md#exit-codes).
- **Help and completion.** The `help` command and the `completion` command
  for bash, zsh, fish and PowerShell work. `completion` accepts
  `--no-descriptions` and ignores it.

Rustleaks owns these formats and names now. Their meaning is the Rustleaks
meaning, which can change in a later release, with a changelog entry.

Help, usage, error wording, the banner, log and summary lines, and the order
of JSON keys and CSV columns can change between releases. Use exit codes and
report fields in scripts.

## Names to use

The Gitleaks names below are legacy names in Rustleaks. They keep working
with no warning, but new setups should use the Rustleaks names.

| Legacy name | Rustleaks name | When both are present |
| --- | --- | --- |
| `GITLEAKS_CONFIG` | `RUSTLEAKS_CONFIG` | The Rustleaks name wins. |
| `GITLEAKS_CONFIG_TOML` | `RUSTLEAKS_CONFIG_TOML` | The Rustleaks name wins. |
| `.gitleaks.toml` | `.rustleaks.toml` | The Rustleaks name wins. |
| `.gitleaksignore` | `.rustleaksignore` | Rustleaks reads both and uses all entries. |
| `gitleaks:allow` | `rustleaks:allow` | Either one hides findings on the line. |
| `--gitleaks-ignore-path` | `--rustleaks-ignore-path` | Same flag. |
| `--ignore-gitleaks-allow` | `--ignore-rustleaks-allow` | Same flag. |

See [Configuration order](cli-reference.md#configuration-order) for the full
order of configuration sources.

## Commands

| Gitleaks | Rustleaks |
| --- | --- |
| `gitleaks git` or `gitleaks detect` | `rustleaks git` |
| `gitleaks dir` or `gitleaks detect --no-git` | `rustleaks dir` |
| `gitleaks stdin` | `rustleaks stdin` |
| `gitleaks protect --staged` | `rustleaks git --staged` |
| `gitleaks protect` | `rustleaks git --pre-commit` |

See [Using Rustleaks in CI and Git hooks](ci.md) for examples.

### Not supported

- The `detect` and `protect` commands.
- The `--diagnostics` and `--diagnostics-dir` flags.
- Colored output. The legacy `--no-color` flag is accepted and has no
  effect, because Rustleaks never prints color.
- Sprig and other helper functions in report templates. Rustleaks supports a
  small, safe part of the Go template language. See
  [Templates](reports.md#templates).
- The optional Gitleaks `gore2regex` build. Rustleaks follows the standard Go
  regular expression behavior.

### Added in Rustleaks

- [Built-in rules](built-in-rules.md): Rustleaks rules for service provider
  tokens, connection strings and other secrets, used with the default rules.
- `--base64-mode extended`, which finds more Base64 text. See
  [Decoding](configuration.md#decoding).
- `--complete-profile`, which fails a scan that did not cover all of its
  input. See [Complete scanning](complete-scanning.md).
- `--scan-git-metadata` for `dir`, which also scans the text metadata files
  in `.git` folders. See [Git metadata](cli-reference.md#git-metadata).
- [The rustleaks-core library](library.md): the detection engine as a Rust
  crate, with budgets, cancellation, sessions and review records.

## Version

`rustleaks version` and `rustleaks --version` print the Rustleaks version,
such as `0.1.0-alpha.1`, not a Gitleaks version. A configuration with a
`minVersion` newer than 8.30.0 still loads, but Rustleaks prints a warning,
because it may not support newer settings.

## SARIF and JUnit reports

SARIF reports name the tool `rustleaks`, with the Rustleaks version as
`semanticVersion` and the Rustleaks repository as `informationUri`. JUnit
reports name the test suite `rustleaks`. Gitleaks uses `gitleaks`, `v8.0.0`
and the Gitleaks project page.

GitHub code scanning tracks alerts by tool name, so it treats Rustleaks as a
new tool. Findings that already have alerts under `gitleaks` get new alerts
under `rustleaks` once, and alerts you dismissed must be dismissed again.

If a CI step looks for the `gitleaks` JUnit test suite, change it to
`rustleaks`.

## Errors that Rustleaks handles more strictly

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

## Findings that can differ

For the same input and configuration, Rustleaks and Gitleaks often report the
same findings, but Rustleaks does not promise it. These are the known
reasons for a difference:

- **More rules.** Without a configuration, and in a configuration with
  `[extend] useDefault = true`, Rustleaks also scans with its own rules,
  whose IDs start with `rustleaks.`. A scan that Gitleaks passes can then
  exit with code 1, and baselines and ignore files from Gitleaks do not
  cover these findings. See [Built-in rules](built-in-rules.md).
- **Default rule allowlists.** The default rules hide some values that are
  clearly not secrets, such as hex digests under hash names and published
  documentation examples. See [Default rules](built-in-rules.md#default-rules).
  To get the Gitleaks findings for these values, use the [Gitleaks default
  configuration](https://github.com/gitleaks/gitleaks/blob/b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b/config/gitleaks.toml)
  as your configuration.
- **Base64.** `--base64-mode compatible`, the default, decodes Base64 the
  same way as Gitleaks. `--base64-mode extended` can find secrets that
  Gitleaks misses.
- **Git folders.** `dir` skips `.git` folders by default, as Gitleaks does.
  `--scan-git-metadata` also scans their text metadata files.
- **Required rules.** When `--enable-rule` or `disabledRules` leaves out a
  rule that a remaining rule needs through `[[rules.required]]`, Rustleaks
  keeps the needed rule without reporting its findings, so the remaining
  rule still reports. Gitleaks then reports nothing for the remaining rule.
- **Git attributes.** When a repository's `.gitattributes` marks a text
  file as binary (`-diff` or `binary`), Gitleaks does not scan it in `git`
  history or `--staged` scans. Rustleaks scans it with Git 2.43 or later.
  When `.gitattributes` marks a file with a NUL byte as text (`diff`),
  Gitleaks scans it and Rustleaks skips it as binary. With `--pre-commit`,
  both follow `.gitattributes`. See [git](cli-reference.md#git).
- **Unicode.** Rustleaks uses newer Unicode tables than the Go version that
  Gitleaks used (Unicode 15). For characters added to Unicode after version
  15, case folding and Unicode character classes in rules can give different
  results. ASCII text is not affected.
- **Archive limits.** Rustleaks limits the entries of one archive, the size
  of one member, the total decompressed bytes of one archive, and its
  temporary storage. Gitleaks has no such limits. When a limit is reached,
  Rustleaks prints a warning and skips the rest of the member or archive, so
  it can report fewer findings for a very large archive or a decompression
  bomb. A complete scan then fails with exit code 2. An archive file from Git
  history that is larger than its limit is skipped with a warning. See
  [Archives](resource-limits.md#archives).
- **Files with archive-like names.** With `--max-archive-depth 0`, the
  default, Rustleaks does not skip a file because of its name. Gitleaks
  skips, without reading it, any file whose name looks like an archive or
  compressed file by the name rules in [Archives](configuration.md#archives),
  such as `docker-compose.branch.yml` (`.br`), `app.browser.js` and
  `notes.zipper.txt`. Rustleaks reports the secrets in those files. Like
  Gitleaks, Rustleaks still skips files whose content starts like a binary
  format. See [Files that are
  skipped](cli-reference.md#files-that-are-skipped).

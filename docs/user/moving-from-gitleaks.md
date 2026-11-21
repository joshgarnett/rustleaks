# Moving from Gitleaks

This guide is for people who use Gitleaks and want to switch to Rustleaks.
It lists what keeps working, the Rustleaks names to use in new setups, and
what you may need to change.

Rustleaks is an independent project. It is not affiliated with or endorsed by
Gitleaks. [Differences from Gitleaks](gitleaks-differences.md) has the full
list of differences.

## What keeps working

- **Configuration files.** A Gitleaks TOML configuration loads without
  changes, including `[extend]`, allowlists, required rules and
  `minVersion`. See [Configuration](configuration.md).
- **Ignore files and baselines.** `.gitleaksignore` files and JSON reports
  used as baselines work, with the same fingerprint format. See [Ignore
  files](configuration.md#ignore-files) and
  [Baselines](configuration.md#baselines).
- **Allow comments.** `gitleaks:allow` on a line hides its findings.
- **Reports.** JSON, CSV, JUnit, SARIF and template reports keep their
  fields. See [Reports](reports.md).
- **Exit codes.** 0 for no findings, the `--exit-code` value for findings
  (1 by default), 1 for errors and 126 for an unknown long flag. See [Exit
  codes](cli-reference.md#exit-codes).

Rustleaks also scans with its own built-in rules, so it can report findings
that Gitleaks does not. See [Built-in rules](built-in-rules.md).

## Names to use

The Gitleaks names below are legacy names in Rustleaks. They keep working
with no warning, but new setups should use the Rustleaks names.

| Legacy name | Rustleaks name |
| --- | --- |
| `GITLEAKS_CONFIG` | `RUSTLEAKS_CONFIG` |
| `GITLEAKS_CONFIG_TOML` | `RUSTLEAKS_CONFIG_TOML` |
| `.gitleaks.toml` | `.rustleaks.toml` |
| `.gitleaksignore` | `.rustleaksignore` |
| `gitleaks:allow` | `rustleaks:allow` |
| `--gitleaks-ignore-path` | `--rustleaks-ignore-path` |
| `--ignore-gitleaks-allow` | `--ignore-rustleaks-allow` |

When both names are present, see [Rustleaks names and legacy
names](gitleaks-differences.md#rustleaks-names-and-legacy-names) for which
one wins.

## Commands

| Gitleaks | Rustleaks |
| --- | --- |
| `gitleaks git` or `gitleaks detect` | `rustleaks git` |
| `gitleaks dir` or `gitleaks detect --no-git` | `rustleaks dir` |
| `gitleaks stdin` | `rustleaks stdin` |
| `gitleaks protect --staged` | `rustleaks git --staged` |
| `gitleaks protect` | `rustleaks git --pre-commit` |

See [Using Rustleaks in CI and Git hooks](ci.md) for examples.

## SARIF and JUnit reports

SARIF reports name the tool `rustleaks`, and JUnit reports name the test
suite `rustleaks`. Gitleaks names both `gitleaks`.

GitHub code scanning tracks alerts by tool name, so it treats Rustleaks as a
new tool. Findings that already have alerts under `gitleaks` get new alerts
under `rustleaks` once, and alerts you dismissed must be dismissed again.

If a CI step looks for the `gitleaks` JUnit test suite, change it to
`rustleaks`.

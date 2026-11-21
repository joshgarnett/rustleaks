# Configuration

This guide is for people who run the `rustleaks` command and want to change
which secrets it reports. It covers the configuration file, how Rustleaks
finds it, and the ways to hide findings you have already reviewed.

## The configuration file

Rustleaks uses the Gitleaks TOML configuration format. A Gitleaks
configuration file works without changes. Rustleaks ships one default
configuration with 222 rules. It is based on the Gitleaks default rules and
adds allowlists that hide some values that are clearly not secrets, such as
hex digests under hash names and published documentation examples. See
[Default rules](gitleaks-differences.md#default-rules).

A small configuration that adds one rule to the default rules looks like this:

```toml
title = "Example config"

[extend]
useDefault = true
disabledRules = ["generic-api-key"]

[[rules]]
id = "example-internal-token"
description = "Internal service token"
regex = '''internal_token\s*=\s*"(it_[a-z0-9]{32})"'''
secretGroup = 1
entropy = 3.0
keywords = ["internal_token"]
tags = ["internal"]

[[rules.allowlists]]
description = "Ignore test fixtures"
paths = ['''(^|/)testdata/''']

[[allowlists]]
description = "Ignore known placeholder values"
stopwords = ["placeholder"]
```

### Top-level fields

| Field | Meaning |
| --- | --- |
| `title` | A name for the configuration. |
| `description` | Free text. |
| `minVersion` | The Gitleaks version that the configuration was written for. See [minVersion](#minversion). |
| `[extend]` | Builds this configuration on top of another one. See [Extending a configuration](#extending-a-configuration). |
| `[[rules]]` | One table for each rule. |
| `[[allowlists]]` | Global allowlists. They apply to every rule, or to the rules listed in `targetRules`. The older single `[allowlist]` table is also accepted. |

### Rule fields

| Field | Meaning |
| --- | --- |
| `id` | The rule ID. It appears in findings and fingerprints. |
| `description` | Text that appears in reports. |
| `regex` | The pattern to find. It uses Go regular expression syntax. |
| `secretGroup` | The capture group in `regex` that holds the secret. |
| `entropy` | The minimum Shannon entropy of the secret. Matches with lower entropy are dropped. |
| `keywords` | The rule runs only when one of these words appears in the input. Case does not matter. |
| `path` | A Go regular expression for the file path. With `regex`, both must match. Without `regex`, the rule reports the file itself. |
| `tags` | Labels copied into each finding. |
| `[[rules.allowlists]]` | Allowlists that apply to this rule only. The older single `[rules.allowlist]` table is also accepted. |
| `[[rules.required]]` | Other rules that must also match nearby. Each entry has an `id` and optional `withinLines` and `withinColumns`. |
| `skipReport` | When `true`, the rule is used only as a required rule and its own findings are not reported. |

Field names are not case sensitive, so `secretGroup` and `secretgroup` mean
the same thing.

### Allowlist fields

An allowlist hides a finding when its conditions match.

| Field | Meaning |
| --- | --- |
| `description` | Free text. |
| `regexes` | Go regular expressions tested against the part of the finding chosen by `regexTarget`. |
| `regexTarget` | `secret` (the default), `match` or `line`. |
| `paths` | Go regular expressions tested against the file path. |
| `commits` | Commit IDs. Case does not matter. |
| `stopwords` | Words that hide the finding when the secret contains them. Case does not matter. |
| `condition` | `OR` (the default) hides the finding when any field matches. `AND` needs every field that is set to match. |
| `targetRules` | Global allowlists only. The rule IDs that the allowlist applies to. Empty means all rules. |

### Extending a configuration

The `[extend]` table builds your configuration on top of a base:

| Field | Meaning |
| --- | --- |
| `useDefault` | When `true`, the base is the default rules. |
| `path` | The path to a base configuration file. |
| `disabledRules` | Rule IDs from the base to leave out. |

You cannot set both `useDefault` and `path`.

A rule in your file can have the same ID as a base rule. Then the values you
set for `description`, `regex`, `path`, `entropy` and `secretGroup` replace
the base values. Your `keywords`, `tags` and allowlists are added to the base
values. Global allowlists from both files apply.

The CLI reads a relative `path` from the current working folder, not from the
folder of the configuration file.

Rustleaks follows at most two levels of `extend`: your file, its base, and the
base of that base. An `[extend]` table in the third file is ignored, and
Rustleaks does not warn about it.

### minVersion

`minVersion` names the Gitleaks version that the configuration was written
for. Rustleaks supports the configuration settings of Gitleaks 8.30.0. When
`minVersion` is newer, Rustleaks prints a warning, because the configuration
may use settings that it does not support, and still runs the scan. A `minVersion`
that is not a valid version, such as `minVersion = "latest"`, is an error.
The default rules ask for `v8.25.0`, so they do not cause a warning.

## Where Rustleaks finds the configuration

Rustleaks uses the first source in this list that is set:

1. `--config PATH` or `-c PATH`.
2. The `RUSTLEAKS_CONFIG` environment variable, a path to a file.
3. The `RUSTLEAKS_CONFIG_TOML` environment variable, which holds the TOML
   text itself.
4. The `GITLEAKS_CONFIG` environment variable, the legacy name for
   `RUSTLEAKS_CONFIG`.
5. The `GITLEAKS_CONFIG_TOML` environment variable, the legacy name for
   `RUSTLEAKS_CONFIG_TOML`.
6. A `.rustleaks.toml` file in the folder you scan.
7. A `.gitleaks.toml` file in the folder you scan, the legacy name for
   `.rustleaks.toml`.
8. The default rules built into Rustleaks.

Empty values are skipped. Steps 6 and 7 apply when the scan target is a
folder: the folder for `dir`, the repository for `git`, and the current folder
for `stdin`.

A scan skips the selected configuration file and the baseline file, so their
contents are not reported as findings. Rustleaks compares the path as you
wrote it with the path it reports. For example, `rustleaks dir . -c my.toml`
skips `my.toml`, but `rustleaks dir . -c ./my.toml` scans it, because the
report path is `my.toml`.

To see which configuration a scan used, run it with `--log-level debug`.
Rustleaks then logs a line such as `using config <embedded-default>`.

## Choosing rules with --enable-rule

`--enable-rule ID` limits the scan to the named rules. Repeat the flag or
separate IDs with commas:

```sh
rustleaks dir . --enable-rule aws-access-token,github-pat
```

An unknown rule ID stops the scan with an error. If a selected rule has
`[[rules.required]]` entries, also select the required rules. Otherwise
Rustleaks logs an error for each missing required rule.

## Ignore files

An ignore file lists findings that Rustleaks should not report. Rustleaks
reads `.rustleaksignore` files and files with the legacy name
`.gitleaksignore`. Both use the same format, and Rustleaks uses all of
them together.

Rustleaks looks in these places:

- the path given with `--rustleaks-ignore-path` (`-i`), which can be an ignore
  file or a folder that holds one. The default is the current folder.
  `--gitleaks-ignore-path` is the legacy name of this flag;
- the folder you scan. For `stdin`, this is the current folder.

Each line holds the fingerprint of one finding. Copy fingerprints from the
`Fingerprint` field of a report or of `--verbose` output.

```text
# A finding in the working tree or in any commit
src/config.py:generic-api-key:12

# A finding in one commit only
4b825dc642cb6eb9a060e54bf8d69288fbee4904:src/config.py:generic-api-key:12
```

A fingerprint is `file:rule-id:line`, or `commit:file:rule-id:line` for a
finding in Git history. The first form also hides the same finding in every
commit. For `stdin`, the file part is empty, so a fingerprint looks like
`:aws-access-token:1`. Blank lines and lines that start with `#` are skipped.
Backslashes in the file part are read as `/`. Rustleaks warns about lines with
a different number of fields.

The file part is the path as Rustleaks reports it, which depends on the path
you give on the command line. `rustleaks dir .` reports `src/config.py`, while
`rustleaks dir project` reports `project/src/config.py`. Scan with the same
path each time, or your fingerprints will not match.

## Baselines

A baseline is a JSON report from an earlier scan. With
`--baseline-path FILE` (`-b FILE`), Rustleaks reports only findings that are
not in the baseline.

```sh
rustleaks git . --report-format json --report-path baseline.json
rustleaks git . --baseline-path baseline.json
```

A finding matches a baseline entry when these fields are equal: rule ID,
description, start and end line, start and end column, file, commit, author,
email, date, commit message and entropy. The match and secret must also be
equal, unless the scan uses `--redact`. Because columns are compared exactly,
make baselines with Rustleaks or with the same Gitleaks revision. See [Line
and column numbers](reports.md#line-and-column-numbers) for how columns are
counted.

If Rustleaks cannot read or parse the baseline file, it logs an error and
scans without a baseline. The exit code does not show this, so check the log.

## Allow comments

Add `rustleaks:allow` to a line to hide findings on that line. The legacy
`gitleaks:allow` comment also works.

```python
api_key = "example-not-a-secret"  # rustleaks:allow
```

The marker is case sensitive and can appear anywhere on the line. To report
these findings anyway, use `--ignore-rustleaks-allow`.
`--ignore-gitleaks-allow` is the legacy name of the same flag.

## Decoding

By default Rustleaks decodes Base64, hex, percent-encoded and Unicode-escaped
text up to 5 levels deep, and scans the decoded bytes too. Change the depth
with `--max-decode-depth N`. Use `0` to turn decoding off. Findings in decoded
text have tags such as `decoded:base64` and `decode-depth:1`.

`--base64-mode` selects how Base64 is decoded:

- `compatible`, the default, decodes padded standard Base64 and unpadded
  URL-safe Base64, and keeps the result only when it is printable ASCII text.
- `extended` also accepts URL-safe Base64, Base64 without padding, and
  decoded bytes that are not printable text. It can find secrets that
  `compatible` mode misses.

Limits of the Base64 modes:

- `extended` rejects Base64 whose unused trailing bits are not zero.
- Both modes find candidates the same way. A candidate needs at least 16
  Base64 characters and must contain a digit or a symbol. It can be part of
  a longer run of text.
- Neither mode finds every Base64 value. Neither mode checks that a whole
  carrier, such as a long malformed string, is valid Base64.
- The decode depth and scan budgets still apply.

## Archives

With `--max-archive-depth N` above 0, Rustleaks opens archives and scans the
files inside them, up to N levels of archives inside archives. The default is
0, which does not open archives: a file is read as plain text, whatever its
name. Files whose content starts like a binary format, such as a ZIP or PDF
file, are skipped. See [Files that are
skipped](cli-reference.md#files-that-are-skipped).

Rustleaks decides whether a file is an archive by its name only, not by its
content. A name that contains `.tar`, `.zip`, `.7z` or `.rar` is an archive.
A name that contains `.gz`, `.xz`, `.zst`, `.zz`, `.br`, `.bz2`, `.lz4`, `.sz`
or `.s2`, or that ends in `.lz` or `.mz`, is a compressed file. For example,
`data.tar.gz` is a compressed TAR archive, and `backup.zip.old` is also read
as a ZIP archive. A [complete scan](complete-scanning.md) also reads names that
end in `.tgz` as compressed TAR archives.

A file inside an archive is reported with `!` between the archive path and the
path inside it, for example `bundle.zip!config/app.env`.

Archives are read as streams, so large archives scan with bounded memory.
Archive size, entry and temporary storage limits apply. See
[Archives](resource-limits.md#archives).

## Other scan options

| Flag | Effect |
| --- | --- |
| `--max-target-megabytes N` | Skip files larger than N megabytes (N times 1,000,000 bytes). `0`, the default, means no limit. |
| `--follow-symlinks` | `dir` only. Scan files that symbolic links point to. |
| `--scan-git-metadata` | `dir` only. Also scan the text metadata files in `.git` folders, such as `config`, `hooks` and `logs`. See [Git metadata](cli-reference.md#git-metadata). |
| `--timeout N` | Stop the scan after N seconds. The scan then fails with exit code 1, or with 2 under `--complete-profile`. `0`, the default, means no timeout. |

See the [command reference](cli-reference.md) for every flag.

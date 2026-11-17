# Reports

This guide is for people who save Rustleaks findings to a file or send them to
another tool. It lists the report formats and the fields of a finding.

## Writing a report

Rustleaks writes a report only when you give `--report-path` (`-r`):

```sh
rustleaks git . --report-path findings.json
rustleaks git . --report-format csv --report-path findings.csv
rustleaks dir . --report-format sarif --report-path -
```

| Flag | Meaning |
| --- | --- |
| `--report-path PATH`, `-r PATH` | Where to write the report. `-` means standard output. The parent folder must exist. An existing file is replaced. |
| `--report-format NAME`, `-f NAME` | `json`, `csv`, `junit`, `sarif` or `template`. |
| `--report-template FILE` | The template file for `--report-format template`. |

Without `--report-format`, Rustleaks picks the format from the file extension:
`.json`, `.csv` or `.sarif`. For any other extension, and for `-`, you must
give `--report-format`. To use a template, give both
`--report-format template` and `--report-template FILE`.

The report is written at the end of the scan, even when there are no findings.
Log lines go to standard error, so `--report-path -` gives clean report output
on standard output.

## Redaction

`--redact` replaces each secret with `REDACTED` in reports and in `--verbose`
output. `--redact=N` hides N percent of each secret and keeps the start. See
[`--redact`](cli-reference.md#reports-and-output) for how to write the value.

Redaction replaces the `Secret` field and every copy of the secret inside
`Match` and the template `Line` field. The SARIF snippet holds the secret, so
it is redacted too. Use redaction whenever a report leaves the machine that
ran the scan, for example when you upload SARIF to GitHub.

## Exit codes

With `--exit-code 0`, a scan that finds secrets still writes its report and
exits with 0. See [Exit codes](cli-reference.md#exit-codes) for every code.

## Finding fields

JSON reports and templates use these field names. Other formats use the same
values under the names shown in their sections below.

| Field | Meaning |
| --- | --- |
| `RuleID` | The ID of the rule that matched. |
| `Description` | The rule description. |
| `StartLine`, `EndLine` | The first and last line of the match. Lines start at 1. |
| `StartColumn`, `EndColumn` | The byte columns of the first and last byte of the match. They have the same values as in Gitleaks reports. See [Line and column numbers](#line-and-column-numbers). |
| `Match` | The text that the rule matched. |
| `Secret` | The part of the match that is the secret. |
| `File` | The file path, as Rustleaks reports it. Empty for `stdin`. A file inside an archive has `!` between the archive path and the inner path, for example `bundle.zip!config/app.env`. |
| `SymlinkFile` | For a file reached through a symbolic link, the link path. Otherwise empty. |
| `Commit` | The commit ID for findings in Git history. Otherwise empty. |
| `Link` | A web link to the line. Only present when Rustleaks can build one. See [Using Rustleaks in CI](ci.md#links-to-findings). |
| `Entropy` | The Shannon entropy of the secret. |
| `Author`, `Email`, `Date`, `Message` | Commit metadata for findings in Git history. Otherwise empty. |
| `Tags` | Tags from the rule. Findings in decoded text also have a `decoded:NAME` tag for each decoding step (`base64`, `hex`, `percent` or `unicode`) and a `decode-depth:N` tag. |
| `Fingerprint` | The ID used by ignore files. `file:rule-id:line`, with `commit:` in front for findings in Git history. |

Paths use `/` as the separator, even on Windows.

## Line and column numbers

`StartLine` and `EndLine` count lines from 1. `StartColumn` and `EndColumn`
count bytes from 1. A character that takes more than one byte in UTF-8 takes
more than one column. `EndColumn` is the column of the last byte of the match.
For a finding in decoded text (tag `decoded:...`), the columns cover the
encoded text in the input.

Rustleaks scans its input in pieces. A piece is the added lines of one Git
diff hunk, or one part of a file or of standard input. Rustleaks reads Git
history with `git log -p -U0`, so a hunk is one block of changed lines. Files
and standard input are read in parts of about 100,000 bytes (see
[Resource limits](resource-limits.md)), so a smaller input is one piece.
Rustleaks tries to end a part at a blank line. If it finds none in the next
25,000 bytes, the next part starts in the middle of a line, and columns on
that line count from the start of the part.

On the first line of a piece, the column is the position of the byte in its
line, counting from 1. On every later line, the column is the position plus 1. `EndColumn` follows the same rule. Gitleaks
counts columns in the same way.

For example, take a configuration with one rule that matches `TOKEN`, and a
file with these three lines:

```text
TOKEN
TOKEN
  TOKEN
```

| Line | Position of the first `T` | `StartColumn` | `EndColumn` |
| ---: | ---: | ---: | ---: |
| 1 | 1 | 1 | 5 |
| 2 | 1 | 2 | 6 |
| 3 | 3 | 4 | 8 |

Line 1 is the first line of the file, so its columns are the positions. Lines
2 and 3 are later lines, so their columns are 1 higher. To get the position on
a later line, subtract 1 from the column.

A match that starts on one line and ends after the last line break of its
piece is an exception. This happens when a file or piece does not end with a
line break. `EndLine` is then the same as `StartLine`, and `EndColumn` is 0.
Gitleaks reports the same values.

The lines and columns always describe the whole match, also when the secret is
only part of it. For a rule whose match starts before the secret, `StartLine`
can be an earlier line than the line of the secret.

Rustleaks keeps this rule for these reasons:

- Reports from Rustleaks and Gitleaks have the same columns.
- A baseline entry matches a finding only when `StartColumn` and `EndColumn`
  are equal. With other columns, findings in existing baselines would come
  back as new findings. See [Baselines](configuration.md#baselines).
- SARIF `startColumn` and `endColumn` use the same values.

Ignore files do not use columns. A fingerprint holds only the file, rule ID,
start line and, for Git history, the commit.

If you use the Rust library and need exact positions, use
`Finding::match_range()` and `Finding::secret_range()`. They give
`FindingRange::Exact` byte offsets into the fragment you scanned, or
`FindingRange::Unavailable` when there is no exact range, for example for
decoded text. See [Reading findings](library.md#reading-findings).

## JSON

`--report-format json` writes an array with one object for each finding,
using the fields above. A scan with no findings writes `[]`.

## CSV

`--report-format csv` writes a header row and one row for each finding. The
columns are `RuleID`, `Commit`, `File`, `SymlinkFile`, `Secret`, `Match`,
`StartLine`, `EndLine`, `StartColumn`, `EndColumn`, `Author`, `Message`,
`Date`, `Email`, `Fingerprint` and `Tags`, with `Link` added when the first
finding has a link. Tags are separated by spaces. CSV has no `Description` or
`Entropy` column. A scan with no findings writes an empty file.

## JUnit

`--report-format junit` writes JUnit XML with one test suite named
`gitleaks`. Each finding is one failed test case. The failure text holds the
finding as JSON.

## SARIF

`--report-format sarif` writes SARIF 2.1.0. Each finding is one result:

| SARIF field | Value |
| --- | --- |
| `ruleId` | `RuleID` |
| `message.text` | The rule ID, file and commit in a sentence |
| `locations[0].physicalLocation.artifactLocation.uri` | `SymlinkFile` if set, otherwise `File` |
| `locations[0].physicalLocation.region` | `StartLine`, `StartColumn`, `EndLine`, `EndColumn` and a `snippet` that holds the secret |
| `partialFingerprints` | `commitSha`, `email`, `author`, `date` and `commitMessage` |
| `properties.tags` | `Tags` |

The `tool.driver.rules` list holds every rule in the configuration, with its
ID and description.

The tool is named `gitleaks`, with `semanticVersion` set to the fixed value
`v8.0.0` and `informationUri` set to the Gitleaks project page. These values
do not describe the Rustleaks version. Rustleaks keeps them because GitHub
code scanning tracks alerts by tool name, so alert history continues when you
move from Gitleaks to Rustleaks.

## Templates

`--report-format template --report-template FILE` renders your own text
format. Templates use a small, safe part of the Go `text/template` language.
The data is the list of findings.

```text
{{range .}}{{.RuleID}} {{.File}}:{{.StartLine}}
{{end}}
```

Inside `range`, these fields are available: `RuleID`, `Description`,
`StartLine`, `EndLine`, `StartColumn`, `EndColumn`, `Line`, `Match`, `Secret`,
`File`, `SymlinkFile`, `Commit`, `Link`, `Entropy`, `Author`, `Email`, `Date`,
`Message`, `Tags` and `Fingerprint`. `Line` is the source line that holds the
match. Except on the first line of a file, a Git diff hunk or standard input,
`Line` starts with the newline character before the line. `Tags` is a list, so use it with `range`
or `len`.

The template language supports:

- the actions `range`, `if`, `with` and `end`;
- variables, such as `{{range $i, $f := .}}` and `{{$x := .RuleID}}`. A
  field name cannot follow a variable, so write `{{with $f}}{{.RuleID}}{{end}}`
  instead of `{{$f.RuleID}}`;
- pipelines, such as `{{.RuleID | quote}}`;
- `{{-` and `-}}` to remove spaces around an action; and
- the functions `len`, `eq`, `ne`, `quote` and `sub`.

It does not support `else`, `define`, `template`, `block`, comments or other
functions, such as `printf`. An unsupported feature fails with an error that
names the `rustleaks-safe-template-v1` profile. The `now` and `date` functions
fail in the CLI, because Rustleaks gives templates no clock.

This example prints one line for each finding, with its index and the quoted
rule ID, and then the number of findings:

```text
{{range $i, $f := .}}{{$i}} {{.RuleID | quote}} {{.File}}:{{.StartLine}}
{{end}}total: {{len .}}
```

A template file can be at most 1 MiB. Rendering stops with an error after
1,000,000 actions or 64 MiB of output, and nesting is limited to 128 levels.

## Field order

The order of keys in JSON objects and of columns in CSV files can change in a
later Rustleaks version. Read fields by name, not by position. Field names,
types and meanings do not change. See the [compatibility
policy](gitleaks-differences.md#compatibility-policy).

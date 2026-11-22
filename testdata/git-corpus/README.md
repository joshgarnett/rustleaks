# Git corpus

These cases cover Git history and diff sources: `git log` and `git diff`
arguments, log options, staged changes, commit metadata, archives in
history, allowlisted commits, cancellation, Git failures and remote URLs.

## Files

- `requests-v1.jsonl`: 34 cases. `operation` is `log` (14 cases), `diff` (7
  cases) or `remote` (13 cases). `repository` names a fixture repository
  under `../fixtures/upstream/testdata/repos/` (`small`, `staged` or
  `archives`), or `empty` for a new empty folder. Optional fields set
  `log_options`, `staged`, a `mutation` of the working tree before the run,
  a `detect` configuration (`config_fixture`), `max_archive_depth`,
  `allow_commits`, and the remote URL for `remote` cases.
- `outcomes-v1.jsonl`: the expected result of each case. `fragments` lists
  the fragments in the order the source emits them, and
  `canonical_fragments` lists them in a fixed order. `findings` lists the
  expected findings of `detect` cases. `issues` lists Git errors, and `error`
  is set when the scan stops. `platform`, `git_version_base64`,
  `arguments_base64` and `command_base64` record how the case was recorded.
- `coverage-v1.json`, `negative-controls-v1.json`, `native-windows-v1.json`
  and `manifest-v1.json`: coverage notes, Windows hashes, counts and hashes
  from when the cases were recorded. No test reads them.

## Tests

`//crates/rustleaks-sources:git_corpus_test` copies the fixture repository
into a temporary folder, renames its `dotGit` folder to `.git`, runs the
case with an empty Git configuration, and compares fragments and findings.
On Windows it fills in the expected backslash form of archive paths
(`windows_file_base64`) before it compares. It counts the
`remote` cases but does not replay them.

## Origin and changes

The cases were recorded from Gitleaks at commit
`b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b` (MIT, see the repository
[`NOTICE`](../../NOTICE)). The outcomes are the expected Rustleaks behavior.
To change a case, edit the JSONL by hand or with a small script in a
reviewed change, keep byte fields in base64, and write the expected value
from the intended behavior. Never change the fixture repositories in
place. See [Changing a case](../README.md#changing-a-case).

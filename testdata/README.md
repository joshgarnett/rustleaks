# Test data

This folder holds the data files that Rustleaks tests read. It is for
contributors. For how to run and add tests, see
[Testing](../docs/dev/testing.md).

## Contents

| Path | Contents | Read by |
| --- | --- | --- |
| `allowlist-corpus/` | Allowlist methods and allowlist decisions during detection | `//crates/rustleaks-core:allowlist_test` |
| `cli-corpus/` | Recorded CLI cases | `//crates/xtask:cli_regression_test` |
| `composite-corpus/` | Required (composite) rules, generic rule suppression and redaction | `//crates/rustleaks-core:composite_corpus_test`, `//crates/rustleaks-core:rustleaks_core_unit_test` |
| `config-corpus/` | Configuration loading, extension and validation errors | `//crates/rustleaks-core:config_test` |
| `decoder-corpus/` | The decoders and detection on decoded text | `//crates/rustleaks-core:rustleaks_core_unit_test`, `//crates/rustleaks-core:detect_corpus_test` |
| `detect-corpus/` | Detection on single fragments, without decoding | `//crates/rustleaks-core:detect_corpus_test`, `//crates/rustleaks-sources:git_scm_test` |
| `generator-corpus/` | Positive and negative samples for the default rules | `//crates/rustleaks-core:default_rule_corpus_test` and others |
| `git-corpus/` | Git log and diff sources | `//crates/rustleaks-sources:git_corpus_test` |
| `regex-corpus/` | Regular expression syntax and matching | `//crates/rustleaks-core:rustleaks_core_unit_test` |
| `report-corpus/` | JSON, CSV, JUnit, SARIF and template reports | `//crates/rustleaks-report:report_corpus_test` |
| `session-corpus/` | Baselines, ignore files and fingerprints | `//crates/rustleaks-core:session_corpus_test` |
| `source-corpus/` | Readers, files, directories, symlinks and archives | `//crates/rustleaks-sources:source_corpus_test` |
| `fixtures/` | Copied fixture files with their licenses | Many tests |
| `quality-corpus/` | Synthetic detection quality cases and their baseline (generated) | `//crates/rustleaks-compat:rustleaks_compat_unit_test`, `just quality-eval` |
| `public-api/` | The `rustleaks-core` public API snapshot (generated) | `cargo xtask public-api-check` |
| `BUILD.bazel` | The `all`, `corpora` and `fixtures` file groups that tests use as data | Bazel |

Each folder has a README that says what its cases cover and which test reads
each file.

`cli-corpus/` holds recorded CLI cases. `//crates/xtask:cli_regression_test`
replays them and checks exit codes, findings, reports, error classes and
child process cleanup. It does not check help or message wording.

## Corpus files

Most `*-corpus/` folders use the same layout:

- `requests-v1.jsonl` has one case per line. `id` is the stable name of the
  case. Byte fields, such as content, paths, configuration text and commit
  metadata, are standard base64 in fields that end in `_base64`, so invalid
  UTF-8 and control bytes stay exact.
- `outcomes-v1.jsonl` has the expected result of each case, with the same
  `id`. `findings` lists the expected findings. `error` is `null`, or an
  object whose `class` names the expected error.
- `manifest-v1.json`, `coverage-v1.json`, `request-metadata-v1.jsonl`,
  `negative-controls-v1.json` and `native-windows-v1.json` hold counts,
  hashes and coverage notes from when the cases were recorded. Most tests do
  not read them. The README of each folder names the ones that a test reads.

Fields such as `upstream_revision`, `go_version`, `oracle_mode`,
`default_config_sha256`, `config_sha256` and `input_sha256` record how a case
was recorded. Lists such as `behavior_ids`, `test_case_ids` and
`assertion_ids` are labels. The tests do not check these fields.

## Origin and licenses

The cases in the `*-corpus/` folders, except `quality-corpus/`, were recorded
from Gitleaks at commit `b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b`
(`v8.30.0-27-gb58d3f1`). The files under `fixtures/upstream/` are copied from
the same commit. Gitleaks is MIT licensed; see [`NOTICE`](../NOTICE). The
archives under `fixtures/archives/` keep their own licenses beside them. See
[`fixtures/README.md`](fixtures/README.md).

`config-corpus/default-gitleaks.toml` is the Gitleaks default configuration
at that commit. Only the configuration cases use it.

## Changing a case

The recorded outcomes are the expected Rustleaks behavior. No tool
regenerates them. A few outcomes record a Gitleaks panic, for example the
`malformed-regex-panic` detection case, `panic` errors in the configuration
cases and `archive-rar5-multivolume` in the source cases. The tests that read
them say which Rustleaks error they expect instead.

- Change an expected value only in a reviewed change to Rustleaks behavior.
  Edit the JSONL by hand or with a small script. Keep one JSON object per
  line, keep byte fields in base64, and keep each request paired with its
  outcome by `id`.
- Write the expected value from the intended behavior. Never copy the
  current Rustleaks output into it.
- When findings, spans, fingerprints, report fields, exit codes or error
  classes change, add an entry to [`CHANGELOG.md`](../CHANGELOG.md). If the
  result then differs from Gitleaks, list it in [Findings that can
  differ](../docs/user/moving-from-gitleaks.md#findings-that-can-differ).
- Several tests check the number of cases or list case IDs. Update them when
  you add or remove a case.
- Use only synthetic values or reviewed upstream fixtures. Never add a live
  credential.
- Do not change the bytes, file modes or the symlink of copied fixtures.

The corpora and fixtures contain secret-shaped test values. `.rustleaks.toml`
allowlists them for the repository self-scan, and
`.github/secret_scanning.yml` excludes them from GitHub secret scanning. Do
not paste decoded values into issues or logs.

## Generated files

Do not edit generated files by hand. Regenerate them with these commands:

| Files | Command |
| --- | --- |
| `quality-corpus/cases-v1.json` | `bazelisk run //crates/rustleaks-compat:rustleaks_quality -- generate` |
| `quality-corpus/baseline-v1.json` | `bazelisk run //crates/rustleaks-compat:rustleaks_quality -- baseline` |
| `public-api/rustleaks-core-0.1.0-alpha.1.txt` (the current API; the name is fixed) | `cargo +nightly-2026-08-21 public-api -p rustleaks-core -sss --color never`, with `cargo-public-api` 0.52.0 |

The quality tool also accepts `check` and `check-baseline`. `just quality-eval`
prints the current quality report. `cargo xtask public-api-check` compares
the public API with the snapshot. See
[`quality-corpus/README.md`](quality-corpus/README.md) and
[`public-api/README.md`](public-api/README.md) for details.

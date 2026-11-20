# Compatibility evidence

This directory holds the evidence that Rustleaks tests replay to check its
compatibility with the pinned Gitleaks revision. It is for contributors and
maintainers. For the compatibility policy, see [Differences from
Gitleaks](../docs/user/gitleaks-differences.md#compatibility-policy). For how
the evidence is tested, see [Testing and
parity](../docs/dev/testing-and-parity.md).

## Contents

| Path | Contents | Status |
| --- | --- | --- |
| `upstream-revision.txt` | Pinned Gitleaks commit and default configuration SHA-256 | Frozen |
| `*-corpus/` except `quality-corpus/` | Historical Go requests, outcomes, manifests and generator records for each behavior area | Frozen |
| `fixtures/` | Copied upstream test fixtures with provenance and licenses | Frozen |
| `behavior-matrix.toml` | Behavior identifiers with their historical Go and Rust evidence | Frozen |
| `test-manifest.toml` | Mapping from upstream tests and identities to Rust tests | Frozen |
| `api-inventory-v1.json` | Exported upstream API identities | Frozen |
| `api-dispositions-v1.jsonl` | Disposition of each upstream API identity | Frozen |
| `presentation-dispositions.toml` | Reviewed changes to presentation text in the frozen CLI corpus, and the behavior records that they replace | Maintained |
| `quality-corpus/` | Synthetic detection-quality cases and their baseline | Generated |
| `public-api/` | Supported `rustleaks-core` public API snapshot | Generated |
| `BUILD.bazel` | Bazel file groups that expose this directory to tests | Maintained |

## Frozen evidence

Frozen files are historical provenance. They record what the Go
implementation did at the pinned revision, and they are never edited. Their
paths, file modes and SHA-256 hashes are listed in
`crates/xtask/src/tooling/frozen_manifest.rs`. The frozen check also rejects
added or removed files inside each frozen directory.

The live Go oracle is retired. Most `cargo xtask` commands named in the frozen
READMEs, `behavior-matrix.toml` and `test-manifest.toml` no longer exist. This
includes the per-corpus `generate` targets and `*-check` commands, `inventory`,
`fixture-check`, `verify-upstream`, `oracle generate --check`, and
`parity --scope`, and `manifest-check`. Use the commands in the next section
instead. No CI job runs a Go oracle. Where a
frozen README says that CI replays a Go oracle or its generators, it describes
the retired process. The frozen files stay unchanged because they are part of
the hashed evidence.

Frozen files also name documentation paths that have since moved. The
`design_evidence` field in `api-dispositions-v1.jsonl` names
`docs/ARCHITECTURE.md` anchors. Those anchors now live in
[`docs/dev/architecture.md`](../docs/dev/architecture.md). Paths such as
`docs/COMPATIBILITY.md` and `docs/RESOURCE_LIMITS.md` in
`behavior-matrix.toml` and `detect-corpus/` are historical labels.

New expectations go into Rust tests with synthetic inputs and independently
reviewed expected values. For functional fields, such as findings, spans,
fingerprints, report fields, exit codes and error classes, current Rust output
must never become its own expected baseline. A reviewed change to presentation
text in the frozen CLI corpus goes into `presentation-dispositions.toml`, as
described in [presentation
dispositions](../docs/dev/testing-and-parity.md#presentation-dispositions).

## Checking the evidence

| Command | What it checks |
| --- | --- |
| `just parity` | Runs `bazelisk test //:parity` |
| `cargo xtask frozen-evidence-check` | Frozen file hashes, modes and path sets, the Git modes of the upstream fixtures, the presentation ledger, and the `rustleaks-sources` symbols that the API dispositions name |
| `cargo xtask regression-check` | The frozen evidence check, then `bazelisk test //:parity` |

The `//:parity` suite in the root `BUILD.bazel` contains these test targets:

- `//crates/rustleaks-core:parity_tests`
- `//crates/rustleaks-sources:parity_tests`
- `//crates/rustleaks-report:parity_tests`
- `//crates/rustleaks-cli:parity_tests`
- `//crates/xtask:cli_regression_test`

`compat/BUILD.bazel` defines no tests. It defines the `all`, `parity_corpora`,
`fixtures` and `quality_default_config` file groups that these tests use as
data.

## Generated files

Do not edit generated files by hand. Regenerate them with these commands:

| Files | Command |
| --- | --- |
| `quality-corpus/cases-v1.json` | `bazelisk run //crates/rustleaks-compat:rustleaks_quality -- generate` |
| `quality-corpus/baseline-v1.json` | `bazelisk run //crates/rustleaks-compat:rustleaks_quality -- baseline` |
| `public-api/rustleaks-core-0.1.0-alpha.1.txt` | `cargo +nightly-2026-08-21 public-api -p rustleaks-core -sss --color never`, with `cargo-public-api` 0.52.0 |

The quality tool also accepts `check` and `check-baseline`. `just quality-eval`
prints the current quality report.
`cargo xtask public-api-check` compares the public API with the snapshot. See
[`quality-corpus/README.md`](quality-corpus/README.md) and
[`public-api/README.md`](public-api/README.md) for details.

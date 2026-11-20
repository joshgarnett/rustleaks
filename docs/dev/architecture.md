# Architecture

This page is for contributors. It describes the crates, how data moves
between them, and where to make common changes. For using the library, see
[Using rustleaks-core](../user/library.md).

## Design rules

- Detection is synchronous and works on bytes in memory. The engine reads no
  files, starts no threads, uses no async runtime, writes no logs and keeps
  no process-wide state.
- An `Engine` is immutable, `Send` and `Sync`. Callers decide how to share it
  and how to schedule scans.
- `rustleaks-core` does not depend on archives, Git, reports, the CLI, async
  runtimes or native libraries. It works on bytes. Two conveniences read
  files: `Baseline::load_go_json(path)` and `config::FileSystemResolver`,
  which reads configuration files named by `[extend] path`. Callers that
  read their own input, such as the CLI, pass bytes instead.
- Regex types do not appear in the public API of `rustleaks-core`.
  Configuration and baseline parse errors carry the `toml` and `serde_json`
  error as their source.
- Owned crates forbid unsafe Rust.
- Every limit is explicit. See [Engine internals](engine-internals.md) and
  [Resource limits](../user/resource-limits.md).

## Crates

| Crate | Responsibility | Published |
| --- | --- | --- |
| `rustleaks-core` | Configuration, regex, keywords, decoding, detection, findings, sessions, native rule packs and review records | Yes, on crates.io |
| `rustleaks-sources` | Files, directories, standard input, archives, Git, links to findings, cancellation and the bounded source runner | No |
| `rustleaks-report` | JSON, CSV, JUnit, SARIF and safe template reports | No |
| `rustleaks-cli` | The `rustleaks` command: arguments, configuration discovery, running a scan, output and exit codes | No |
| `rustleaks-compat` | Quality evaluation and performance workloads | No |
| `xtask` | Repository checks, generators, release, security, fuzz and performance tools | No |
| `rustleaks-bzip2`, `rustleaks-rar-codec`, `rustleaks-sevenz` | Safe forks of archive decoders, used only by `rustleaks-sources` (and `rustleaks-sevenz` uses `rustleaks-bzip2`) | No |

Dependencies point one way: `rustleaks-sources` and `rustleaks-report` depend
on `rustleaks-core`, and `rustleaks-cli` depends on all three. Nothing depends
on `rustleaks-cli`, `rustleaks-compat` or `xtask`.

The archive decoders sit behind the `archives` feature of
`rustleaks-sources`. No decoder type crosses the source API, and no decoder
enters `rustleaks-core`. RAR2 uses the registry crate `compcol` privately. See
[Dependencies](dependencies.md) for why the forks exist.

## Data flow

A scan moves through these stages:

```text
configuration TOML
      |
      v
  ConfigLoader ---> compiled configuration ---> Engine
                                                  ^
  Source (file, directory, archive, Git) ---> Fragment
                                                  |
                                                  v
                                         ScanOutcome (findings)
                                                  |
                                                  v
                     SessionPolicy and ScanSession (ignores, baseline, dedupe)
                                                  |
                                                  v
                                   Reporter (JSON, CSV, JUnit, SARIF, template)
```

The CLI connects these stages. A library user can use only the parts they
need, for example the engine alone.

<a id="root-cli-generator-auxiliary-packages"></a>

### Workspace, CLI and tools

The workspace root owns package policy and validation. The CLI is a thin
consumer of the libraries. `rustleaks-compat` and `xtask` are test and
maintenance tools. They are never published.

### Configuration

`rustleaks-core` parses TOML into a validated, immutable compiled
configuration (`config` module). The default rules,
`crates/rustleaks-core/default/gitleaks.toml`, are built into the crate. They
are based on the upstream copy in `compat/config-corpus/default-gitleaks.toml`.
Native rule packs load through `native::NativePolicy`, which adds stricter
validation before the normal loader runs. Regex types stay private.

<a id="detection-and-codec"></a>

### Detection and decoding

The engine (`engine.rs`) scans one `Fragment` with `ScanOptions` and an
optional `ScanControl`. For each rule it applies keywords, the regex, entropy,
allowlists, required (composite) rules and location mapping. The decoder
(`decoder/`) finds Base64, hex, percent and Unicode escape candidates and
scans the decoded bytes again, up to the decode depth. The result is a
`ScanOutcome`: complete, or partial with a structured termination.

<a id="scm-and-regexp"></a>

### Regex and Git

The regex frontend (`regex/`) translates Go regex syntax to the private
`regex-automata` backend. It is private to `rustleaks-core`. Git processes
and the construction of links to findings (`scm.rs`) live in
`rustleaks-sources`.

### Sources

A source (`Source` trait in `rustleaks-sources/src/source.rs`) produces
fragments and structured `SourceIssue` values. `SourceRunner` can scan
fragments on several worker threads with bounded queues and optional budgets.
It submits only fragments that finished scanning to a session. Complete-target
mode reads each eligible input to the end before scanning it.

### Findings and reports

The core owns the finding model (`model.rs`) and sessions (`session.rs`).
Sessions apply ignore files, baselines, fingerprints and deduplication across
fragments. The core parses ignore files and baselines from bytes, and the CLI
reads those files. For library users, `Baseline::load_go_json(path)` reads a
baseline file and parses it. `rustleaks-report` writes findings through the
`Reporter` trait. It does not change detection state.

## Names

The project uses the name `rustleaks`. Gitleaks names stay only where
compatibility needs them: configuration fields, `.gitleaks.toml`,
`.gitleaksignore`, `GITLEAKS_CONFIG`, legacy flags, report field names, the
`gitleaks` tool name in SARIF and JUnit reports, historical evidence, fixture
identity and attribution. These names do not identify the product.

## Where to add things

### A detection rule

- The default rules are Rustleaks-owned and based on the pinned Gitleaks
  configuration. A change to them needs review, tests in
  `crates/rustleaks-core/tests/default_rules.rs` (which names every
  difference from the upstream copy), an entry in
  [Default rules](../user/gitleaks-differences.md#default-rules), a changelog
  entry, and a measurement on a held-out set that was not used to design it.
  A change that makes Rustleaks miss secrets needs maintainer approval. Do not
  edit the upstream copy; it changes only with a new pin. See
  [Updating upstream](updating-upstream.md).
- Add a new rule to a native rule pack. See
  [Rule pack authoring](rule-pack-authoring.md).
- Engine behavior that rules depend on, such as a new predicate, belongs in
  `rustleaks-core` with tests in `crates/rustleaks-core/tests/`.

### A source

1. Implement `Source` in `rustleaks-sources`. Emit owned fragments and
   structured issues. Check the cancellation token between bounded steps.
2. Give every buffer, count and child process an explicit limit. Return a
   typed issue or error when a limit is reached.
3. Export the type from `crates/rustleaks-sources/src/lib.rs`. Keep
   dependency types private. Put new codecs behind the `archives` feature.
4. Connect it in `crates/rustleaks-cli/src/source.rs` if the CLI needs it.
5. Add tests under `crates/rustleaks-sources/tests/` and register them. See
   [Testing and parity](testing-and-parity.md#adding-a-test).
6. Update [Engine internals](engine-internals.md), the
   [threat model](threat-model.md) and, for new dependencies,
   [Dependencies](dependencies.md).

### A report format

1. Add a module in `crates/rustleaks-report/src/` that implements
   `Reporter`.
2. Export it from `crates/rustleaks-report/src/lib.rs`.
3. Accept the format name in `crates/rustleaks-cli/src/output.rs` and add it
   to `REPORT_FORMATS` in `crates/rustleaks-cli/src/cli_spec.rs`.
4. Add tests in `crates/rustleaks-report/tests/reporters.rs` with expected
   output written by hand, and a CLI test in
   `crates/rustleaks-cli/tests/cli/reports.rs`.
5. Document the format in the user [reports guide](../user/reports.md).

### A CLI flag

1. Parse the flag in `crates/rustleaks-cli/src/args.rs` and store it in
   `Options`.
2. Add it to the command table in `crates/rustleaks-cli/src/cli_spec.rs`.
   Help, usage and shell completion are built from this table. Unit tests
   check that every flag in the table parses.
3. Use the value in `run.rs`, `source.rs`, `config.rs` or `output.rs`.
4. Add tests in the matching topic file under `crates/rustleaks-cli/tests/cli/`.
   Write the expected exit code, findings and output by hand.
5. Document the flag in the user
   [command reference](../user/cli-reference.md).

A new flag must not change the meaning of an existing Gitleaks flag. See the
[compatibility policy](../user/gitleaks-differences.md#compatibility-policy).

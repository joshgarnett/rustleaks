# Rustleaks repository instructions

## Repository contract

Rustleaks is an independent, engine-first secret scanner in Rust. It started
as a port of one pinned Gitleaks revision and now stands on its own, as
defined in the
[compatibility policy](docs/user/gitleaks-differences.md#compatibility-policy).
Gitleaks configuration files, ignores, baselines, allow comments, exit codes,
report fields, and supported Gitleaks commands, flags, environment variables
and file names keep working and keep their meaning. Findings may differ from
Gitleaks when Rustleaks loses no secret; each difference is documented and
tested. Help, usage, error wording, logs, the banner, and JSON key or CSV
column order are presentation that Rustleaks owns.

Keep `rustleaks-core` independent of files, archives, Git, reports, the CLI,
async runtimes and native libraries. Source adapters belong in
`rustleaks-sources`, formatting in `rustleaks-report`, orchestration in
`rustleaks-cli`, and unpublished regression or maintenance code in
`rustleaks-compat` or `xtask`. Owned codec crates are source implementation
details and must not enter the default core graph or public API. See
[the architecture](docs/dev/architecture.md).

`compat/upstream-revision.txt` pins Gitleaks commit
`b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b` and default configuration SHA-256
`e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf`.
Compatibility evidence is under `compat/`. The packaged configuration is
`crates/rustleaks-core/default/gitleaks.toml`, with a checked copy at
`compat/config-corpus/default-gitleaks.toml`.

## Commands

Run commands from the repository root. Just is the public interface. Bazel is
the authority for builds, tests, lint, formatting, documentation, parity
replay and target compilation.

| Need | Command |
| --- | --- |
| Verify installed tools | `just doctor` |
| Check formatting | `just format` |
| Lint, prose, docs, build and target checks | `just check` |
| Run one test | `bazelisk test //crates/rustleaks-core:engine_test` |
| Run all first-party tests | `just test` |
| Repeat all tests to expose flakes | `just flake-check` |
| Run the complete local Bazel gate | `just ci` |
| Replay committed compatibility evidence | `just parity` |
| Check packages and external consumers | `just package-check` |
| Build API documentation | `just docs` |
| Run security policy | `just security` |
| Build and smoke fuzz targets | `just fuzz-build` and `just fuzz-smoke` |

Use Cargo only for package metadata, crates.io packaging, `cargo xtask`, and
the named security, fuzz, Miri and MSRV tools that maintained recipes call.
Never use Cargo to bypass a failed Bazel action.

The required targets are `x86_64-unknown-linux-gnu`,
`aarch64-unknown-linux-gnu`, `x86_64-unknown-linux-musl`,
`aarch64-unknown-linux-musl`, `x86_64-apple-darwin`,
`aarch64-apple-darwin`, `x86_64-pc-windows-msvc` and
`aarch64-pc-windows-msvc`. Cross-compilation proves only compilation. A
support claim needs native build, test, feature, parity, example and relevant
CLI evidence for the exact target. Current native evidence is described in
[Testing and parity](docs/dev/testing-and-parity.md#platforms).

## Invariants

- Keep configuration meaning, exit codes, report fields, error classes, and
  the mappings in `compat/test-manifest.toml` unchanged. Error classes include
  the structured error kinds of the `rustleaks-core` library, such as
  `ConfigError` kinds. A change to findings, spans or fingerprints must not
  lose a secret, needs a changelog entry, and a difference from Gitleaks is
  listed in `docs/user/gitleaks-differences.md`. Historical Go observations
  are frozen provenance; validate current behavior with Rust regression tests
  and local evidence checks. Specify new expectations for these functional
  fields independently of the implementation under test. Never hide a
  functional difference with normalization. Never use current output as the
  expected value for these fields. The live Go oracle and automatic upstream
  rediscovery are retired.
- Presentation (help, usage, error wording, logs, banner, summaries, and JSON
  key or CSV column order) may change. Each change needs an updated
  expectation that a reviewer checks against its stated intent. When the
  change replaces frozen CLI evidence, record it as a presentation disposition
  in `compat/presentation-dispositions.toml`.
- Keep detection synchronous, in-memory, `Send + Sync`, and free of implicit
  file, environment, log, thread, async-runtime or process-global behavior.
  Keep C and C++ build steps and dependency implementation types out of the
  default engine graph and public API.
- Do not hand-edit generated corpora, inventories, snapshots or lockfiles.
  Preserve bytes, modes, symlinks, provenance, hashes, adjacent licenses and
  `NOTICE` attribution for copied configuration and fixtures.
- Use only synthetic values or reviewed upstream fixtures in tests, examples,
  fuzz seeds and issues. Treat findings and crash artifacts as sensitive.
- Owned crates forbid unsafe Rust. Apply the
  [threat model](docs/dev/threat-model.md),
  [resource limits](docs/user/resource-limits.md) with
  [engine internals](docs/dev/engine-internals.md), and the
  [dependency policy](docs/dev/dependencies.md) when their boundaries change.
- Write concise factual prose. Do not include marketing claims, em dashes,
  emojis, private context, change history outside `CHANGELOG.md`, or
  unsupported compatibility, security, performance, platform or readiness
  claims.

## Issues, commits and pull requests

Follow [CONTRIBUTING.md](CONTRIBUTING.md) for what belongs in an issue, issue
labels, the commit subject grammar, types and scopes, commit contents, the
checks before committing, and pull request and merge rules.

## Skills

Task-specific procedures are in `.agents/skills/`. Use the matching skill for
upstream synchronization, parity audit, rule maintenance, build maintenance,
release work, security audit, and GitHub issues, commits, pull requests,
reviews and merges.

## Approval boundaries

Stop for maintainer approval before:

- adding or updating dependencies, toolchains, `rules_rust`, the Gitleaks pin
  or the copied default configuration;
- changing GitHub settings or ownership;
- enabling paid services;
- accepting a security exception;
- removing a supported Gitleaks command, flag, environment variable or file
  name, changing the meaning of a configuration, report field or exit code,
  or making Rustleaks miss secrets that it found before;
- selecting a release version;
- creating or publishing a release or crate; or
- using a credential.

A local dry run does not authorize publication. Changes to help, usage, error
wording, log, banner and summary lines, and JSON key and CSV column order need
review but not maintainer approval.

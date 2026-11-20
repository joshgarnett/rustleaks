# Rustleaks repository instructions

## Repository contract

Rustleaks is an independent secret scanner in Rust, based on one pinned
Gitleaks revision. The
[compatibility policy](docs/user/gitleaks-differences.md#compatibility-policy)
defines what it keeps:

- Gitleaks configuration files, ignore files, baselines, allow comments, exit
  codes, report fields, and the supported Gitleaks commands, flags,
  environment variables and file names keep working and keep their meaning.
- Findings can differ from Gitleaks when Rustleaks loses no secret. Each
  difference is listed in `docs/user/gitleaks-differences.md` and covered by a
  test.
- Help, usage, error wording, logs, the banner, summaries, and JSON key or CSV
  column order are presentation. Rustleaks owns them.

Rustleaks has no Go oracle and does not track Gitleaks automatically. Do not
install Go or check out Gitleaks to create expected values. Commands named in
frozen `compat/` files do not run.

Keep `rustleaks-core` independent of files, archives, Git, reports, the CLI,
async runtimes and native libraries. Source adapters belong in
`rustleaks-sources`, formatting in `rustleaks-report`, orchestration in
`rustleaks-cli`, and unpublished regression or maintenance code in
`rustleaks-compat` or `xtask`. Owned codec crates are source implementation
details and must not enter the default core graph or public API. See
[the architecture](docs/dev/architecture.md).

`compat/upstream-revision.txt` pins the Gitleaks commit and the SHA-256 of the
unchanged upstream copy of the default configuration,
`compat/config-corpus/default-gitleaks.toml`. Compatibility evidence is under
`compat/`. The shipped default rules,
`crates/rustleaks-core/default/gitleaks.toml`, are Rustleaks-owned and based
on that copy. Each difference from it is listed in
[Default rules](docs/user/gitleaks-differences.md#default-rules) and named in
`crates/rustleaks-core/tests/default_rules.rs`.

## Commands

Run commands from the repository root. Just is the public interface. Bazel is
the authority for builds, tests, lint, formatting, documentation, parity
replay and target compilation.

| Need | Command |
| --- | --- |
| Run one test | `bazelisk test //crates/rustleaks-core:engine_test` |
| Run all first-party tests | `just test` |
| Check formatting | `just format` |
| Lint, prose, docs, build and target checks | `just check` |
| Run before opening a pull request | `just ci` and `just security` |
| All local release and compatibility checks, from a clean committed tree | `cargo xtask qualify` |

[Local workflow](CONTRIBUTING.md#local-workflow) lists the command for each
kind of change.

Use Cargo only for package metadata, crates.io packaging, `cargo xtask`, and
the named security, fuzz, Miri and MSRV tools that Just recipes call. Never
use Cargo to bypass a failed Bazel action.

The eight required targets are listed in
[Testing and parity](docs/dev/testing-and-parity.md#platforms).
Cross-compilation proves only compilation. A support claim needs native
build, test, feature, parity, example and relevant CLI evidence for the exact
target.

## Invariants

- Do not change configuration meaning, exit codes, report fields, error
  classes (including `rustleaks-core` error kinds such as `ConfigError`
  kinds) or the mappings in `compat/test-manifest.toml`, and do not make
  Rustleaks miss a secret it found before, without maintainer approval. See
  [Approval boundaries](#approval-boundaries).
- Any change to findings, spans or fingerprints needs a changelog entry and a
  Rust test. When it differs from Gitleaks, list it in
  `docs/user/gitleaks-differences.md`.
- Write expected findings, spans, fingerprints, report fields, exit codes and
  error classes from the intended behavior, never from current output. Never
  hide a functional difference with normalization. Frozen Go observations
  under `compat/` never change.
- A presentation change needs an updated test expectation that a reviewer
  checks against its stated intent. It does not need maintainer approval.
  [Presentation
  dispositions](docs/dev/testing-and-parity.md#presentation-dispositions)
  says when to record one and which comparisons still pin key and column
  order.
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

Task procedures are in `.agents/skills/`. Use the matching skill for
compatibility work (the Gitleaks pin and compatibility evidence), rule
maintenance, build maintenance, release work, security audit, and GitHub
issues, commits, pull requests, reviews and merges.

## Approval boundaries

Stop for maintainer approval before:

- adding or updating dependencies, toolchains, `rules_rust`, the Gitleaks pin
  or the upstream copy of the default configuration;
- changing GitHub settings or ownership;
- enabling paid services;
- accepting a security exception;
- removing a supported Gitleaks command, flag, environment variable or file
  name, changing the meaning of a configuration, report field, error class or
  exit code, or making Rustleaks miss secrets that it found before;
- selecting a release version;
- creating or publishing a release or crate; or
- using a credential.

A local dry run does not authorize publication. A change to the shipped
default rules needs normal review, tests and a listed difference, and
maintainer approval only when it makes Rustleaks miss a secret.

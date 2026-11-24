# Rustleaks repository instructions

## Repository contract

Rustleaks is an independent secret scanner in Rust. It started from Gitleaks
commit `b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b` and does not track Gitleaks.
These keep working and keep their meaning, as Rustleaks behavior:

- the configuration format, ignore files, baselines, allow comments,
  fingerprints, exit codes and report fields;
- the commands, flags, environment variables and file names, including the
  legacy Gitleaks names listed in
  [Moving from Gitleaks](docs/user/moving-from-gitleaks.md#names-to-use).

Findings can change when Rustleaks finds more or gives a clearer result. A
change that makes Rustleaks miss a secret it found before needs maintainer
approval. Help, usage, error wording, logs, the banner, summaries, and JSON
key or CSV column order are presentation.

Do not install Go or check out Gitleaks to create expected values.

Keep `rustleaks-core` independent of archives, Git, reports, the CLI, async
runtimes and native libraries. It reads no files except through the two
explicit file helpers named in the architecture. Source adapters belong in
`rustleaks-sources`, formatting in `rustleaks-report`, orchestration in
`rustleaks-cli`, and unpublished regression or maintenance code in
`rustleaks-eval` or `xtask`. Owned codec crates are source implementation
details and must not enter the default core graph or public API. See
[the architecture](docs/dev/architecture.md).

The built-in rules are the Gitleaks-based rules in
`crates/rustleaks-core/default/gitleaks.toml` and the Rustleaks rule files
beside it. Rustleaks changes them in place. Test
data, including cases recorded from Gitleaks and copied fixtures, is under
`testdata/`; see [its README](testdata/README.md).

## Commands

Run commands from the repository root. Just is the public interface. Bazel is
the authority for builds, tests, lint, formatting, documentation and target
compilation.

| Need | Command |
| --- | --- |
| Run one test | `bazelisk test //crates/rustleaks-core:engine_test` |
| Run all first-party tests | `just test` |
| Check formatting | `just format` |
| Lint, prose, docs, build and target checks | `just check` |
| Run before opening a pull request | `just ci` and `just security` |

[Local workflow](CONTRIBUTING.md#local-workflow) owns the full list: the
command for each kind of change, the clean-clone checks and the release
candidate checks.

Use Cargo only for what [Local workflow](CONTRIBUTING.md#local-workflow)
lists, and never to bypass a failed Bazel action.

[Platforms](docs/dev/testing.md#platforms) lists the eight required targets
and the evidence that a support claim needs. Cross-compilation proves only
compilation.

## Invariants

- Any change to findings, spans or fingerprints needs a Rust test and a
  [changelog entry](CONTRIBUTING.md#changelog).
- Write expected values from the intended behavior, never from current
  output, and never hide a functional difference with normalization. A
  presentation change updates its test expectation and needs no maintainer
  approval. [Rules for tests](docs/dev/testing.md#rules-for-tests) and
  [Test data](docs/dev/testing.md#test-data) own the details, including the
  cases under `testdata/`.
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

Task procedures are in `.agents/skills/`. Use the matching skill for rule
maintenance, build maintenance, release work, security audit, and GitHub
issues, commits, pull requests, reviews and merges.

## Approval boundaries

Stop for maintainer approval before:

- adding or updating dependencies, toolchains or `rules_rust`;
- changing GitHub settings or ownership;
- enabling paid services;
- accepting a security exception;
- removing a supported command, flag, environment variable or file name,
  including a legacy Gitleaks name;
- changing the meaning of a configuration, report field, error class or exit
  code. Error classes include `rustleaks-core` error kinds, such as the
  `ConfigError` kinds;
- making Rustleaks miss secrets that it found before;
- selecting a release version;
- creating or publishing a release or crate, or pushing to the Homebrew tap
  or Scoop bucket; or
- using a credential.

A local dry run does not authorize publication. A change to the built-in
rules needs normal review, tests and a
[changelog entry](CONTRIBUTING.md#changelog). It needs maintainer approval
only when it makes Rustleaks miss a secret.

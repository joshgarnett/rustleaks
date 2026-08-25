# Rustleaks repository instructions

## Repository contract

Rustleaks is an engine-first Rust port of selected behavior from one pinned
Gitleaks revision. Keep `rustleaks-core` independent of files, archives, Git,
reports, the CLI, async runtimes, and native libraries. Source adapters belong
in `rustleaks-sources`, formatting in `rustleaks-report`, orchestration in
`rustleaks-cli`, and unpublished oracle or maintenance code in
`rustleaks-compat` or `xtask`. Owned codec crates are source implementation
details and must not enter the default core graph or public API.

The accepted upstream identity is in `compat/upstream-revision.txt`. It pins
Gitleaks commit `b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b` and default-config
SHA-256 `e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf`.
Compatibility evidence is under `compat/`; the packaged config is
`crates/rustleaks-core/default/gitleaks.toml`, with a checked mirror at
`compat/config-corpus/default-gitleaks.toml`.

## Commands

Run commands from the repository root. Just is the public interface, and Bazel
is authoritative for normal builds, tests, lint, formatting, documentation,
parity replay, and target compilation.

| Need | Command |
| --- | --- |
| Verify installed tools | `just doctor` |
| Check formatting | `just format` |
| Lint, prose, docs, build, and target checks | `just check` |
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
the named security, fuzz, Miri, and MSRV tooling invoked by maintained
recipes. Never use Cargo to bypass a failed Bazel action.

The required targets are `x86_64-unknown-linux-gnu`,
`aarch64-unknown-linux-gnu`, `x86_64-unknown-linux-musl`,
`aarch64-unknown-linux-musl`, `x86_64-apple-darwin`,
`aarch64-apple-darwin`, `x86_64-pc-windows-msvc`, and
`aarch64-pc-windows-msvc`. Cross-compilation proves only compilation. A support
claim requires native build, test, feature, parity, example, and relevant CLI
evidence for the exact target. Consult `docs/COMPATIBILITY.md` for current
native evidence.

## Invariants

- Preserve supported configuration and detection behavior, byte findings,
  exact spans, structured errors, and the mappings in
  `compat/test-manifest.toml`. Use the pinned Go oracle when behavior is
  unclear. Never normalize away a semantic difference.
- Keep detection synchronous, in-memory, `Send + Sync`, and free of implicit
  file, environment, log, thread, async-runtime, or process-global behavior.
  Keep C and C++ build steps and dependency implementation types out of the
  default engine graph and public API.
- Do not hand-edit generated corpora, inventories, snapshots, or lockfiles.
  Preserve bytes, modes, symlinks, provenance, hashes, adjacent licenses, and
  `NOTICE` attribution for copied configuration and fixtures.
- Use only synthetic values or reviewed upstream fixtures in tests, examples,
  fuzz seeds, and issues. Treat findings and crash artifacts as sensitive.
- Owned crates forbid unsafe Rust. Apply `docs/THREAT_MODEL.md`,
  `docs/RESOURCE_LIMITS.md`, and `docs/DEPENDENCY_SAFETY.md` when their
  boundaries change.
- Write concise factual prose. Do not include marketing claims, em dashes,
  emojis, private context, goal history, or unsupported compatibility,
  security, performance, platform, or readiness claims.

Use the matching repository skill for upstream synchronization, parity audit,
rule maintenance, build maintenance, release work, or security audit. Those
skills contain task-specific procedures that do not belong in every session.

## Commits and pull requests

Subjects use `<type>(<scope>)!: <description>`, with optional scope and `!`.
The description is imperative and present tense, starts with a lowercase word
or project identifier as grammar requires, has no final period, and is at most
72 characters. `!` requires a `BREAKING CHANGE: ...` footer.

Use the standard Git-generated `Revert "..."` subject only for a real revert,
and preserve its explanation of the reverted commit.

Use the narrowest type: `feat`, `fix`, `perf`, `refactor`, `test`, `docs`,
`build`, `ci`, `style`, or `chore`. Use `chore` only when no other type fits.
When useful, choose the narrowest stable scope: `core`, `sources`, `report`,
`cli`, `compat`, `xtask`, `bazel`, `deps`, `docs`, `ci`, or `release`. Omit a
scope for cross-cutting work. Never use a goal, agent, review round, ticket, or
temporary task as a scope.

Keep one reviewable logical state per commit: behavior with direct tests,
generators with generated artifacts, and manifests with lockfiles. Separate
unrelated documentation, dependency, build, and behavior changes. Use a body
for lasting reasons, compatibility effects, security constraints, or
non-obvious decisions. Add only true trailers; never invent links, signoffs,
co-authors, or reviews.

Before committing, inspect status, all diffs, and untracked files; stage
explicit paths; inspect the complete staged diff; run the relevant gate and
`git diff --cached --check`. Pull request titles follow the same grammar
because pull requests are squash merged. Do not merge with incomplete checks,
reviews, or conversations.

## Approval boundaries

Stop for maintainer approval before adding or updating dependencies,
toolchains, `rules_rust`, the Gitleaks pin, or copied default configuration;
changing GitHub settings or ownership; enabling paid services; accepting a
security or compatibility exception; selecting a release version; creating or
publishing a release or crate; or using a credential. A local dry run does not
authorize publication.

# Contributing

Rustleaks is an unpublished alpha. Contributions should preserve the pinned
compatibility profile and the separation between the core engine, source
adapters, report formatting, and CLI behavior.

## Local checks

Install Bazelisk, Just, and the toolchain selected by `rust-toolchain.toml`.
The repository pins Bazel in `.bazelversion`; `just doctor` reports the selected
versions without installing or changing anything. The complete upstream oracle
also requires the pinned repository at `../gitleaks`, Go, and the exact
auxiliary Cargo tools checked by `xtask`.

Use `just --list` to discover the public commands. Run focused Bazel targets
while editing, then run the complete local gate:

```sh
just ci
```

`just build`, `just test`, `just docs`, `just parity`, and `just check` expose
the canonical named Bazel targets. Formatting and Clippy are Bazel checks, and
the check gate also compiles the library/feature graph for all eight declared
targets. Cross-compilation is compile-only evidence; matching native runners
remain a separate requirement.

Cargo remains the public package metadata interface. Use `just package-check`
for extracted external Cargo and Bazel consumers, and `just release-dry-run`
for Cargo's locked no-upload publish check. `just deps-repin` is the only
public path that regenerates Cargo, crate-universe, and Bazel module lockfiles.

## Compatibility changes

Do not update the upstream revision, packaged default configuration, frozen
corpora, fixtures, public API snapshot, or safe Rust dispositions in isolation.
Follow [the upstream update procedure](docs/UPDATING_UPSTREAM.md). Explain any
intentional difference and add direct evidence that fails when the contract is
violated.

Use synthetic or upstream-provided test values. Never commit real credentials.

## Commit messages

Use Conventional Commits with a lowercase imperative description, for example
`test(core): cover native allow markers`. Keep behavior changes with their
tests and generated artifacts. Do not commit build output, local settings, raw
audit notes, or planning files.

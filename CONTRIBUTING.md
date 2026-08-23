# Contributing

Rustleaks is an unpublished alpha. Contributions should preserve the pinned
compatibility profile and the separation between the core engine, source
adapters, report formatting, and CLI behavior.

## Local checks

Install the toolchain selected by `rust-toolchain.toml`. The complete parity
gate also requires the pinned upstream repository at `../gitleaks`, Go, and
the exact auxiliary Cargo tools checked by `xtask`.

Run focused tests while editing, then run:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --all-features --no-deps --locked
cargo test --workspace --all-targets --all-features --locked
cargo xtask parity --all
```

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

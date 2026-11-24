# Supported Rust API snapshot

`rustleaks-core.txt` is the supported public API snapshot of
`rustleaks-core`. It holds the current API. It is generated with
`cargo-public-api` 0.52.0 on the `nightly-2026-08-21` toolchain:

```sh
cargo +nightly-2026-08-21 public-api -p rustleaks-core -sss --color never
```

`cargo xtask public-api-check` runs the same command and requires the output
to match the snapshot exactly. `cargo xtask qualify` runs that check. The
snapshot leaves out blanket implementations, auto-trait implementations and
auto-derived implementations. Every addition, removal or signature change
needs a reviewed update of the snapshot.

The snapshot does not show whether a change is breaking. For every release
candidate, also run `cargo-semver-checks` against the latest version of
`rustleaks-core` on crates.io, selected with `--baseline-version`. GitHub
release tags can lag crate publication, so read the version from crates.io.
For a prerelease candidate, pass `--release-type minor`. Without it, the tool
treats a prerelease version change as a major release and can skip checks.
Run every supported feature profile and review the API changes by hand.

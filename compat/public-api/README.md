# Supported Rust API snapshot

`rustleaks-core-0.1.0-alpha.1.txt` is the first supported Rust API baseline. It
is generated with `cargo-public-api 0.52.0` using:

```sh
cargo public-api -p rustleaks-core -sss --color never
```

The snapshot intentionally omits blanket implementations, auto-trait
implementations, and auto-derived implementations. The local public-API gate
requires exact output, so additions, removals, and signature changes all need
an explicit reviewed baseline update during the alpha series.

Once a prior crate release exists, supplement the snapshot with
`cargo-semver-checks` against the latest published registry version, selected
with `--baseline-version`. GitHub release tags may lag crate publication.
For prerelease candidates, explicitly pass `--release-type minor` so additive
API changes are allowed while breaking changes are checked. The tool otherwise
treats a prerelease version change as a major release and can skip those checks.
Run every supported feature profile and review the API changes manually.

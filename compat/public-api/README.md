# Supported Rust API snapshot

`rustleaks-core-0.1.0-alpha.1.txt` is the first supported Rust API baseline. It
is generated with `cargo-public-api 0.52.0` using:

```sh
cargo public-api -p rustleaks-core -sss --color never
```

The snapshot intentionally omits blanket implementations, auto-trait
implementations, and auto-derived implementations. The local public-API gate
requires exact output, so additions, removals, and signature changes all need
an explicit reviewed baseline update during the alpha series. Once a published
release tag exists, semver comparison against that tag supplements this exact
first-release snapshot.

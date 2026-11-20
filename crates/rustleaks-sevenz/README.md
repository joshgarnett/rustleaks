# rustleaks-sevenz

A safe, bounded 7z decoder for the Rustleaks archive sources. It reads 7z
archives and decodes members. It has no encoder and no AES support, so
encrypted members fail as an unsupported method.

The crate is internal to Rustleaks and is not published. Only
`rustleaks-sources` uses it, behind its `archives` feature. No type from this
crate appears in a public API.

- Upstream: [`sevenz-rust2`](https://crates.io/crates/sevenz-rust2) 0.20.2.
- License: Apache-2.0, in `LICENSE`.

See [Dependencies](../../docs/dev/dependencies.md#archive-codec-decision) for
the upstream commit and archive SHA-256, the changes from upstream, the reason
for the fork and the conditions for replacing it.

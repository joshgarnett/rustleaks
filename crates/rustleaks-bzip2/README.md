# rustleaks-bzip2

This page is for contributors.

A safe BZip2 decoder for the Rustleaks archive sources. Invalid input fails
with a structured error instead of a panic.

The crate is internal to Rustleaks and is not published. Only
`rustleaks-sources` (behind its `archives` feature) and `rustleaks-sevenz` use
it. No type from this crate appears in a public API.

- Upstream: [`bzip2-rs`](https://github.com/paolobarbolini/bzip2-rs) 0.1.2.
- License: MIT or Apache-2.0, in `LICENSE-MIT` and `LICENSE-APACHE`.

See [Dependencies](../../docs/dev/dependencies.md#archive-codec-decision) for
the upstream commit and archive SHA-256, the changes from upstream, the reason
for the fork and the conditions for replacing it.

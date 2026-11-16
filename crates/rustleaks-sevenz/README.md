# rustleaks-sevenz

This crate is derived from the
[`sevenz-rust2` 0.20.2 decoder](https://crates.io/crates/sevenz-rust2)
and is maintained in-tree under its Apache-2.0 terms. The license text is in
`LICENSE` next to this file. The fork version is `0.20.2-rustleaks.1`. The
upstream archive SHA-256 is
`29225600349ef74beda5a9fffb36ac660a24613c0bde9315d0c49be1d51e9c24` and the
upstream commit is `424ebdb8fa98b78b8e1c18f73c9add6972fe5496`.

The fork keeps only 7z reading. It removes the encoder, writer, file system
extraction and AES code, so encrypted members fail as an unsupported method.
It adds checked offsets, fallible allocation, bounded metadata and checks of
the coder graph. The graph check rejects duplicate stream bindings, invalid
packed inputs and cycles before any decoder is built. The crate forbids
unsafe code and follows the workspace Rust 1.95 policy. Its default features
turn on the Brotli, BZip2, Deflate, LZ4 and Zstandard decoders. BZip2 uses the
in-tree `rustleaks-bzip2` fork.

The released `sevenz-rust2` 0.22.2 with the needed codecs adds `zstd-sys`, a
native linked library, so it is not used. The changes above cannot be made
with an extension trait around the upstream API.

The crate is not published. Only `rustleaks-sources` uses it, behind the
`archives` feature, and no type from this crate appears in a public API. See
[Dependencies](../../docs/dev/dependencies.md#archive-codec-decision) for the
decision and the conditions for replacing the fork.

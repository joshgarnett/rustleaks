# rustleaks-bzip2

This crate is derived from the
[`bzip2-rs` 0.1.2 decoder](https://github.com/paolobarbolini/bzip2-rs) and is
maintained in-tree under its MIT/Apache-2.0 terms. The local fork replaces
decoder `unwrap`, `unreachable!`, and input-consumption assertions with
structured failures, replaces `crc32fast` with a safe, table-free
implementation of the non-reflected BZip2 CRC-32, and adopts the workspace's
Rust 1.88 policy.

Using `bzip2-rs` directly would restore those panic paths on hostile input.
Using `bzip2 0.6.1` instead would introduce its `libbz2-rs-sys` unsafe boundary
without cargo-vet coverage. Neither gap can be corrected by an extension trait
because the relevant state transitions and CRC implementation are private to
the upstream crates. Keeping this fork in-tree makes the required boundary
enforceable by the workspace.

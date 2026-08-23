# rustleaks-bzip2

This crate is derived from the
[`bzip2-rs` 0.1.2 decoder](https://github.com/paolobarbolini/bzip2-rs) and is
maintained in-tree under its MIT/Apache-2.0 terms. The local fork replaces
`crc32fast` with a safe, table-free implementation of the non-reflected BZip2
CRC-32 and adopts the workspace's Rust 1.85 policy. Keeping the fork in-tree
makes those boundaries enforceable by the workspace.

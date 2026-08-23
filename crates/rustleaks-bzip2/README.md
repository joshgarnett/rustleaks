# rustleaks-bzip2

This crate is the [`bzip2-rs` 0.1.2 decoder](https://github.com/paolobarbolini/bzip2-rs), maintained in-tree under its
MIT/Apache-2.0 terms. The decoder algorithm is unchanged; its `crc32fast`
dependency is replaced by a small safe, table-free implementation of the
non-reflected BZip2 CRC-32. Keeping the fork in-tree makes the no-unsafe and
Rust 1.85 boundaries enforceable by the workspace.

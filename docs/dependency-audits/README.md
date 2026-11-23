# Dependency audits

This folder is for maintainers. Each file is a dated review of exact
dependency versions: the source, the selected features, unsafe code, build
scripts, licenses and how Rustleaks uses the package. A review applies only
to the versions it names. The dependency policy is in
[Dependencies](../dev/dependencies.md).

The cargo-vet records in `supply-chain/audits.toml` cite these files. A full
audit reviews one complete version. A delta audit reviews only the changes
between two versions and builds on an earlier full audit of the older
version. File names describe the review batch, not the package, so use the
table below to find a package.

| Package | Version | Audit | Kind |
| --- | --- | --- | --- |
| `adler2` | 2.0.1 | [runtime-adler2-batch-17.md](runtime-adler2-batch-17.md) | Full |
| `aho-corasick` | 1.1.5 | [core-aho-corasick-batch-7.md](core-aho-corasick-batch-7.md) | Full |
| `alloc-no-stdlib` | 2.0.4 | [runtime-small-residual-batch-41.md](runtime-small-residual-batch-41.md) | Full |
| `alloc-no-stdlib` | 2.0.4 to 3.0.0 | [maintenance-2026-11.md](maintenance-2026-11.md) | Delta |
| `alloc-stdlib` | 0.2.4 | [runtime-small-residual-batch-41.md](runtime-small-residual-batch-41.md) | Full |
| `alloc-stdlib` | 0.2.4 to 0.3.0 | [maintenance-2026-11.md](maintenance-2026-11.md) | Delta |
| `base64` | 0.23.1 | [core-base64-batch-5.md](core-base64-batch-5.md) | Full |
| `bitflags` | 2.13.1 | [runtime-bitflags-batch-32.md](runtime-bitflags-batch-32.md) | Full |
| `bitflags` | 2.13.1 to 2.13.2 | [maintenance-2026-11.md](maintenance-2026-11.md) | Delta |
| `block-buffer` | 0.12.1 | [runtime-block-buffer-batch-19.md](runtime-block-buffer-batch-19.md) | Full |
| `brotli-decompressor` | 5.0.3 | [runtime-compression-batch-42.md](runtime-compression-batch-42.md) | Full |
| `brotli-decompressor` | 5.0.3 to 6.2.0 | [maintenance-2026-11.md](maintenance-2026-11.md) | Delta |
| `brotli-decompressor` | 6.2.0 to 6.3.2 | [maintenance-2026-11-20.md](maintenance-2026-11-20.md) | Delta |
| `cfg-if` | 1.0.4 | [runtime-cfg-if-batch-16.md](runtime-cfg-if-batch-16.md) | Full |
| `cfg-if` | 1.0.4 to 1.0.5 | [maintenance-2026-11.md](maintenance-2026-11.md) | Delta |
| `compcol` | 0.6.10 | [runtime-compcol-batch-39.md](runtime-compcol-batch-39.md) | Full |
| `compcol` | 0.6.10 to 0.7.8 | [compcol-0.7.8.md](compcol-0.7.8.md) | Delta, for the cargo-vet exemption |
| `compcol` | 0.7.8 to 0.8.0 | [maintenance-2026-11-20.md](maintenance-2026-11-20.md) | Delta, for the cargo-vet exemption |
| `const-oid` | 0.10.2 | [runtime-const-oid-batch-27.md](runtime-const-oid-batch-27.md) | Full |
| `cpufeatures` | 0.3.0 | [runtime-small-residual-batch-41.md](runtime-small-residual-batch-41.md) | Full |
| `crc32fast` | 1.5.1 | [runtime-crc32fast-batch-25.md](runtime-crc32fast-batch-25.md) | Full |
| `crc32fast` | 1.5.1 to 1.5.4 | [maintenance-2026-11.md](maintenance-2026-11.md) | Delta |
| `crypto-common` | 0.2.2 | [runtime-crypto-common-batch-18.md](runtime-crypto-common-batch-18.md) | Full |
| `digest` | 0.11.3 | [runtime-digest-batch-26.md](runtime-digest-batch-26.md) | Full |
| `equivalent` | 1.0.2 | [runtime-equivalent-batch-22.md](runtime-equivalent-batch-22.md) | Full |
| `equivalent` | 1.0.2 to 1.0.3 | [maintenance-2026-11.md](maintenance-2026-11.md) | Delta |
| `errno` | 0.3.14 | [runtime-errno-batch-23.md](runtime-errno-batch-23.md) | Full |
| `filetime` | 0.2.29 | [runtime-filetime-batch-24.md](runtime-filetime-batch-24.md) | Full |
| `flate2` | 1.1.9 | [runtime-compression-batch-42.md](runtime-compression-batch-42.md) | Full |
| `flate2` | 1.1.9 to 1.1.10 | [maintenance-2026-11.md](maintenance-2026-11.md) | Delta |
| `flate2` | 1.1.10 to 1.1.11 | [maintenance-2026-11-20.md](maintenance-2026-11-20.md) | Delta |
| `hashbrown` | 0.17.1 | [runtime-hashbrown-batch-38.md](runtime-hashbrown-batch-38.md) | Full |
| `hybrid-array` | 0.4.14 | [runtime-hybrid-array-batch-28.md](runtime-hybrid-array-batch-28.md) | Full |
| `hybrid-array` | 0.4.14 to 0.4.15 | [maintenance-2026-11.md](maintenance-2026-11.md) | Delta |
| `indexmap` | 2.14.0 to 2.14.2 | [maintenance-2026-11.md](maintenance-2026-11.md) | Delta |
| `itoa` | 1.0.18 | [core-leaves-batch-1.md](core-leaves-batch-1.md) | Full |
| `libc` | 0.2.189 | [platform-bindings-batch-43.md](platform-bindings-batch-43.md) | Full |
| `libc` | 0.2.190 to 0.2.191 | [maintenance-2026-11.md](maintenance-2026-11.md) | Delta |
| `linux-raw-sys` | 0.12.1 | [platform-bindings-batch-43.md](platform-bindings-batch-43.md) | Full |
| `lz4_flex` | 0.14.0 | [runtime-lz4-flex-batch-30.md](runtime-lz4-flex-batch-30.md) | Full |
| `lz4_flex` | 0.14.0 to 0.14.2 | [maintenance-2026-11-20.md](maintenance-2026-11-20.md) | Delta |
| `lzma-rust2` | 0.20.0 | [runtime-lzma-rust2-batch-36.md](runtime-lzma-rust2-batch-36.md) | Full |
| `lzma-rust2` | 0.20.0 to 0.25.0 | [maintenance-2026-11.md](maintenance-2026-11.md) | Delta |
| `memchr` | 2.8.3 | [core-memchr-batch-6.md](core-memchr-batch-6.md) | Full |
| `miniz_oxide` | 0.8.9 to 0.9.1 | [runtime-miniz-oxide-batch-29.md](runtime-miniz-oxide-batch-29.md) | Delta |
| `proc-macro2` | 1.0.107 | [core-proc-macro-batch-3.md](core-proc-macro-batch-3.md) | Full |
| `quote` | 1.0.47 | [core-proc-macro-batch-3.md](core-proc-macro-batch-3.md) | Full |
| `rawzip` | 0.5.1 | [runtime-rawzip-batch-35.md](runtime-rawzip-batch-35.md) | Full |
| `rawzip` | 0.5.1 to 0.5.2 | [maintenance-2026-11.md](maintenance-2026-11.md) | Delta |
| `regex-automata` | 0.4.18 | [core-regex-automata-batch-14.md](core-regex-automata-batch-14.md) | Full |
| `regex-automata` | 0.4.18 | [regex-meta-backend.md](regex-meta-backend.md) | Selected features |
| `regex-automata` | 0.4.18 to 0.4.19 | [maintenance-2026-11-23.md](maintenance-2026-11-23.md) | Delta |
| `regex-syntax` | 0.8.11 | [core-regex-syntax-batch-13.md](core-regex-syntax-batch-13.md) | Full |
| `regex-syntax` | 0.8.11 to 0.8.12 | [maintenance-2026-11-23.md](maintenance-2026-11-23.md) | Delta |
| `rustix` | 1.1.4 | [maintenance-rustix-batch-40.md](maintenance-rustix-batch-40.md) | Full |
| `rustix` | 1.1.4 to 1.1.6 | [maintenance-2026-11.md](maintenance-2026-11.md) | Delta |
| `semver` | 1.0.28 | [core-leaves-batch-2.md](core-leaves-batch-2.md) | Full |
| `serde` | 1.0.229 | [core-serde-batch-10.md](core-serde-batch-10.md) | Full |
| `serde_core` | 1.0.229 | [core-serde-core-batch-9.md](core-serde-core-batch-9.md) | Full |
| `serde_derive` | 1.0.229 | [core-serde-derive-batch-8.md](core-serde-derive-batch-8.md) | Full |
| `serde_json` | 1.0.151 | [core-serde-json-batch-11.md](core-serde-json-batch-11.md) | Full |
| `serde_json` | 1.0.151 to 1.0.154 | [maintenance-2026-11.md](maintenance-2026-11.md) | Delta |
| `serde_spanned` | 1.1.1 | [core-leaves-batch-1.md](core-leaves-batch-1.md) | Full |
| `serde_spanned` | 1.1.1 to 1.1.2 | [maintenance-2026-11.md](maintenance-2026-11.md) | Delta |
| `serde_spanned` | 1.1.2 to 1.1.3 | [maintenance-2026-11-20.md](maintenance-2026-11-20.md) | Delta |
| `sha2` | 0.11.1 | [maintenance-2026-11.md](maintenance-2026-11.md) | Full |
| `sha2` | 0.11.0 | [runtime-sha2-exception.md](runtime-sha2-exception.md) | Exception, resolved by 0.11.1 |
| `simd-adler32` | 0.3.10 | [runtime-simd-adler32-batch-20.md](runtime-simd-adler32-batch-20.md) | Full |
| `syn` | 3.0.4 | [core-syn-batch-15.md](core-syn-batch-15.md) | Full |
| `syn` | 3.0.4 to 3.0.9 | [maintenance-2026-11.md](maintenance-2026-11.md) | Delta |
| `tar` | 0.4.46 | [maintenance-tar-batch-34.md](maintenance-tar-batch-34.md) | Full |
| `thiserror` | 2.0.20 | [core-proc-macro-batch-3.md](core-proc-macro-batch-3.md) | Full |
| `thiserror` | 2.0.20 to 2.0.21 | [maintenance-2026-11.md](maintenance-2026-11.md) | Delta |
| `thiserror-impl` | 2.0.20 | [core-leaves-batch-2.md](core-leaves-batch-2.md) | Full |
| `thiserror-impl` | 2.0.20 to 2.0.21 | [maintenance-2026-11.md](maintenance-2026-11.md) | Delta |
| `tinyvec` | 1.12.0 | [runtime-tinyvec-batch-33.md](runtime-tinyvec-batch-33.md) | Full |
| `toml` | 1.1.4+spec-1.1.0 | [core-toml-batch-4.md](core-toml-batch-4.md) | Full |
| `toml` | 1.1.4+spec-1.1.0 to 1.2.0+spec-1.1.0 | [maintenance-2026-11.md](maintenance-2026-11.md) | Delta |
| `toml` | 1.2.0+spec-1.1.0 to 1.2.1+spec-1.1.0 | [maintenance-2026-11-20.md](maintenance-2026-11-20.md) | Delta |
| `toml_datetime` | 1.1.1+spec-1.1.0 | [core-leaves-batch-1.md](core-leaves-batch-1.md) | Full |
| `toml_datetime` | 1.1.1+spec-1.1.0 to 1.1.2+spec-1.1.0 | [maintenance-2026-11.md](maintenance-2026-11.md) | Delta |
| `toml_datetime` | 1.1.2+spec-1.1.0 to 1.1.3+spec-1.1.0 | [maintenance-2026-11-20.md](maintenance-2026-11-20.md) | Delta |
| `toml_parser` | 1.1.3+spec-1.1.0 | [core-toml-batch-4.md](core-toml-batch-4.md) | Full |
| `toml_parser` | 1.1.3+spec-1.1.0 to 1.1.5+spec-1.1.0 | [maintenance-2026-11.md](maintenance-2026-11.md) | Delta |
| `toml_writer` | 1.1.2+spec-1.1.0 | [core-leaves-batch-1.md](core-leaves-batch-1.md) | Full |
| `toml_writer` | 1.1.2+spec-1.1.0 to 1.2.0+spec-1.1.0 | [maintenance-2026-11.md](maintenance-2026-11.md) | Delta |
| `twox-hash` | 2.1.4 | [runtime-twox-hash-batch-31.md](runtime-twox-hash-batch-31.md) | Full |
| `twox-hash` | 2.1.4 to 2.1.5 | [maintenance-2026-11.md](maintenance-2026-11.md) | Delta |
| `typenum` | 1.20.1 | [runtime-typenum-batch-37.md](runtime-typenum-batch-37.md) | Full |
| `unicode-ident` | 1.0.24 | [core-leaves-batch-2.md](core-leaves-batch-2.md) | Full |
| `unicode-ident` | 1.0.24 to 1.0.27 | [maintenance-2026-11.md](maintenance-2026-11.md) | Delta |
| `windows-link` | 0.2.1 | [runtime-windows-link-batch-21.md](runtime-windows-link-batch-21.md) | Full |
| `windows-sys` | 0.61.2 | [platform-bindings-batch-43.md](platform-bindings-batch-43.md) | Full |
| `winnow` | 1.0.4 | [core-winnow-batch-12.md](core-winnow-batch-12.md) | Full |
| `winnow` | 1.0.4 to 1.0.5 | [maintenance-2026-11.md](maintenance-2026-11.md) | Delta |
| `xattr` | 1.6.1 to 1.7.0 | [maintenance-2026-11.md](maintenance-2026-11.md) | Delta |
| `zmij` | 1.0.23 | [core-leaves-batch-2.md](core-leaves-batch-2.md) | Full |
| `zstd-zero` | 0.1.0 | [runtime-small-residual-batch-41.md](runtime-small-residual-batch-41.md) | Full |
| `zstd-zero` | 0.1.0 to 0.2.1 | [maintenance-2026-11.md](maintenance-2026-11.md) | Delta |

# Dependency safety boundary

All owned crate roots use `#![forbid(unsafe_code)]`, and the release gate
rejects owned production `unsafe`. That statement does not extend to the
complete dependency graph: selected registry dependencies contain internal
unsafe code.

The reviewed normal-runtime graphs at `0.1.0-alpha.1` are identified by these
normalized `cargo tree --locked --edges normal --prefix none --target all`
SHA-256 values. Normalization removes only the absolute workspace checkout
path; external path identities remain part of the digest.
The all-target union fails closed on target-specific dependency changes even
when the release gate runs on macOS; warning-denied target compilation remains
separate evidence and native Linux/Windows execution remains follow-up work.

| Root and features | Tree SHA-256 |
| --- | --- |
| `rustleaks-core` | `d58ae3874c4c31586e859cab2ac5659608b55c07e7c771991b37700d56faadc1` |
| `rustleaks-report` | `31d643c37aef98750509103e02a81c8a54c36593899db6f237ce8b4aa21c6b88` |
| `rustleaks-sources` | `8bb90a9651d9f074b2362f23efbfb0dde8edfd12f82a76a606e5048d102232d9` |
| `rustleaks-sources --all-features` | `507c513d16c3667a362f7f1f62b43c81e0b6bd6bf27d73fe38f85bc961f44b32` |
| `rustleaks-cli --all-features` | `abf38e45586827bbc0320814a8dcb7a5a5bafdea44f65f5bf7772b2426116877` |

The workspace-wide locked resolution contains custom build targets in
`crc32fast 1.5.1`, `libc 0.2.189`, `proc-macro2 1.0.107`, `quote 1.0.47`,
`rustix 1.1.4`, `serde 1.0.229`, `serde_core 1.0.229`, `serde_json 1.0.151`,
`thiserror 2.0.20`, and `zmij 1.0.23`. No resolved package declares Cargo's
native `links` key, and the selected normal all-feature source graph contains
no `cc`, `cmake`, `bindgen`, `pkg-config`, `vcpkg`, or native `-sys` crate.
Several listed build targets belong only to target-specific development tools;
the exact normal-runtime graph hashes above remain the publication boundary.

The enforced cargo-geiger signal requires used unsafe constructs in these 25
package/version identities on every checked host:

```text
aho-corasick@1.1.5
alloc-no-stdlib@2.0.4
alloc-stdlib@0.2.4
block-buffer@0.12.1
brotli-decompressor@5.0.3
const-oid@0.10.2
hybrid-array@0.4.14
itoa@1.0.18
lz4_flex@0.14.0
lzma-rust2@0.16.5
lzma-rust2@0.19.0
memchr@2.8.3
proc-macro2@1.0.107
regex-automata@0.4.7
semver@1.0.28
serde_core@1.0.229
serde_json@1.0.151
sha2@0.11.0
syn@3.0.3
toml_parser@1.1.3+spec-1.1.0
twox-hash@2.1.3
unicode-ident@1.0.24
winnow@0.7.15
winnow@1.0.4
zmij@1.0.23
```

Target selection can additionally expose used unsafe in `cpufeatures@0.3.0`
and `libc@0.2.189`. The gate permits only those two reviewed target-specific
additions to the common set.

All first-party packages report zero used unsafe constructs and forbid unsafe
code. The gate fails if a common package disappears, an unreviewed package
appears, or first-party status changes. This inventory is a change detector,
not an audit or reachability claim.

The publishable core's relevant unsafe-bearing boundary is narrow:

- `aho-corasick`, `regex-automata`, and `memchr` provide checked search APIs
  over borrowed byte slices and isolate architecture-specific acceleration;
- `serde`, `serde_json`, `toml`, `winnow`, and their numeric/parser helpers
  provide safe parsing and serialization APIs; and
- proc-macro dependencies run at build time and are not linked into the
  runtime library.

The unpublished archive feature adds pure-Rust compression and container
decoders. `lzma-rust2` has optimization disabled, `lz4_flex` selects checked
and safe encode/decode features, and the in-tree bzip2, RAR, RAR2, and 7z forks
forbid owned unsafe. XZ checksums retain exact-pinned `sha2`; its selected
portable/hardware dispatch is the principal intentional archive dependency
unsafe boundary. Archive inputs are additionally constrained by depth, entry,
member, cumulative, and spool limits and are covered by hostile-input harnesses.

`rustix`, `libc`, `linux-raw-sys`, and `windows-sys` appear only through
target-specific development checks used to observe process cleanup; they are
not normal dependencies of the publishable core. Platform graph selection must
be re-audited if one becomes a normal dependency.

A conservative source scan also finds the word `unsafe` in files belonging to
several selected crates. This over-approximates active code because it includes
comments, tests, build code, unused features, and other target branches. It is
an inventory signal, not a reachability claim. The safety argument is the exact
feature graph, safe API boundary, resource controls, focused tests/fuzzing, and
version/source policy together, not a claim that all dependencies are safe
Rust.

Any dependency version, feature, target, or publication-boundary change reopens
this review. `cargo deny check` must also pass advisories, bans, licenses, and
sources. Native Linux/Windows execution remains a nonblocking runtime
follow-up; target compilation does not validate architecture-specific unsafe
paths at runtime.

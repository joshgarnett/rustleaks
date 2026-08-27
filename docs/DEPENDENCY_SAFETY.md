# Dependency safety boundary

All owned crate roots use `#![forbid(unsafe_code)]`, and the release gate
rejects owned production `unsafe`. That statement does not extend to the
complete dependency graph: selected registry dependencies contain internal
unsafe code.

Dependency review uses the locked Cargo and Bazel resolutions, cargo-deny,
cargo-vet, RustSec, and the unsafe inventory. It does not fingerprint complete
dependency trees. Exact tree digests changed for every routine version update
without identifying whether the change crossed a security boundary.

The targeted dependency gate evaluates the all-target normal graph for
`rustleaks-core` and the all-feature graph for `rustleaks-sources`. It rejects
higher-layer or owned codec dependencies in core, common native build helpers,
native `-sys` crates, and any resolved package declaring Cargo's `links` key.
Warning-denied target compilation remains separate evidence.

The enforced cargo-geiger signal requires used unsafe constructs in these 23
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
lzma-rust2@0.20.0
memchr@2.8.3
proc-macro2@1.0.107
regex-automata@0.4.18
semver@1.0.28
serde_core@1.0.229
serde_json@1.0.151
sha2@0.11.0
syn@3.0.4
toml_parser@1.1.3+spec-1.1.0
twox-hash@2.1.3
unicode-ident@1.0.24
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
decoders. `lzma-rust2 0.20.0` has optimization disabled, `lz4_flex` selects
checked and safe encode/decode features, and the retained in-tree bzip2, RAR,
and 7z forks forbid owned unsafe. RAR2 uses upstream `compcol 0.3.1` with only
`alloc` and `rar2`; its selected source matches the previously owned RAR2
implementation. XZ checksums retain exact-pinned `sha2`; its selected
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

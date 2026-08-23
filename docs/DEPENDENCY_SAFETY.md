# Dependency safety boundary

All owned crate roots use `#![forbid(unsafe_code)]`, and the release gate
rejects owned production `unsafe`. That statement does not extend to the
complete dependency graph: selected registry dependencies contain internal
unsafe code.

The reviewed normal-runtime graphs at `0.1.0-alpha.1` are identified by these
`cargo tree --locked --edges normal --prefix none --target all` SHA-256 values.
The all-target union fails closed on target-specific dependency changes even
when the release gate runs on macOS; warning-denied target compilation remains
separate evidence and native Linux/Windows execution remains follow-up work.

| Root and features | Tree SHA-256 |
| --- | --- |
| `rustleaks-core` | `aaead9358e53674f93f0c77185adf51a12a23c6407c229d21cc19a167ad631bb` |
| `rustleaks-report` | `60c9b8d5bde4e2746d47844567c86e4b0a9972243af186501e49224e6d58a3c7` |
| `rustleaks-sources` | `856c46dfc954ff66679da827fe58766cfef6d391529a4203e767e8c8a6083d4f` |
| `rustleaks-sources --all-features` | `7de1b426b4b8b069c56cf9fd2d5accddacd780987c214eeda97244ee6a5d0f9b` |
| `rustleaks-cli --all-features` | `6ee21bdba7367e6b117ac89a77e4f45dd473fa7cb0284035d68722045959ef89` |

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

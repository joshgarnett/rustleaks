# Dependency policy

- Prefer small, maintained crates with compatible permissive licenses and a
  current security posture. Record lasting choices in this document and commit
  `Cargo.lock`.
- `rustleaks-core` must not depend on the CLI, source, report, archive, Git,
  async-runtime, or parallel-runtime crates. Its public API must not expose a
  regex implementation type.
- Source and report crates depend only downstream on core; the CLI may assemble
  all three. Compatibility tooling and `xtask` are unpublished workspace leaves.
- Owned crates forbid unsafe code. Any dependency containing necessary unsafe
  code requires isolation, rationale, license review, and adversarial tests.
- License and advisory checks are required before release. An advisory may be
  waived only with a time-bounded, evidence-backed entry in
  `supply-chain-exceptions.toml`; it may not be hidden by removing the check.
- Publishable dependencies normally use MSRV-compatible semver ranges.
  `regex-syntax` requires `^0.8.5` and `regex-automata` requires `^0.4.12` so
  downstream applications can unify the maintained 0.8 and 0.4 release lines.
  These minima use Unicode 16 tables, making post-Unicode-15 property and case
  data an explicit compatibility difference from the pinned Go oracle. The
  private frontend still limits accepted property names to the Go namespace,
  and generated Go simple-lowercase tables used outside regular expressions
  remain pinned to Unicode 15. Dependency updates require the complete regex
  oracle and security review. Development uses the pinned toolchain; CI also
  builds the declared MSRV and current native platform lanes.
- `serde_json` is a core runtime dependency because the upstream baseline file
  is a JSON report. The session parser wraps its tokenizer with a private
  compatibility visitor for Go field matching, null/duplicate handling,
  invalid UTF-8, and lone
  surrogate replacement; no JSON type appears in the public session API.
- The `rustleaks-sources/archives` feature is the only production archive-codec
  boundary. No archive type crosses the public source API, no codec enters
  `rustleaks-core`, and the default feature lane resolves none of them. The
  selected codec graph is exact-pinned and uses in-tree safe Rust forks only
  where the source boundary requires them. The reviewed unsafe boundary, codec
  rationale, resource controls, and validation evidence are maintained in
  [dependency safety](DEPENDENCY_SAFETY.md) and the codec-adjacent licenses and
  notices.

## Archive codec decisions

- `compcol 0.3.1` replaces the owned `rustleaks-compcol` copy. It is the newest
  release compatible with Rust 1.85. Only `alloc` and `rar2` are enabled, and
  its RAR2 source is unchanged from the 0.3.0 code previously maintained
  in-tree. The 0.4 through 0.6 release lines require Rust 1.88.
- `rustleaks-bzip2` remains a fork of `bzip2-rs 0.1.2`. The fork replaces
  decoder `unwrap`, `unreachable!`, and input-consumption assertions with
  structured failures and replaces `crc32fast` with owned safe CRC code. The
  current `bzip2 0.6.1` alternative uses `libbz2-rs-sys`, which would add a
  large unsafe dependency boundary without cargo-vet coverage.
- `rustleaks-rar-codec` remains isolated because upstream `rars 0.9.3` requires
  Rust 1.87 and brings writing, encryption, recovery, parallelism, and
  filesystem functionality outside the source adapter contract.
- `rustleaks-sevenz` remains isolated from `sevenz-rust2 0.20.2` because the
  owned decoder removes encoder and filesystem APIs and carries checked parser,
  allocation, and coder-graph hardening used by the archive resource boundary.
  These changes cannot be supplied by an extension trait around the upstream
  public API.

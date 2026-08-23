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
  `regex-syntax 0.8.4` and `regex-automata 0.4.7` are exact-pinned under
  D-0011 because their Unicode-15 tables are observable Go compatibility data;
  updates require the complete regex oracle and security review. Development
  uses the pinned toolchain; CI also builds the declared MSRV and current
  native platform lanes.
- `serde_json` is a core runtime dependency because the upstream baseline file
  is a JSON report. M8 wraps its tokenizer with a private compatibility visitor
  for Go field matching, null/duplicate handling, invalid UTF-8, and lone
  surrogate replacement; no JSON type appears in the public session API.
- The `rustleaks-sources/archives` feature is the only production archive-codec
  boundary. D-0018 exact-pins its safe native codec set. The in-tree
  `rustleaks-sevenz`, `rustleaks-compcol`, `rustleaks-rar-codec`, and
  `rustleaks-bzip2` forks all forbid unsafe code, build at Rust 1.85, and replace
  unsafe-accelerated CRC or codec paths with safe implementations. `crc32fast` is absent from the selected
  graph; owned gzip, ZIP, 7z, and RAR verification uses table-free safe Rust
  CRC-32 code. The direct XZ checksum path retains the single documented
  dependency exception: exact-pinned `sha2 0.11.0` contains audited internal
  unsafe implementations behind a safe API. No archive type crosses the public
  source API, no codec enters `rustleaks-core`, and the default feature lane
  resolves none of them.
  The 7z fork validates header-derived counts with fallible allocations,
  exposes a caller-controlled decoder-memory ceiling, disables unsafe LZMA
  optimization, uses one decoder thread, and contains parser panics as
  structured corruption. Its selected native decode profile includes COPY,
  DELTA, LZMA/LZMA2, BCJ/BCJ2, Deflate, bzip2, Brotli, LZ4, and Zstandard;
  exact pinned-Go fixtures exercise every non-encrypted registered method.
  Brotli and LZ4 use exact-pinned pure-Rust decoders whose selected
  configurations forbid unsafe code; LZ4 additionally uses checked decoding
  and disables its unsafe acceleration features. Bzip2 uses an in-tree
  MIT/Apache-2.0 decoder fork with an owned table-free safe CRC-32 so the
  ordinary bzip2 path does not inherit `crc32fast` acceleration. Snappy, S2,
  and MinLZ framing and block decoding are implemented in the owned source
  crate with safe Rust, checked allocation, and an owned table-free CRC-32C;
  they add no codec dependency or platform-specific implementation.
  RAR 1.5/4 and RAR5 containers are parsed by owned checked Rust. Stored and
  RAR2 members use the in-tree MIT `rustleaks-compcol` fork. RAR3/RAR5 LZ,
  PPMd, RARVM/builtin filters, and cross-member solid state use the
  dependency-free `rustleaks-rar-codec` fork from `bitplane/rars` 0.9.3. Its
  explicit upstream `COPYING` grant is retained because the upstream Cargo
  license metadata names different licenses; the fork does not claim the
  metadata grant. The selected crate forbids unsafe code and backports only
  post-1.85 integer helpers. The backward-compatible upstream interface
  supplies neither passwords nor a volume resolver, so encrypted and
  unnamed-stream multi-volume inputs produce exact structured dispositions
  instead of invoking external tools or panicking.

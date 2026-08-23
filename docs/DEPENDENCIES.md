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
  `regex-syntax 0.8.4` and `regex-automata 0.4.7` are exact-pinned because
  their Unicode-15 tables are observable Go compatibility data;
  updates require the complete regex oracle and security review. Development
  uses the pinned toolchain; CI also builds the declared MSRV and current
  native platform lanes.
- `serde_json` is a core runtime dependency because the upstream baseline file
  is a JSON report. The session parser wraps its tokenizer with a private
  compatibility visitor for Go field matching, null/duplicate handling,
  invalid UTF-8, and lone
  surrogate replacement; no JSON type appears in the public session API.
- The `rustleaks-sources/archives` feature is the only production archive-codec
  boundary. No archive type crosses the public source API, no codec enters
  `rustleaks-core`, and the default feature lane resolves none of them. The
  selected codec graph is exact-pinned and uses in-tree safe Rust forks where
  necessary. The reviewed unsafe boundary, codec rationale, resource controls,
  and validation evidence are maintained in
  [dependency safety](DEPENDENCY_SAFETY.md) and the codec-adjacent licenses and
  notices.

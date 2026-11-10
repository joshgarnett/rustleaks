# Changelog

## [0.1.0-alpha.7] - 2026-11-09

- Use pooled meta regex searches and capture-free whole-match enumeration.
- Reuse normalized fragment bytes, original newline indexes and compiled
  capture metadata while retaining finding and budget behavior.
- Add large-fragment throughput workloads, backend differential regressions
  and documented cache, compile-time and memory limits.
- Verify downloaded published CLI archives on all eight native targets.

## [0.1.0-alpha.6] - 2026-11-06

- Add explicit native policy composition with bounded rule packs, collision checks,
  exact policy identity, and bounded source-omitting explanations.
- Add opt-in Azure Service Bus/Event Hubs, Azure App Configuration, and MongoDB
  credential rules with an independent synthetic quality comparison.
- Add offline historical GitHub token-layout annotations with explicit unknown
  checksum status and no finding suppression.
- Add bounded review records with expiry and stale policy/source/options checks,
  occurrence-preserving grouping, and JSON persistence.
- Add per-fragment and aggregate source scan budgets with explicit partial outcomes,
  cancellation cleanup, and conservative accounting after worker failure.
- Reject invalid 7z coder graphs and overflowing stream counts; add an opt-in
  strict member-length policy while preserving the default early-EOF behavior.
- Correct recursive detected-secret removal, CSV/XML escaping, Git path/hunk
  handling, worker termination, and archive cancellation.
- Add optional bounded fuzz, deep-security, profiling, quality-evaluation, and
  private performance-report workflows with explicit evidence limitations.
- Retire the live Go oracle and preserve historical evidence with Rust regression
  replay and integrity checks.

## [0.1.0-alpha.5] - 2026-11-05

- Require Rust 1.95 and align Cargo, Bazel, CI, package consumers, and release
  tooling on Rust 1.95.0.
- Update the optional RAR2 decoder to `compcol 0.7.8`, including corrected
  repeated-match offset history and bounded speculative output reservation.

## [0.1.0-alpha.4] - 2026-11-04

- Bound estimated PikeVM search working sets before cache allocation and
  return a structured compile error when the configured limits exceed the
  supported working-set ceiling.
- Validate combined bzip2 stream checksums, reject large-window Brotli streams,
  and handle overflowing Git commit dates without panicking.
- Update Rust dependencies while retaining Rust 1.88 and compatible public
  dependency ranges. Update the unpublished oracle toolchain to Go 1.26.10.
- Update pinned GitHub Actions, repair platform provenance checks and the
  Linux fixture race, and exercise newest allowed registry dependencies.

## [0.1.0-alpha.3] - 2026-08-27

- Require Rust 1.88 and use that toolchain consistently in Cargo, Bazel, CI,
  package, and release validation.
- Update the optional RAR2 implementation to `compcol 0.6.10` after auditing
  its dependency, unsafe-code, build-script, native-code, and resource-limit
  boundaries.
- Update maintained GitHub Actions to reviewed immutable revisions.
- Run nonpublishing release qualification without an environment approval,
  execute independent compatibility, security, fuzz, and self-scan gates in
  parallel, and reuse the verified artifacts in protected crates.io and GitHub
  release workflows.

## [0.1.0-alpha.2] - 2026-08-27

- Permit `regex-automata ^0.4.12` and `regex-syntax ^0.8.5` so downstream
  applications can resolve the maintained dependency lines without conflicting
  with Rustleaks exact pins.
- Accept post-Unicode-15 property and case-fold additions from compatible regex
  backend releases while retaining the Go property namespace and generated
  lowercase helpers.

## [0.1.0-alpha.1] - 2026-08-26

- Add the publishable `rustleaks-core` package with a synchronous, byte-first
  configuration and detection API.
- Package the pinned upstream default configuration and implement custom rules,
  extension merging, selection, required rules, allowlists, decoding,
  composites, redaction, fingerprints, baselines, ignores, and sessions.
- Add controlled scans with cooperative cancellation and explicit work,
  decoded-byte, and finding-record budgets.
- Add exact or explicitly unavailable finding ranges, content-omitting debug
  output, and recursive detected-secret removal for embedding callers.
- Add unpublished Rust source, archive, Git, report, CLI, compatibility, and
  codec workspace crates.
- Add native Rustleaks config, ignore, flag, environment, and allow-marker
  names while retaining the upstream spellings for backward compatibility.
- Differentially test the pinned compatibility profile against a bounded Go
  oracle and committed corpora.
- Add exact-candidate package, docs.rs, compatibility, security, fuzz, and
  eight-target release dry runs with twice-built native archives, checksums,
  target CycloneDX SBOMs, Cargo-to-Bazel reconciliation, and dry-run
  provenance plus GitHub-native signed attestations.

Hosted native workflows cover the declared Linux, Windows, macOS, and musl
target matrix. The crates.io package and GitHub release identify the published
version and exact source commit.

[0.1.0-alpha.1]: https://github.com/joshgarnett/rustleaks/releases/tag/v0.1.0-alpha.1
[0.1.0-alpha.2]: https://github.com/joshgarnett/rustleaks/releases/tag/v0.1.0-alpha.2
[0.1.0-alpha.3]: https://github.com/joshgarnett/rustleaks/releases/tag/v0.1.0-alpha.3
[0.1.0-alpha.4]: https://github.com/joshgarnett/rustleaks/releases/tag/v0.1.0-alpha.4
[0.1.0-alpha.5]: https://crates.io/crates/rustleaks-core/0.1.0-alpha.5
[0.1.0-alpha.6]: https://crates.io/crates/rustleaks-core/0.1.0-alpha.6

[0.1.0-alpha.7]: https://github.com/joshgarnett/rustleaks/releases/tag/v0.1.0-alpha.7

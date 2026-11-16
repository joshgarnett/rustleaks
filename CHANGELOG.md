# Changelog

## [Unreleased]

- Adopt a standalone compatibility policy. Help, usage and error wording, log
  and banner lines, and the order of JSON keys and CSV columns are no longer
  compatibility guarantees and can change. Findings, configuration meaning,
  report fields, exit codes, and supported Gitleaks commands, flags and
  environment variables stay compatible with the pinned Gitleaks revision.
- Add opt-in complete-target scanning with `--complete-profile FILE`. Eligible
  file and archive targets are read to the end under explicit limits. Each
  such scan writes one final `rustleaks_scan_status` line to standard error,
  and an incomplete scan exits with code 2.
- Add the `--native-pack` CLI option and the opt-in native rule packs
  `rustleaks-providers-v1` and `rustleaks-connections-v1`. Select packs with
  `NativePolicy` or `--native-pack`; `rustleaks-extra-v1` can be selected the
  same way.
- Add the `bytes-v1` native regex dialect and `buffer-v1` rule associations.
  An associated helper rule binds only to a primary match from the same
  decoded buffer.
- Add bounded local checks for Mapbox secret tokens and Vercel AI Gateway
  tokens. The `rustleaks-core` package now includes the static token table
  and licenses for the Vercel check.
- Recognize a final `.tgz` suffix as a gzip-compressed TAR archive in
  complete-target scans, including nested archives, directories and Git blobs.
- Share retained source lines of 4 KiB or more between findings with the same
  original byte range, which reduces memory for dense findings on long lines.
- Add opt-in extended Base64 decoding with `Base64Mode::Extended` through
  `ScanOptions::builder().base64_mode(...)` and `--base64-mode extended`.
  Extended mode decodes candidates to arbitrary bytes with standard or
  URL-safe alphabets, with or without padding. `Base64Mode::Compatible`
  remains the default.
- Add libpq keyword password rules for quoted and unquoted values to
  `rustleaks-connections-v1`, which now has 14 rule definitions.
- Add archive regression tests for verified TAR members before truncation,
  corrupt gzip input, and archive-depth exclusions.

The pinned default configuration and default detection behavior are unchanged.

## [0.1.0-alpha.9] - 2026-11-12

- Buffer built-in CLI reports written to standard output and preserve rendering,
  drain and flush error reporting.
- Avoid constructing discarded regex search engines during allowlist validation
  while retaining syntax, size and working-set checks.
- Defer decoder setup until a decode pass is admitted and skip newline-free
  blocks when indexing original fragment locations.
- Reduce directory and Git metadata allocations and bound source queue retries
  before waiting for worker progress.
- Add regression coverage for output failures, regex validation, byte locations,
  source paths, queue notifications, cancellation and worker cleanup.
- Include indexed license and attribution texts in native archives and provide
  GNU corresponding-source materials with native relink evidence.

## [0.1.0-alpha.8] - 2026-11-10

- Anchor eligible default-rule searches at keyword hits and precompute keyword
  indexes, with bounded configuration analysis and exact-match fallbacks.
- Reduce repeated filtering, normalization, decoding, generic suppression and
  baseline lookup work while preserving findings, spans and cancellation checks.
- Reduce report and diagnostic write overhead, reuse file buffers, and improve
  archive checksum and zstd history handling.
- Return complete multi-worker source findings in producer order.
- Add regression coverage and performance measurements against alpha.6 and
  alpha.7, including configuration, startup and process-memory costs.

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

[Unreleased]: https://github.com/joshgarnett/rustleaks/compare/v0.1.0-alpha.9...HEAD
[0.1.0-alpha.1]: https://crates.io/crates/rustleaks-core/0.1.0-alpha.1
[0.1.0-alpha.2]: https://github.com/joshgarnett/rustleaks/releases/tag/v0.1.0-alpha.2
[0.1.0-alpha.3]: https://github.com/joshgarnett/rustleaks/releases/tag/v0.1.0-alpha.3
[0.1.0-alpha.4]: https://github.com/joshgarnett/rustleaks/releases/tag/v0.1.0-alpha.4
[0.1.0-alpha.5]: https://crates.io/crates/rustleaks-core/0.1.0-alpha.5
[0.1.0-alpha.6]: https://github.com/joshgarnett/rustleaks/releases/tag/v0.1.0-alpha.6
[0.1.0-alpha.7]: https://github.com/joshgarnett/rustleaks/releases/tag/v0.1.0-alpha.7
[0.1.0-alpha.8]: https://github.com/joshgarnett/rustleaks/releases/tag/v0.1.0-alpha.8
[0.1.0-alpha.9]: https://github.com/joshgarnett/rustleaks/releases/tag/v0.1.0-alpha.9

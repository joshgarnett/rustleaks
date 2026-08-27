# Changelog

## Unreleased

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

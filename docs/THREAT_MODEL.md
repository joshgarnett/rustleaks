# Threat model

This model covers the unpublished `0.1.0-alpha.1` workspace at the pinned
compatibility revision. Review it whenever a public input, feature, dependency,
build rule, workflow, or release path changes.

## Assets and trust

Scanned bytes, repositories, archives, paths, configuration, regular
expressions, templates, report fields, command-line values, and dependency
updates are untrusted. A finding is sensitive because its secret, match, line,
metadata, or required finding may contain a live credential. Test data must be
synthetic or a reviewed upstream fixture.

The security objectives are to preserve exact findings within the supported
compatibility profile, return a structured error or bounded partial result for
hostile input, keep first-party code free of unsafe Rust, avoid implicit
network or process-global activity in the core engine, and prevent incidental
disclosure of finding values.

The local controls do not establish that every dependency is defect-free or
that every supported target has runtime evidence. They establish a reviewed,
locked boundary and fail when that boundary changes.

## Boundary map

| Boundary | Implementation | Controls and limits | Evidence | Remaining limitations |
| --- | --- | --- | --- | --- |
| Engine and findings | `rustleaks-core/src/engine.rs`, `model.rs` | Byte-oriented input; checked locations; exact or explicitly unavailable source ranges; content-omitting `Debug`; recursive detected-secret removal; aggregate decoded-byte, work-unit, and finding-record budgets; cooperative cancellation; caller-selected per-target size | Engine, model, controlled-scan, disclosure, corpus, property, parity, and `fragment_scan` fuzz tests | One regex evaluation or transform is indivisible. Many Rust allocations may still abort on exhaustion. The compatibility wrapper is unlimited by design. Raw buffers are not zeroized, and detected-secret removal does not classify unrelated metadata. |
| Configuration and rules | `rustleaks-core/src/config/`, `rustleaks-core/src/regex/` | Individual regex source 1 MiB, nesting 4,096, compiled NFA 256 MiB, extension depth 2, at most 4,096 selected rules and 8 MiB selected-rule source; structured parse and compile errors | Configuration, rule-extension, regex corpus, Go differential, property, `config`, and `go_regex` fuzz tests | Regex limits apply per expression. The caller owns aggregate configuration input and file resolution outside the loader's bounded operations. |
| Decoders and locations | `rustleaks-core/src/decoder/`, `rustleaks-core/src/model.rs` | Caller-selected decode depth; output and work charged to aggregate scan budgets; checked offset and range composition | Decoder, arbitrary-byte, location, range-composition, parity, and `fragment_scan` fuzz tests | Cancellation is observed between decode work units, not within an individual transform. |
| Files and directories | `rustleaks-sources/src/file.rs`, `directory.rs`, `path.rs`, `runner.rs` | Bounded chunks and queue; optional file-size cap; symlink hop limit 64; virtual path normalization; bounded workers; every worker joined | File, directory, path, symlink escape, chunk partition, cancellation, and source corpus tests | Files can change during a scan. Caller-selected streaming policies can remain open-ended if no outer bound is installed. |
| Archives | `rustleaks-sources/src/archive.rs`, retained owned codecs, and selected upstream decoders | Virtual archive paths; absolute, parent, device, and link escape rejection; default depth 8, 10,000 entries, 64 MiB member, 256 MiB total, 64 MiB spool; checked expansion accounting | Per-format fixtures, traversal and link tests, bomb and nesting tests, panic-policy example, and `archive` fuzz target | RAR3/RAR5 and 7z dependency parsing uses unwind containment. Those compressed paths are rejected under `panic=abort`. Allocation failure can still abort. |
| Git and SCM metadata | `rustleaks-sources/src/git.rs`, `scm.rs` | Direct argument vectors without a shell; option terminators and isolated Git configuration; hooks and interactive prompts disabled; no credential helper; bounded patch, blob, stderr, metadata, path, file, hunk, and commit counts; child termination and reap | Hostile revision/path tests, command-vector properties, temporary repository sequences, Git corpus, parity, and in-process `git_patch` fuzzing | Git is an external executable. Runtime behavior depends on the installed Git and host file system. Fuzzing covers the parser in-process and does not spawn Git per iteration. |
| Reports and CLI | `rustleaks-report/src/`, `rustleaks-cli/src/args.rs`, `output.rs`, `run.rs` | JSON and XML escaping; byte-golden compatibility reports; bounded safe templates; report writes return I/O errors; `--redact[=PERCENT]` transforms findings before output; terminal control characters are escaped in single-line diagnostics and verbose fields; default diagnostics report classifications and counts rather than secret values | Report and CLI corpora, byte-golden tests, invalid-byte, terminal-control, and redaction tests, template properties and fuzzing | Compatibility reporters preserve finding values when explicitly requested. CSV is a data interchange format and does not neutralize spreadsheet formulas. Do not open an unreviewed CSV in a spreadsheet. Verbose finding output is an explicit disclosure surface. |
| Dependencies | `Cargo.lock`, `deny.toml`, `supply-chain/`, `supply-chain-exceptions.toml`, dependency documentation | Locked versions and sources; license, advisory, ban, source, build-script, native-code, unsafe, graph, and vet policy; dated cargo-vet bootstrap reviews | `just security`, targeted dependency-boundary checks, cargo-deny, fresh RustSec audit, cargo-vet, cargo-geiger, Miri, and owned-unsafe checks | A vet exemption is not an audit. The 61 bootstrap exemptions require review by 2026-11-23 and must decrease as source audits are completed. Dependency unsafe code remains within the documented safe-API boundary. |
| Bazel and local automation | `MODULE.bazel`, `MODULE.bazel.lock`, `cargo-bazel-lock.json`, `BUILD.bazel`, `justfile`, `crates/xtask` | Pinned Bazel and Rust repositories; lockfiles; declared inputs; sandbox-compatible actions; exact tool versions; Bazel-backed public recipes | `just ci`, build-system contract tests, package consumers, target compile matrix, and lock consistency checks | Local caches are not a trust boundary for release provenance. Remote cache and untrusted CI execution policy remain release requirements. |
| Hosted CI | `.github/workflows/` and `.github/actions/setup/` | Top-level read-only permissions; minimum job grants; reviewed full-SHA action pins; secretless pull request jobs; separate oracle and release contexts | Pull request and default-branch CI, CodeQL, dependency review, native target, nightly, weekly, and non-publishing release runs on GitHub Actions | Hosted checks do not establish release provenance. Publication permissions, attestations, and trusted publishing remain deferred. |
| Releases | Package metadata, release-only Bazel configurations, `.github/workflows/release-dry-run.yml`, protected `release` environment, and local release checks | Package normalization, public API snapshot, MSRV and docs.rs checks, clean external consumers, exact-main approval, isolated repeat builds, byte comparison, deterministic archives, checksums, Cargo-to-Bazel CycloneDX reconciliation, and dry-run provenance | `just release-dry-run`, exact-candidate hosted qualification, native smoke tests, bundle verification, and GitHub environment settings | No package has been published. The exact candidate still needs a successful hosted run, signed GitHub attestations, reviewed trusted publishing, and an explicit publication decision. |

Exact numeric limits and caller ownership are maintained in
[`RESOURCE_LIMITS.md`](RESOURCE_LIMITS.md). Dependency reasoning is maintained
in [`DEPENDENCY_SAFETY.md`](DEPENDENCY_SAFETY.md).

## Secret handling

The engine returns the matched secret because that is its documented API.
Callers must treat findings, baselines, fragments, and serialized reports as
sensitive. Their content-omitting `Debug` implementations expose structure,
lengths, locations, and counts without traversing retained bytes. Callers must
still decide whether that metadata is appropriate for a particular sink.
`Finding::redacted` preserves upstream report behavior and intentionally does
not redact required findings, so it is not a disclosure-safe transform.
`Finding::without_detected_secrets` recursively removes detected secret byte
sequences and drops a retained fragment, but remaining metadata can still
contain unrelated or undetected sensitive content. Trust boundaries should
receive a narrow caller-owned projection. The CLI applies `--redact` before
verbose and report output. Supplying a report destination or `--verbose` is an
explicit request to disclose finding fields; use `--redact` for routine use
and automation.

Finding and fragment buffers use ordinary Rust ownership. Cloning duplicates
their bytes, and dropping them does not guarantee memory zeroization. Keep raw
values in the narrowest practical scope and do not claim process-memory
erasure.

Errors, warnings, summaries, dependency output, fuzz artifacts, and crash
reproducers must not contain real credentials. Fuzz seeds and regressions use
only synthetic values. Raw crash and audit artifacts remain private until
their provenance and content have been reviewed.

## Abuse cases and expected outcomes

- Malformed configuration, regex, template, archive, Git output, or report
  values must return a structured error or a documented bounded partial result.
- Excessive nesting, expansion, history, entries, paths, files, matches, or
  findings must stop at an explicit bound without wrapping arithmetic.
- Absolute paths, parent traversal, unsafe links, devices, Git options placed
  where a revision or path is expected, and repository-local hooks or config
  must not escape their logical boundary.
- Cancellation and timeout must terminate bounded owned work, kill spawned Git
  children when needed, and reap every child and worker.
- A dependency, feature, source, unsafe, native, build-script, license,
  advisory, or vet-policy delta must fail a local policy gate until reviewed.

## Review triggers

Re-run the complete review after any parser, regex backend, decoder, archive
codec, Git command, reporter, CLI output, public API, feature, lockfile,
dependency policy, Bazel module, workflow, or release change. A minimized fuzz
failure must become an ordinary regression before its artifact is removed.
Platform-specific claims require matching native execution; cross-compilation
alone is not runtime evidence.

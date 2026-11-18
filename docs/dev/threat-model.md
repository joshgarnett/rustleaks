# Threat model

This page is for maintainers and security reviewers. It lists what Rustleaks
treats as untrusted, the boundaries in the code, their controls, and the
limits that remain. Review it when a public input, feature, dependency, build
rule, workflow or release path changes.

## Assets and trust

These inputs are untrusted: scanned bytes, repositories, archives, paths,
configuration, regular expressions, templates, report fields, command-line
values and dependency updates.

A finding is sensitive. Its secret, match, line, metadata or required
findings may hold a live credential. Test data must be synthetic or a
reviewed upstream fixture.

The security goals are to:

- keep exact findings within the supported compatibility profile;
- return a structured error or a bounded partial result for hostile input;
- keep first-party code free of unsafe Rust;
- avoid hidden network or process-wide activity in the engine; and
- prevent accidental disclosure of finding values.

The local checks do not prove that every dependency is free of defects, or
that every target has runtime evidence. They keep a reviewed, locked boundary
and fail when that boundary changes.

## Boundary map

| Boundary | Code | Main controls | Tests |
| --- | --- | --- | --- |
| Engine and findings | `rustleaks-core/src/engine.rs`, `model.rs` | Byte input, checked locations, scan budgets, cooperative cancellation, `Debug` without content | Engine, model, controlled-scan, disclosure, property, parity, `fragment_scan` fuzz |
| Configuration and rules | `rustleaks-core/src/config/`, `regex/` | Per-expression regex limits, extension depth 2, 4,096 selected rules, 8 MiB selected rule source, structured errors | Configuration, extension, regex corpus, property, `config` and `go_regex` fuzz |
| Native packs and diagnostics | `rustleaks-core/src/native.rs`, `explanation.rs`, `validation.rs` | Explicit selection, exact identity, strict fields, no rule collisions, 32 packs, 1 MiB TOML, 1,024 rules, 65,536 explanation records | Native policy, native rules, disclosure, offline layout |
| Review records | `rustleaks-core/src/triage.rs`, `rustleaks-report/src/triage.rs` | Policy, options and completion binding; finite reasons and expiry; 4,096 records, 100,000 findings, 8 MiB JSON | Core and report triage tests, examples |
| Decoders and locations | `rustleaks-core/src/decoder/`, `model.rs` | Caller decode depth, decoded bytes and work in budgets, checked offsets | Decoder, arbitrary bytes, locations, parity, `fragment_scan` fuzz |
| Files and directories | `rustleaks-sources/src/file.rs`, `directory.rs`, `path.rs`, `runner.rs`, `runner/budget.rs` | Bounded chunks and queue, optional complete targets, symlink hop limit 64, path normalization, optional budgets, workers joined | File, directory, path, symlink escape, chunking, complete-target, cancellation, budget and panic cleanup tests |
| Archives | `rustleaks-sources/src/archive.rs`, codec forks, selected decoders | No extraction to disk, no link following, checked coder graphs, depth 8, 10,000 entries, 64 MiB member, 256 MiB total, 64 MiB spool | Format fixtures, traversal, link, bomb and nesting tests, panic policy example, `archive` fuzz |
| Git and links | `rustleaks-sources/src/git.rs`, `scm.rs` | No shell, option terminators, isolated Git config, hooks and prompts off, no credential helper, streamed output with limits for each commit, child killed and reaped | Hostile revision and path tests, command vector properties, temporary repositories, Git corpus, `git_patch` fuzz |
| Reports and CLI | `rustleaks-report/src/`, `rustleaks-cli/src/args.rs`, `output.rs`, `run.rs` | JSON and XML escaping, bounded templates, `--redact` before output, escaped terminal control characters, counts instead of values in diagnostics | Report and CLI corpora, invalid byte, terminal control and redaction tests, template properties and fuzz |
| Dependencies | `Cargo.lock`, `deny.toml`, `supply-chain/`, `supply-chain-exceptions.toml` | Locked versions and sources, vet inventory, license, advisory, ban, build script, native code and unsafe policy | `just security`, cargo-deny, RustSec, cargo-vet, cargo-geiger, Miri |
| Bazel and local tools | `MODULE.bazel`, lockfiles, `BUILD.bazel`, `justfile`, `crates/xtask` | Pinned toolchains and lockfiles, declared inputs, exact tool versions, private bounded output, verified process cleanup | `just ci`, build system checks, package consumers, target compile matrix |
| Hosted CI | `.github/workflows/`, `.github/actions/setup/` | Read-only default permissions, minimal job grants, actions pinned by full SHA, no secrets in pull request and dry-run jobs | Pull request, nightly, weekly, CodeQL, native and dry-run workflows |
| Releases | Package metadata, release Bazel configs, `release-dry-run.yml`, `publish.yml`, `release.yml`, `release` environment | Exact-main qualification, repeat builds with byte comparison, checksums, SBOMs, signed provenance, protected publication | `just release-dry-run`, hosted qualification, native smoke tests, attestation and bundle checks |

Exact limits are in [Engine internals](engine-internals.md) and
[Resource limits](../user/resource-limits.md). Dependency reasoning is in
[Dependencies](dependencies.md). The
[regex backend review](../dependency-audits/regex-meta-backend.md) covers the
meta engine, its caches and the reverse NFA fallback.

## Known limits by boundary

### Engine and findings

- One regex search or transform cannot be interrupted.
- Many Rust allocations can abort when memory runs out.
- `Engine::scan_fragment` has no limits by design.
- Raw buffers are not zeroized. Removing detected secrets does not clean
  unrelated metadata.
- Budgets bound logical payload, spans and normalization, not process memory.
  Dense long lines can use the payload budget on a small input; callers must
  keep the incomplete status.

### Configuration and rules

- Regex limits apply per expression, not to the whole engine.
- Lazy DFA and fallback caches stay across scans and grow with concurrency or
  cloning.
- When the lazy DFA gives up, the search falls back to PikeVM. A fixed pattern
  stays linear, but hostile input or large Unicode classes can remove the
  speedup.
- The PikeVM estimate covers dependency search tables and stacks, but not
  allocator overhead.
- The caller owns reading configuration files. `FileSystemResolver` and the
  CLI read at most 16 MiB of each file. Other callers own the size of the
  text they pass.
- Configuration is untrusted, so literal-anchor analysis is capped by choice
  and step counts, and the full keyword DFA is used only within the keyword
  size and depth limits.

### Native packs and diagnostics

- Exact identity bytes contain pack sources and need a deliberate export.
- Parse errors can contain input details.
- Explanation counts reveal scan activity.
- Checksums and unsupported formats stay `Unknown`.
- Pack limits do not bound total compile memory.
- `buffer-v1` relations search each decoded segment as its own buffer, so one
  carrier cannot satisfy another's required predicate. Unfinished native
  rules publish no partial results.
- `bytes-v1` patterns compile directly to a private byte matcher and keep the
  normal compile and cache limits.
- The Mapbox and Vercel predicates use fixed buffers, do no I/O, and stop as
  typed partial scans on budget or cancellation. The tokenizer check verifies
  the source hash, size, licenses and every derived byte; runtime input
  cannot supply a vocabulary.

See [Rule pack authoring](rule-pack-authoring.md).

### Review records

- Callers must bind source references to immutable bytes and metadata.
- The core cannot authenticate an external registry.
- An acknowledgement does not prove safety or completion.
- Identifiers are sensitive metadata. The output store owns atomic
  replacement and access control.

See [Using rustleaks-core](../user/library.md#review-records).

### Decoders and locations

- Cancellation is checked between decode steps, not inside one transform.

### Files and directories

- Files can change during a scan. A complete target is bounded input, not a
  file system snapshot.
- Streaming input has no limit unless the caller sets one.
- Budget reservations can reduce concurrency. Producer buffers and single
  metadata fields are not counted.
- Intentional exclusions stay separate from coverage failures, and a failed
  complete target publishes no partial prefix.

### Archives

- 7z short member reads stay compatible by default. Callers can require the
  declared lengths.
- Compressed RAR3, RAR5 and 7z decoding relies on catching panics. These
  paths are rejected under `panic=abort`.
- Allocation failure can still abort.

### Git and links

- Git is an external program. Behavior depends on the installed Git and the
  host file system.
- Fuzzing covers the patch parser in process. It does not run Git. Each
  input is also parsed in one-byte and varied chunks, which must give the
  same result as the whole input.
- Git output is parsed while Git runs. Memory follows the largest file record
  of one commit. Commit identities that the runner keeps for its count grow
  with the history, up to 100,000,000 commits.

### Reports and CLI

- Reports keep finding values when the user asks for them.
- CSV does not neutralize spreadsheet formulas. Do not open an unreviewed CSV
  in a spreadsheet.
- `--verbose` output and report files are an explicit disclosure.

### Dependencies

- A vet exemption is not an audit. Ordinary exemptions need review by their
  recorded date. The standing `compcol` exemption needs review when its
  enforced scope changes. See [Security checks](security-checks.md).
- Dependency unsafe code stays inside the documented safe API boundary.

### Bazel, CI and releases

- Local caches are not a trust boundary for release provenance.
- Native profile and fuzz evidence is specific to the host and workload.
- Remote cache and untrusted CI execution policy are release requirements.
- Only artifact builders get attestation permission. Publication jobs get
  only what their action needs.
- Each release still needs a hosted run, an approved publication path and an
  explicit decision.

## Secret handling

The engine returns the matched secret, because that is its purpose. Callers
must treat findings, baselines, fragments and reports as sensitive.

- `Debug` output of these types shows structure, lengths, locations and
  counts, but not the bytes. Callers still decide whether that metadata may
  go to a given log or service.
- `Finding::redacted` keeps the upstream report behavior and does not redact
  required findings. It is not safe for disclosure.
- `Finding::without_detected_secrets` removes detected secret bytes
  recursively and drops a kept fragment. Other metadata can still hold
  sensitive content. Give a trust boundary a narrow projection that the
  caller owns.
- The CLI applies `--redact` before verbose and report output. A report path
  or `--verbose` is an explicit request to disclose finding fields. Use
  `--redact` in automation.
- Finding and fragment buffers use normal Rust ownership. Clones copy the
  bytes, and dropping them does not zero memory. Do not claim memory erasure.
- Errors, warnings, summaries, dependency output, fuzz artifacts and crash
  reproducers must not contain real credentials. Fuzz seeds and regressions
  use synthetic values. Raw crash and audit artifacts stay private until
  reviewed.

## Abuse cases

| Input | Expected result |
| --- | --- |
| Malformed configuration, regex, template, archive, Git output or report value | Structured error or documented bounded partial result |
| Too much nesting, expansion, history, entries, paths, files, matches or findings | Stop at an explicit limit, without integer wrapping |
| Absolute paths, parent traversal, unsafe links, devices, Git options in place of a revision or path, repository hooks or config | No escape from the logical boundary |
| Cancellation or timeout | Owned work stops, Git children are killed, every child and worker is reaped |
| Change in dependencies, features, sources, unsafe code, native code, build scripts, licenses, advisories or vet policy | A local policy check fails until reviewed |

## When to review again

Repeat the full review after a change to any of these:

- a parser, the regex backend, a decoder or an archive codec;
- a Git command, a reporter or CLI output;
- the public API, a feature or a lockfile;
- the dependency policy or the Bazel module; or
- a workflow or the release process.

A minimized fuzz failure must become an ordinary regression test before its
artifact is deleted. A platform claim needs native execution on that
platform; cross-compilation alone is not runtime evidence.

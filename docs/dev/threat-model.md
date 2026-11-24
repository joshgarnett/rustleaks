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

- never lose a secret that the default rules find without maintainer
  approval, and record every finding change in the changelog;
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
| Engine and findings | `rustleaks-core/src/engine.rs`, `model.rs` | Byte input, checked locations, scan budgets, cooperative cancellation, `Debug` without content | Engine, model, controlled-scan, disclosure, property, detection corpus, `fragment_scan` fuzz |
| Configuration and rules | `rustleaks-core/src/config/`, `regex/` | Per-expression regex limits, extension depth 2, 4,096 selected rules, 8 MiB selected rule source, structured errors | Configuration, extension, regex corpus, property, `config` and `go_regex` fuzz |
| Native packs and diagnostics | `rustleaks-core/src/native.rs`, `explanation.rs`, `validation.rs` | Fixed built-in composition or caller-chosen packs, exact identity, strict fields, no rule collisions, 32 packs, 1 MiB TOML, 1,024 rules, 65,536 explanation records | Native policy, native rules, disclosure, offline layout |
| Review records | `rustleaks-core/src/triage.rs` | Policy, options and completion binding; finite reasons and expiry; 4,096 records, 100,000 findings, 8 MiB JSON | Core triage tests, examples |
| Decoders and locations | `rustleaks-core/src/decoder/`, `model.rs` | Caller decode depth, decoded bytes and work in budgets, checked offsets | Decoder, arbitrary bytes, locations, decoder corpus, `fragment_scan` fuzz |
| Files and directories | `rustleaks-sources/src/file.rs`, `directory.rs`, `path.rs`, `runner.rs`, `runner/budget.rs` | Bounded chunks and queue, optional complete targets, symlink hop limit 64, path normalization, optional budgets, workers joined | File, directory, path, symlink escape, chunking, complete-target, cancellation, budget and panic cleanup tests |
| Archives | `rustleaks-sources/src/archive.rs`, `archive/`, `rar.rs`, codec forks, selected decoders | Streamed members, no member extraction to disk, no link following, checked coder graphs, depth 8, 1,000,000 entries, 4 GiB member, 16 GiB total, 1 GiB spool, 64 MiB parts in memory, anonymous owner-only temporary spool files | Format fixtures, traversal, link, bomb, nesting, streaming equivalence and spool cleanup tests, panic policy example, `archive` fuzz |
| Git and links | `rustleaks-sources/src/git.rs`, `git/`, `scm.rs` | No shell, commit names checked before `--stdin`, no network commands, repository textconv, external diff, fsmonitor and signature programs turned off, streamed output with limits for each commit, child killed and reaped | Hostile revision and path tests, command vector properties, temporary repositories, Git corpus, `git_patch` fuzz |
| Reports and CLI | `rustleaks-report/src/`, `rustleaks-cli/src/args.rs`, `output.rs`, `run.rs` | JSON and XML escaping, bounded templates, `--redact` before output, escaped terminal control characters, counts instead of values in diagnostics | Report and CLI corpora, invalid byte, terminal control and redaction tests, template properties and fuzz |
| Dependencies | `Cargo.lock`, `deny.toml`, `supply-chain/`, `supply-chain-exceptions.toml` | Locked versions and sources, vet inventory, license, advisory, ban, build script, native code and unsafe policy | `just security`, cargo-deny, RustSec, cargo-vet, cargo-geiger, Miri |
| Bazel and local tools | `MODULE.bazel`, lockfiles, `BUILD.bazel`, `justfile`, `crates/xtask` | Pinned toolchains and lockfiles, declared inputs, exact tool versions, private bounded output, verified process cleanup | `just ci`, build system checks, package consumers, target compile matrix |
| Hosted CI | `.github/workflows/`, `.github/actions/setup/` | Read-only default permissions, minimal job grants, actions pinned by full SHA, no secrets in pull request and dry-run jobs | Pull request, nightly, weekly, CodeQL, native and dry-run workflows |
| Releases | Package metadata, release Bazel configs, `//release/linux-packages`, `release-dry-run.yml`, `publish.yml`, `release.yml`, `release` environment | Exact-main qualification, repeat builds with byte comparison, Linux packages checked against the archive, checksums, SBOMs, signed provenance, protected publication | `just release-dry-run`, hosted qualification, native smoke tests, package installs on glibc 2.28, attestation and bundle checks |
| Package managers | `packages.yml`, `joshgarnett/homebrew-tap`, `joshgarnett/scoop-bucket`, packaging GitHub App, `release` environment | Formula and manifest written from attested archives and checksums, release tag matched to the release commit, installs and channel versions checked before any push and without a credential, one-hour App token for contents write on the two repositories only, in a protected publish job that runs only Git, the GitHub CLI and the pinned token action, no version moves back and no stable channel moves to a pre-release | Workflow policy check, `release-artifact package-managers` and `check-upgrade` tests, Homebrew and Scoop install jobs |

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
- A configuration found in the scanned folder is input from that folder. It
  can turn off rules, allow findings, and read any file the user can read
  through `[extend]` or a symbolic link. The CLI shows only the kind and
  position of a parse or decode error, never the file text. Pass `--config`
  to keep a scanned folder from choosing its own configuration.
- The `Display` text of a parse or decode `ConfigError` quotes the file.
  Library callers that show it own that disclosure.
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
- Memory grows with the number of detection threads (`--jobs`, which has
  no fixed maximum) and with the directory reader threads (up to 2 in the
  CLI). The walking thread still makes every path, size and symbolic link
  decision before a file is opened. Every thread is joined before the scan
  returns. See [Source runner budgets](engine-internals.md#source-runner-budgets)
  and [Directory reader threads](engine-internals.md#directory-reader-threads).
- Intentional exclusions stay separate from coverage failures, and a failed
  complete target publishes no partial prefix.

### Archives

- 7z short member reads stay compatible by default. Callers can require the
  declared lengths.
- Compressed RAR3, RAR5 and 7z decoding relies on catching panics. These
  paths are rejected under `panic=abort`. A panic in the scan of a 7z member
  is raised again after the decoder returns.
- Allocation failure can still abort.
- Members are scanned while they are read. A CRC or length check that fails
  at the end of a member, or a later damaged part, is reported after the
  bytes before it were scanned. A complete target is published only after a
  read without failure.
- ZIP, 7z, Zstandard and LZ4 input that is not a file on disk is copied to a
  spool: memory up to 1 MiB, then a temporary file. Temporary files are
  created with `create_new` in the system temporary folder (`TMPDIR`, `TMP`
  or `TEMP`) under an unpredictable name, with mode `0600` on Unix. On Unix
  the name is removed right after creation; on Windows the file is opened
  with no sharing and delete-on-close. No path is reused, and the data is
  removed on every exit path, including a killed process. The spool limit
  bounds the bytes held at once by one traversal. A memory-backed temporary
  folder turns spool files into memory use.
- The RAR3 PPMd model is limited only by the model size in the member
  header, up to 256 MB in the RAR format. Rustleaks keeps the model in
  larger structures, so at that size it can take more than 2 GB. It grows
  with the decoded data, up to about 80 bytes for each decoded byte in a
  measured worst case, so one member within the 64 MiB limit can reach that
  size. A RAR archive inside a RAR archive can hold more than one model at
  once.
- The XZ decoder sizes its dictionary from the stream header without a
  Rustleaks limit. Bzip2 blocks are at most 900 kB, and large-window Brotli is
  rejected.

### Git and links

- Git is an external program. Behavior depends on the installed Git and the
  host file system.
- The scanned repository's Git configuration and attributes still apply,
  apart from the textconv, external diff, fsmonitor and signature programs
  that the source turns off. `--log-opts` can turn them back on. A worktree
  `git diff` (`--pre-commit`) still runs the repository's clean filters
  (`filter.<driver>.clean` and `.process`), whose output replaces the
  content that is scanned, as it does for `git add`.
- History and staged scans read Git attributes from the empty tree
  (`attr.tree`) and run Git without `GIT_ATTR_SOURCE`, so the repository's
  `.gitattributes` cannot mark a text file as binary (`-diff` or `binary`)
  to keep it out of the patch. Git then decides from the content, so a file
  with a NUL byte near its start is binary even when `.gitattributes` marks
  it as text (`diff`). Git before 2.43 ignores `attr.tree`. Attributes from
  `.git/info/attributes`, `core.attributesFile` and the system file still
  apply. A worktree `git diff` (`--pre-commit`) keeps all attributes. In
  each of these cases Git shows no patch for a binary file, and the scan
  reads it only when it is an archive, with no issue.
- Fuzzing covers the patch parser in process. It does not run Git. Each
  input is also parsed in one-byte and varied chunks, which must give the
  same result as the whole input.
- Git output is parsed while Git runs. Memory follows the largest file record
  of one commit. Commit identities that the runner keeps for its count grow
  with the history, up to 100,000,000 commits.
- An archive blob streams from `git cat-file` into an archive spool. Over its
  limit, Git is stopped and reaped, and the blob is skipped with an issue.
- With several history processes (up to 6 in the CLI), a scan starts more
  Git children with the same executable and environment. Commit names reach
  `git log --stdin` only after they are checked to be hexadecimal object
  names, because `--stdin` also accepts options. Each process maps the
  repository's packs, so memory grows with the process count. Every child is
  killed and reaped on stop, error and cancellation. See
  [Git history processes](engine-internals.md#git-history-processes).
- `rustleaks-sources` starts its child processes one at a time. On macOS and
  other targets without `pipe2`, a child started while another thread
  creates a pipe can inherit that pipe, and two `git log` processes that
  hold each other's input open wait forever. A program that embeds
  `rustleaks-sources` and starts its own children on other threads during a
  history scan can still cause this.

### Reports and CLI

- Reports keep finding values when the user asks for them.
- CSV does not neutralize spreadsheet formulas. Do not open an unreviewed CSV
  in a spreadsheet.
- CSV and template reports keep control characters from paths, rule IDs and
  other fields. JUnit replaces C0 controls but keeps C1 controls. Print
  these reports to a terminal only when the input is trusted.
- Report files are created with the default mode from the umask, and a
  symbolic link at the report path is followed.
- Baseline files are read without a size limit. The user chooses the path.
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
- The packaging App key is the only stored workflow secret. Anyone who can
  approve a `release` environment job can push to the tap and bucket, which
  changes what `brew install` and `scoop install` give users. The job that
  reads the key runs no Rustleaks code, setup action or Cargo build, so no
  build script runs beside it. It trusts Git and the GitHub CLI of the
  hosted runner image. The Scoop install check runs the pinned Scoop
  installer, which downloads Scoop and its main bucket without a pin, in a
  job with no credential.
- The release dry run installs `rpm` from the Ubuntu archive without a
  version pin, in the glibc jobs that can request attestations. The job log
  records `rpmbuild --version`. The `.rpm` check compares the package with
  the archive, but does not prove which `rpmbuild` wrote it.
- Each release still needs a hosted run, an approved publication path and an
  explicit decision.

## Secret handling

The engine returns the matched secret, because that is its purpose. Callers
must treat findings, baselines, fragments and reports as sensitive.

- `Debug` output of these types shows structure, lengths, locations and
  counts, but not the bytes. Callers still decide whether that metadata may
  go to a given log or service.
- `Finding::redacted` masks the primary secret in the secret, match and
  line fields, and replaces the whole line of a decoded finding. It does
  not redact required findings and is not safe for disclosure.
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

# Changelog

## [Unreleased]

- Scans use less CPU time, and scans of large folder trees with many
  detection threads use less memory. Each detection thread now keeps its own
  pattern search caches. All threads together keep an estimated 128 MiB of
  them, and each thread at least 8 MiB. A thread frees the caches it used
  least recently when it reaches its share. Before, each pattern kept caches
  for every thread that searched it and never freed them. Scans also skip
  rules whose keywords do not occur without visiting them, allocate less in
  the decoder and in commit and stop word checks, and check for cancellation
  less often. The decoder skips bytes that cannot start an encoded value.
  Git history scans keep one copy of each commit's metadata for all of its
  fragments, hand Git output to the parser in larger pieces, and allocate
  each hunk once. These numbers compare with 0.2.0 on an Apple M5 Ultra
  with 12 detection threads. A folder scan of the gitlab tree peaked at
  211 MB instead of 317 MB and used 10 percent less CPU time. A folder scan
  of the Linux tree used 22 percent less CPU time. Git history scans of
  rails and django used 15 and 19 percent less CPU time and up to 7 percent
  more memory. Findings, reports and exit codes do not change.
- In `rustleaks-core`, `ScanScratch` and `Engine::scan_fragment_with_scratch`
  let a thread that scans many fragments reuse search caches and buffers,
  with a limit on the caches. The outcome is the same as with
  `Engine::scan_fragment_controlled`. The new
  `ScanCancellation::reads_state_only` method lets the engine poll a signal
  that only reads a flag once for a run of work units instead of once per
  unit. It returns false by default and true for `AtomicBool`, and the
  `rustleaks` command's scan threads use it too. A scan cancelled through
  such a signal can stop at a later checkpoint and report more work units
  than before.
- In `rustleaks-core`, `ByteText::from_shared` is public. It wraps shared
  bytes without copying them. Cloning a `ByteText` still copies its bytes.

## [0.2.0] - 2026-11-24

0.2.0 is the first Rustleaks release that is not a pre-release. It can be
installed with Homebrew, Scoop, or the new `.deb` and `.rpm` packages.
Rustleaks no longer tracks a Gitleaks revision. Gitleaks configuration files,
ignore files, baselines, allow comments and the legacy Gitleaks names keep
working.

Check these changes before you upgrade:

- SARIF reports name the tool `rustleaks` and JUnit reports name the suite
  `rustleaks`. GitHub code scanning opens new alerts for existing findings
  once.
- In `rustleaks-core`, the default configuration has every built-in rule, as
  the CLI does. `ConfigLoader::with_builtin_rules`,
  `honor_gitleaks_allow`, `UPSTREAM_REVISION` and `DEFAULT_CONFIG_REVISION`
  are removed.
- When two built-in rules report the same secret, one finding is reported.
  Baseline and ignore entries for the dropped findings no longer match.
- Git history scans now read files that `.gitattributes` marks as binary, and
  can report more findings.

- On Unix, a new `--report-path` file is created with mode `0600`, so only
  its owner can read it. Before, it got the default mode from the umask. An
  existing file keeps its owner and mode.
- A symbolic link at `--report-path` is refused: the scan fails with exit
  code 1 before it starts, and the file that the link points to is not
  changed. Before, Rustleaks followed the link and replaced that file. On
  Unix, `/dev/stdout`, `/dev/stderr` and `/dev/fd/N` still work. On
  Windows, `NUL` and the other DOS device names still work. `-` still
  writes to standard output.
- A `--baseline-path` file larger than 256 MiB is not loaded. As with a
  baseline that cannot be read, Rustleaks logs an error and scans without
  the baseline. Before, a baseline file of any size was read into memory.
- A RAR3 member compressed with PPMd that sets a model larger than 64 MiB is
  skipped with a limit warning, together with the rest of its RAR archive.
  The RAR format allows models of up to 256 MiB, and Rustleaks used to build
  them, which could take more than 2 GB of memory for one small archive.
  Members with a model of 64 MiB or less decode as before.
- A normal scan now reads a file whose name ends in `.tgz` as a
  gzip-compressed TAR archive, as a complete scan already did. Before, a
  normal scan skipped such a file as binary, so secrets inside it were
  missed. A `.tgz` file that does not start with the gzip magic bytes is
  read as its other suffixes name it, such as `x.tar.tgz` as a TAR, and
  otherwise as a plain file. In a normal scan, a gzip `x.gz.tgz` is read as
  a gzip stream of one file. Before, a complete scan reported such files as
  a decode issue.
- Git runs with `LC_ALL=C` and without `LANGUAGE` during scans and remote
  discovery, unless the caller's command environment sets them. With a
  translated Git, harmless rename-limit and auto-gc warnings were reported
  as Git errors, a repository without a remote failed discovery, and a
  complete scan could end incomplete.
- bzip2 input whose blocks hold random or already compressed data, such as
  a `.tar.bz2` of JAR files or images, now decodes. Before, decoding stopped
  with `huffman bitstream truncated` and the rest of the input was not
  scanned. The decoder also no longer keeps the whole compressed input in
  memory.
- bzip2 files with several streams, as written by `pbzip2` or joined with
  `cat`, are decoded in full. Before, only the first stream was scanned, with
  no warning. Data after the last stream that is not a bzip2 stream gives a
  decode issue.
- 7z archives with many Zstandard members no longer allocate and zero the
  whole 7z memory limit for each block. One buffer is reused from block to
  block, and a block without Zstandard frees it.
- A 7z LZMA coder with fewer than 5 property bytes gives the decode issue
  `LZMA properties too short` instead of `7z decoder panicked on untrusted
  input`. Other 7z decode and limit issues show a plain message instead of
  Rust debug text.
- `ReviewPolicy::for_builtin` works when the policy has two or more
  built-in rule files, including every built-in rule as the CLI uses them.
  It returned `ReviewError::InvalidReference` because policy references did
  not allow the `,` that the built-in reference uses. Policy references now
  allow `,`.
- The `rustleaks-core` crate package no longer includes
  `data/cl100k_base.tiktoken`, which only tests use.
- `CompiledRule` equality no longer depends on whether the rule came from a
  rule file added with `NativePolicy::with_pack`.

- `git` history scans and `--staged` scans now report secrets in text files
  that the repository's `.gitattributes` marks as binary, such as with
  `*.env -diff` or `*.lock binary`. Git showed no patch for these files, so
  Rustleaks skipped them without a warning, and a complete scan still
  counted as complete. `git log` and `git diff --staged` now pass
  `-c attr.tree=` with the empty tree of the repository's object format and
  run without `GIT_ATTR_SOURCE`, so Git decides from the content alone.
  Rustleaks runs `git rev-parse --show-object-format` once before these
  scans to choose the tree. This needs Git 2.43 or later; earlier versions
  ignore the setting. Because the content decides, a file with a NUL byte
  near its start that `.gitattributes` marks as text (`diff`) is now
  skipped as binary in these scans; before, Rustleaks scanned it. Attributes
  from `.git/info/attributes` and `core.attributesFile` still apply.
  `--pre-commit` keeps the attributes, because it needs the clean filters
  that they name. History scans of repositories that mark large text files
  as binary read more data and can report more findings. A `GIT_ATTR_SOURCE`
  value that Git rejects no longer makes history and `--staged` scans fail.
- Git history and diff scans no longer run the textconv, external diff,
  fsmonitor or signature programs that the scanned repository's
  configuration names. Every `git log` and `git diff` passes
  `--no-textconv`, `--no-ext-diff`, `--no-color` and `-c core.fsmonitor=`,
  and `git log` also passes `--no-show-signature`. A repository's
  `.gitattributes` and `.git/config` could set a textconv filter, which Git
  ran during the scan and whose output replaced the file content, so a
  secret could be hidden. Scans now see the raw content. A file that a
  textconv filter used to turn into text, such as a document converted by a
  driver you set up, is now shown as binary and scanned only when it is an
  archive. `--log-opts` values come after these options and can turn them
  back on. `color.ui=always` in a Git configuration no longer makes history
  scans fail. `--pre-commit` still applies the repository's clean filters
  (`filter.<driver>.clean` and `.process`), as `git add` does.
- A rule in an extending configuration with the ID of a built-in rule that
  depends on helper rules, such as `rustleaks.azure-servicebus-key-comma`,
  now reports matches of its own `regex`. Before, it reported nothing.
  Keywords added to such a rule without a `regex` now also let it run.
- When `disabledRules` or `--enable-rule` leaves out a rule that a remaining
  rule needs, through `[[rules.required]]` or a built-in helper, Rustleaks
  keeps the needed rule without reporting its findings. Before, the
  remaining rule reported nothing, and with `--enable-rule` Rustleaks logged
  an error for each missing required rule.
- 7z header parsing no longer allocates the decoded header, the file table or
  the block table by sizes the archive declares beyond its limits. Other
  header tables are still bounded only by the header length. An encoded header
  must decode to no more than the 7z memory limit (64 MiB, or the member limit
  if lower), or the archive is skipped with a limit warning. An archive that
  declares more entries, or more blocks, than the entry limit is skipped
  before its file or block table is built, with the same warning as for too
  many entries. 7z members compressed with Zstandard are decoded as a stream,
  so memory no longer grows with the member size. A Zstandard member whose
  compressed size is above the memory limit is now scanned instead of skipped.
- A configuration file that fails to parse or decode no longer prints its
  text. The error names the kind of error and the file, and for a parse error
  the line and column. A configuration in the scanned folder can name any
  readable file in `[extend]` or through a symbolic link, so the old message
  could print lines of a file outside the scan, even with `--redact`. Inline
  configuration errors already showed only the kind of error.
- With `--redact`, a finding of a decoded secret now has its whole `Line`
  replaced by the redacted secret. The line held the secret in encoded form,
  so replacing the decoded bytes left it unchanged, and a report template
  that prints `{{.Line}}` showed the encoded secret. `Finding::redacted`
  does the same in the library. Other findings and the JSON, CSV, JUnit and
  SARIF reports do not change.
- Diagnostics and verbose output escape the Unicode bidirectional controls
  (U+061C, U+200E, U+200F, U+202A to U+202E and U+2066 to U+2069) as they
  already escape control characters, so a path cannot change the order in
  which a terminal shows the line.
- Regex updates: `regex-syntax` 0.8.12 and `regex-automata` 0.4.19. An
  alternation whose branches share a repetition prefix, such as `ab*b|ab*c`,
  now reports the leftmost-first match, as Go does. A regex search no longer
  panics when the bounded backtracker cannot take any input. The regex cache
  pool uses 8 shards instead of one per CPU. Applications that use the
  library get these changes when they resolve these versions or later. No
  built-in rule's findings change. The audits are in
  `docs/dependency-audits/maintenance-2026-11-23.md`.
- Install Rustleaks with Homebrew (`brew install joshgarnett/tap/rustleaks`)
  on macOS and Linux, with Scoop on Windows, or from the new `.deb` and
  `.rpm` packages for Linux x86_64 and ARM64 with glibc 2.28 or later. All
  channels install the program from the release archives. The packages
  install `/usr/bin/rustleaks` and the archive's documents under
  `/usr/share/doc/rustleaks`, and are covered by each glibc target's
  checksums and signed attestation. A release now has 67 assets. The new
  `Update Package Managers` workflow writes the formula and manifest from
  a published release, checks each install, and pushes them after
  approval. The tap and bucket never move from a stable release to a
  pre-release. A version without a pre-release suffix is published as a
  GitHub release instead of a pre-release.
- Scans with all built-in rules use less CPU time and memory. Findings, their
  order, reports and exit codes do not change. A rule's regular expression is
  no longer searched when the text lacks a literal that every match must
  contain, and more rules use literal-anchored searches. The keyword search
  also finds the literals of native rules, so a native rule whose literals are
  absent costs no further work. The decoder finds candidate encoded values
  with a byte scanner instead of a regular expression, rejects base64 values
  whose first bytes would not decode to printable text, and caches only values
  it accepts. Most regular expressions build their matcher at their first
  search instead of at load. The figures below compare with the code before
  this change on an Apple M5 Ultra Mac (36 logical CPUs, macOS 27.2.1), with 12
  threads and the median of three runs. Folder scans of 13 public repositories
  used 17 to 46 percent less CPU time (linux 19.7 s to 10.7 s) and 20 to 33
  percent less peak memory (linux 263 MB to 202 MB). They finished up to 18
  percent sooner. Git history scans of 9 repositories used 3 to 17 percent
  less CPU time and finished in about the same time; peak memory was 8 to 32
  percent lower, except ruby, which reached 284 MB against 271 MB. On 1 GiB
  synthetic inputs, CPU time fell by 12 to 46 percent. An empty scan takes
  about 39 ms and 31 MB of peak memory, against 44 ms and 39 MB. Each added
  detection thread costs about 23 MB of peak memory on a folder scan of
  gitlab, against about 33 MB. `ScanUsage::normalization_bytes` can be lower
  for the same input: it no longer counts the decoder's candidate search or
  searches that a missing literal skips, so a
  `ScanBudget::max_normalization_bytes` limit stops fewer scans. See
  `docs/dev/engine-internals.md#startup-memory-of-the-built-in-rules` for
  where startup memory goes.
- Fix composite rules in custom native packs
  (`NativePolicy::with_pack`) when explanations are off: a
  `[[rules.required]]` rule is now gated by its own keywords and literals, as
  it already was with explanations. It used the primary rule's keyword data,
  which could drop or add a composite finding. Built-in rules and CLI
  configurations were not affected.
- When a Rustleaks rule and another built-in rule report the same secret at
  the same bytes of the same file and commit, only one finding is reported.
  15 reviewed rule pairs do this, listed in
  `docs/user/built-in-rules.md#findings-from-two-rules`. Where both rules name
  the same provider, the default rule's finding stays and the Rustleaks rule's
  finding is no longer reported: `rustleaks.grafana-api-key-base64`,
  `rustleaks.alibaba-access-key-id-boundary`,
  `rustleaks.association.planetscale-api-token`,
  `rustleaks.association.artifactory-api-key`,
  `rustleaks.association.artifactory-reference-token`,
  `rustleaks.gitlab-incoming-mail-address-token` and
  `rustleaks.slack-config-access-token-166`. `rustleaks.xai-api-key-80` gives
  way to `rustleaks.xai-api-key-delimiter`. Where a provider rule names the
  issuer of a key that a broader rule also accepts, the provider rule's
  finding stays. `stripe-access-token` is no longer reported for WorkOS and
  Highnote keys. `rustleaks.stripe-access-token-delimiter` is no longer
  reported for Clerk keys, and `jwt` for Temporal Cloud and Monday tokens. No secret is lost: each
  dropped finding has a reported finding with the same secret, and each rule
  still reports secrets that the other rule does not. Fewer findings means
  fewer fingerprints; baseline and ignore entries for the dropped findings no
  longer match anything. An ignore or baseline entry for the reported finding
  now also hides the secret, since the dropped finding is no longer reported
  next to it. The pairs are listed in new `[[overlaps]]` entries
  in `rustleaks-providers-v1.toml`.
  `NativePolicyError::InvalidNativeOverlap` reports a malformed entry.
- In `rustleaks-core`, `ConfigLoader::load_default` and
  `[extend] useDefault = true` now give every built-in rule, as the CLI does:
  the default rules plus the `rustleaks-extra-v1`, `rustleaks-providers-v1`
  and `rustleaks-connections-v1` rules. Library scans that use the default
  can report more findings, with rule IDs that start with `rustleaks.`.
  `ConfigLoader::with_builtin_rules` is removed, since its behavior is now
  the default. `ConfigLoader::with_default_config` replaces the whole
  default, without the Rustleaks rules; pass `config::DEFAULT_CONFIG` to it
  for the default rules alone. The CLI already used every built-in rule.
- The built-in review reference and `NativePolicyIdentity` change, so review
  records made with 0.1.0-alpha.12 are reported as stale. The causes are the
  new `[[overlaps]]` entries, comments in the rule files that no longer
  describe them as opt-in, and a new header in the default rules file, which
  no longer names a Gitleaks commit. `DEFAULT_CONFIG_SHA256`,
  `EXTRA_RULES_V1_SHA256` and `PROVIDER_RULES_V1_SHA256` change. Only the
  overlap entries change which findings are reported.
- SARIF reports name the tool `rustleaks`, with the Rustleaks version as
  `semanticVersion` and the Rustleaks repository as `informationUri`. They
  named the tool `gitleaks`, with the fixed version `v8.0.0` and the
  Gitleaks project page. GitHub code scanning tracks alerts by tool name, so
  after this change, findings that already have alerts get new alerts under
  `rustleaks` once. JUnit reports name the test suite `rustleaks` instead of
  `gitleaks`. Update any CI step that looks for the old name. Findings,
  other report content and exit codes do not change.
- The Gitleaks names `GITLEAKS_CONFIG`, `GITLEAKS_CONFIG_TOML`,
  `.gitleaks.toml`, `.gitleaksignore`, `gitleaks:allow`,
  `--gitleaks-ignore-path`, `--ignore-gitleaks-allow` and `--no-color` are
  now documented as legacy names. They keep working, with no warning. Help
  lists `--no-color` with the legacy flag names. A new guide,
  `docs/user/moving-from-gitleaks.md`, lists what keeps working and the
  Rustleaks names to use and the differences from Gitleaks. It replaces
  `docs/user/gitleaks-differences.md`. The default rule allowlists are
  described in `docs/user/built-in-rules.md`.
- Help and the `minVersion` warning no longer describe Rustleaks as an
  implementation of Gitleaks. The warning now reads `config minVersion
  <version> is newer than Gitleaks 8.30.0, the newest configuration version
  that Rustleaks supports, so some settings may not be supported`. The
  `--base64-mode` help and documentation now say which Base64 forms each
  mode decodes.
- `ScanOptions::honor_gitleaks_allow` and
  `ScanOptionsBuilder::honor_gitleaks_allow` are removed. Use
  `honor_allow_markers`, which has the same meaning.
- Rustleaks no longer tracks a Gitleaks revision. The public constants
  `rustleaks_core::UPSTREAM_REVISION` and
  `rustleaks_core::config::DEFAULT_CONFIG_REVISION` are removed. Findings,
  report fields and exit codes do not change.

## [0.1.0-alpha.12] - 2026-11-21

- Every scan uses all built-in rules. Without a configuration, and with
  `[extend] useDefault = true`, Rustleaks now adds its own rules for
  provider tokens and connection strings to the Gitleaks-derived default
  rules. Their IDs start with `rustleaks.`. Scans can report more findings
  than before and than Gitleaks, and a scan that passed can now exit with
  code 1. On the two held-out test sets, recall rose from 0.834 to 0.848 and
  from 0.724 to 0.787, and precision stayed within 0.002. On one Apple
  silicon Mac, folder scans of five public repositories took 2% to 21% more
  wall time and 49% to 70% more peak memory than with the Gitleaks-derived
  rules alone. A configuration that does not extend the default is used as
  written. See `docs/user/built-in-rules.md`.
- The connection rules find more forms. They find `Password=` or `Pwd=`
  before the server or host property, Oracle
  `jdbc:oracle:thin:user/password@host` URLs, and the `password=` option of
  Oracle and SQLite JDBC URLs. They also find passwords in `mssql`,
  `sqlserver`, `oracle`, `clickhouse`, `cockroachdb`, `couchdb`, `influxdb`,
  `cassandra`, `neo4j` and `bolt` URIs, in `+driver` forms such as
  `postgresql+psycopg2://`, and in `nats`, `mqtt`, `mqtts`, `memcached` and
  `memcache` URIs. `https://user:password@host` is still not covered.
- The `--native-pack` flag is removed, since the rules it selected are now
  always used. The rule files keep their IDs inside Rustleaks.
  `ConfigLoader::with_builtin_rules` gives library users the same rules as
  the CLI. `ConfigLoader::load_default` without it is unchanged.
- Startup is faster. On one Apple silicon Mac, an empty scan with all
  built-in rules takes about 44 ms; 0.1.0-alpha.11 took 69 ms with the same
  rule files. A configuration that does not extend the default takes about
  27 ms, as before, because the built-in rules compile only when used. The
  embedded rules skip a temporary size check that a test runs on them
  instead, and each rule file is parsed and validated once instead of twice.
  Custom configurations keep the full check.
- Fix `--redact` with `--verbose`: the `Required:` lines of composite rules
  (`[[rules.required]]`) printed helper values, such as client IDs, in full.
  They are now masked with the same percent as the main secret. Reports did
  not include these values and do not change.
- A 7z archive that needs more memory than its limit is now reported as a
  limit warning, like other limits. It was reported as a decode error, which
  looked like a broken archive. Findings and exit codes do not change.
- The error for a missing required rule no longer shows the rule ID after
  `config path=`. Some other CLI messages use plainer words.
- `ScanOptions::honor_gitleaks_allow` and
  `ScanOptionsBuilder::honor_gitleaks_allow` are deprecated. Use
  `honor_allow_markers`, which has the same meaning.
- The `rustleaks-core` package no longer includes the test suite, which
  needed files outside the package. The crate documentation on docs.rs now
  starts with the README.
- The 7z, bzip2 and RAR decoder forks keep only the code that
  `rustleaks-sources` uses. Decoding does not change.
- Maintainer tools: `cargo xtask qualify` now checks only a clean candidate
  tree, the bounded composite resource tests, the public API snapshot and the
  minimum Rust version, since other gates run the rest. The performance
  budgets for one host class are removed; releases compare the previous
  release with the candidate using the scanner comparison instead. Eleven
  unused `cargo xtask` commands and checks that repeated hash-pinned evidence
  checks are removed. The CredData comparison workload scores findings on
  unlabeled lines as unknown, not as false positives. `default_rules_test`
  now runs with the other tests.
- Archive codec updates: `brotli-decompressor` 6.3.2, `lz4_flex` 0.14.2 and
  `compcol` 0.8.0. The RAR2 decoder in `compcol` 0.8.0 streams output from a
  fixed window instead of holding the whole member in memory. Findings do
  not change. `toml` 1.2.1 and `flate2` 1.1.11 are also updated. The audits
  are in `docs/dependency-audits/maintenance-2026-11-20.md`.
- The documentation separates user guides from developer guides, describes
  the current compatibility policy and lists the developer docs in
  `docs/dev/README.md`.
- `rustleaks-sources` removes the unused `SourceStage::ArchiveIdentify`,
  `SourceStage::Spool` and `SourceStage::Callback` stages and the unused
  `SourceIssueKind::GitParse` and `SourceIssueKind::GitCommand` issue kinds.
  No source produced them. Code that names them no longer compiles.

## [0.1.0-alpha.11] - 2026-11-20

- Use less CPU with several detection threads. Idle threads used to queue on
  one lock to receive the next piece of input. Now they park until a piece
  arrives, and the scheduling thread checks a full queue without a lock. On
  a 36-CPU macOS host with 12 threads, a Git history scan of mongo used 30
  percent less CPU and finished 11 percent sooner, and folder scans of mongo
  and linux used 7 to 9 percent less CPU. With one or four threads, scans
  take the same time as before. Findings, their order, reports and exit
  codes do not change.
- The default rules are now Rustleaks-owned, based on the Gitleaks default
  configuration at the same pin. The unchanged upstream copy stays in
  `compat/config-corpus/default-gitleaks.toml`, and
  `config::DEFAULT_CONFIG_SHA256` is now the SHA-256 of the shipped rules.
  Each change is listed in Differences from Gitleaks under Default rules.
- Hide more values that are clearly not secrets in the default rules, so they
  are not reported. `generic-api-key` no longer reports hex digests under hash
  names such as `token_md5`, Git object IDs under commit or revision names,
  Subresource Integrity values, Stripe publishable keys, and UUIDs under
  identifier names such as `token_id` or `client_id`. No rule reports the
  exact documentation examples that Discord, Azurite, Telegram, Slack and
  Google publish. The default rules still have 222 rules. On the 2026-11-19
  comparison sets, findings on non-secret values fell from 114 to 13 on the
  generated set used to design the changes and from 213 to 184 on an
  independent held-out set, with the same secrets found. UUIDs under
  `client_id` style names, such as Keycloak client IDs, are no longer
  reported.

## [0.1.0-alpha.10] - 2026-11-19

- Windows release builds accept the reviewed MSVC toolset, 14.51.36231, or a
  newer MSVC 14 toolset from the same Visual Studio edition. Hosted runners
  update MSVC on their own schedule, and the ARM64 runner moved to
  14.52.37025. For a newer toolset, the release manifest and
  `licenses/index.json` record the toolset version and the actual hash and
  size of each MSVC file. The Microsoft scope notice says so. Windows SDK
  files stay pinned.
- Document that with `--max-archive-depth 0`, the default, Rustleaks reads
  files whose names look like archives, such as `docker-compose.branch.yml`
  or `notes.zipper.txt`, as plain text, while Gitleaks skips them unread.
  Rustleaks behaves as in 0.1.0-alpha.9, and a test now covers it.
- Read `git` history with several `git log` processes at the same time: one
  for each detection thread, up to 6. One `git log` process uses about one
  CPU, so before, more detection threads did not make history scans faster.
  Rustleaks lists the commits with `git rev-list`, shows batches of 250
  commits with separate `git log` processes, and reads their output in list
  order, so it reads the same text as from one process. Findings, their
  order, reports, warnings and exit codes do not change, also when Git fails
  or a commit reaches a limit. Only the Git error text in the log can differ.
  On a 36-CPU host with the default thread count, history scans of mongo,
  typescript and rails took about a third of the time. `--jobs 1`,
  `--log-opts`, `--staged`, `--pre-commit`, a configured `format.pretty`,
  error output from `git rev-list`, and histories of one batch use one
  process. Up to 132 MiB of Git output waits for the parser, and the
  `git_stderr_bytes` limit counts the error output of all processes together.
  `rustleaks-sources` adds `GitSource::history_processes` and
  `GitSource::history_batch_commits`; the default is still one process.
- Scan with one detection thread for each CPU that Rustleaks may use, up to
  12. Before, a scan used one thread unless a `--complete-profile` file set
  `workers`. On Linux the CPU count follows CPU affinity and cgroup CPU
  quotas. Add
  `--jobs N` (`-j N`) to set the number of threads. It has no fixed maximum
  and replaces `workers` in a profile. Findings, their order, reports,
  warnings and exit codes do not depend on the number of threads. Memory
  grows with the number of threads, so use a lower `--jobs` value to use less
  memory. Without a profile, up to one piece of input for each thread waits
  for a thread, but never more than 1,024. `--log-level debug` prints the
  thread count. `SourceRunner::default` in `rustleaks-sources` still uses one
  worker.
- Make `dir` scans of folders with many small files faster. With two or more
  detection threads, one thread walks the folder and two threads open and
  read the files that it finds. Before, one thread did all of this, and
  opening each file was the slowest step. The walk still makes every path,
  size and symbolic link decision, and archives are still read one at a
  time. Pieces and warnings reach the detection threads in walk order, so
  findings, their order, reports, warnings and exit codes do not change. The
  reading threads hold at most 18 more pieces of input and two read buffers
  of 100,000 bytes. On a 36-CPU macOS host, a folder of 100,000 files of 64
  bytes took about 1.2 s instead of 1.9 s, and a large public
  repository 2.2 to 2.4 s instead of 2.9 to 3.2 s. With `--jobs 1`, files
  are read as before. `DirectoryOptions::read_threads` in
  `rustleaks-sources` sets the number of reading threads; the default is 1.
- Fix archive scans that skipped large archives. With `--max-archive-depth`,
  a whole archive had to fit in 64 MiB and each member in 64 MiB, so a 200 MB
  `release.tar.gz` or a 1 GB `backup.zip` was skipped. Rustleaks now reads
  archives as streams and scans each member while it decompresses it. ZIP and
  7z files found by `dir` are read in place. Other ZIP, 7z, Zstandard and LZ4
  input, such as a ZIP inside a TAR or an archive from Git, is copied to
  memory up to 1 MiB. Larger copies go to an anonymous temporary file that
  only the owner can read and that is removed on every path. RAR members,
  Snappy and MinLZ streams and some headers stay in memory, up to 64 MiB. The
  new defaults for one archive are 1,000,000 entries, 4 GiB for one member,
  16 GiB in total and 1 GiB of temporary storage. One archive file from Git
  can have 1 GiB. Findings do not change for members that scanned before.
  Members before a damaged part or a limit are now scanned before the
  warning. This includes the bytes of a member whose CRC check fails at its
  end. A compressed file over the member limit is scanned up to the limit.
  An archive file from Git over its limit is skipped with a warning instead
  of stopping the scan with exit code 1.
- Fix `git` scans that stopped with exit code 1 on long histories, such as
  those of Rails or Django, because the whole `git log` output had to fit in
  256 MiB and 2,000,000 lines. Rustleaks now reads Git output while Git runs
  and parses one changed file at a time, so memory follows the largest change
  instead of the whole history. The patch byte, patch line, file, hunk and
  metadata limits now apply to each commit. The `--complete-profile` keys
  `git_patch_bytes`, `git_patch_lines`, `git_files`, `git_hunks` and
  `git_metadata_bytes` have the same meaning. The default limits for one commit
  are 1 GiB and 16,000,000 lines. The limit on distinct commits rises from
  1,000,000 to 100,000,000. Findings do not change for histories that scanned
  before. When Git fails, or a later commit reaches a limit or cannot be read,
  the scan still exits with code 1. Its report can now hold findings from the
  commits before that point, and a log line can come later than before.
- Adopt a standalone compatibility policy. Help, usage and error wording, log
  and banner lines, and the order of JSON keys and CSV columns are no longer
  compatibility guarantees and can change. Findings, configuration meaning,
  report fields, exit codes, and supported Gitleaks commands, flags and
  environment variables stay compatible with the pinned Gitleaks revision.
- Read `.gitleaksignore` and `.rustleaksignore` files one line at a time.
  Rustleaks loads these files from the scanned folder, so the scanned
  repository controls their size. Before, Rustleaks read the whole file into
  memory before it checked the 64 KiB line limit. Entries, warnings and
  errors do not change.
- Limit each configuration file to 16 MiB. A configuration can come from
  the scanned folder, and Rustleaks read it whole with no limit. A larger
  file now fails to load before Rustleaks reads more than 16 MiB, and the
  scan exits with 1. This applies to `--config`, the configuration
  environment variables that name a file, `.gitleaks.toml` and
  `.rustleaks.toml` in the scanned folder, `[extend]` files, and
  `FileSystemResolver` in `rustleaks-core`, where the error is a
  `ConfigError::Resolve`. The largest packaged configuration is under 1 MiB.
- Remove the 64 MiB limit on template report output. A template report
  larger than 64 MiB stopped the scan with exit code 1, and Gitleaks has no
  such limit. Rustleaks writes the report while it renders, so the report
  size does not change memory use. The 1,000,000-action limit still bounds
  the work of rendering. `TemplateLimits::default()` in `rustleaks-report`
  now sets `max_output_bytes` to `TemplateLimits::NO_OUTPUT_LIMIT`.
- Let the template action limit grow with the number of findings. A
  template report stopped with exit code 1 after 1,000,000 actions, so a
  normal template that uses about 30 actions for each finding failed at
  about 33,000 findings. Gitleaks has no such limit. The limit is now
  1,000,000 actions plus 1,000 for each finding. A template whose work grows
  faster than the number of findings still stops with exit code 1.
  `TemplateLimits` in `rustleaks-report` has a new `actions_per_finding`
  field, which `TemplateLimits::new` sets to 0.
- Read the `--baseline-path` file in the CLI and parse it with
  `Baseline::from_go_json`, so the core engine no longer reads it.
  `Baseline::load_go_json` stays as a wrapper for library users. Baseline
  matches, warnings and errors do not change.
- Keep at most 10,000 source warnings and errors, such as unreadable or
  skipped files, in a scan without `--complete-profile`. Before, Rustleaks
  kept every one in memory until the end of the scan. Later ones are
  counted, and one log line, such as "15000 more source warnings and errors
  were not shown", gives their number. The scan, its exit code and its
  report do not change.
- Add the `help [command]` command, which prints the same help as
  `<command> --help`, and the `completion <shell>` command, which prints a
  completion script for bash, zsh, fish or PowerShell. `completion` accepts
  and ignores the Gitleaks `--no-descriptions` flag.
- Change the CLI help. It now lists every flag, including `--native-pack`,
  `--complete-profile` and `--base64-mode`, and groups flags by topic. Parser
  usage blocks are shorter and point to `rustleaks help <command>`. Argument
  count, `--exit-code` value, unknown command, `version` argument and
  misplaced `--version` errors are reworded.
- Change the baseline error for a report element that is not a finding to
  say that it expects "a finding object from a JSON report, or null".
- Fix a false "config requires a newer Gitleaks version" warning on every scan
  with the default configuration. Rustleaks now compares the config
  `minVersion` with the implemented Gitleaks version, 8.30.0, instead of its
  own package version, and ignores semantic version build metadata. When a
  config needs a newer version, the warning now says which Gitleaks version it
  requires and which one Rustleaks implements.
- Fix a repeated warning for an invalid ignore file entry when the ignore path
  and the scanned folder are the same folder. An ignore file reached by two
  paths, such as the default ignore path and the scanned folder, a relative
  path or a symlink, is now read once. The warning for an entry with the wrong
  number of fields gives the field count, file and line in plain text instead
  of Rust debug output. The warning for a line of 64 KiB or longer also gives
  the file and line.
- Fix truncated `.lz4` files that were scanned in part without a warning,
  and that a complete scan counted as complete. An LZ4 stream that ends
  after its header, inside a block size, before its end mark or before a
  checksum that its header declares now gives a decode warning, like other
  damaged compressed files, and makes a complete scan incomplete.
- Remove quadratic work in decoding, native rule line numbers and the
  cancellable generic finding filter. Decoding now charges work only for the
  earlier decoded segments that a candidate overlaps. Native rules count line
  numbers once per rule and input instead of once per match. Work for many
  encoded values or dense native matches now grows linearly with the input.
  Findings and reports do not change. The `work_units` value in the
  `--complete-profile` status line is lower for such inputs, so more input
  fits a given work budget.
- Speed up scans with native rule packs. One keyword search over each
  buffer now answers the keyword checks of every native rule, instead of one
  search for each rule keyword. Pack rules without keywords now skip their
  expression on a buffer that lacks every literal the expression requires.
  Findings and reports do not change. The `work_units` value in the
  `--complete-profile` status line is lower for such scans, so more input
  fits a given work budget.
- Start faster with native rule packs. Allowlist patterns that many rules
  repeat are now validated and compiled once for each configuration. Each
  rule's regular expression is still checked when the configuration loads,
  but its matcher is built when a scan first uses it, so rules whose
  keywords never appear do not pay that cost.
- Add three forms to the opt-in `rustleaks-providers-v1` pack. They are
  Alibaba Cloud AccessKey IDs with 17 to 21 byte bodies, Slack configuration
  access tokens with 1 to 10 digit segments, and xAI API keys with 70 to 120
  byte bodies before a delimiter. The pack now has 303 rules.
- Fix the opt-in `rustleaks-connections-v1` semicolon connection rules so
  adjacent connections that share one semicolon each give a finding. In
  `Host=one;Pwd=R7!q;Host=two;Pwd=T8!w;` both passwords are now reported. A
  host key can also start after other ASCII punctuation, a control byte or a
  non-ASCII byte, and the match then starts at the key.
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
- Add the opt-in `--scan-git-metadata` flag for `dir` and
  `DirectoryOptions::scan_git_metadata`. A `.git` folder that a path
  allowlist would skip is entered, and only its text metadata files are
  scanned: `config`, `config.worktree`, `HEAD`, `FETCH_HEAD`, `ORIG_HEAD`,
  `description`, `packed-refs`, `.git-credentials`, `credentials`, the files
  in `hooks`, `info` and `logs`, and submodule `config` files. Objects, the
  index, pack files and lock files are never read. Path allowlists, size
  limits and symlink rules still apply to each file. Without the flag, `dir`
  skips `.git` folders that a path allowlist matches, as before. The default
  configuration matches folders named exactly `.git` below the scan path.
- Fix `dir --follow-symlinks` so a symbolic link to a FIFO, socket or device,
  such as `/dev/zero`, is skipped instead of opened. Before, such a link could
  block the scan or make it read without end. Links to regular files are
  scanned as before.
- Fix quadratic time and memory for native pack association rules on input
  with many credential pairs. A rule whose helpers have no line limit now
  builds one helper list per input buffer and shares it across its findings
  in that buffer. A rule with a line window or a `same-candidate` relation
  looks up the helpers that can relate to a finding instead of checking all
  of them. Findings and their required findings do not change. Work-unit and
  finding-record counts for these rules are lower.
- Document that report lines and columns describe the whole match, and that a
  match ending after the last line break of a file has `EndLine` equal to
  `StartLine` and `EndColumn` 0, as in Gitleaks. Document the location and
  decoded findings of the `rustleaks.kubernetes-secret-yaml-long-context`
  rule. Detection and report values do not change.

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

[Unreleased]: https://github.com/joshgarnett/rustleaks/compare/v0.2.0...HEAD
[0.1.0-alpha.1]: https://crates.io/crates/rustleaks-core/0.1.0-alpha.1
[0.1.0-alpha.2]: https://github.com/joshgarnett/rustleaks/releases/tag/v0.1.0-alpha.2
[0.1.0-alpha.3]: https://github.com/joshgarnett/rustleaks/releases/tag/v0.1.0-alpha.3
[0.1.0-alpha.4]: https://github.com/joshgarnett/rustleaks/releases/tag/v0.1.0-alpha.4
[0.1.0-alpha.5]: https://crates.io/crates/rustleaks-core/0.1.0-alpha.5
[0.1.0-alpha.6]: https://github.com/joshgarnett/rustleaks/releases/tag/v0.1.0-alpha.6
[0.1.0-alpha.7]: https://github.com/joshgarnett/rustleaks/releases/tag/v0.1.0-alpha.7
[0.1.0-alpha.8]: https://github.com/joshgarnett/rustleaks/releases/tag/v0.1.0-alpha.8
[0.1.0-alpha.9]: https://github.com/joshgarnett/rustleaks/releases/tag/v0.1.0-alpha.9
[0.1.0-alpha.10]: https://github.com/joshgarnett/rustleaks/releases/tag/v0.1.0-alpha.10
[0.1.0-alpha.11]: https://github.com/joshgarnett/rustleaks/releases/tag/v0.1.0-alpha.11
[0.1.0-alpha.12]: https://github.com/joshgarnett/rustleaks/releases/tag/v0.1.0-alpha.12
[0.2.0]: https://github.com/joshgarnett/rustleaks/releases/tag/v0.2.0

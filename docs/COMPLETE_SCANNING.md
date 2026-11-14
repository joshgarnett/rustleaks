# Bounded complete-target scanning

`rustleaks-sources` offers an additive source policy that assembles one logical
target through clean EOF before detection. Existing constructors retain legacy
fragmentation. Selecting this library policy does not change the CLI default,
the pinned Gitleaks configuration, or the frozen compatibility corpus.

A complete target gives the engine all accepted bytes in one call. This permits
matches, multiline expressions, line allowlists, required rules and encoded
values to span historical source-fragment boundaries. It does not establish a
universal overlap length or support matching across separate logical targets.

## Selecting the policy

| API | Effect |
| --- | --- |
| `FileOptions::complete(maximum)` | Selects complete assembly with a caller-supplied positive, inclusive byte ceiling. |
| `FileOptions::complete_target_bytes()` | Returns that ceiling, or `None` for legacy fragments. |
| `FileSource::with_options` / `from_source_reader` | Applies the selected policy to a reader, including a caller-owned stdin reader. |
| `DirectoryOptions::file_options` | Applies it to eligible directory files and decorated archive members. |
| `ArchiveSource::with_options` | Applies it to plaintext and decoded leaf targets. Archive limits remain separate. |
| `GitSource::archive_file_options` | Applies it to archive blobs expanded from Git. Text hunk construction is unchanged. |
| `SourceRunner::fail_on_coverage_error(true)` | Stops on a typed failed-coverage event from any source, including Git or a caller-defined adapter. |
| `SourceRunner::with_budget` | Installs caller-selected per-target reservations and aggregate operation limits. |

The source byte ceiling alone does not bound engine allocation or operation
results. Supply finite `SourceBudget` allowances for original bytes, fragments
and retained issues, and finite per-fragment and aggregate `ScanBudget`
allowances for decoded bytes, work units, finding records, finding payload
admission, collected spans and normalization bytes. Every finite aggregate
engine allowance requires a finite matching per-fragment allowance. Callers
also select decode depth and cooperative cancellation.

These are caller-owned limits, not recommended production defaults. Logical
payload counters are not total heap or RSS quotas. Finding payload admission
counts initial finding byte fields and required projections; later session or
report decoration, allocator capacities and overhead are outside that counter.
Archive buffers, directory enumeration, Git patch retention, configuration and
regex caches have separate resource contracts. See
[Resource and cancellation contract](RESOURCE_LIMITS.md).

## Reads and MIME selection

A complete file source reads directly from the supplied reader, independently
of the legacy buffered-reader refill policy. Each read requests at most the
remaining source allowance plus one byte. Exact-cap input is accepted after
EOF; observing the next byte fails the target. Metadata is not the sole size
bound. Allocation and size arithmetic failures are terminal.

Data accompanied by EOF completes the target. Data accompanied by a non-EOF
error fails it and publishes none of its bytes. A `SourceReader` returning zero
bytes with `ReadStatus::Continue` fails as no progress; there is no retry loop.
An overreported byte count also fails. Cancellation is checked around each
read but cannot interrupt a blocking reader call. A complete-mode `FileSource`
permits one visit attempt; it cannot later publish the tail of an
unsuccessful attempt.

MIME eligibility examines the first `min(target length, 100000)` bytes after
bounded clean EOF. The sample is assembled independently of short-read
partitions. Signatures beyond that window do not affect this policy. This is
a named native selection rule, not an assertion that a fixed prefix reproduces
full-file or legacy MIME classification. The source cap precedes MIME
selection, so an oversized application file fails the cap instead of being
silently excluded without a complete read.

## Eligible inputs and failure status

Completion applies to the selected eligible domain. Existing deliberate
exclusions include configured source path allowlists, directory file-size
gates, unfollowed symlinks, directory symlink targets, empty files skipped by
directory metadata policy, application MIME classification, and archive depth
selection. `SourceIssueDisposition::Excluded` marks reported exclusion issues.
`CoverageFailure` identifies inputs that could not be obtained completely.
Silent exclusions remain silent unless their existing issue option is enabled.

Complete directory traversal applies a known path exclusion before metadata
lookup, symlink resolution or opening. An excluded dangling symlink therefore
does not prevent later eligible files from being scanned. The equivalent
eligible symlink failure remains terminal. Legacy traversal retains its
historical gate order.

Archive path pruning retains its existing first-level member scope. Complete
TAR and ZIP traversal can exclude a validated member name before copying or
decoding its payload. This does not waive container structure, entry-count,
spool, TAR header/body/padding bounds, or ZIP local-header and compressed-range
checks. A bad payload CRC confined to an excluded ZIP member need not be
verified. Formats that require decoding shared blocks to obtain later eligible
members still enforce the decoder and container checks needed for that work.
Nested members do not acquire a broader path-pruning policy from this mode.

Complete archive construction forces strict 7z declared member lengths, even
if `ArchiveOptions::strict_7z_member_lengths(false)` was supplied. A short
member stream fails; it is not published as a complete member. This adds no
authenticity claim or checksum coverage beyond the decoder's existing checks.

Directory metadata, opening and traversal failures, and archive spool, member,
decode, corruption and resource failures produce terminal `SourceError`
results in complete mode. No failed file target is delivered to detection.
Already completed targets can remain in the result. For arbitrary source
adapters, select the runner's coverage-error policy as well: it rejects failed
issue events, including fragments coupled to an issue, before scheduling them.

A runner reports source failures as `SourceTermination::SourceError`, exhausted
scan allowances as `BudgetExceeded`, cancellation as `Cancelled`, worker
failure as `WorkerPanic`, and consumer-requested stop as `Stopped`. None means
complete coverage. A partial engine scan contributes no findings for that
target. Budget stops can retain a scheduling-dependent subset of earlier
completed targets; worker counts do not multiply the aggregate allowances.

## Finding coordinates and Git scope

For a completely assembled file or archive leaf, exact raw byte ranges refer
to that target's original bytes, beginning at offset zero. Same-line findings
remain separate occurrences; fingerprints are not an occurrence-deduplication
key. Decoded findings retain their existing encoded-segment location
projection, and raw byte ranges remain explicitly `FindingRange::Unavailable`.

Git text targets remain parsed addition-hunk buffers. Context and deletion
lines are outside that domain, and separate hunks are not combined into a
whole-file target. Raw ranges refer to the supplied hunk buffer, not absolute
positions in the historical blob. Git archive leaves use complete-target
assembly only when the new archive file options are selected.

The engine's existing skip policies still apply. In particular,
`ScanOptions::max_target_bytes` is a skip option, not a substitute for complete
source assembly or an incomplete-result resource budget.

## Explicit CLI profile

`--complete-profile /absolute/path/scan.limits` selects this native policy for
`stdin`, `dir`, or `git`. Without the option, the existing CLI route is unchanged.
The option is documented here separately from the frozen legacy help text.
Configuration selection, environment precedence, automatic configuration
lookup, enabled rules, allowlists, ignore files, baselines, redaction and report
formats continue to use their normal CLI contracts. Select provider rules with
`--native-pack rustleaks-providers-v1`, as described in
[detection policy](DETECTION_POLICY.md). The profile does not select or replace
rules.

The profile is a versioned ASCII `key=unsigned-decimal` format, not TOML.
All fields below are mandatory. Order is unrestricted; surrounding spaces and
tabs, blank lines, CRLF, and full-line `#` comments are accepted. Duplicate or
unknown keys, missing fields, signs, numeric overflow, inline comments and
unsupported versions fail before input scanning. Profile reads consume at most
16 KiB plus one byte; 16 KiB is inclusive. Diagnostics do not reproduce profile
values. All numbers must fit the current target's `usize`.

`target_bytes`, worker/queue counts, archive/Git limits and SCM-link limits must
be positive. Version 1 accepts at most 64 workers and 1024 queue slots, bounding
requested detection threads and eager channel slots before runner construction.
These scheduling guards are not a heap quota. The original-byte, fragment and
issue operation allowances and
all engine allowances permit zero. All ceilings are inclusive. The six
`fragment_` engine dimensions apply to one target; the corresponding
`operation_` dimensions count the entire operation, including rejected partial
engine work. The profile always enables failed-coverage termination.

A positive `--max-target-megabytes` is rejected with this option: that legacy
flag intentionally excludes files and is not an incomplete-result budget.
Use `target_bytes` for source admission. Decode depth, archive depth and timeout
retain their existing explicit flags. Git text scans still cover selected
additions, not complete historical blobs; archive leaves use complete assembly.

In complete mode, known config and baseline self-exclusions are applied before
file reads, using the same exact normalized `FilePath` values as the CLI's
existing exclusion filter. Symlink aliases are not substituted for resolved
file paths. Archive descendants use exact decorated leaf paths, including
compressed streams; an exact container path does not suppress its descendants.
Directory mapping uses the actual emitted path spelling, including `./`, and
preserves logical-root translation. Skipped control files do not consume
complete-mode admitted source bytes; legacy accounting remains unchanged.
Archive container and shared-decoder checks required for eligible members
still apply. Unnamed stdin retains its existing plaintext source domain;
archive depth does not infer a filename or add content-based archive detection.

The following values are an experimental profile for supervised measurements,
not production defaults or a heap limit. Save and review the file explicitly;
no profile is selected automatically.

```text
version=1
target_bytes=8388608
operation_original_bytes=268435456
operation_fragments=200000
operation_issues=1024
workers=1
queue_capacity=1
fragment_decoded_bytes=33554432
operation_decoded_bytes=134217728
fragment_work_units=10000000
operation_work_units=100000000
fragment_finding_records=100000
operation_finding_records=200000
fragment_finding_payload_bytes=33554432
operation_finding_payload_bytes=67108864
fragment_collected_spans=500000
operation_collected_spans=2000000
fragment_normalization_bytes=268435456
operation_normalization_bytes=536870912
archive_entries=10000
archive_member_bytes=8388608
archive_total_bytes=33554432
archive_spool_bytes=8388608
git_patch_bytes=33554432
git_patch_lines=500000
git_stderr_bytes=1048576
git_blob_bytes=8388608
git_metadata_bytes=1048576
git_path_bytes=65536
git_files=100000
git_hunks=200000
scm_link_bytes=4194304
operation_scm_link_bytes=33554432
```

Archive entry/member/expanded/spool limits apply to each archive traversal and
remain distinct from target and operation scan admission. Git limits bound
patch bytes and lines, stderr, archive blobs, metadata, paths, files and hunks
according to `GitLimits`. SCM-link limits count exact retained link bytes.
Allocation-free checked sizing admits each link against both its own cap and
the operation cap before percent escaping or construction. Unknown/disabled
platform, absent remote and empty commit remain not-applicable link states.
Discovery, construction or admission failures make the result incomplete;
`--platform none` explicitly disables discovery and links.

## CLI completion record

Every parsed scan invocation with `--complete-profile` emits exactly one final
`rustleaks_scan_status version=1 ...` line on stderr, independently of log level.
It contains only fixed field names, fixed status values and numeric counters.
Consumers must retain this record with the findings report and require
`status=complete` before treating the result or timing as a complete scan.
An empty findings array alone does not establish completion.

Only `SourceTermination::Completed` produces `status=complete`. Reasons for
incompletion include `profile_error`, `setup_failure`, `coverage_failure`,
`resource_exhaustion`, `cancelled`, `worker_failure`, `metadata_failure`,
`report_failure`, `stopped`, and `unknown_termination`. Complete-mode incomplete
results return exit 2, overriding any configured findings exit code;
`--exit-code 2` is therefore rejected. A complete clean scan returns zero.
Complete findings retain the selected findings exit code, including an explicit
zero.

The record includes selected source scope and decode/archive depth, retained
finding count, `reports=complete|partial`, and final source/engine usage when
available. Structured runner and link exhaustion includes `resource`,
`budget_scope`, `limit`, `consumed` and `requested`. Adapter errors without a
structured numerical budget use `none` for those fields. Engine usage includes
failed work; `usage_exact=0` identifies inexact panic accounting. SCM usage is
admitted link bytes, including a reservation if subsequent construction fails.
Report failure can leave partial report bytes; status output failure still
returns exit 2, and a missing record must never be accepted as completion.

Earlier complete targets can remain in an incomplete report. No failed
complete file or partial engine fragment contributes prefix findings. Report
schemas remain unchanged, so an incomplete report must travel with its status
record. A failed operation may retain a scheduling-dependent subset of earlier
targets.

These limits do not bound directory enumeration, configuration loading,
compiled-rule storage, allocator capacity, regex caches or hard wall-clock
execution. Redaction, session fingerprints and report conversion have separate
payload costs; an 8 MiB source cap is not an 8 MiB memory quota. Dense findings
on one long line can exhaust payload allowance even on a small input. Record
such cases as incomplete coverage, not successful fast scans.

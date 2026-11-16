# Complete scanning

This guide is for people who need proof that a scan covered all of its input,
for example in an audit or a release gate. It explains the
`--complete-profile` option, the profile file, and the status line that a
complete scan prints.

Complete scanning is not in 0.1.0-alpha.9. To use it now, [build from
source](getting-started.md#build-from-source).

## Why complete scanning exists

A normal scan does not fail when it skips some input. Some inputs can be
skipped or cut short without failing the scan:

- Large files are read in pieces of about 100,000 bytes. A match that crosses
  the edge of a piece can be missed.
- A file that cannot be read, or an archive that is damaged, is reported in
  the log, and the scan can still exit with 0.
- No limit is set on the total work, so one very large input can make a scan
  slow or use a lot of memory.

With `--complete-profile FILE`, Rustleaks changes these rules:

- Each file, archive member or standard input stream that the scan covers is
  read to the end and scanned as one piece, up to a byte limit that you
  choose.
- Every input that cannot be read in full makes the scan incomplete.
- Every work and size limit comes from the profile file.
- At the end, Rustleaks prints one status line that says whether the scan was
  complete.
- An incomplete scan exits with code 2.

## Running a complete scan

`--complete-profile` works with `dir`, `git` and `stdin`:

```sh
rustleaks dir . --complete-profile scan.limits --report-path findings.json
```

A relative path is read from the current working folder. Rustleaks never
picks a profile by itself.

All other options work as usual: configuration, `--enable-rule`,
`--native-pack`, ignore files, baselines, allow comments, redaction and
reports. `--max-decode-depth`, `--max-archive-depth` and `--timeout` still
set the decode depth, the archive depth and the time limit.

Two options cannot be used with a profile:

- `--max-target-megabytes` with a value above 0. That option skips large
  files, which a complete scan does not allow. Use `target_bytes` in the
  profile instead.
- `--exit-code 2`. Exit code 2 is kept for incomplete scans.

## The profile file

A profile is a plain ASCII text file, not TOML. Each line has the form
`key=value`, where the value is a whole number without a sign.

```text
# Example profile. These values are a starting point, not tuned defaults.
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

Format rules:

- Every key in the list below is required, in any order.
- Unknown keys, repeated keys, signs, inline comments and values that are too
  large fail before the scan starts.
- Blank lines and lines that start with `#` are skipped. Spaces and tabs
  around keys and values are allowed. Windows line endings are allowed.
- The file can be at most 16 KiB.
- Every limit includes its value: a limit of 10 allows 10.
- A value of 0 is a limit of zero, not "no limit". This is different from
  command-line flags such as `--timeout 0`. Keys marked "yes" in the table
  below must be above 0.
- Error messages do not repeat values from the profile.

### Profile keys

In this table, a piece is the unit that Rustleaks scans in one step: one file,
one archive member, one Git diff hunk, or standard input. The whole scan is
called the operation.

| Key | Meaning | Must be above 0 |
| --- | --- | --- |
| `version` | Profile format version. Must be `1`. | yes |
| `target_bytes` | Largest file, archive member or standard input, in bytes. A larger input makes the scan incomplete. | yes |
| `operation_original_bytes` | Total input bytes for the whole scan. | no |
| `operation_fragments` | Total number of pieces for the whole scan. | no |
| `operation_issues` | Number of source warnings, such as skipped files, that the scan may keep. | no |
| `workers` | Number of detection threads, at most 64. | yes |
| `queue_capacity` | Number of pieces that can wait for a worker, at most 1,024. | yes |
| `fragment_decoded_bytes`, `operation_decoded_bytes` | Bytes produced by decoding, per piece and for the whole scan. | no |
| `fragment_work_units`, `operation_work_units` | Detection work, per piece and for the whole scan. | no |
| `fragment_finding_records`, `operation_finding_records` | Findings created, per piece and for the whole scan. | no |
| `fragment_finding_payload_bytes`, `operation_finding_payload_bytes` | Bytes copied into findings, per piece and for the whole scan. | no |
| `fragment_collected_spans`, `operation_collected_spans` | Raw pattern matches collected, per piece and for the whole scan. | no |
| `fragment_normalization_bytes`, `operation_normalization_bytes` | Bytes used to prepare text for pattern matching, per piece and for the whole scan. | no |
| `archive_entries` | Entries in one archive. | yes |
| `archive_member_bytes` | Size of one archive member after decompression. | yes |
| `archive_total_bytes` | Total decompressed bytes of one archive. | yes |
| `archive_spool_bytes` | Temporary storage for one archive. | yes |
| `git_patch_bytes`, `git_patch_lines` | Size of the `git log` or `git diff` output. | yes |
| `git_stderr_bytes` | Size of Git error output that Rustleaks keeps. | yes |
| `git_blob_bytes` | Size of one archive file read from Git. | yes |
| `git_metadata_bytes` | Size of commit metadata, such as messages. | yes |
| `git_path_bytes` | Length of one file path in Git output. | yes |
| `git_files`, `git_hunks` | Number of changed files and diff hunks in Git output. | yes |
| `scm_link_bytes` | Length of one finding link. | yes |
| `operation_scm_link_bytes` | Total length of all finding links. | yes |

A work unit is an internal count of detection steps. It has no fixed time
cost. To choose work and finding limits, run a scan on typical input with a
large profile and read the `work_units` and other usage values from the status
line.

The archive keys apply only when `--max-archive-depth` is above 0. The Git and
link keys apply only to `git` scans.

## The status line

Every scan with `--complete-profile` prints exactly one status line at the end
of standard error. It is printed at every log level.

```text
rustleaks_scan_status version=1 status=complete reason=complete source_scope=directory_targets findings=1 reports=complete decode_depth=5 archive_depth=0 resource=none budget_scope=none limit=none consumed=none requested=none usage=available original_bytes=74 fragments=2 completed_fragments=2 decoded_bytes=0 work_units=16 finding_records=1 finding_payload_bytes=224 collected_spans=4 normalization_bytes=0 usage_exact=1 issues=0 scm_link_bytes=0
```

The line holds only fixed names and numbers. It never holds paths, secrets or
profile values.

| Field | Meaning |
| --- | --- |
| `status` | `complete` or `incomplete`. |
| `reason` | Why the scan ended. See the table below. |
| `source_scope` | What was scanned: `directory_targets`, `stdin_targets` or `git_additions_and_archive_leaves`. |
| `findings` | Number of findings kept. |
| `reports` | `complete`, or `partial` when the scan was incomplete. |
| `decode_depth`, `archive_depth` | The depths used. |
| `resource`, `budget_scope`, `limit`, `consumed`, `requested` | For a limit that stopped the scan: which resource, whether the limit was per `fragment`, per `operation` or per `link`, the limit, the amount used, and the amount asked for. `none` otherwise. See the note below the table. |
| `usage` | `available` when the counters below are present, `unavailable` otherwise. |
| `original_bytes`, `fragments`, `completed_fragments`, `decoded_bytes`, `work_units`, `finding_records`, `finding_payload_bytes`, `collected_spans`, `normalization_bytes` | What the scan used. |
| `usage_exact` | `1` when the counters are exact. `0` after an internal worker failure. |
| `issues` | Number of source warnings. |
| `scm_link_bytes` | Total length of finding links. |

The `resource` fields are filled only in two cases. The first is when a
whole-scan or per-piece limit from the profile stops the scan, such as
`operation_work_units`. The second is when a finding link is too long. When a
size limit on one input stops the scan, such
as `target_bytes` or an archive or Git limit, the status line has
`reason=resource_exhaustion` and `resource=none`. The log line before it
names the input.

### Reasons

| Reason | Meaning |
| --- | --- |
| `complete` | Every input that the scan covers was scanned in full. |
| `profile_error` | The profile could not be read or is not valid, or it conflicts with another option. |
| `setup_failure` | The scan could not start, for example because of a configuration error. |
| `coverage_failure` | An input could not be read in full, for example a read error or a damaged archive. |
| `resource_exhaustion` | A limit from the profile was reached. |
| `cancelled` | The scan was stopped, for example by `--timeout`. |
| `worker_failure` | A detection worker failed. |
| `metadata_failure` | Rustleaks could not find the Git remote or build a finding link within its limits. |
| `report_failure` | The report could not be written. |
| `stopped`, `unknown_termination` | The scan ended in another way that is not a complete scan. |

## Exit codes

A complete scan exits with 0 when it finds nothing and with the `--exit-code`
value, 1 by default, when it finds secrets. An incomplete scan exits with 2,
for any reason. See [Exit codes](cli-reference.md#exit-codes).

## Reading the result safely

- Treat a scan as complete only when the status line says `status=complete`.
  An empty report alone does not prove that the scan was complete.
- Keep the status line with the report. An incomplete scan can still write a
  report with findings from the inputs that did finish. Which earlier inputs
  are included can change from run to run.
- A missing status line means the scan did not complete.

## What a complete scan does not cover

A complete scan covers the inputs of the selected command and rules.
It does not mean that every byte on disk was checked, or that every possible
secret format was found.

- Files that a configuration allowlist excludes by path, binary files,
  symbolic links that are not followed, and archives deeper than
  `--max-archive-depth` are skipped on purpose. They do not make the scan
  incomplete.
- A `git` scan still covers only the lines added in each commit, not whole
  files. Archive files found in Git history are read in full.
- Standard input is not checked for archives by content.
- The profile limits count input bytes, decoded bytes, copied bytes and
  detection steps. They do not limit the total memory of the process or the
  time the scan takes. A long line with many findings can use a lot of
  memory, and it can reach the finding payload limit even when the input is
  small.

A complete scan also opens one archive name that a normal scan does not. See
[Archives](configuration.md#archives).

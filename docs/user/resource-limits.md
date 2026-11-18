# Resource limits

This guide is for people who scan large or untrusted input with the
`rustleaks` command or the `rustleaks-core` library. It lists the built-in
limits, the options that change them, and what happens when a scan reaches
one.

## The most important rule

A scan that reaches a limit has not checked all of its input. Treat it as
incomplete coverage, not as a clean result. Depending on the limit, Rustleaks
skips one input with a warning, or stops and exits with code 1. Only a scan
with `--complete-profile` turns every coverage gap into a failure. See
[Complete scanning](complete-scanning.md).

## Limits in normal CLI scans

| What | Default | How to change it | When reached |
| --- | --- | --- | --- |
| Decode depth | 5 levels | `--max-decode-depth N`; `0` turns decoding off | Deeper encoded text is not decoded. |
| Archive depth | 0, archives are not opened | `--max-archive-depth N` | Deeper archives are not opened. |
| Entries in one archive | 10,000 | Profile key `archive_entries` | Warning; the rest of the archive, or for 7z and RAR the whole archive, is skipped. |
| One archive member, decompressed | 64 MiB | Profile key `archive_member_bytes` | Warning; the member, or for 7z the whole archive, is skipped. |
| One archive, decompressed in total | 256 MiB | Profile key `archive_total_bytes` | Warning; the rest of the archive, or for 7z and RAR the whole archive, is skipped. |
| Temporary storage for one archive | 64 MiB | Profile key `archive_spool_bytes` | Warning; the archive is skipped. |
| File size | No limit | `--max-target-megabytes N` (N times 1,000,000 bytes) | Warning; the file is skipped. |
| Size of one scanned piece of a file | About 100,000 bytes | Profile key `target_bytes`, which makes each file one piece | Larger files are scanned in several pieces. |
| Symbolic link hops | 64 | Fixed | Warning; the link is skipped. |
| `git log` or `git diff` output for one commit | 1 GiB and 16,000,000 lines | Profile keys `git_patch_bytes` and `git_patch_lines` | The scan stops with exit code 1. |
| Git error output kept | 1 MiB | Profile key `git_stderr_bytes` | The scan stops with exit code 1. |
| One archive file read from Git | 256 MiB | Profile key `git_blob_bytes` | The scan stops with exit code 1. |
| Metadata of one commit | 16 MiB | Profile key `git_metadata_bytes` | The scan stops with exit code 1. |
| One path in Git output | 1 MiB | Profile key `git_path_bytes` | The scan stops with exit code 1. |
| Changed files and diff hunks in one commit | 1,000,000 files, 2,000,000 hunks | Profile keys `git_files` and `git_hunks` | The scan stops with exit code 1. |
| Distinct commits counted | 100,000,000 | Fixed | The scan stops with exit code 1. |
| Time | No limit | `--timeout N` seconds | The scan stops with exit code 1 and reports what it found so far. |
| Detection work and finding memory | No limit | Profile keys that start with `fragment_` and `operation_` | The scan stops and is incomplete (exit 2). |

The profile keys belong to a `--complete-profile` file, so you can change
these limits only in a complete scan. In a complete scan, reaching any limit
makes the scan incomplete, and it exits with 2. See [Complete
scanning](complete-scanning.md#profile-keys). Complete scanning is not in
0.1.0-alpha.9.

Detection work grows with the input size, the number of rules and the decode
depth. Many encoded values in one piece of input, such as one Base64 value on
each line, need work in proportion to their number. Work counts can change
between releases, so measure them again before you reuse work limits.

`--timeout` is checked between steps. A single long step, such as one pattern
search over a large input, finishes before the scan stops. The timeout is not
a hard deadline.

### Git history

Rustleaks reads `git log` output while Git runs. It keeps one changed file of
one commit in memory at a time, so the memory for Git output follows the
largest change, not the length of the history. The Git limits above apply to
each commit, from one `commit` line of the output to the next. No limit
applies to the total size of the history. A `git diff`, used by `--staged`
and `--pre-commit`, has no commits, so its whole output counts as one commit.

When Git fails, or a later commit reaches a limit or cannot be read, the scan
stops with exit code 1. The report can then hold findings from the commits
before that point.

### Limits on input you give Rustleaks

| What | Limit |
| --- | --- |
| Command-line arguments | 4,096 |
| One command-line value or path | 1 MiB |
| Path components when Rustleaks cleans a path | 4,096 |
| `--enable-rule` IDs | 4,096. The selected rules can hold at most 8 MiB of rule source text. |
| `--native-pack` flags | 32 |
| `extend` levels in a configuration | 2 |
| One regular expression | 1 MiB of source, 4,096 levels of nesting, and 256 MiB for each compiled form. A repeat count can be at most 1,000, and the counts of nested repeats multiplied together can be at most 1,000. |
| Native rule packs together | 32 packs, 1 MiB of TOML, 1,024 rules |
| One line of an ignore file | 64 KiB. Parsing of that file stops at a longer line. |
| Report template | 1 MiB of source, 1,000,000 actions, 64 MiB of output, 128 levels of nesting |
| Complete-scan profile file | 16 KiB |

A configuration or rule pack that exceeds these limits fails to load.

## Large inputs under the example profile

This section shows what the [example
profile](complete-scanning.md#the-profile-file) does with some large inputs.
Use it to judge whether that profile fits your input. It is not a promise
about other inputs, rules or releases.

A scan that stops at a limit is incomplete. It exits with 2, and its report
can miss secrets. It is not a pass. In the runs below, a stopped scan reported
none or only some of the GitHub tokens planted in its input.

How the scans were run:

- An optimized build from source.
- All rules: the default rules plus the `rustleaks-extra-v1`,
  `rustleaks-providers-v1` and `rustleaks-connections-v1` native packs.
- `--complete-profile` with the example profile, `--max-decode-depth 5`,
  `--max-archive-depth 0` and `--base64-mode compatible`.
- Synthetic inputs with known GitHub tokens. Each row is one scan of one file,
  or of one folder where the row says so.

| Input | Size | Result | Limit that stopped the scan |
| --- | --- | --- | --- |
| A folder of 132 files with plain tokens, or of 186 files with Base64 tokens. Each file has one token, or one almost valid token, across byte 4,096. | 4,160 to 4,216 bytes per file | Complete. Every planted token was found once, on the right line. | None |
| The same, with the token across byte 65,536, 100,000, 125,000, 153,672 or 182,344 | 65,600 to 182,464 bytes per file | Stopped. Each scan reported 7 to 16 of its 50 or 72 planted tokens. | `operation_work_units`, the limit for the whole scan |
| One 64-byte JSON record per line. A token on every line, on every other line, or on no line. | 512 KiB and 2 MiB | Stopped. No planted token was reported. | `fragment_work_units`, the limit for one file |
| The same records on one long line, with tokens | 512 KiB and 2 MiB | Stopped. No planted token was reported. | `fragment_finding_payload_bytes`, because each finding keeps a copy of the whole line |
| The same records on one long line, without valid tokens | 512 KiB and 2 MiB | Stopped | `fragment_work_units` |
| One Base64 value that holds 4,096 records, encoded once or twice | 289,467 and 385,951 bytes | Stopped. No planted token was reported. | `fragment_work_units` |
| 20,000 lines, each the Base64 form of one token | 1,140,021 bytes | Stopped. No planted token was reported. | `fragment_work_units` |

The last row comes from a separate scan, not from the fixture check that
produced the other rows. It used the same options. A second run of that input
with a much larger profile completed. It needed about 71 million work units in one file with `--base64-mode compatible`,
and about 95 million with `--base64-mode extended`. The example profile allows
10 million for one file. With the default rules alone, the same input
completed under the example profile in both modes and needed less than 250,000
work units.

If your input looks like a stopped row, raise the limit that the status line
names, run the scan again, and check that the status line says
`status=complete`. See [Complete scanning](complete-scanning.md#the-status-line).

## Memory

Rustleaks does not set a limit on total process memory, and the limits above
are not memory limits. Some cases use much more memory than the input size:

- Each finding keeps a copy of its source line. Many findings on one long line
  can use a lot of memory, even for a small file.
- Some native pack association rules, such as
  `rustleaks.association.planetscale-api-token`, attach every helper in a
  piece of the input to every finding of the rule in that piece. Rustleaks
  stores that list once, and the `--complete-profile` limits count it once.
  Verbose output (`--verbose`) prints one `Required` line for each helper of
  each finding, so its size grows with findings times helpers. No limit
  bounds it, also with `--complete-profile`.
- Rustleaks may stop the process if memory runs out.

For untrusted input, run Rustleaks with an operating system memory limit, or
use `--complete-profile` to limit finding records and finding bytes.

## Limits for library users

The `rustleaks-core` engine sets no limits by default. See [Budgets and
cancellation](library.md#budgets-and-cancellation) for the budgets and for
what your program must do.

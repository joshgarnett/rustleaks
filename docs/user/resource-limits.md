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
| `git log` or `git diff` output | 256 MiB and 2,000,000 lines | Profile keys `git_patch_bytes` and `git_patch_lines` | The scan stops with exit code 1. |
| Git error output kept | 1 MiB | Profile key `git_stderr_bytes` | The scan stops with exit code 1. |
| One archive file read from Git | 256 MiB | Profile key `git_blob_bytes` | The scan stops with exit code 1. |
| Commit metadata | 16 MiB | Profile key `git_metadata_bytes` | The scan stops with exit code 1. |
| One path in Git output | 1 MiB | Profile key `git_path_bytes` | The scan stops with exit code 1. |
| Changed files and diff hunks in Git output | 1,000,000 files, 2,000,000 hunks | Profile keys `git_files` and `git_hunks` | The scan stops with exit code 1. |
| Distinct commits counted | 1,000,000 | Fixed | The scan stops with exit code 1. |
| Time | No limit | `--timeout N` seconds | The scan stops with exit code 1 and reports what it found so far. |
| Detection work and finding memory | No limit | Profile keys that start with `fragment_` and `operation_` | The scan stops and is incomplete (exit 2). |

The profile keys belong to a `--complete-profile` file, so you can change
these limits only in a complete scan. In a complete scan, reaching any limit
makes the scan incomplete, and it exits with 2. See [Complete
scanning](complete-scanning.md#profile-keys). Complete scanning is not in
0.1.0-alpha.9.

`--timeout` is checked between steps. A single long step, such as one pattern
search over a large input, finishes before the scan stops. The timeout is not
a hard deadline.

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

## Memory

Rustleaks does not set a limit on total process memory, and the limits above
are not memory limits. Some cases use much more memory than the input size:

- Each finding keeps a copy of its source line. Many findings on one long line
  can use a lot of memory, even for a small file.
- Rustleaks may stop the process if memory runs out.

For untrusted input, run Rustleaks with an operating system memory limit, or
use `--complete-profile` to limit finding records and finding bytes.

## Limits for library users

The `rustleaks-core` engine sets no limits by default. See [Budgets and
cancellation](library.md#budgets-and-cancellation) for the budgets and for
what your program must do.

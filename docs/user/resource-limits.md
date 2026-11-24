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
| Entries in one archive | 1,000,000 | Profile key `archive_entries` | Warning; the rest of the archive, or for 7z the whole archive, is skipped. |
| One archive member, decompressed | 4 GiB | Profile key `archive_member_bytes` | Warning. See [Archives](#archives). |
| One archive, decompressed in total | 16 GiB | Profile key `archive_total_bytes` | Warning; the rest of the archive is skipped. |
| Temporary storage for one archive | 1 GiB | Profile key `archive_spool_bytes` | Warning; the ZIP, 7z, Zstandard or LZ4 archive that needs it is skipped. |
| Archive parts kept in memory | 64 MiB, or the member limit if it is lower | Fixed | Warning; the member or archive is skipped. See [Archives](#archives). |
| PPMd model size that a RAR3 member sets | 64 MiB | Fixed | Warning; the member and the rest of the RAR archive are skipped. See [Archives](#archives). |
| File size | No limit | `--max-target-megabytes N` (N times 1,000,000 bytes) | Warning; the file is skipped. |
| Size of one scanned piece of a file | About 100,000 bytes | Profile key `target_bytes`, which makes each file one piece | Larger files are scanned in several pieces. |
| Symbolic link hops | 64 | Fixed | Warning; the link is skipped. |
| `git log` or `git diff` output for one commit | 1 GiB and 16,000,000 lines | Profile keys `git_patch_bytes` and `git_patch_lines` | The scan stops with exit code 1. |
| Git error output kept | 1 MiB, for all `git log` processes of a scan together | Profile key `git_stderr_bytes` | The scan stops with exit code 1. |
| One archive file read from Git | 1 GiB, and at most the archive temporary storage | Profile keys `git_blob_bytes` and `archive_spool_bytes` | Warning; the archive is skipped. |
| Metadata of one commit | 16 MiB | Profile key `git_metadata_bytes` | The scan stops with exit code 1. |
| One path in Git output | 1 MiB | Profile key `git_path_bytes` | The scan stops with exit code 1. |
| Changed files and diff hunks in one commit | 1,000,000 files, 2,000,000 hunks | Profile keys `git_files` and `git_hunks` | The scan stops with exit code 1. |
| Distinct commits counted | 100,000,000 | Fixed | The scan stops with exit code 1. |
| Source warnings and errors kept, such as unreadable or skipped files | 10,000 | Profile key `operation_issues` | Later ones are counted, not kept, and one log line gives their number. The scan goes on, and the exit code and report do not change. |
| Time | No limit | `--timeout N` seconds | The scan stops with exit code 1 and reports what it found so far. |
| Detection threads | One for each CPU that Rustleaks may use, up to 12 | `--jobs N`, or profile key `workers` | Not a coverage limit. Findings do not depend on it. See [Detection threads](#detection-threads). |
| `git log` processes that read history at the same time | One for each detection thread, up to 6 | `--jobs N`, or profile key `workers` | Not a coverage limit. Findings do not depend on it. See [Git history](#git-history). |
| Detection work and finding memory | No limit | Profile keys that start with `fragment_` and `operation_` | The scan stops and is incomplete (exit 2). |

The profile keys belong to a `--complete-profile` file, so you can change
these limits only in a complete scan. In a complete scan, reaching any limit
makes the scan incomplete, and it exits with 2. See [Complete
scanning](complete-scanning.md#profile-keys).

Detection work grows with the input size, the number of rules and the decode
depth. Many encoded values in one piece of input, such as one Base64 value on
each line, need work in proportion to their number. Work counts can change
between releases, so measure them again before you reuse work limits.

`--timeout` is checked between steps. A single long step, such as one pattern
search over a large input, finishes before the scan stops. The timeout is not
a hard deadline.

### Git history

Rustleaks reads `git log` output while Git runs. It parses one changed file of
one commit at a time, so the memory for Git output follows the largest change,
not the length of the history. Detection threads can hold more diff hunks; see
[Detection threads](#detection-threads). The Git limits above apply to
each commit, from one `commit` line of the output to the next. No limit
applies to the total size of the history. A `git diff`, used by `--staged`
and `--pre-commit`, has no commits, so its whole output counts as one commit.

When Git fails, or a later commit reaches a limit or cannot be read, the scan
stops with exit code 1. The report can then hold findings from the commits
before that point.

#### Several Git processes

One `git log` process uses about one CPU, so it limits how fast a history
scan can be. With more than one detection thread, Rustleaks reads the
history with several `git log` processes at the same time: one for each
detection thread, up to 6. Each process reads a part of the history, and
Rustleaks reads their output in history order. So findings, their order,
reports, warnings and exit codes do not change.

Rustleaks uses one process with `--jobs 1` or the profile key `workers=1`,
and with `--log-opts`, `--staged` or `--pre-commit`, because those options
can change which commits Git shows. It also uses one process for a short
history and in a few other cases. When Git fails, the error text in the log
line comes from the process that failed. See [Git history
processes](../dev/engine-internals.md#git-history-processes) for how the
parts are read and joined.

Memory and error output:

- Each `git log` process maps the pack files of the repository and keeps its
  own caches. For large histories, one process can use from hundreds of
  megabytes to more than 2 GB. A process for one part of the history usually
  uses less than one process for the whole history. To use less memory, set
  a lower `--jobs` value.
- The error output of all `git log` processes counts toward
  `git_stderr_bytes` together. A warning that each process writes, such as
  the one about a too low `diff.renameLimit`, counts once for each process
  that writes it.

### Detection threads

Rustleaks scans with one detection thread for each CPU that it may use, up
to 12. On Linux, this number follows the CPU affinity and the cgroup CPU
quota of the process. If Rustleaks cannot find the number, it uses one
thread. `--jobs` can set more. See
[More threads are not always faster](#more-threads-are-not-always-faster).

`--jobs N` sets the number of threads. It has no fixed maximum. If the system
cannot start a thread, the scan stops before it reads any input and exits
with 1, or with 2 under `--complete-profile`. `--jobs` also replaces
`workers` in a `--complete-profile` file, so the order is `--jobs`, then the
profile, then the CPU count up to 12.

Findings, their order, reports, warnings and exit codes are the same for any
number of threads. A scan that stops early, because of `--timeout` or a
profile limit, can have different findings.

One thread reads the input and splits it into pieces. Each detection thread
scans one piece at a time. Without a profile, up to N pieces wait for a
thread, but never more than 1,024. With a profile, `queue_capacity` sets
this number. So memory grows with the thread count:

- At most 2 times N plus 1 pieces are in memory when the queue holds N. A
  piece of a file is about 100,000 bytes. A piece of Git history is one diff
  hunk, which can be as large as one changed file.
- In a `dir` scan, the threads that read files hold a few more pieces. See
  [Reading files](#reading-files).
- Each detection thread keeps its own pattern search caches.

With `--complete-profile`, a piece of a file is the whole file, up to
`target_bytes`.

#### Reading files

In a `dir` scan with two or more detection threads, one thread walks the
folder in the same order as with one thread. It checks every path, size and
symbolic link before a file is opened. Two other threads open the files that
pass and split them into pieces. The pieces and the warnings reach the
detection threads in walk order, so findings, their order, reports, warnings
and exit codes are the same as with one thread.

Archives, and compressed files such as `app.log.gz`, are read by the walking
thread, so a scan still reads one archive at a time. With `--jobs 1`, the
walking thread reads every file itself.

#### More threads are not always faster

Past some number of threads, a scan gets no faster, but each added thread
still uses memory. The scan is then limited by something that more
detection threads do not speed up:

- For a folder, two threads read the files. When the detection threads scan
  pieces faster than these threads can open and read files, added threads
  wait. This happens first on folders with many small files, where opening
  each file takes most of the time.
- For Git history, `git log -p` produces the input. Up to 6 `git log`
  processes run at the same time, one for each detection thread. Past that,
  history scans are usually limited by Git, not by detection threads. See
  [Several Git processes](#several-git-processes).
- Input with many matches, such as files dense with keywords, keeps gaining
  from more threads for longer, because detection is most of the work.

To find the best value for your input, time a scan at a few `--jobs` values.
To use less memory, set a lower value.

### Archives

Rustleaks reads archives as streams. It decompresses and scans each member
while it reads it, so memory does not grow with the size of a member or of
the archive. A member is split into pieces in the same way as a file.

ZIP and 7z archives need random access. An archive file found by `dir` is
read in place. Any other ZIP or 7z input, such as one inside another archive
or one read from Git, is first copied to temporary storage: in memory up to
1 MiB, and otherwise to a temporary file.
Zstandard and LZ4 streams that are not files on disk are copied in the same
way, because Rustleaks checks their frame structure before it decodes them.
TAR and the other compressed formats need no temporary storage.

Temporary files:

- are created in the system temporary folder, which `TMPDIR` sets on Unix
  and `TMP` or `TEMP` sets on Windows;
- can be read and written only by the user who runs Rustleaks;
- have no name after they are created on Unix, and are deleted when they are
  closed on Windows, so they are removed on every path, also after an error,
  a cancelled scan or a stopped process; and
- count toward the temporary storage limit of one archive, together with the
  copies kept in memory. Nested copies count together.

If the temporary folder is in memory, such as a `tmpfs` folder on Linux,
temporary files use memory.

The limits work as follows:

- **Entries.** Each TAR, ZIP and RAR entry counts when it is read. A 7z
  archive counts all its entries before it is read, so it is skipped as a
  whole when they do not fit.
- **One member.** A TAR, ZIP or 7z member whose stated size is above the
  limit is not read. For TAR and ZIP, the rest of the archive is skipped too;
  for 7z, the whole archive is skipped. A compressed file, such as
  `app.log.gz`, has no stated size. Rustleaks scans it up to the limit and
  then reports the warning.
- **Total.** Rustleaks counts the bytes of each member and the bytes that
  each decompression step produces. A member inside a compressed TAR, such as
  `release.tar.gz`, counts once for the TAR stream and once as a member. When
  the total is reached, the bytes before it are scanned and the rest of the
  archive is skipped.
- **Parts kept in memory.** Some parts cannot be streamed: a whole RAR member
  (packed and decoded), a whole Snappy or MinLZ stream, a TAR long name, 7z
  headers, and the decoder dictionaries of 7z, Zstandard and LZIP. Each is
  limited to 64 MiB, or to the member limit if it is lower. A RAR member over
  the limit skips the rest of the RAR archive. A larger dictionary or 7z
  header skips the stream or archive.
- **RAR3 PPMd model.** A RAR3 member compressed with PPMd sets the size of
  its PPMd model, up to 256 MiB. Rustleaks reads a model of up to 64 MiB.
  The member limit does not lower this limit. A member that sets a larger
  model is not decoded: Rustleaks reports a warning and skips that member
  and the rest of the RAR archive. The RAR3 test archives in Rustleaks, made
  with RAR at its best compression (`-m5`), set 25 MiB. Rustleaks keeps the
  model in larger structures than RAR does. The worst case measured so far
  took about 200 MiB of memory when set to 25 MiB, and about 450 MiB when
  set to 64 MiB. These are measurements, not limits. From the sizes of its
  structures, the model can take at most about 34 times the size it sets,
  about 2.1 GiB at 64 MiB. The model grows with the decoded data, so it
  reaches its size only when a member fills it. A RAR archive inside a RAR
  archive keeps the outer model while it reads the inner one. With
  `--max-archive-depth N`, nested RAR archives can hold up to N models at
  once, so up to N times these amounts.
- **Git.** An archive file from Git history is copied to temporary storage
  before it is read. A file larger than `git_blob_bytes` or the temporary
  storage limit is skipped with a warning, and the history scan continues.

Because members are scanned while they are read, a damaged or too large
archive can be reported after some of its members, or part of one member,
were scanned. A member whose CRC check fails at its end is already scanned
when the warning appears. In a complete scan, a member is published only
after it has been read without a failure, but members before the failure
stay in the report, and the scan is incomplete.

The defaults are high because memory does not depend on them. The member and
total limits bound the work that one archive, such as a decompression bomb,
can cause. The temporary storage limit bounds the disk space of nested ZIP and
7z archives and of archives from Git. A scan reads one archive at a time. An
archive from Git can hold its own copy and the temporary storage of the
archives inside it at the same time.

### Limits on input you give Rustleaks

| What | Limit |
| --- | --- |
| Command-line arguments | 4,096 |
| One command-line value or path | 1 MiB |
| Path components when Rustleaks cleans a path | 4,096 |
| `--enable-rule` IDs | 4,096. The selected rules and the rules they require can hold at most 8 MiB of rule source text. |
| `extend` levels in a configuration | 2 |
| One configuration file, including `.gitleaks.toml` or `.rustleaks.toml` in the scanned folder and each `[extend]` file | 16 MiB. A larger file fails to load before Rustleaks reads more than 16 MiB of it. |
| `--baseline-path` file | 256 MiB. Rustleaks reads no more than 256 MiB of a larger file. It logs an error and scans without the baseline, as for a baseline it cannot read. See [Baselines](configuration.md#baselines). |
| One regular expression | 1 MiB of source, 4,096 levels of nesting, and 256 MiB for each compiled form. A repeat count can be at most 1,000, and the counts of nested repeats multiplied together can be at most 1,000. |
| Native rule files in one `NativePolicy` (library) | 32 files, 1 MiB of TOML, 1,024 rules |
| One line of an ignore file | 64 KiB. Parsing of that file stops at a longer line. Rustleaks reads an ignore file one line at a time, so it never holds more than one line of the file in memory, plus the entries it keeps. |
| Report template | 1 MiB of source, 1,000,000 actions plus 1,000 actions for each finding, 128 levels of nesting. The report size has no limit, because Rustleaks writes the report while it renders. |
| Complete-scan profile file | 16 KiB |

A configuration or rule file that exceeds these limits fails to load.

## Large inputs under the example profile

Some inputs need much more work or finding memory than their size suggests.
Under the [example profile](complete-scanning.md#the-profile-file), they can
stop a complete scan:

- Many encoded values, such as one Base64 value on each line, can reach
  `fragment_work_units` or `operation_work_units`. The Rustleaks rules add
  more work for each value.
- Many findings on one long line can reach `fragment_finding_payload_bytes`,
  because each finding keeps a copy of the whole line.

A scan that stops at a limit is incomplete. It exits with 2, and its report
can miss secrets. It is not a pass. If this happens, raise the limit that the
status line names, run the scan again, and check that the status line says
`status=complete`. See [Complete scanning](complete-scanning.md#the-status-line).

## Memory

Rustleaks does not set a limit on total process memory, and the limits above
are not memory limits. Some cases use much more memory than the input size:

- Each finding keeps a copy of its source line. Many findings on one long line
  can use a lot of memory, even for a small file.
- Some Rustleaks association rules, such as
  `rustleaks.association.ramp-client-secret`, attach every helper in a
  piece of the input to every finding of the rule in that piece. Rustleaks
  stores that list once, and the `--complete-profile` limits count it once.
  Verbose output (`--verbose`) prints one `Required` line for each helper of
  each finding, so its size grows with findings times helpers. No limit
  bounds it, also with `--complete-profile`.
- Archives use read buffers for each archive level, plus the parts kept in
  memory that [Archives](#archives) lists. The XZ decoder sizes its
  dictionary from the stream header, without a Rustleaks limit. A complete
  scan holds each member in memory, up to `target_bytes`.
- Each detection thread holds its own piece of input and search caches. See
  [Detection threads](#detection-threads).
- Rustleaks may stop the process if memory runs out.

For untrusted input, run Rustleaks with an operating system memory limit, or
use `--complete-profile` to limit finding records and finding bytes.

## Limits for library users

The `rustleaks-core` engine sets no limits by default. See [Budgets and
cancellation](library.md#budgets-and-cancellation) for the budgets and for
what your program must do.

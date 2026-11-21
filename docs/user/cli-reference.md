# Command reference

This page is for people who run `rustleaks` and need the exact name, value and
default of a command or flag. The other guides explain how to use each
feature, and this page links to them.

## Synopsis

```text
rustleaks <command> [flags] [path]
```

| Command | What it does |
| --- | --- |
| `git [repository]` | Scan the commits of a Git repository, or its staged or unstaged changes. |
| `dir [path]` | Scan a folder or a single file. `file` and `directory` are other names for this command. |
| `stdin` | Scan bytes read from standard input. |
| `version` | Print the Rustleaks version. |
| `help [command]` | Print help for Rustleaks or for one command. |
| `completion <shell>` | Print a shell completion script. |

`rustleaks` with no command, or with only scan flags, prints the main help and
exits with 0.

## Command-line rules

- The path for `git` and `dir` defaults to the current folder (`.`). These
  commands accept at most one path. `stdin` accepts no path. Extra paths are
  an error.
- A flag value can follow the flag as a separate argument (`--config my.toml`)
  or after `=` (`--config=my.toml`). `--redact` is different: its value must
  use `=`, as in `--redact=20`.
- Switch flags, such as `--verbose`, also accept `=true` and `=false`, for
  example `--verbose=false`.
- Short flags are `-c`, `-r`, `-f`, `-b`, `-l`, `-i`, `-j`, `-v` and `-h`.
  Give the value of a short flag as the next argument, as in `-r out.json`.
  Only `-c` also accepts `=`, as in `-c=my.toml`.
- `--` ends the flags. Every argument after it is a path.
- Flags that every scan command shares can come before or after the command.
  Flags that belong to one command, such as `--staged` or `--follow-symlinks`,
  must come after that command.
- `--version` works only without a command. `rustleaks version` prints only
  the version number. `rustleaks --version` prints `rustleaks version` and
  the number.
- The command line can have at most 4,096 arguments, and one value or path can
  be at most 1 MiB.

## Commands

### git

```text
rustleaks git [flags] [repository]
```

Scans the history of a Git repository. Rustleaks runs the `git` program from
your `PATH`, so Git must be installed.

By default Rustleaks runs `git log -p -U0 --full-history --all
--diff-filter=tuxdb`, which covers every commit reachable from any branch or
tag. Only the lines that each commit adds are scanned.

| Flag | Value | Effect |
| --- | --- | --- |
| `--log-opts` | Text | Replaces the options after `git log -p -U0`. Rustleaks splits the value at each space and does not use shell quoting, so do not put quotes inside the value. Rustleaks warns about a word that starts and ends with a quote. Example: `--log-opts="main..HEAD"`. |
| `--staged` | None | Scan changes that are staged but not committed yet (`git diff --staged`). |
| `--pre-commit` | None | Scan changes in the working tree that are not staged yet (`git diff`). |
| `--platform` | `github`, `gitlab`, `azuredevops`, `gitea`, `bitbucket` or `none` | Build links to findings for this platform. `none` turns links off. Without this flag, or with an empty value or `unknown`, Rustleaks finds the platform from the remote URL. Case does not matter. |

With both `--staged` and `--pre-commit`, Rustleaks scans the staged changes.
`--log-opts` has no effect with either of them. Findings from `--staged` and
`--pre-commit` have no commit and no link. See [Using Rustleaks in CI and Git
hooks](ci.md) for examples.

### dir

```text
rustleaks dir [flags] [path]
```

Scans a folder and everything below it, or a single file. `file` and
`directory` are other names for `dir`.

| Flag | Value | Effect |
| --- | --- | --- |
| `--follow-symlinks` | None | Scan files that symbolic links point to. Without this flag, links are skipped. |
| `--scan-git-metadata` | None | Also scan the text metadata files in `.git` folders. See [Git metadata](#git-metadata). |

The `File` field of a finding depends on the path you give. See [Ignore
files](configuration.md#ignore-files).

#### Files that are skipped

`dir` does not scan these files:

- files and folders that a path allowlist matches, such as `.git` folders
  with the default configuration;
- symbolic links, unless you give `--follow-symlinks`;
- files larger than `--max-target-megabytes`, with a warning; and
- files whose first bytes match a known binary format, without a warning.

The binary check looks at the content, not the name. It skips:

- programs and libraries: Windows, ELF and Mach-O executables, WebAssembly
  and Android DEX files;
- archives and compressed files: ZIP and formats built on it, such as JAR or
  DOCX, and TAR, RAR, 7z, gzip, bzip2, XZ, Zstandard, LZIP, Unix compress,
  CAB, InstallShield CAB, `ar`, Debian and RPM packages, and ISO 9660 disk
  images;
- documents: PDF, PostScript, RTF and Microsoft Office files;
- fonts: WOFF, WOFF2, TrueType, OpenType and Embedded OpenType; and
- other formats: SQLite databases, DICOM files, Flash (SWF) files, Chrome
  extensions (CRX) and NES ROM images.

Images, audio and video files are scanned. The check looks only at the
first bytes, so a text file that happens to start like one of these formats,
for example with `%!` or `MZ`, is skipped too. The same check applies to
each file inside an archive and to standard input. With
`--max-archive-depth` above 0, a file whose name marks it as an archive is
opened instead. See [Archives](configuration.md#archives).

#### Git metadata

The default configuration has a global path allowlist entry,
`(?:^|/)\.git$`, so `dir` skips every `.git` folder below the scan path, as
Gitleaks does. Text
files in a `.git` folder can still hold secrets. A remote URL in `config` can
contain a token, a hook script can contain a credential, and older Git
versions or other tools can write a URL with a token to other metadata
files.

`--scan-git-metadata` enters a `.git` folder that a path allowlist would
skip and scans only these files:

- `config`, `config.worktree`, `HEAD`, `FETCH_HEAD`, `ORIG_HEAD`,
  `description`, `packed-refs`, `.git-credentials` and `credentials`, directly
  in the `.git` folder;
- every file in `hooks`, `info` and `logs` and their subfolders, except names
  that end in `.lock`; and
- every file named `config` in `modules` and its subfolders, which holds the
  configuration of submodules.

Rustleaks decides by name alone, so it never lists, inspects or reads
`objects`, `index` files, pack files or lock files. Commit history is
compressed in `objects`. Use `rustleaks git` to scan it.

Name matching has these limits:

- The `.git` name must match exactly, like the default path allowlist entry.
  A folder named `.GIT` is not skipped by that entry, so Rustleaks scans it in
  full with or without this flag.
- The `objects` and `.lock` checks ignore case. A submodule named `objects`
  or `index`, or one whose name ends in `.lock`, is not covered.
- A `.git` file, as in a submodule or linked worktree checkout, only points to
  the real Git folder. It is skipped.
- A `.git` folder given as the scan path, as in `rustleaks dir repo/.git`, is
  not matched by the default entry. Rustleaks scans all of it, with or
  without this flag.

Other rules still apply to each selected file:

- Path allowlists apply to each file path, such as `repo/.git/config`. The
  default `(?:^|/)\.git$` entry matches only the folder, so it does not skip
  these files. To skip some of them, add a path allowlist such as
  `(?:^|/)\.git/logs/`.
- `--max-target-megabytes`, `--follow-symlinks`, `--max-archive-depth` and
  `--complete-profile` work as for any other file. Rustleaks never enters a
  `.git` folder that is a symbolic link.
- If no path allowlist matches a `.git` folder, for example with a custom
  configuration, Rustleaks scans the whole folder with or without this flag.

The built-in Git credential URL rules can then report findings in
`.git/config` and `.git-credentials`.

The flag works only with `dir`. Gitleaks does not scan these files, so a scan
with this flag can report findings that Gitleaks does not.

### stdin

```text
rustleaks stdin [flags]
```

Scans the bytes on standard input. There is no file name, so the `File` field
is empty and Rustleaks does not open archives by name. Input whose first bytes
match a binary format is skipped, as for [files](#files-that-are-skipped).
Configuration files and ignore files are looked up in the current folder.

### version

```text
rustleaks version
```

Prints the Rustleaks version number on standard output. It accepts the scan
flags and ignores them.

### help

```text
rustleaks help [command]
```

`rustleaks help` prints the main help: commands, shared flags, the
configuration order and the exit codes. `rustleaks help <command>` prints the
same page as `rustleaks <command> --help`. `-h` and `--help` work everywhere.
`help` accepts the scan flags and ignores them.

### completion

```text
rustleaks completion <shell>
```

Prints a completion script for `bash`, `zsh`, `fish` or `powershell` on
standard output. It accepts the scan flags and ignores them. It also accepts
`--no-descriptions` for Gitleaks compatibility and ignores it. See [Shell
completion](#shell-completion) to install a script.

## Flags for scan commands

The `git`, `dir` and `stdin` commands accept every flag in this section. The
`version`, `help` and `completion` commands accept them too, but ignore them.

### Configuration

| Flag | Short | Value | Default | Effect |
| --- | --- | --- | --- | --- |
| `--config` | `-c` | Path | None | Read the configuration from this file. See [Configuration order](#configuration-order). |
| `--enable-rule` | | Rule IDs | All rules | Use only these rules. Separate IDs with commas or repeat the flag. An unknown ID is an error. See [Configuration](configuration.md#choosing-rules-with---enable-rule). |

### Suppression

| Flag | Short | Value | Default | Effect |
| --- | --- | --- | --- | --- |
| `--baseline-path` | `-b` | Path | None | Do not report findings that are in this JSON report. See [Baselines](configuration.md#baselines). |
| `--rustleaks-ignore-path` | `-i` | Path | `.` | Read ignore entries from this file, or from `.rustleaksignore` and `.gitleaksignore` in this folder. Ignore files in the scanned folder are always read too. `--gitleaks-ignore-path` is another name. See [Ignore files](configuration.md#ignore-files). |
| `--ignore-rustleaks-allow` | | None | Off | Report findings on lines with a `rustleaks:allow` or `gitleaks:allow` comment. `--ignore-gitleaks-allow` is another name. |

### Reports and output

| Flag | Short | Value | Default | Effect |
| --- | --- | --- | --- | --- |
| `--report-path` | `-r` | Path | None | Write a report to this file. `-` writes it to standard output. |
| `--report-format` | `-f` | `json`, `csv`, `junit`, `sarif` or `template` | From the extension of `--report-path` | The report format. The extension works for `.json`, `.csv` and `.sarif`. |
| `--report-template` | | Path | None | The template file. Also give `--report-format template`. |
| `--exit-code` | | Whole number | `1` | The exit code when the scan finds secrets. See [Exit codes](#exit-codes). |
| `--redact` | | Optional percent, after `=` | Off | Hide secrets in logs, `--verbose` output and reports. Without a value, hide the whole secret. `--redact=20` hides 20 percent. |
| `--verbose` | `-v` | None | Off | Print each finding on standard output. |

See [Reports](reports.md) for the formats and fields.

### Limits and decoding

| Flag | Value | Default | Effect |
| --- | --- | --- | --- |
| `--max-target-megabytes` | Whole number | `0` | Skip files larger than this many megabytes (1,000,000 bytes each). `0` or less means no limit. |
| `--max-decode-depth` | Whole number | `5` | Decode encoded text up to this many levels deep. `0` or less turns decoding off. |
| `--base64-mode` | `compatible` or `extended` | `compatible` | How to find Base64 text. `extended` also decodes padded URL-safe and unpadded standard Base64, and keeps binary output. See [Decoding](configuration.md#decoding). |
| `--max-archive-depth` | Whole number | `0` | Scan inside archives nested up to this many levels deep. `0` or less does not open archives. See [Archives](configuration.md#archives). |
| `--timeout` | Seconds | `0` | Stop the scan after this many seconds and exit with 1, or with 2 under `--complete-profile`. `0` or less means no time limit. |
| `--jobs`, `-j` | Whole number of 1 or more | The number of CPUs that Rustleaks may use, up to 12 | Scan with this many detection threads. Findings, reports, warnings and exit codes do not depend on this number. It replaces `workers` in a `--complete-profile` file. See [Detection threads](resource-limits.md#detection-threads) for its effect on speed and memory. |
| `--complete-profile` | Path | None | Scan with the limits in this profile file and report whether the scan was complete. See [Complete scanning](complete-scanning.md). |

### Logging

| Flag | Short | Value | Default | Effect |
| --- | --- | --- | --- | --- |
| `--log-level` | `-l` | `trace`, `debug`, `info`, `warn`, `error` or `fatal` | `info` | Show log lines at this level and above. `err` also means `error`. Case does not matter. An unknown value prints a warning and uses `info`. |
| `--no-banner` | | None | Off | Do not print the banner. |

### Other flags

| Flag | Short | Effect |
| --- | --- | --- |
| `--help` | `-h` | Print help for the command. |
| `--version` | | Print `rustleaks version` and the version number. Works only without a command. |

### Legacy flag names

These older names also work:

| Legacy name | Effect |
| --- | --- |
| `--gitleaks-ignore-path` | Same as `--rustleaks-ignore-path`. |
| `--ignore-gitleaks-allow` | Same as `--ignore-rustleaks-allow`. |
| `--no-color` | Accepted and ignored. Rustleaks never prints color. |

## Environment variables

| Variable | Meaning |
| --- | --- |
| `RUSTLEAKS_CONFIG` | The path of a configuration file. |
| `RUSTLEAKS_CONFIG_TOML` | The configuration text itself. |
| `GITLEAKS_CONFIG` | Legacy name for `RUSTLEAKS_CONFIG`. |
| `GITLEAKS_CONFIG_TOML` | Legacy name for `RUSTLEAKS_CONFIG_TOML`. |

An empty variable is skipped. Rustleaks reads no other environment variables
itself. The `git` program that it runs reads its own variables, such as
`GIT_DIR`.

## Configuration order

Rustleaks uses the first configuration that it finds: `--config`, then the
environment variables above, then a `.rustleaks.toml` or `.gitleaks.toml` file
in the scanned folder, then the built-in default rules. See [Where Rustleaks
finds the configuration](configuration.md#where-rustleaks-finds-the-configuration)
for the full order.

## Files Rustleaks reads

| File | When |
| --- | --- |
| `.rustleaks.toml`, `.gitleaks.toml` | In the scanned folder, when no configuration flag or variable is set. |
| `.rustleaksignore`, `.gitleaksignore` | In the scanned folder, and in the folder or file given with `--rustleaks-ignore-path`. |
| Baseline file | With `--baseline-path`. |
| Template file | With `--report-template`. |
| Profile file | With `--complete-profile`. |

A scan can skip the selected configuration file and the baseline file. See
[Where Rustleaks finds the
configuration](configuration.md#where-rustleaks-finds-the-configuration).

## Output streams

| Output | Stream |
| --- | --- |
| Banner, log lines, summary and errors | Standard error |
| The status line of a complete scan | Standard error |
| Findings from `--verbose` | Standard output |
| A report with `--report-path -` | Standard output |
| Help, version and completion scripts | Standard output |

## Exit codes

| Code | When |
| --- | --- |
| 0 | The scan finished and found nothing. `help`, `version` and `completion` also exit with 0. |
| 1 | The scan found secrets (change this value with `--exit-code`), or an error happened without `--complete-profile`. |
| 2 | A scan with `--complete-profile` was not complete. With a profile, errors during the scan exit with 2. See [Complete scanning](complete-scanning.md). |
| 126 | The command line has an unknown long flag, such as `--nope`. |

Errors that exit with 1 include a bad configuration, a Git error, `--timeout`,
an unknown command, an unknown short flag, a missing or bad flag value, and
too many paths. `--exit-code` does not change the code for errors. Command
line errors exit with 1 or 126 even with `--complete-profile`, because they
happen before the scan starts.

With the defaults, findings and errors both exit with 1. To tell them apart,
set `--exit-code` to another value, such as 3. Do not use 2 or 126.

`--exit-code` accepts a whole number from -2147483648 to 2147483647. On Linux
and macOS, the operating system keeps only the lowest 8 bits of an exit code,
so use a value from 0 to 255. With `--complete-profile`, `--exit-code 2` is an
error, and the exit code is then 2. Findings hidden by an ignore file, a
baseline or an allow comment do not count as findings.

## Shell completion

`rustleaks completion <shell>` prints the script. Open a new shell after you
install it.

Bash: save the script in your completions folder.

```sh
mkdir -p ~/.local/share/bash-completion/completions
rustleaks completion bash > ~/.local/share/bash-completion/completions/rustleaks
```

Or add this line to `~/.bashrc`:

```sh
eval "$(rustleaks completion bash)"
```

Zsh: save the script as `_rustleaks` in a folder that is in `$fpath`.

```sh
mkdir -p ~/.zfunc
rustleaks completion zsh > ~/.zfunc/_rustleaks
```

Then add these lines to `~/.zshrc`:

```zsh
fpath=(~/.zfunc $fpath)
autoload -Uz compinit && compinit
```

Fish: save the script in your completions folder.

```sh
mkdir -p ~/.config/fish/completions
rustleaks completion fish > ~/.config/fish/completions/rustleaks.fish
```

PowerShell: load the script in the current session.

```powershell
rustleaks completion powershell | Out-String | Invoke-Expression
```

To load it in every session, add that line to your `$PROFILE` file.

## Limits

Rustleaks has built-in limits on archives, Git output, configuration and
templates. See [Resource limits](resource-limits.md).

# Fixtures

This folder holds copied fixture files. Keep their bytes, paths and file
modes unchanged. Tests that change a fixture, such as the Git tests, work on
a temporary copy.

## `upstream/`

`upstream/testdata/` is a copy of the Gitleaks test fixtures at commit
`b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b`. It holds configuration files,
Git repositories, archives, baselines, ignore files and expected reports.
The files keep their MIT provenance (see the repository
[`NOTICE`](../../NOTICE)), their paths and bytes, their executable modes,
and the one symlink,
`upstream/testdata/repos/symlinks/file_symlink/symlinked_id_ed25519`. The
copy has 214 regular files, four of them executable.

The Git repositories under `upstream/testdata/repos/` store their Git
metadata in a folder named `dotGit`. Tests copy a repository and rename
that folder to `.git`.

## `archives/`

These archives come from other projects. Each folder keeps its license and
a README with its source.

- `bodgit-sevenzip-v1.6.1/`: 7z decoder fixtures from
  `github.com/bodgit/sevenzip` v1.6.1, under the BSD-3-Clause license.
- `mholt-archives-v0.1.5/`: a two-part RAR archive from
  `github.com/mholt/archives` v0.1.5, under the MIT license.
- `rar-test-files-16b785c/`: RAR3 and RAR5 archives from
  `ssokolow/rar-test-files` commit
  `16b785c2b1b504e99fc307676e5369a26d3ce060`, under the CC0 dedication.

The source corpus case `archive-rar2-compressed` in
`../source-corpus/requests-v1.jsonl` is a RAR2 archive built around the
compressed payload of the `rar2` decoder test in `compcol` 0.3.0 (MIT). That
test says the payload was made with `rar` 2.60. Only a RAR2 container header
was added around it.

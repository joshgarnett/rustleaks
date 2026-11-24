# Source corpus

These cases cover the sources that turn input into fragments: readers,
single files, directory walks, symlinks, skipped paths, size limits, buffer
and chunk boundaries, and cancellation. They also cover archives and
compressed files (zip, tar, 7z, RAR, gzip, xz, zstd, bzip2 and others),
including nested and corrupt archives.

## Files

- `requests-v1.jsonl`: 124 cases. `operation` is one of:
  - `reader` (9 cases): read `content_base64` as a stream.
  - `file` (86 cases): read one file named `logical_path` (or
    `path_base64`). Its bytes are in `content_base64`, or in the file that
    `fixture_path` names under `../fixtures/upstream/`. Many archive cases
    hold the archive bytes in `content_base64`.
  - `files` (21 cases): walk a directory. `fixture_path` names a folder
    under `../fixtures/upstream/` to copy, or `entries` lists the folders,
    files and symlinks to create in a temporary folder.
  - `boundary` (8 cases): check where chunks split, with `buffer_size` and
    `max_peek_size`.

  Optional fields set `max_archive_depth`, `max_file_size`,
  `follow_symlinks`, `skip_paths_base64`, `worker_limit`, cancellation, and
  `detect` with `config_fixture` to also run detection.
- `outcomes-v1.jsonl`: the expected result of each case. `fragments` lists
  the fragments in the order the source emits them, and
  `canonical_fragments` lists them in a fixed order. Each fragment has its
  bytes, path, Windows path and symlink path. `bytes_nil` tells an absent
  byte buffer from an empty one. `findings` lists the expected findings,
  `issues` lists skipped or failed inputs, and `error` is set when the scan
  stops. The outcomes were recorded on macOS (`platform`).
- `coverage-v1.json`, `negative-controls-v1.json`, `native-windows-v1.json`
  and `manifest-v1.json`: coverage notes, Windows hashes, counts and hashes
  from when the cases were recorded. No test reads them.

## Tests

`//crates/rustleaks-sources:source_corpus_test` replays the cases and
counts the ones it does not replay. It skips `boundary-empty`, because
Rustleaks rejects a zero buffer size. On Windows it also skips nine symlink
and permission cases that depend on Unix file metadata.

The archive fuzz seeds in `crates/rustleaks-sources/fuzz/` also use some
archive cases from `requests-v1.jsonl`.

## Origin and changes

The cases were recorded from Gitleaks at commit `b58d3f1` (MIT, see
[`NOTICE`](../../NOTICE)). Some archive cases hold copies of the archives in
`../fixtures/archives/`; see [the fixtures README](../fixtures/README.md).
See [Changing a case](../README.md#changing-a-case).

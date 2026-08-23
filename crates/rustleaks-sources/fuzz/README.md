# `rustleaks-sources` fuzz targets

This standalone package enables the production `archives` feature without
changing the root workspace or lockfile.

## `archive`

The first byte selects TAR, ZIP, 7z, RAR, compressed TAR, or one of the native
stream decoders. At most 8 KiB reaches the source. Traversal is limited to two
archive layers, eight entries, 4 KiB per member, 8 KiB total decoded bytes,
and an 8 KiB spool. File fragments use 512-byte chunks with 128 bytes of
boundary read-ahead. Control bits exercise pre-cancellation, cancellation from
the callback, and normal callback stop.

This target is intentionally supported only with `panic=unwind`. The 7z/RAR
dependency guards can convert known dependency panics into recoverable issues
only under unwind builds. A compile-time guard rejects `panic=abort`, and an
outer `catch_unwind` immediately resumes any panic not contained by production
code so libFuzzer records the input as a failure. No claim is made that archive
decoding is panic-contained in a downstream `panic=abort` binary.

## `reader_schedule`

This target drives the public compatibility reader protocol with bounded
zero-progress, short, data-plus-EOF, data-plus-error, overreported-count,
cancellation, stop, and callback-error schedules. Each operation produces at
most 15 bytes and the schedule is capped by the 4 KiB fuzz input.

Run bounded smoke campaigns from this directory:

```sh
cargo +nightly fuzz run archive seeds/archive -- \
  -max_len=8192 -max_total_time=60 -timeout=5 -rss_limit_mb=2048
cargo +nightly fuzz run reader_schedule seeds/reader_schedule -- \
  -max_len=4096 -max_total_time=60 -timeout=5 -rss_limit_mb=1024
```

Replay a saved artifact exactly:

```sh
cargo +nightly fuzz run archive artifacts/archive/crash-<hash>
```

These are bounded panic/hang/resource-pathology campaigns, not native
Linux/Windows runtime evidence and not universal OOM guarantees.

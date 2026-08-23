# `rustleaks-report` fuzz targets

This is a standalone `cargo-fuzz` package and does not participate in the root
workspace or lockfile.

## `template`

The target frames at most 8 KiB into no more than 4 KiB of arbitrary
byte-preserving safe-template source and up to four bounded findings. Parsing
and rendering use 128 actions and an 8 KiB output ceiling. Parsed arbitrary
templates render both to memory and to a writer that rejects bytes after a
fuzz-selected prefix. A fixed valid template and immediately rejecting writer
prove destination errors propagate on every execution, even when the arbitrary
template is invalid or empty.

Run a bounded smoke campaign from this directory:

```sh
cargo +nightly fuzz run template seeds/template -- \
  -max_len=8192 -max_total_time=60 -timeout=5 -rss_limit_mb=1024
```

Replay a saved artifact exactly:

```sh
cargo +nightly fuzz run template artifacts/template/crash-<hash>
```

The target is a bounded panic/hang/resource-pathology check. It does not imply
a universal OOM guarantee or native Linux/Windows runtime execution.

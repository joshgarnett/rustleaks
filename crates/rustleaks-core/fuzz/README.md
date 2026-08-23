# `rustleaks-core` fuzz targets

This is a standalone `cargo-fuzz` package. Its inner `[workspace]` keeps root
workspace resolution, commands, and `Cargo.lock` unchanged.

## Targets

### `go_regex`

The target includes the crate-private production module directly, compiles
patterns fallibly, and exercises its source, backend/capture metadata,
existence, whole-match iteration, and capture iteration APIs. Every input is
framed as:

```text
u16 little-endian pattern length | pattern bytes | arbitrary haystack bytes
```

The declared length is reduced modulo the payload boundary, so every input of
at least two bytes is usable. Pattern bytes are converted with UTF-8 loss
replacement because Rust patterns must be valid UTF-8; haystack bytes remain
unchanged, including malformed UTF-8.

Seed the target from the frozen 3,618-request Go regex corpus and run a bounded
smoke test from this directory:

```sh
ruby seed_regex_corpus.rb
cargo +nightly fuzz run go_regex corpus/go_regex -- \
  -max_len=4096 -max_total_time=60 -rss_limit_mb=2048
```

To replay a saved libFuzzer failure exactly:

```sh
cargo +nightly fuzz run go_regex artifacts/go_regex/crash-<hash>
```

The target intentionally has no semantic assertions: any Go/Rust parity claim
continues to come from the frozen oracle replay. Fuzzing is for panics, memory
safety defects, and resource pathologies over arbitrary input.

Resource limits matter. Production accepts source patterns up to 1 MiB and
caps the compiled Thompson NFA at 256 MiB. Malformed haystacks allocate a
normalized buffer plus an offset map, and `find_all`/`captures_all` allocate in
proportion to the number of matches and capture slots. Keep `-max_len`, RSS,
wall-time, and CI duration bounded; increase them deliberately for longer
campaigns.

### `config`

`config` converts at most 8 KiB of arbitrary bytes with UTF-8 loss replacement,
then exercises both the separate parse/compile path and `load_toml`. The loader
uses no filesystem resolver and an empty fuzz default, so random extension
requests cannot perform I/O or repeatedly compile the full embedded ruleset.

### `fragment_scan`

`fragment_scan` scans at most 8 KiB of arbitrary content plus fixed percent,
hex, and base64 decoder seeds. It uses two small fixed rules, decode depth two,
an exact target-byte ceiling, path/origin variants, and canonical repeated-scan
equality. Every returned location is checked for valid line/column ordering.

### `session`

`session` frames at most 16 KiB into arbitrary baseline JSON, ignore records,
and finding bytes. It also runs guaranteed baseline and exact-ignore
suppression cases, repeated immutable-policy classification, and mutable
session collection.

Run bounded local smoke campaigns from this directory:

```sh
cargo +nightly fuzz run config seeds/config -- \
  -max_len=8192 -max_total_time=60 -timeout=5 -rss_limit_mb=2048
cargo +nightly fuzz run fragment_scan seeds/fragment_scan -- \
  -max_len=8192 -max_total_time=60 -timeout=5 -rss_limit_mb=2048
cargo +nightly fuzz run session seeds/session -- \
  -max_len=16384 -max_total_time=60 -timeout=5 -rss_limit_mb=2048
```

Replay saved artifacts by replacing the seed directory with the artifact path:

```sh
cargo +nightly fuzz run fragment_scan artifacts/fragment_scan/crash-<hash>
```

The harness caps protect routine fuzz jobs; production boundary behavior still
requires focused tests at the larger documented limits. OOM may abort and is
not represented as a universal fallible-allocation guarantee.

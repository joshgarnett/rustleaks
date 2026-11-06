# `rustleaks-core` fuzz targets

The limits below describe smoke and extended campaigns. The optional deep
profile raises each target input cap to 64 KiB. Fragment scanning additionally
permits depth 4, 2 MiB decoded bytes, 65,536 work units and 512 findings. The
runner records the selected profile; the test-only shared helper supplies both
harness limits and synthetic seeds. Large config rules and match suffixes lie
beyond the smoke boundary. Separate structured cases check decoded-byte,
finding-record and configuration-selection boundaries. See the
[structured-case contract](../../../docs/SECURITY_STRESS.md).

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

`just fuzz-smoke` generates the frozen 3,618-request Go regex seed corpus and
runs all eight bounded targets with private diagnostics. For retained local
output, run `just fuzz run --output /private/tmp/rustleaks-core-fuzz-run` from
the repository root. The output path must be new and outside the checkout;
this example uses macOS's non-symlink temporary directory.

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

Use the maintained runner from the repository root:

```sh
just fuzz-smoke
just fuzz run --output /private/tmp/rustleaks-core-fuzz-run
```

Failed runs retain a private reproduction bundle. Explicit-output successful
runs retain evolved corpora. The [private fuzz workflow](../../../docs/SECURITY_CONTROLS.md#private-local-fuzz-evidence)
documents exact-option campaign replay, artifact reproduction and crash
minimization, successful corpus merging, and explicit reviewed local promotion.
Direct cargo-fuzz commands print raw crash bytes and do not supply that
retention policy. Treat all crash inputs and diagnostics as sensitive.

The harness caps protect routine fuzz jobs; production boundary behavior still
requires focused tests at the larger documented limits. OOM may abort and is
not represented as a universal fallible-allocation guarantee.

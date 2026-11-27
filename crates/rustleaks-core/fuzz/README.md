# `rustleaks-core` fuzz targets

This page is for contributors. This folder is a standalone `cargo-fuzz`
package for the core engine. Its own `[workspace]` keeps the root workspace,
its commands and `Cargo.lock` unchanged.

## Targets

| Target | What it covers | Input limit | Seeds |
| --- | --- | --- | --- |
| `go_regex` | Go regex translation, compiling, captures, empty matches, invalid bytes and repeated matching | 4 KiB | Generated from `testdata/regex-corpus/requests-v1.jsonl` |
| `config` | TOML parsing, compiling and `load_toml`, rule extension, allowlists and composite rules | 8 KiB | `seeds/config/` |
| `fragment_scan` | Decoders, locations, invalid bytes, overlaps, redaction, limits and repeated scans | 8 KiB | `seeds/fragment_scan/` |
| `session` | Baseline JSON, ignore records, deduplication and session state | 16 KiB | `seeds/session/` |

Each target has a dictionary in `dictionaries/<target>.dict`. The deep
profile raises every input limit to 64 KiB. In that profile,
`fragment_scan` also allows decode depth 4, 2 MiB of decoded bytes, 65,536
work units and 512 findings.

## Input formats

- `go_regex` reads a little-endian `u16` pattern length, the pattern bytes,
  and then the haystack bytes. The length is reduced modulo the remaining
  input, so every input of two or more bytes is used. Pattern bytes are
  converted to UTF-8 with replacement. Haystack bytes stay unchanged,
  including malformed UTF-8.
- `config` converts the input to UTF-8 with replacement. The loader has no
  file resolver and an empty default, so extension requests do no I/O.
- `fragment_scan` scans the input with fixed percent, hex and Base64 decoder
  seeds, two small rules and decode depth two. It checks that repeated scans
  are equal and that every location has valid line and column order.
- `session` splits the input into baseline JSON, ignore records and finding
  bytes. It also runs fixed baseline and ignore suppression cases.

The targets check for panics, memory errors and resource problems. They make
no claim about expected findings; the corpus tests under `testdata/` check
those.

## Running

To run only this crate's targets, from the repository root:

```sh
just fuzz run --targets go_regex,config,fragment_scan,session \
  --output /private/tmp/rustleaks-core-fuzz-run
```

The output folder must be new and outside the checkout. Treat crash inputs
and diagnostics as sensitive. Direct `cargo fuzz` commands print raw crash
bytes, so use `just fuzz`. `just fuzz-build` and `just fuzz-smoke` cover
every fuzz target in the four crates. See
[Fuzzing](../../../docs/dev/security-checks.md#fuzzing) for replay,
minimizing and corpus promotion.
For inputs above these limits, see the [larger structured
tests](../../../docs/dev/security-checks.md#larger-structured-tests).

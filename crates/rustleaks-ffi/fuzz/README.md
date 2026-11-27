# `rustleaks-ffi` fuzz targets

This page is for contributors. This folder is a standalone `cargo-fuzz`
package for the C ABI crate. It is not part of the root workspace or its
lockfile.

## Targets

| Target | What it covers | Input limit | Seeds |
| --- | --- | --- | --- |
| `exports` | Every exported C function, called with valid pointers and arbitrary configuration, option keys and values, rule IDs, scan arguments, cancel handles and scanned bytes | 8 KiB | `seeds/exports/` |

The dictionary is `dictionaries/exports.dict`.

The target runs `rustleaks_ffi::harness::exercise`, a safe Rust client of
the C ABI. The input starts with a two-byte configuration length and the
configuration, then up to seven option calls, a path and the scan argument
fields. Next comes a choice of no cancel handle, a fresh one or one that is
already set, and then the scanned bytes. Each run also reads the ABI number, the
version, the rules, the worker count and the input limit. The target never loads the built-in rules, so
each run stays short. It checks that every call returns a known status,
that every range in a finding lies inside the input, and that the match
text equals the input bytes at the match range when nothing is redacted.
`//crates/rustleaks-ffi:exports_fuzz_test` replays the seeds and short
generated inputs in the normal tests.

The deep profile allows 64 KiB inputs.

## Running

To run only this crate's target, from the repository root:

```sh
just fuzz run --targets exports --output /private/tmp/rustleaks-ffi-fuzz-run
```

The output folder must be new and outside the checkout. Treat crash inputs
and diagnostics as sensitive. `just fuzz-build` and `just fuzz-smoke` cover
every fuzz target. See
[Fuzzing](../../../docs/dev/security-checks.md#fuzzing) for replay,
minimizing and corpus promotion.

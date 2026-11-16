# `rustleaks-report` fuzz targets

This page is for contributors. This folder is a standalone `cargo-fuzz`
package for the report crate. It is not part of the root workspace or its
lockfile.

## Targets

| Target | What it covers | Input limit | Seeds |
| --- | --- | --- | --- |
| `template` | Safe template parsing, rendering, escaping, output limits, writer errors and repeated rendering | 8 KiB | `seeds/template/` |

The dictionary is `dictionaries/template.dict`.

The target splits its input into at most 4 KiB of template source and up to
four findings. Parsing and rendering allow 128 actions and 8 KiB of output.
Each template renders to memory and to a writer that fails after a selected
prefix. A fixed valid template with a writer that fails at once checks on
every run that writer errors are returned.

The deep profile allows 64 KiB inputs, 32 KiB of template source, 512
actions, 128 KiB of output and 16 findings.

## Running

Run these commands from the repository root:

```sh
just fuzz-build
just fuzz-smoke
just fuzz run --output /private/tmp/rustleaks-report-fuzz-run
```

The output folder must be new and outside the checkout. Treat crash inputs
and diagnostics as sensitive. Direct `cargo fuzz` commands print raw crash
bytes and do not keep the private output rules. See the [private fuzz
workflow](../../../docs/dev/security-checks.md#private-local-fuzz-evidence)
for replay, minimizing and corpus promotion, and the [larger structured
tests](../../../docs/dev/security-checks.md#larger-structured-tests) for
inputs above these limits.
